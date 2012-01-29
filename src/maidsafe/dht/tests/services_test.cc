/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <algorithm>
#include <functional>
#include <set>
#include <utility>
#include <bitset>

#include "boost/lexical_cast.hpp"
#include "boost/thread.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/alternative_store.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/dht/log.h"
#include "maidsafe/dht/service.h"
#include "maidsafe/dht/message_handler.h"
#include "maidsafe/dht/routing_table.h"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/dht/rpcs.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/dht/utils.h"
#include "maidsafe/dht/return_codes.h"
#include "maidsafe/dht/tests/test_utils.h"

namespace arg = std::placeholders;

namespace maidsafe {

namespace dht {

namespace test {

namespace {

const uint16_t g_kKademliaK = 16;

boost::posix_time::time_duration time_out = transport::kDefaultInitialTimeout;

inline void CreateRSAKeys(std::string *public_key, std::string *private_key) {
  asymm::Keys kp;
  asymm::GenerateKeyPair(&kp);
  asymm::EncodePublicKey(kp.public_key, public_key);
  asymm::EncodePrivateKey(kp.private_key, private_key);
}

}  // unnamed namespace

class MockTransportServiceTest : public transport::Transport {
 public:
  explicit MockTransportServiceTest(boost::asio::io_service &asio_service)  // NOLINT
      : transport::Transport(asio_service) {}
  virtual transport::TransportCondition StartListening(
      const transport::Endpoint &) { return transport::kSuccess; }
  virtual transport::TransportCondition Bootstrap(
      const std::vector<transport::Endpoint> &) {
    return transport::kSuccess;
  }
  virtual void StopListening() {}
  virtual void Send(const std::string &,
                    const transport::Endpoint &,
                    const transport::Timeout &) {}
};

class AlternativeStoreTrue: public AlternativeStore {
 public:
  virtual ~AlternativeStoreTrue() {}
  virtual bool Has(
      const std::string&,
      const ValidationData& = ValidationData()) const {
    return true;
  }
};

class AlternativeStoreFalse: public AlternativeStore {
 public:
  virtual ~AlternativeStoreFalse() {}
  virtual bool Has(
      const std::string&,
      const ValidationData& = ValidationData()) const {
    return false;
  }
};

typedef std::shared_ptr<AlternativeStoreTrue> AlternativeStoreTruePtr;
typedef std::shared_ptr<AlternativeStoreFalse> AlternativeStoreFalsePtr;

class ServicesTest: public CreateContactAndNodeId, public testing::Test {
 public:
  ServicesTest()
      : CreateContactAndNodeId(g_kKademliaK),
        contact_(),
        node_id_(NodeId::kRandomId),
        routing_table_(new RoutingTable(node_id_, g_kKademliaK)),
        alternative_store_(),
        key_pair_(new asymm::Keys()),
        info_(),
        rank_info_(),
        service_(new Service(routing_table_, alternative_store_,
                             GetPrivateKeyPtr(key_pair_), g_kKademliaK)),
        num_of_pings_(0) {
    service_->set_node_joined(true);
    service_->set_contact_validation_getter(std::bind(
        &DummyContactValidationGetter, arg::_1, arg::_2));
  }

  virtual void SetUp() {}

  PrivateKeyPtr GetPrivateKeyPtr(KeyPairPtr key_pair) {
    return PrivateKeyPtr(new asymm::PrivateKey(key_pair->private_key));
  }

  void FakePingContact(Contact /*contact*/) {
    ++num_of_pings_;
  }

  void Clear() {
    routing_table_->Clear();
    num_of_pings_ = 0;
  }

  void CheckServiceConstructAttributes(const Service& service, uint16_t k) {
    EXPECT_EQ(0U, service.routing_table_->Size());
    EXPECT_FALSE(service.node_joined_);
    EXPECT_EQ(k, service.k_);
  }


  void DoOps(std::function<bool()> ops, bool expectation, std::string op) {
    EXPECT_EQ(expectation, ops()) <<"For: " << op;
  }

  virtual void TearDown() {}

 protected:

  void PopulateRoutingTable(uint16_t count) {
    for (int num_contact = 0; num_contact < count; ++num_contact) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(routing_table_, contact, rank_info_);
    }
  }
  void PopulateRoutingTable(uint16_t count, uint16_t pos) {
    for (int num_contact = 0; num_contact < count; ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(node_id_, pos);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(routing_table_, contact, rank_info_);
    }
  }

  size_t GetRoutingTableSize() const {
    return routing_table_->Size();
  }

  size_t CountUnValidatedContacts() const {
    return routing_table_->unvalidated_contacts_.size();
  }

  size_t CountPendingOperations() const {
    return 0;
  }




  Contact contact_;
  NodeId node_id_;
  std::shared_ptr<RoutingTable> routing_table_;
  AlternativeStorePtr alternative_store_;
  KeyPairPtr key_pair_;
  transport::Info info_;
  RankInfoPtr rank_info_;
  std::shared_ptr<Service> service_;
  int num_of_pings_;
};


TEST_F(ServicesTest, BEH_FindNodes) {
  NodeId target_id = GenerateUniqueRandomId(node_id_, 503);
  Contact target = ComposeContact(target_id, 5001);
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact sender = ComposeContact(sender_id, 5001);

  protobuf::FindNodesRequest find_nodes_req;
  find_nodes_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
  find_nodes_req.set_key(target_id.String());
  {
    service_->set_node_joined(false);
    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp, &time_out);
    EXPECT_FALSE(find_nodes_rsp.result());
    service_->set_node_joined(true);
  }
  {
    // try to find a node from an empty routing table
    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp, &time_out);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(0U, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();
  {
    // try to find the target from an k/2 filled routing table
    // (not containing the target)
    PopulateRoutingTable(g_kKademliaK / 2);
    EXPECT_EQ(g_kKademliaK / 2, GetRoutingTableSize());

    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp, &time_out);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(g_kKademliaK / 2, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(g_kKademliaK / 2, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();
  {
    // try to find the target from a 2*k filled routing table
    // (not containing the target)
    PopulateRoutingTable(g_kKademliaK, 500);
    PopulateRoutingTable(g_kKademliaK, 501);
    EXPECT_EQ(2 * g_kKademliaK, GetRoutingTableSize());

    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp, &time_out);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(g_kKademliaK, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(2 * g_kKademliaK, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();
  {
    // try to find the target from a 2*k filled routing table
    // (containing the target)
    PopulateRoutingTable(g_kKademliaK, 500);
    PopulateRoutingTable(g_kKademliaK - 1, 501);
    AddContact(routing_table_, target, rank_info_);
    EXPECT_EQ(2 * g_kKademliaK, GetRoutingTableSize());

    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp, &time_out);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(g_kKademliaK, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(2 * g_kKademliaK, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
    // the target must be contained in the response's closest_nodes
    bool target_exist(false);
    for (int i = 0; i < find_nodes_rsp.closest_nodes_size(); ++i) {
      Contact current(FromProtobuf(find_nodes_rsp.closest_nodes(i)));
      if (current.node_id() == target_id)
        target_exist = true;
    }
    ASSERT_EQ(true, target_exist);
  }
  Clear();
  {
    // try to find the target from a 2*k+1 filled routing table
    // (containing the sender, but not containing the target)
    PopulateRoutingTable(g_kKademliaK, 500);
    PopulateRoutingTable(g_kKademliaK, 501);
    AddContact(routing_table_, sender, rank_info_);
    EXPECT_EQ(2 * g_kKademliaK + 1, GetRoutingTableSize());

    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp, &time_out);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(g_kKademliaK, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(2 * g_kKademliaK + 1, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }

  Clear();
  {
    // try to find the target from a 2*k filled routing table
    // where num_nodes_requested < g_kKademliaK, it should return
    // g_kKademliaK contacts
    PopulateRoutingTable(g_kKademliaK, 500);
    PopulateRoutingTable(g_kKademliaK, 501);
    EXPECT_EQ(2 * g_kKademliaK, GetRoutingTableSize());

    protobuf::FindNodesResponse find_nodes_rsp;
    find_nodes_req.set_num_nodes_requested(g_kKademliaK/2);
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp, &time_out);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(g_kKademliaK, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(2 * g_kKademliaK, GetRoutingTableSize());
  }
  Clear();
  {
    // try to find the target from a 2*k filled routing table
    // where num_nodes_requested > g_kKademliaK, it should return
    // num_nodes_requested contacts
    PopulateRoutingTable(g_kKademliaK, 500);
    PopulateRoutingTable(g_kKademliaK, 501);
    EXPECT_EQ(2 * g_kKademliaK, GetRoutingTableSize());

    protobuf::FindNodesResponse find_nodes_rsp;
    find_nodes_req.set_num_nodes_requested(g_kKademliaK*3/2);
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp, &time_out);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(g_kKademliaK*3/2, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(2 * g_kKademliaK, GetRoutingTableSize());
  }
}

}  // namespace test_service

}  // namespace dht

}  // namespace maidsafe
