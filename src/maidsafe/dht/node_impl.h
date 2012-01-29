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

#ifndef MAIDSAFE_DHT_NODE_IMPL_H_
#define MAIDSAFE_DHT_NODE_IMPL_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "boost/asio/io_service.hpp"
#include "boost/asio/deadline_timer.hpp"
#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "boost/signals2/connection.hpp"
#include "boost/thread/shared_mutex.hpp"
#include "boost/thread/locks.hpp"
#include "boost/filesystem.hpp"

#include "maidsafe/dht/node_impl_structs.h"
#include "maidsafe/dht/config.h"
#include "maidsafe/dht/node-api.h"
#include "maidsafe/dht/contact.h"
#include "maidsafe/dht/node_container.h"

namespace bptime = boost::posix_time;
namespace bf = boost::filesystem3;
namespace maidsafe {

namespace dht {

struct KeyValueTuple;
class Service;
class RoutingTable;
template <typename T>
class Rpcs;

class NodeImpl {
 public:
  NodeImpl(AsioService &asio_service,                         // NOLINT (Fraser)
           TransportPtr listening_transport,
           MessageHandlerPtr message_handler);

  // virtual destructor to allow tests to use a derived NodeImpl and befriend it
  // rather than polluting this with friend tests.
  virtual ~NodeImpl();
  bool setConfigPath(bf::path &config_file) { config_file_ = config_file; }
  bf::path ConfigPath() { return config_file_; }
  bool LoadConfig();
  bool WriteConfig();
  void Join();
  void Leave();
  void FindValue(const Key &key,
                 FindValueFunctor callback,
                 const uint16_t &extra_contacts = 0);
  void FindNodes(const Key &key,
                 FindNodesFunctor callback,
                 const uint16_t &extra_contacts = 0);
  void GetContact(const NodeId &node_id, GetContactFunctor callback);
  void SetContactValidationGetter(
      asymm::GetPublicKeyAndValidationFunctor contact_validation_getter);
  void SetContactValidator(asymm::ValidatePublicKeyFunctor contact_validator);
  void SetValidate(asymm::ValidateFunctor validate_functor);
  void Ping(const Contact &contact, PingFunctor callback);
  void GetAllContacts(std::vector<Contact> *contacts);
  void GetBootstrapContacts(std::vector<Contact> *contacts);
  Contact my_contact() const { return my_contact_; }
  bool joined() const { return joined_; }
  OnOnlineStatusChangePtr on_online_status_change() {
    return on_online_status_change_;
  }

  bool client_only_node() const { return client_only_node_; }

  uint16_t k() const { return k_; }

  friend class NodeContainer<maidsafe::dht::NodeImpl>;

 private:
  NodeImpl(const NodeImpl&);
  NodeImpl &operator=(const NodeImpl&);
  void JoinFindValueCallback(FindValueReturns find_value_returns,
                             std::vector<Contact> bootstrap_contacts,
                             const NodeId &node_id,
                             JoinFunctor callback,
                             bool none_reached);
  void JoinSucceeded(JoinFunctor callback);
  void JoinFailed(JoinFunctor callback, int result);

  template <typename T>
  void NotJoined(T callback);

  template <typename T>
  void FailedValidation(T callback);

  OrderedContacts GetClosestContactsLocally(const Key &key,
                                            const uint16_t &total_contacts);

  void FoundValueLocally(const FindValueReturns &find_value_returns,
                         FindValueFunctor callback);

  void PingCallback(RankInfoPtr rank_info,
                    int result,
                    Contact peer,
                    PingFunctor callback);

  void StartLookup(LookupArgsPtr lookup_args);
// probably not needed 
  void ValidateContact(const Contact &contact);


  AsioService &asio_service_;
  TransportPtr listening_transport_;
  MessageHandlerPtr message_handler_;
  PublicKeyPtr default_public_key_;
  PrivateKeyPtr default_private_key_;
  AlternativeStorePtr alternative_store_;
  OnOnlineStatusChangePtr on_online_status_change_;
  bool client_only_node_;
  /** Kademlia k parameter */
  const uint16_t k_;
  /** Kademlia alpha parameter to define how many contacts are to be queried
   *  per lookup iteration */
  const uint16_t kAlpha_;
  /** Kademlia beta parameter to define how many contacts are required to have
   *  responded in a lookup iteration before starting a new iteration */
  const uint16_t kBeta_;
  const bptime::seconds kMeanRefreshInterval_, kDataStoreCheckInterval_;
  std::shared_ptr<Service> service_;
  std::shared_ptr<RoutingTable> routing_table_;
  std::shared_ptr<Rpcs<transport::TcpTransport>> rpcs_;
  asymm::GetPublicKeyAndValidationFunctor contact_validation_getter_;
  asymm::ValidatePublicKeyFunctor contact_validator_;
  asymm::ValidateFunctor validate_functor_;
  Contact my_contact_;
  bool joined_;
  boost::signals2::connection ping_oldest_contact_, validate_contact_,
                              ping_down_contact_;
  boost::asio::deadline_timer refresh_data_store_timer_;
  bf::path config_file_;
};

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_NODE_IMPL_H_
