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

#include <utility>
#include <set>

#include "maidsafe/dht/service.h"

#include "maidsafe/common/alternative_store.h"
#include "maidsafe/common/crypto.h"

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/dht/rpcs.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/dht/message_handler.h"
#include "maidsafe/dht/return_codes.h"
#include "maidsafe/dht/routing_table.h"
#include "maidsafe/dht/utils.h"
#include "maidsafe/dht/log.h"


namespace arg = std::placeholders;

namespace maidsafe {

namespace dht {

Service::Service(std::shared_ptr<RoutingTable> routing_table,
                 AlternativeStorePtr alternative_store,
                 PrivateKeyPtr private_key,
                 const uint16_t &k)
    : routing_table_(routing_table),
      alternative_store_(alternative_store),
      private_key_(private_key),
      node_joined_(false),
      node_contact_(),
      k_(k),
      client_node_id_(NodeId().String()),
      contact_validation_getter_(std::bind(&StubContactValidationGetter,
                                           arg::_1, arg::_2)),
      contact_validator_(std::bind(&StubContactValidator, arg::_1, arg::_2,
                                   arg::_3)),
      validate_functor_(std::bind(&StubValidate, arg::_1, arg::_2, arg::_3)) {}

Service::~Service() {}

void Service::ConnectToSignals(MessageHandlerPtr message_handler) {
  // Connect service to message handler for incoming parsed requests
  message_handler->on_ping_request()->connect(
      MessageHandler::PingReqSigPtr::element_type::slot_type(
          &Service::Ping, this, _1, _2, _3, _4).track_foreign(
              shared_from_this()));
  message_handler->on_find_value_request()->connect(
      MessageHandler::FindValueReqSigPtr::element_type::slot_type(
          &Service::FindValue, this, _1, _2, _3, _4).track_foreign(
              shared_from_this()));
  message_handler->on_find_nodes_request()->connect(
      MessageHandler::FindNodesReqSigPtr::element_type::slot_type(
          &Service::FindNodes, this, _1, _2, _3, _4).track_foreign(
              shared_from_this()));
}

bool Service::CheckParameters(const std::string &method_name,
                              const Key *key,
                              const std::string *message,
                              const std::string *message_signature) const {
  std::string debug_msg(DebugId(node_contact_) + " - in " + method_name + ": ");
  if (!node_joined_) {
    DLOG(WARNING) << debug_msg << ": Not joined.";
    return false;
  }
  if (!private_key_) {
    DLOG(WARNING) << debug_msg << ": NULL private_key.";
    return false;
  }
  if (key && !key->IsValid()) {
    DLOG(WARNING) << debug_msg << ": invalid Kad key.";
    return false;
  }
  if (message && message->empty()) {
    DLOG(WARNING) << debug_msg << ": empty message.";
    return false;
  }
  if (message_signature && message_signature->empty()) {
    DLOG(WARNING) << debug_msg << "signature empty.";
    return false;
  }
  return true;
}

void Service::Ping(const transport::Info &info,
                   const protobuf::PingRequest &request,
                   protobuf::PingResponse *response,
                   transport::Timeout*) {
  response->set_echo("");
  if (!CheckParameters("Ping", NULL, &request.ping()))
    return;
  response->set_echo(request.ping());
  DLOG(INFO) << "\t" << DebugId(node_contact_) << " PING from "
             << DebugId(FromProtobuf(request.sender()));
  AddContactToRoutingTable(FromProtobuf(request.sender()), info);
}

void Service::FindValue(const transport::Info &info,
                        const protobuf::FindValueRequest &request,
                        protobuf::FindValueResponse *response,
                        transport::Timeout*) {
  response->set_result(false);
  Key key(request.key());
  if (!CheckParameters("FindValue", &key))
    return;

  Contact sender(FromProtobuf(request.sender()));

  // Are we the alternative value holder?
  if (alternative_store_ && (alternative_store_->Has(key.String()))) {
    *(response->mutable_alternative_value_holder()) = ToProtobuf(node_contact_);
    response->set_result(true);
    AddContactToRoutingTable(sender, info);
    return;
  }


  size_t num_nodes_requested(k_);
  if (request.has_num_nodes_requested() && request.num_nodes_requested() > k_)
    num_nodes_requested = request.num_nodes_requested();

  std::vector<Contact> closest_contacts, exclude_contacts;
  routing_table_->GetCloseContacts(key, num_nodes_requested,
                                   exclude_contacts, &closest_contacts);
  for (size_t i = 0; i < closest_contacts.size(); ++i)
    (*response->add_closest_nodes()) = ToProtobuf(closest_contacts[i]);

  response->set_result(true);
  AddContactToRoutingTable(sender, info);
}

void Service::FindNodes(const transport::Info &info,
                        const protobuf::FindNodesRequest &request,
                        protobuf::FindNodesResponse *response,
                        transport::Timeout*) {
  response->set_result(false);
  Key key(request.key());
  if (!CheckParameters("FindNodes", &key))
    return;

  size_t num_nodes_requested(k_);
  if (request.has_num_nodes_requested() && request.num_nodes_requested() > k_)
    num_nodes_requested = request.num_nodes_requested();

  std::vector<Contact> closest_contacts, exclude_contacts;
  routing_table_->GetCloseContacts(key, num_nodes_requested, exclude_contacts,
                                   &closest_contacts);
  for (size_t i = 0; i < closest_contacts.size(); ++i)
    *response->add_closest_nodes() = ToProtobuf(closest_contacts[i]);
  response->set_result(true);

  Contact sender(FromProtobuf(request.sender()));
  if (sender.node_id().String() != client_node_id_) {
    routing_table_->AddContact(FromProtobuf(request.sender()),
                               RankInfoPtr(new transport::Info(info)));
  }
}

void Service::AddContactToRoutingTable(const Contact &contact,
                                       const transport::Info &info) {
  if (contact.node_id().String() != client_node_id_) {
#ifdef DEBUG
    int result(routing_table_->AddContact(contact,
               RankInfoPtr(new transport::Info(info))));
    if (result != kSuccess)
      DLOG(ERROR) << DebugId(node_contact_) << ": Failed to add contact "
                  << DebugId(contact) << " (result " << result << ")";
#else
    routing_table_->AddContact(contact, RankInfoPtr(new transport::Info(info)));
#endif
  }
}


}  // namespace dht

}  // namespace maidsafe
