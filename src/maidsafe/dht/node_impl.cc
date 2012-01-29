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
#include <map>

#include "maidsafe/common/alternative_store.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/transport/tcp_transport.h"

#include "maidsafe/dht/log.h"
#include "maidsafe/dht/node_impl.h"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/dht/kademlia.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/dht/node_id.h"
#include "maidsafe/dht/rpcs.h"
#include "maidsafe/dht/return_codes.h"
#include "maidsafe/dht/routing_table.h"
#include "maidsafe/dht/service.h"
#include "maidsafe/dht/utils.h"

namespace arg = std::placeholders;

namespace maidsafe {
namespace dht {

namespace {
bool FindResultError(int result) {
  return (result != kSuccess &&
          result != kFoundAlternativeStoreHolder &&
          result != kFailedToFindValue);
}
}  // unnamed namespace

NodeImpl::NodeImpl(AsioService &asio_service,                 // NOLINT (Fraser)
                   TransportPtr listening_transport,
                   MessageHandlerPtr message_handler,
                   KeyPairPtr default_asym_key_pair,
                   AlternativeStorePtr alternative_store)
    : asio_service_(asio_service),
      listening_transport_(listening_transport),
      message_handler_(message_handler),
      default_public_key_(),
      default_private_key_(),
      alternative_store_(alternative_store),
      on_online_status_change_(new OnOnlineStatusChangePtr::element_type),
      kDataStoreCheckInterval_(bptime::seconds(1)),
      service_(),
      routing_table_(),
      rpcs_(),
      contact_validation_getter_(std::bind(&StubContactValidationGetter,
                                           arg::_1, arg::_2)),
      contact_validator_(std::bind(&StubContactValidator, arg::_1, arg::_2,
                                   arg::_3)),
      validate_functor_(std::bind(&StubValidate, arg::_1, arg::_2, arg::_3)),
      contact_(),
      joined_(false),
      ping_oldest_contact_(),
      validate_contact_(),
      ping_down_contact_(),
      refresh_data_store_timer_(asio_service_) {
  if (default_asym_key_pair) {
    default_private_key_ = PrivateKeyPtr(
        new asymm::PrivateKey(default_asym_key_pair->private_key));
    default_public_key_ = PublicKeyPtr(
        new asymm::PublicKey(default_asym_key_pair->public_key));
  }
}

NodeImpl::~NodeImpl() {
  if (joined_)
    Leave(NULL);
}

void NodeImpl::Join(const NodeId &node_id,
                    std::vector<Contact> bootstrap_contacts,
                    JoinFunctor callback) {
  if (joined_) {
    asio_service_.post(std::bind(&NodeImpl::JoinSucceeded, this, callback));
    return;
  }

  // Remove our own Contact if present
  bootstrap_contacts.erase(
      std::remove_if(bootstrap_contacts.begin(), bootstrap_contacts.end(),
          std::bind(&HasId, arg::_1, node_id)), bootstrap_contacts.end());

  if (!client_only_node_ && listening_transport_->listening_port() == 0) {
    return asio_service_.post(std::bind(&NodeImpl::JoinFailed, this, callback,
                                        kNotListening));
  }

  // TODO(Viv) Remove Pub Key From Class Member and take in as Argument
  if (!default_private_key_ || !default_public_key_) {
    DLOG(INFO) << "Creating Keypair";
    asymm::Keys key_pair;
    asymm::GenerateKeyPair(&key_pair);
    default_private_key_.reset(new asymm::PrivateKey(key_pair.private_key));
    default_public_key_.reset(new asymm::PublicKey(key_pair.public_key));
  } else {
    DLOG(INFO) << EncodeToHex(node_id.String());
  }

  if (!rpcs_) {
    rpcs_.reset(new Rpcs<transport::TcpTransport>(asio_service_,
                                                  default_private_key_));
  }

  // TODO(Fraser#5#): 2011-07-08 - Need to update code for local endpoints.
  if (!client_only_node_) {
    std::vector<transport::Endpoint> local_endpoints;
    // Create contact_ information for node and set contact for Rpcs
    transport::Endpoint endpoint;
    endpoint.ip = listening_transport_->transport_details().endpoint.ip;
    endpoint.port = listening_transport_->transport_details().endpoint.port;
    local_endpoints.push_back(endpoint);
    contact_ =
        Contact(node_id, endpoint, local_endpoints,
                listening_transport_->transport_details().rendezvous_endpoint,
                false, false, node_id.String(),
                *default_public_key_, "");
    rpcs_->set_contact(contact_);
  } else {
    contact_ = Contact(node_id, transport::Endpoint(),
                       std::vector<transport::Endpoint>(),
                       transport::Endpoint(), false, false,
                       node_id.String(),
                       *default_public_key_, "");
    protobuf::Contact proto_contact(ToProtobuf(contact_));
    proto_contact.set_node_id(NodeId().String());
    rpcs_->set_contact(FromProtobuf(proto_contact));
  }

  routing_table_.reset(new RoutingTable(node_id, k_));
  // Connect the slots to the routing table signals.
  ConnectValidateContact();
  ConnectPingDownContact();

  if (bootstrap_contacts.empty()) {
    // This is the first node on the network.
    asio_service_.post(std::bind(&NodeImpl::JoinSucceeded, this, callback));
    return;
  }

  // Ensure bootstrap contacts are valid
  bootstrap_contacts.erase(std::remove(bootstrap_contacts.begin(),
                                       bootstrap_contacts.end(), Contact()),
                           bootstrap_contacts.end());
  if (bootstrap_contacts.empty()) {
    return asio_service_.post(std::bind(&NodeImpl::JoinFailed, this, callback,
                                        kInvalidBootstrapContacts));
  }

  OrderedContacts search_contacts(CreateOrderedContacts(node_id));
  search_contacts.insert(bootstrap_contacts.front());
  bootstrap_contacts.erase(bootstrap_contacts.begin());
  FindValueArgsPtr find_value_args(
      new FindValueArgs(node_id, k_, search_contacts, true,
                        default_private_key_,
                        std::bind(&NodeImpl::JoinFindValueCallback, this,
                                  arg::_1, bootstrap_contacts, node_id,
                                  callback, true)));

  DLOG(INFO) << "Before StartLookup";
  StartLookup(find_value_args);
}

void NodeImpl::JoinFindValueCallback(FindValueReturns find_value_returns,
                                     std::vector<Contact> bootstrap_contacts,
                                     const NodeId &node_id,
                                     JoinFunctor callback,
                                     bool none_reached) {

  if (none_reached && !NodeContacted(find_value_returns.return_code) &&
      bootstrap_contacts.empty()) {
    JoinFailed(callback, kContactFailedToRespond);
  } else if ((find_value_returns.return_code != kFailedToFindValue) &&
             !bootstrap_contacts.empty()) {
    if (NodeContacted(find_value_returns.return_code))
      none_reached = false;
    OrderedContacts search_contacts(CreateOrderedContacts(node_id));
    search_contacts.insert(bootstrap_contacts.front());
    bootstrap_contacts.erase(bootstrap_contacts.begin());
    FindValueArgsPtr find_value_args(
        new FindValueArgs(node_id, k_, search_contacts, true,
            default_private_key_, std::bind(&NodeImpl::JoinFindValueCallback,
                                         this, arg::_1, bootstrap_contacts,
                                         node_id, callback, none_reached)));
    StartLookup(find_value_args);
  } else {
    JoinSucceeded(callback);
  }
}

void NodeImpl::JoinSucceeded(JoinFunctor callback) {
  joined_ = true;
  if (!client_only_node_) {
    service_.reset(new Service(routing_table_,
                               alternative_store_, default_private_key_, k_));
    service_->set_node_joined(true);
    service_->set_node_contact(contact_);
    service_->ConnectToSignals(message_handler_);
    service_->set_contact_validation_getter(contact_validation_getter_);
    service_->set_contact_validator(contact_validator_);
    service_->set_validate(validate_functor_);
  }
  callback(kSuccess);
}

void NodeImpl::JoinFailed(JoinFunctor callback, int result) {
  callback(result);
}

void NodeImpl::Leave(std::vector<Contact> *bootstrap_contacts) {
  joined_ = false;
  refresh_data_store_timer_.cancel();
  ping_oldest_contact_.disconnect();
  validate_contact_.disconnect();
  ping_down_contact_.disconnect();
  if (!client_only_node_)
    service_.reset();
  GetBootstrapContacts(bootstrap_contacts);
}


template <>
void NodeImpl::NotJoined<FindNodesFunctor> (FindNodesFunctor callback) {
  callback(kNotJoined, std::vector<Contact>());
}

template <>
void NodeImpl::NotJoined<GetContactFunctor> (GetContactFunctor callback) {
  callback(kNotJoined, Contact());
}

template <typename T>
void NodeImpl::FailedValidation(T callback) {
  callback(kFailedValidation);
}

OrderedContacts NodeImpl::GetClosestContactsLocally(
    const Key &key,
    const uint16_t &total_contacts) {
  std::vector<Contact> close_nodes, excludes;
  routing_table_->GetCloseContacts(key, total_contacts, excludes, &close_nodes);
  OrderedContacts close_contacts(CreateOrderedContacts(close_nodes.begin(),
                                                       close_nodes.end(), key));
  // This node's ID will not be held in the routing table, so add it now.  The
  // iterative lookup will take care of the (likely) case that it's not within
  // the requested number of closest contacts.
  if (!client_only_node_)
    close_contacts.insert(contact_);
  return close_contacts;
}

void NodeImpl::FindValue(const Key &key,
                         PrivateKeyPtr private_key,
                         FindValueFunctor callback,
                         const uint16_t &extra_contacts,
                         bool cache) {
  if (!joined_) {
    return asio_service_.post(std::bind(&NodeImpl::NotJoined<FindValueFunctor>,
                                        this, callback));
  }
  if (!private_key)
    private_key = default_private_key_;
  OrderedContacts close_contacts(
      GetClosestContactsLocally(key, k_ + extra_contacts));

  // If this node is not client-only & is within the k_ closest do a local find.
  if (!client_only_node_) {
    uint16_t closest_count(0);
    auto itr(close_contacts.begin());
    while (itr != close_contacts.end() && closest_count != k_) {
      if (*itr == contact_) {
        std::vector<Contact> contacts;
        if (alternative_store_ && alternative_store_->Has(key.String())) {
          FindValueReturns find_value_returns(kFoundAlternativeStoreHolder,
                                              contacts,
                                              contact_, Contact());
          asio_service_.post(std::bind(&NodeImpl::FoundValueLocally, this,
                                       find_value_returns, callback));
          return;
        }
      }
      ++itr;
      ++closest_count;
    }
  }

  FindValueArgsPtr find_value_args(new FindValueArgs(key, k_ + extra_contacts,
      close_contacts, cache, private_key, callback));
  StartLookup(find_value_args);
}

void NodeImpl::FoundValueLocally(const FindValueReturns &find_value_returns,
                                 FindValueFunctor callback) {
  callback(find_value_returns);
}

void NodeImpl::FindNodes(const Key &key,
                         FindNodesFunctor callback,
                         const uint16_t &extra_contacts) {
  if (!joined_) {
    return asio_service_.post(std::bind(&NodeImpl::NotJoined<FindNodesFunctor>,
                                        this, callback));
  }
  OrderedContacts close_contacts(
      GetClosestContactsLocally(key, k_ + extra_contacts));
  FindNodesArgsPtr find_nodes_args(new FindNodesArgs(key, k_ + extra_contacts,
      close_contacts, default_private_key_, callback));
  StartLookup(find_nodes_args);
}

void NodeImpl::GetContact(const NodeId &node_id, GetContactFunctor callback) {
  if (node_id == contact_.node_id()) {
    asio_service_.post(std::bind(&NodeImpl::GetOwnContact, this, callback));
    return;
  }

  if (!joined_) {
    return asio_service_.post(std::bind(&NodeImpl::NotJoined<GetContactFunctor>,
                                        this, callback));
  }

  std::vector<Contact> close_nodes, excludes;
  routing_table_->GetCloseContacts(node_id, k_, excludes, &close_nodes);
  OrderedContacts close_contacts(CreateOrderedContacts(close_nodes.begin(),
                                                       close_nodes.end(),
                                                       node_id));
  // If we have the contact in our own routing table, ping it, otherwise start
  // a lookup for it.
  if ((*close_contacts.begin()).node_id() == node_id) {
    rpcs_->Ping(default_private_key_,
                *close_contacts.begin(),
                std::bind(&NodeImpl::GetContactPingCallback, this, arg::_1,
                          arg::_2, *close_contacts.begin(), callback));
  } else {
    GetContactArgsPtr get_contact_args(
        new GetContactArgs(node_id, k_, close_contacts, default_private_key_,
                           callback));
    StartLookup(get_contact_args);
  }
}

void NodeImpl::SetContactValidationGetter(
    asymm::GetPublicKeyAndValidationFunctor contact_validation_getter) {
  contact_validation_getter_ = contact_validation_getter;
  if (service_)
    service_->set_contact_validation_getter(contact_validation_getter_);
}

void NodeImpl::SetContactValidator(
    asymm::ValidatePublicKeyFunctor contact_validator) {
  contact_validator_ = contact_validator;
  if (service_)
    service_->set_contact_validator(contact_validator_);
}

void NodeImpl::SetValidate(asymm::ValidateFunctor validate_functor) {
  validate_functor_ = validate_functor;
  if (service_)
    service_->set_validate(validate_functor_);
}

void NodeImpl::GetOwnContact(GetContactFunctor callback) {
  callback(kSuccess, contact_);
}

void NodeImpl::GetContactPingCallback(RankInfoPtr rank_info,
                                      int result,
                                      Contact peer,
                                      GetContactFunctor callback) {
  AsyncHandleRpcCallback(peer, rank_info, result);
  if (result == kSuccess)
    callback(kSuccess, peer);
  else
    callback(kFailedToGetContact, Contact());
}

void NodeImpl::Ping(const Contact &contact, PingFunctor callback) {
  if (!joined_) {
    return asio_service_.post(std::bind(&NodeImpl::NotJoined<PingFunctor>,
                                        this, callback));
  }
  rpcs_->Ping(default_private_key_,
              contact,
              std::bind(&NodeImpl::PingCallback, this, arg::_1, arg::_2,
                        contact, callback));
}

void NodeImpl::PingCallback(RankInfoPtr rank_info,
                            int result,
                            Contact peer,
                            PingFunctor callback) {
  AsyncHandleRpcCallback(peer, rank_info, result);
  callback(result);
}

void NodeImpl::IncrementFailedRpcs(const Contact &contact) {
  routing_table_->IncrementFailedRpcCount(contact.node_id());
}

void NodeImpl::UpdateRankInfo(const Contact &contact, RankInfoPtr rank_info) {
  routing_table_->UpdateRankInfo(contact.node_id(), rank_info);
}

RankInfoPtr NodeImpl::GetLocalRankInfo(const Contact &contact) const {
  return routing_table_->GetLocalRankInfo(contact);
}

void NodeImpl::GetAllContacts(std::vector<Contact> *contacts) {
  routing_table_->GetAllContacts(contacts);
}

void NodeImpl::GetBootstrapContacts(std::vector<Contact> *contacts) {
  if (!contacts)
    return;
  routing_table_->GetBootstrapContacts(contacts);

  // Allow time to validate and add the first node on the network in the case
  // where this node is the second.
  int attempts(0);
  const int kMaxAttempts(50);
  while (attempts != kMaxAttempts && contacts->empty()) {
    Sleep(bptime::milliseconds(100));
    routing_table_->GetBootstrapContacts(contacts);
    ++attempts;
  }

  if (contacts->empty())
    contacts->push_back(contact_);
}

void NodeImpl::StartLookup(LookupArgsPtr lookup_args) {
  BOOST_ASSERT(lookup_args->kNumContactsRequested >= k_);
  boost::mutex::scoped_lock lock(lookup_args->mutex);
  DoLookupIteration(lookup_args);
}

void NodeImpl::DoLookupIteration(LookupArgsPtr lookup_args) {

}

void NodeImpl::IterativeFindCallback(
    RankInfoPtr rank_info,
    int result,
    const std::vector<Contact> &contacts,
    const Contact &alternative_store,
    Contact peer,
    LookupArgsPtr lookup_args) {
  // It is only OK for a node to return no meaningful information if this is
  // the second to join the network (peer being the first)
  boost::mutex::scoped_lock lock(lookup_args->mutex);
  bool second_node(false);
  if (result == kIterativeLookupFailed &&
      lookup_args->lookup_contacts.size() == 1) {
    result = kSuccess;
    second_node = true;
  }

  AsyncHandleRpcCallback(peer, rank_info, result);
  auto this_peer(lookup_args->lookup_contacts.find(peer));
  --lookup_args->total_lookup_rpcs_in_flight;
  BOOST_ASSERT(lookup_args->total_lookup_rpcs_in_flight >= 0);
  if (this_peer == lookup_args->lookup_contacts.end()) {
    DLOG(ERROR) << DebugId(contact_) << ": Can't find " << DebugId(peer)
                << " in lookup args.";
    return;
  }

  // Note - if the RPC isn't from this iteration, it will be marked as kDelayed.
  if ((*this_peer).second.rpc_state == ContactInfo::kSent)
    --lookup_args->rpcs_in_flight_for_current_iteration;

  // If the RPC returned an error, remove peer 
  if (FindResultError(result)) {
    lookup_args->lookup_contacts.erase(this_peer);
  }

  // If DoLookupIteration didn't send any RPCs, this will hit -1.
  BOOST_ASSERT(lookup_args->rpcs_in_flight_for_current_iteration >= -1);

  // If we should stop early (found value, or found single contact), do so.
  if (AbortLookup(result, contacts, alternative_store,
                  peer, second_node, lookup_args))
    return;

  // Handle result if RPC was successful.
  auto shortlist_upper_bound(lookup_args->lookup_contacts.begin());
  if (FindResultError(result)) {
    shortlist_upper_bound = GetShortlistUpperBound(lookup_args);
  } else {
    (*this_peer).second.rpc_state = ContactInfo::kRepliedOK;
    OrderedContacts close_contacts(CreateOrderedContacts(contacts.begin(),
        contacts.end(), lookup_args->kTarget));
    shortlist_upper_bound = InsertCloseContacts(close_contacts, lookup_args,
                                                this_peer);
  }

  // Check to see if the lookup phase and/or iteration is now finished.
  bool iteration_complete(false);
  int shortlist_ok_count(0);

  // If the lookup phase is marked complete, but we still have <
  // kNumContactsRequested then try to get more contacts from the local routing
  // table.
  if (lookup_args->lookup_phase_complete &&
      shortlist_ok_count != lookup_args->kNumContactsRequested) {
    std::vector<Contact> close_nodes, excludes;
    excludes.reserve(shortlist_ok_count + lookup_args->downlist.size());
    auto shortlist_itr(lookup_args->lookup_contacts.begin());
    while (shortlist_itr != lookup_args->lookup_contacts.end())
      excludes.push_back((*shortlist_itr++).first);
    auto downlist_itr(lookup_args->downlist.begin());
    while (downlist_itr != lookup_args->downlist.end())
      excludes.push_back((*downlist_itr++).first);
    routing_table_->GetCloseContacts(lookup_args->kTarget, k_, excludes,
                                     &close_nodes);
    if (!close_nodes.empty()) {
      OrderedContacts close_contacts(
          CreateOrderedContacts(close_nodes.begin(), close_nodes.end(),
                                lookup_args->kTarget));
      shortlist_upper_bound =
          InsertCloseContacts(close_contacts, lookup_args,
                              lookup_args->lookup_contacts.end());
      lookup_args->lookup_phase_complete = false;
    } else {
      DLOG(WARNING) << DebugId(contact_) << ": Lookup is returning only "
                    << shortlist_ok_count << " contacts (k is " << k_ << ").";
    }
  }

  // If the lookup phase is still not finished, set cache candidate and start
  // next iteration if due.
  if (!lookup_args->lookup_phase_complete) {
    if (!FindResultError(result))
      lookup_args->cache_candidate = (*this_peer).first;
    if (iteration_complete)
      DoLookupIteration(lookup_args);
    return;
  }
}

bool NodeImpl::AbortLookup(
    int result,
    const std::vector<Contact> &contacts,
    const Contact &alternative_store,
    const Contact &peer,
    bool second_node,
    LookupArgsPtr lookup_args) {
  if (lookup_args->kOperationType == LookupArgs::kFindValue) {
    // If the value was returned, or the peer claimed to have the value in its
    // alternative store, we're finished with the lookup.
    if (result == kSuccess || result == kFoundAlternativeStoreHolder ||
        second_node) {

      FindValueReturns find_value_returns(result,
                                          contacts, alternative_store,
                                          lookup_args->cache_candidate);
      lookup_args->lookup_phase_complete = true;
      std::static_pointer_cast<FindValueArgs>(lookup_args)->callback(
          find_value_returns);
      // TODO(Fraser#5#): 2011-08-16 - Send value to cache_candidate here.
//      if (std::static_pointer_cast<FindValueArgs>(lookup_args)->cache)
    }
    return lookup_args->lookup_phase_complete;
  } else if (lookup_args->kOperationType == LookupArgs::kGetContact) {
    // If the peer is the target, we're finished with the lookup, whether the
    // RPC timed out or not.
    if (peer.node_id() == lookup_args->kTarget) {
      lookup_args->lookup_phase_complete = true;
      if (result == kSuccess) {
        std::static_pointer_cast<GetContactArgs>(lookup_args)->callback(
            kSuccess, peer);
      } else {
        std::static_pointer_cast<GetContactArgs>(lookup_args)->callback(
            kFailedToGetContact, Contact());
      }
    }
    return lookup_args->lookup_phase_complete;
  }
  return false;
}

LookupContacts::iterator NodeImpl::GetShortlistUpperBound(
    LookupArgsPtr lookup_args) {
  uint16_t count(0);
  auto shortlist_upper_bound(lookup_args->lookup_contacts.begin());
  while (count != lookup_args->kNumContactsRequested &&
         shortlist_upper_bound != lookup_args->lookup_contacts.end()) {
    ++shortlist_upper_bound;
    ++count;
  }
  return shortlist_upper_bound;
}

LookupContacts::iterator NodeImpl::InsertCloseContacts(
    const OrderedContacts &contacts,
    LookupArgsPtr lookup_args,
    LookupContacts::iterator this_peer) {
  if (!contacts.empty()) {
    auto existing_contacts_itr(lookup_args->lookup_contacts.begin());
    auto new_contacts_itr(contacts.begin());
    auto insertion_point(lookup_args->lookup_contacts.end());
    ContactInfo contact_info;
    if (existing_contacts_itr != lookup_args->lookup_contacts.end()) {
      if (this_peer != lookup_args->lookup_contacts.end())
        contact_info = ContactInfo((*this_peer).first);
      while ((new_contacts_itr != contacts.end()) &&
             (existing_contacts_itr != lookup_args->lookup_contacts.end())) {
        if (contacts.key_comp()((*existing_contacts_itr).first,
                                 *new_contacts_itr)) {
          insertion_point = existing_contacts_itr++;
        } else if (contacts.key_comp()(*new_contacts_itr,
                                       (*existing_contacts_itr).first)) {
          insertion_point = lookup_args->lookup_contacts.insert(
              insertion_point, std::make_pair(*new_contacts_itr++,
                                              contact_info));
        } else {
          insertion_point = existing_contacts_itr;
          if (this_peer != lookup_args->lookup_contacts.end()) {
            (*existing_contacts_itr++).second.providers.push_back(
                (*this_peer).first);
          }
          ++new_contacts_itr;
        }
      }
    }
    while (new_contacts_itr != contacts.end()) {
      insertion_point = lookup_args->lookup_contacts.insert(
          insertion_point, std::make_pair(*new_contacts_itr++,
                                          contact_info));
    }
  }
  auto itr = lookup_args->lookup_contacts.find(contact_);
  if (itr != lookup_args->lookup_contacts.end() && !client_only_node_) {
    (*itr).second.rpc_state = ContactInfo::kRepliedOK;
  }
  return GetShortlistUpperBound(lookup_args);
}


bool NodeImpl::NodeContacted(const int &code) {
  switch (code) {
    case transport::kError:
    case transport::kSendFailure:
    case transport::kSendTimeout:
    case transport::kSendStalled:
    case kIterativeLookupFailed:
      return false;
    default:
      return true;
  }
}



void NodeImpl::ValidateContact(const Contact &contact) {
  asymm::GetPublicKeyAndValidationCallback callback(
      std::bind(&NodeImpl::ValidateContactCallback, this, contact, arg::_1,
                arg::_2));
  contact_validation_getter_(contact.public_key_id(), callback);
}

void NodeImpl::ValidateContactCallback(
    Contact contact,
    asymm::PublicKey public_key,
    asymm::ValidationToken public_key_validation) {
  bool valid = contact_validator_(contact.public_key_id(),
                                  public_key, public_key_validation);
  routing_table_->SetValidated(contact.node_id(), valid);
}

void NodeImpl::ConnectValidateContact() {
  if (validate_contact_ == boost::signals2::connection()) {
    validate_contact_ = routing_table_->validate_contact()->connect(
        std::bind(&NodeImpl::ValidateContact, this, arg::_1));
  }
}

void NodeImpl::PingDownContact(const Contact &down_contact) {
  rpcs_->Ping(default_private_key_,
              down_contact,
              std::bind(&NodeImpl::PingDownContactCallback, this,
                        down_contact, arg::_1, arg::_2));
}

void NodeImpl::PingDownContactCallback(Contact down_contact,
                                       RankInfoPtr rank_info,
                                       const int &result) {
  if (result != kSuccess) {
    // Increment failed RPC count until down contact is removed from the routing
    // table
    for (int i = 0, result = 0;
        result != kFailedToFindContact && i < kFailedRpcTolerance + 1; ++i)
      result = routing_table_->IncrementFailedRpcCount(down_contact.node_id());
  } else {
    // Add the contact again to update its last_seen to now
    routing_table_->AddContact(down_contact, rank_info);
  }
}

void NodeImpl::ConnectPingDownContact() {
  if (ping_down_contact_ == boost::signals2::connection()) {
    ping_down_contact_ = routing_table_->ping_down_contact()->connect(
        std::bind(&NodeImpl::PingDownContact, this, arg::_1));
  }
}

void NodeImpl::HandleRpcCallback(const Contact &contact,
                                 RankInfoPtr rank_info,
                                 const int &result) {
  int routing_table_result(kSuccess);
  if (!FindResultError(result)) {
    // Add the contact to update its last_seen to now
    routing_table_result = routing_table_->AddContact(contact, rank_info);
  } else {
    routing_table_result =
        routing_table_->IncrementFailedRpcCount(contact.node_id());
  }
#ifdef DEBUG
  if (routing_table_result != kSuccess)
    DLOG(INFO) << DebugId(contact_) << ": Failed to update routing table for "
               << "contact " << DebugId(contact) << ".  RPC result: " << result
               << "  Update result: " << routing_table_result;
#endif
}

void NodeImpl::AsyncHandleRpcCallback(const Contact &contact,
                                      RankInfoPtr rank_info,
                                      const int &result) {
  asio_service_.post(std::bind(&NodeImpl::HandleRpcCallback, this, contact,
                               rank_info, result));
}

}  // namespace dht
}  // namespace maidsafe
