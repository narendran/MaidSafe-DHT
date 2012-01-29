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

#ifndef MAIDSAFE_DHT_RPCS_H_
#define MAIDSAFE_DHT_RPCS_H_

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "boost/tuple/tuple.hpp"

#include "maidsafe/common/utils.h"
#include "maidsafe/transport/transport.h"

#include "maidsafe/dht/node_id.h"
#include "maidsafe/dht/message_handler.h"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/dht/rpcs.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/dht/utils.h"
#include "maidsafe/dht/config.h"
#include "maidsafe/dht/contact.h"
#include "maidsafe/dht/rpcs_objects.h"
#include "maidsafe/dht/log.h"

namespace arg = std::placeholders;


namespace maidsafe {

namespace dht {

typedef std::function<void(RankInfoPtr, const int&)> RpcPingFunctor;
typedef std::function<void(RankInfoPtr,
                           const int&,
                           const std::vector<Contact>&,
                           const Contact&)> RpcFindValueFunctor;
typedef std::function<void(RankInfoPtr,
                           const int&,
                           const std::vector<Contact>&)> RpcFindNodesFunctor;

struct RpcsFailurePeer {
 public:
  RpcsFailurePeer() : peer(), rpcs_failure(1) {}
  Contact peer;
  uint16_t rpcs_failure;
};

template <typename TransportType>
class Rpcs {
 public:
  Rpcs(AsioService &asio_service, PrivateKeyPtr private_key)  // NOLINT (Fraser)
      : asio_service_(asio_service),
        kFailureTolerance_(2),
        contact_(),
        default_private_key_(private_key),
        connected_objects_() {}
  virtual ~Rpcs() {}
  virtual void Ping(PrivateKeyPtr private_key,
                    const Contact &peer,
                    RpcPingFunctor callback);
  virtual void FindValue(const Key &key,
                         const uint16_t &nodes_requested,
                         PrivateKeyPtr private_key,
                         const Contact &peer,
                         RpcFindValueFunctor callback);
  virtual void FindNodes(const Key &key,
                         const uint16_t &nodes_requested,
                         PrivateKeyPtr private_key,
                         const Contact &peer,
                         RpcFindNodesFunctor callback);
  void set_contact(const Contact &contact) { contact_ = contact; }

  virtual void Prepare(PrivateKeyPtr private_key,
                       TransportPtr &transport,
                       MessageHandlerPtr &message_handler);

  std::pair<std::string, std::string> MakeStoreRequestAndSignature(
    const Key &key,
    const std::string &value,
    const std::string &signature,
    const boost::posix_time::seconds &ttl,
    PrivateKeyPtr private_key);

  std::pair<std::string, std::string> MakeDeleteRequestAndSignature(
    const Key &key,
    const std::string &value,
    const std::string &signature,
    PrivateKeyPtr private_key);

 protected:
  AsioService &asio_service_;
  const uint16_t kFailureTolerance_;

 private:
  Rpcs(const Rpcs&);
  Rpcs& operator=(const Rpcs&);
  void PingCallback(const std::string &random_data,
                    const transport::TransportCondition &transport_condition,
                    const transport::Info &info,
                    const protobuf::PingResponse &response,
                    const uint32_t &index,
                    RpcPingFunctor callback,
                    const std::string &message,
                    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);

  void FindValueCallback(
      const transport::TransportCondition &transport_condition,
      const transport::Info &info,
      const protobuf::FindValueResponse &response,
      const uint32_t &index,
      RpcFindValueFunctor callback,
      const std::string &message,
      std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);

  void FindNodesCallback(
      const transport::TransportCondition &transport_condition,
      const transport::Info &info,
      const protobuf::FindNodesResponse &response,
      const uint32_t &index,
      RpcFindNodesFunctor callback,
      const std::string &message,
      std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);


  Contact contact_;
  PrivateKeyPtr default_private_key_;
  ConnectedObjectsList connected_objects_;
};



template <typename TransportType>
void Rpcs<TransportType>::Ping(PrivateKeyPtr private_key,
                               const Contact &peer,
                               RpcPingFunctor callback) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(private_key, transport, message_handler);
  uint32_t object_indx =
      connected_objects_.AddObject(transport, message_handler);

  protobuf::PingRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  std::string random_data(RandomString(50 + (RandomUint32() % 50)));
  request.set_ping(random_data);
  std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer(new RpcsFailurePeer);
  rpcs_failure_peer->peer = peer;
  std::string message(message_handler->WrapMessage(request, peer.public_key()));

  // Connect callback to message handler for incoming parsed response or error
  message_handler->on_ping_response()->connect(
      std::bind(&Rpcs::PingCallback, this, random_data, transport::kSuccess,
                arg::_1, arg::_2, object_indx, callback, message,
                rpcs_failure_peer));
  message_handler->on_error()->connect(
      std::bind(&Rpcs::PingCallback, this, random_data, arg::_1,
                transport::Info(), protobuf::PingResponse(), object_indx,
                callback, message, rpcs_failure_peer));
  DLOG(INFO) << "\t2 " << DebugId(contact_) << " PING to " << DebugId(peer);
  transport->Send(message,
                  peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

template <typename TransportType>
void Rpcs<TransportType>::FindValue(const Key &key,
                                    const uint16_t &nodes_requested,
                                    PrivateKeyPtr private_key,
                                    const Contact &peer,
                                    RpcFindValueFunctor callback) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(private_key, transport, message_handler);
  uint32_t object_indx =
      connected_objects_.AddObject(transport, message_handler);

  protobuf::FindValueRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_key(key.String());
  request.set_num_nodes_requested(nodes_requested);
  std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer(new RpcsFailurePeer);
  rpcs_failure_peer->peer = peer;

  std::string message =
      message_handler->WrapMessage(request, peer.public_key());
  // Connect callback to message handler for incoming parsed response or error
  message_handler->on_find_value_response()->connect(std::bind(
      &Rpcs::FindValueCallback, this, transport::kSuccess, arg::_1, arg::_2,
      object_indx, callback, message, rpcs_failure_peer));
  message_handler->on_error()->connect(std::bind(
      &Rpcs::FindValueCallback, this, arg::_1, transport::Info(),
      protobuf::FindValueResponse(), object_indx, callback, message,
      rpcs_failure_peer));
  DLOG(INFO) << "\t" << DebugId(contact_) << " FIND_VALUE to " << DebugId(peer);
  transport->Send(message, peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

template <typename TransportType>
void Rpcs<TransportType>::FindNodes(const Key &key,
                                    const uint16_t &nodes_requested,
                                    PrivateKeyPtr private_key,
                                    const Contact &peer,
                                    RpcFindNodesFunctor callback) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(private_key, transport, message_handler);
  uint32_t object_indx =
      connected_objects_.AddObject(transport, message_handler);

  protobuf::FindNodesRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_key(key.String());
  request.set_num_nodes_requested(nodes_requested);
  std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer(new RpcsFailurePeer);
  rpcs_failure_peer->peer = peer;

  std::string message =
      message_handler->WrapMessage(request, peer.public_key());
  // Connect callback to message handler for incoming parsed response or error
  message_handler->on_find_nodes_response()->connect(std::bind(
      &Rpcs::FindNodesCallback, this, transport::kSuccess, arg::_1, arg::_2,
      object_indx, callback, message, rpcs_failure_peer));
  message_handler->on_error()->connect(std::bind(
      &Rpcs::FindNodesCallback, this, arg::_1, transport::Info(),
      protobuf::FindNodesResponse(), object_indx, callback, message,
      rpcs_failure_peer));
  DLOG(INFO) << "\t" << DebugId(contact_) << " FIND_NODES to " << DebugId(peer);
  transport->Send(message, peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

template <typename TransportType>
void Rpcs<TransportType>::PingCallback(
    const std::string &random_data,
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::PingResponse &response,
    const uint32_t &index,
    RpcPingFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  DLOG(INFO) << "\t" << DebugId(contact_) << " PING response from "
             << DebugId(rpcs_failure_peer->peer);
  if ((transport_condition != transport::kSuccess) &&
      (rpcs_failure_peer->rpcs_failure < kFailureTolerance_)) {
    ++(rpcs_failure_peer->rpcs_failure);
    TransportPtr transport = connected_objects_.GetTransport(index);
    transport->Send(message,
                    rpcs_failure_peer->peer.PreferredEndpoint(),
                    transport::kDefaultInitialTimeout);
  } else {
    connected_objects_.RemoveObject(index);
    if (transport_condition != transport::kSuccess) {
      callback(RankInfoPtr(new transport::Info(info)), transport_condition);
      return;
    }
    if (response.IsInitialized() && response.echo() == random_data) {
      callback(RankInfoPtr(new transport::Info(info)), transport::kSuccess);
    } else {
      callback(RankInfoPtr(new transport::Info(info)), transport::kError);
    }
  }
}

template <typename TransportType>
void Rpcs<TransportType>::FindValueCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::FindValueResponse &response,
    const uint32_t &index,
    RpcFindValueFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  if ((transport_condition != transport::kSuccess) &&
    (rpcs_failure_peer->rpcs_failure < kFailureTolerance_)) {
    ++(rpcs_failure_peer->rpcs_failure);
    TransportPtr transport = connected_objects_.GetTransport(index);
    transport->Send(
        message, rpcs_failure_peer->peer.PreferredEndpoint(),
        transport::kDefaultInitialTimeout);
  } else {
    connected_objects_.RemoveObject(index);
    std::vector<Contact> contacts;
    Contact alternative_value_holder;

    if (transport_condition != transport::kSuccess) {
      callback(RankInfoPtr(new transport::Info(info)), transport_condition,
               contacts, alternative_value_holder);
      return;
    }
    if (!response.IsInitialized() || !response.result()) {
      callback(RankInfoPtr(new transport::Info(info)), transport::kError,
               contacts, alternative_value_holder);
      return;
    }

    if (response.has_alternative_value_holder()) {
      alternative_value_holder =
          FromProtobuf(response.alternative_value_holder());
      callback(RankInfoPtr(new transport::Info(info)),
               kFoundAlternativeStoreHolder, contacts,
               alternative_value_holder);
      return;
    }


    if (response.closest_nodes_size() != 0) {
      for (int i = 0; i < response.closest_nodes_size(); ++i)
        contacts.push_back(FromProtobuf(response.closest_nodes(i)));
      DLOG(INFO) << "\t" << DebugId(contact_) << " FIND_VALUE response from "
                 << DebugId(rpcs_failure_peer->peer) << " found "
                 << contacts.size() << " contacts.";
      callback(RankInfoPtr(new transport::Info(info)), kFailedToFindValue,
               contacts, alternative_value_holder);
      return;
    }
    callback(RankInfoPtr(new transport::Info(info)), kIterativeLookupFailed,
             contacts, alternative_value_holder);
  }
}

template <typename TransportType>
void Rpcs<TransportType>::FindNodesCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::FindNodesResponse &response,
    const uint32_t &index,
    RpcFindNodesFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  if ((transport_condition != transport::kSuccess) &&
      (rpcs_failure_peer->rpcs_failure < kFailureTolerance_)) {
    ++(rpcs_failure_peer->rpcs_failure);
    TransportPtr transport = connected_objects_.GetTransport(index);
    transport->Send(
        message, rpcs_failure_peer->peer.PreferredEndpoint(),
        transport::kDefaultInitialTimeout);
  } else {
    connected_objects_.RemoveObject(index);
    std::vector<Contact> contacts;
    if (transport_condition != transport::kSuccess) {
      callback(RankInfoPtr(new transport::Info(info)), transport_condition,
               contacts);
      return;
    }
    if (!response.IsInitialized() || !response.result()) {
      callback(RankInfoPtr(new transport::Info(info)), transport::kError,
               contacts);
      return;
    }

    if (response.closest_nodes_size() != 0) {
      for (int i = 0; i < response.closest_nodes_size(); ++i)
        contacts.push_back(FromProtobuf(response.closest_nodes(i)));
      callback(RankInfoPtr(new transport::Info(info)), transport::kSuccess,
               contacts);
      return;
    }
    callback(RankInfoPtr(new transport::Info(info)), kIterativeLookupFailed,
             contacts);
  }
}


template <typename TransportType>
void Rpcs<TransportType>::Prepare(PrivateKeyPtr private_key,
                                  TransportPtr &transport,
                                  MessageHandlerPtr &message_handler) {
  transport.reset(new TransportType(asio_service_));
  message_handler.reset(new MessageHandler(private_key ? private_key :
                                                        default_private_key_));
  // Connect message handler to transport for incoming raw messages
  transport->on_message_received()->connect(
      transport::OnMessageReceived::element_type::slot_type(
          &MessageHandler::OnMessageReceived, message_handler.get(),
          _1, _2, _3, _4).track_foreign(message_handler));
  transport->on_error()->connect(
      transport::OnError::element_type::slot_type(
          &MessageHandler::OnError, message_handler.get(),
          _1, _2).track_foreign(message_handler));
}

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_RPCS_H_
