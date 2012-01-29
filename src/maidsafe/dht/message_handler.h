/* Copyright (c) 2010 maidsafe.net limited
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

#ifndef MAIDSAFE_DHT_MESSAGE_HANDLER_H_
#define MAIDSAFE_DHT_MESSAGE_HANDLER_H_

#include <memory>
#include <string>
#include "boost/concept_check.hpp"
#include "boost/signals2/signal.hpp"
#include "maidsafe/transport/message_handler.h"

#include "maidsafe/dht/config.h"
#include "maidsafe/dht/version.h"

#if MAIDSAFE_DHT_VERSION != 3107
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-dht library.
#endif


namespace bs2 = boost::signals2;

namespace maidsafe {

namespace dht {

namespace protobuf {
class PingRequest;
class PingResponse;
class FindValueRequest;
class FindValueResponse;
class FindNodesRequest;
class FindNodesResponse;
}  // namespace protobuf

namespace test {
class KademliaMessageHandlerTest_BEH_WrapMessagePingResponse_Test;
class KademliaMessageHandlerTest_BEH_WrapMessageFindValueResponse_Test;
class KademliaMessageHandlerTest_BEH_WrapMessageFindNodesResponse_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessagePingRqst_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessagePingRsp_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageFValRqst_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageFValRsp_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageFNodeRqst_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageFNodeRsp_Test;
class KademliaMessageHandlerTest;
}  // namespace test

// Highest possible message type ID, use as offset for type extensions.
const int kMaxMessageType(transport::kMaxMessageType + 1000);

enum MessageType {
  kPingRequest = transport::kMaxMessageType + 1,
  kPingResponse,
  kFindValueRequest,
  kFindValueResponse,
  kFindNodesRequest,
  kFindNodesResponse
};

class MessageHandler : public transport::MessageHandler {
 public:
  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::PingRequest&,
           protobuf::PingResponse*,
           transport::Timeout*)>> PingReqSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::PingResponse&)>> PingRspSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::FindValueRequest&,
           protobuf::FindValueResponse*,
           transport::Timeout*)>> FindValueReqSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::FindValueResponse&)>> FindValueRspSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::FindNodesRequest&,
           protobuf::FindNodesResponse*,
           transport::Timeout*)>> FindNodesReqSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::FindNodesResponse&)>> FindNodesRspSigPtr;


  explicit MessageHandler(PrivateKeyPtr private_key)
    : transport::MessageHandler(private_key),
      on_ping_request_(new PingReqSigPtr::element_type),
      on_ping_response_(new PingRspSigPtr::element_type),
      on_find_value_request_(new FindValueReqSigPtr::element_type),
      on_find_value_response_(new FindValueRspSigPtr::element_type),
      on_find_nodes_request_(new FindNodesReqSigPtr::element_type),
      on_find_nodes_response_(new FindNodesRspSigPtr::element_type) {}
  virtual ~MessageHandler() {}

  std::string WrapMessage(const protobuf::PingRequest &msg,
                          const asymm::PublicKey &recipient_public_key);
  std::string WrapMessage(const protobuf::FindValueRequest &msg,
                          const asymm::PublicKey &recipient_public_key);
  std::string WrapMessage(const protobuf::FindNodesRequest &msg,
                          const asymm::PublicKey &recipient_public_key);


  PingReqSigPtr on_ping_request() { return on_ping_request_; }
  PingRspSigPtr on_ping_response() { return on_ping_response_; }
  FindValueReqSigPtr on_find_value_request() { return on_find_value_request_; }
  FindValueRspSigPtr on_find_value_response() {
    return on_find_value_response_;
  }
  FindNodesReqSigPtr on_find_nodes_request() { return on_find_nodes_request_; }
  FindNodesRspSigPtr on_find_nodes_response() {
    return on_find_nodes_response_;
  }

 protected:
  virtual void ProcessSerialisedMessage(const int &message_type,
                                        const std::string &payload,
                                        const SecurityType &security_type,
                                        const std::string &message_signature,
                                        const transport::Info &info,
                                        std::string *message_response,
                                        transport::Timeout *timeout);

 private:
  friend class test::KademliaMessageHandlerTest_BEH_WrapMessagePingResponse_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_WrapMessageFindValueResponse_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_WrapMessageFindNodesResponse_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessagePingRqst_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessagePingRsp_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageFValRqst_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageFValRsp_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageFNodeRqst_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageFNodeRsp_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest;

  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);

  std::string WrapMessage(const protobuf::PingResponse &msg,
                          const asymm::PublicKey &recipient_public_key);
  std::string WrapMessage(const protobuf::FindValueResponse &msg,
                          const asymm::PublicKey &recipient_public_key);
  std::string WrapMessage(const protobuf::FindNodesResponse &msg,
                          const asymm::PublicKey &recipient_public_key);

  PingReqSigPtr on_ping_request_;
  PingRspSigPtr on_ping_response_;
  FindValueReqSigPtr on_find_value_request_;
  FindValueRspSigPtr on_find_value_response_;
  FindNodesReqSigPtr on_find_nodes_request_;
  FindNodesRspSigPtr on_find_nodes_response_;

};

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_MESSAGE_HANDLER_H_
