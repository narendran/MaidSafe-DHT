/* Copyright (c) 2011 maidsafe.net limited
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


#include "boost/lexical_cast.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/thread/thread.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/dht/config.h"
#include "maidsafe/dht/message_handler.h"
#include "maidsafe/dht/utils.h"

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/dht/rpcs.pb.h"
#include "maidsafe/dht/tests/wrapper.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

namespace arg = std::placeholders;

namespace maidsafe {

namespace dht {

namespace test {

class KademliaMessageHandlerTest: public testing::Test {
 public:
  KademliaMessageHandlerTest() : default_public_key_(),
                                 msg_hndlr_(),
                                 msg_hndlr_no_securifier_(PrivateKeyPtr()),
                                 invoked_slots_(),
                                 slots_mutex_() {
    asymm::Keys key_pair;
    asymm::GenerateKeyPair(&key_pair);
    msg_hndlr_.reset(new MessageHandler(
        PrivateKeyPtr(new asymm::PrivateKey(key_pair.private_key))));
    default_public_key_ = key_pair.public_key;
//    Mock asymm::Validate Func to Always return true;
  }
  virtual void SetUp() {}
  virtual void TearDown() {}
  static void SetUpTestCase() { asymm::GenerateKeyPair(&rsa_keypair_); }

  template<class T>
  T GetWrapper(std::string encrypted, std::string key) {
    std::string encrypt_aes_seed = encrypted.substr(1, 512);
    std::string decrypted_message;
    asymm::PrivateKey private_key;
    asymm::DecodePrivateKey(key, &private_key);
    asymm::Decrypt(encrypt_aes_seed, private_key, &decrypted_message);
    encrypt_aes_seed = decrypted_message;
    std::string aes_key = encrypt_aes_seed.substr(0, 32);
    std::string kIV = encrypt_aes_seed.substr(32, 16);
    std::string serialised_message =
        crypto::SymmDecrypt(encrypted.substr(513), aes_key, kIV);
    protobuf::WrapperMessage decrypted_msg;
    decrypted_msg.ParseFromString(serialised_message);
    T result;
    result.ParseFromString(decrypted_msg.payload());
    return result;
  }
  template<class T>
  std::string EncryptMessage(T request,
                             std::string publick_key,
                             MessageType request_type) {
    protobuf::WrapperMessage message;
    message.set_msg_type(request_type);
    message.set_payload(request.SerializeAsString());
    std::string result(1, kAsymmetricEncrypt);
    std::string seed = RandomString(48);
    std::string key = seed.substr(0, 32);
    std::string kIV = seed.substr(32, 16);
    std::string encrypt_message =
        crypto::SymmEncrypt(message.SerializeAsString(), key, kIV);
    std::string encrypt_aes_seed;
    asymm::PublicKey public_key;
    asymm::DecodePublicKey(publick_key, &public_key);
    asymm::Encrypt(seed, public_key, &encrypt_aes_seed);
    result += encrypt_aes_seed + encrypt_message;
    return result;
  }

  void PingRequestSlot(const transport::Info&,
                       const dht::protobuf::PingRequest& request,
                       dht::protobuf::PingResponse* response,
                       transport::Timeout*) {
    boost::mutex::scoped_lock lock(slots_mutex_);
    auto it = invoked_slots_->find(kPingRequest);
    if (it != invoked_slots_->end())
      ++((*it).second);
    response->set_echo(request.ping());
  }

  void PingResponseSlot(const transport::Info&,
                        const dht::protobuf::PingResponse&) {
    boost::mutex::scoped_lock lock(slots_mutex_);
    auto it = invoked_slots_->find(kPingResponse);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }

  void FindValueRequestSlot(const transport::Info&,
                            const dht::protobuf::FindValueRequest&,
                            dht::protobuf::FindValueResponse* response,
                            transport::Timeout*) {
    boost::mutex::scoped_lock lock(slots_mutex_);
    auto it = invoked_slots_->find(kFindValueRequest);
    if (it != invoked_slots_->end())
      ++((*it).second);
    response->set_result(true);
  }

  void FindValueResponseSlot(const transport::Info&,
                             const dht::protobuf::FindValueResponse&) {
    boost::mutex::scoped_lock lock(slots_mutex_);
    auto it = invoked_slots_->find(kFindValueResponse);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }

  void FindNodesRequestSlot(const transport::Info&,
                            const dht::protobuf::FindNodesRequest&,
                            dht::protobuf::FindNodesResponse* response,
                            transport::Timeout*) {
    boost::mutex::scoped_lock lock(slots_mutex_);
    auto it = invoked_slots_->find(kFindNodesRequest);
    if (it != invoked_slots_->end())
      ++((*it).second);
    response->set_result(true);
  }

  void FindNodesResponseSlot(const transport::Info&,
                             const dht::protobuf::FindNodesResponse&) {
    boost::mutex::scoped_lock lock(slots_mutex_);
    auto it = invoked_slots_->find(kFindNodesResponse);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }

  void InitialiseMap() {
    invoked_slots_.reset(new std::map<MessageType, uint16_t>);
  }

  void ConnectToHandlerSignals() {
    msg_hndlr_->on_ping_request()->connect(std::bind(
        &KademliaMessageHandlerTest::PingRequestSlot, this, arg::_1, arg::_2,
        arg::_3, arg::_4));
    msg_hndlr_->on_ping_response()->connect(std::bind(
        &KademliaMessageHandlerTest::PingResponseSlot, this, arg::_1, arg::_2));
    msg_hndlr_->on_find_value_request()->connect(std::bind(
        &KademliaMessageHandlerTest::FindValueRequestSlot,
        this, arg::_1, arg::_2, arg::_3, arg::_4));
    msg_hndlr_->on_find_value_response()->connect(std::bind(
        &KademliaMessageHandlerTest::FindValueResponseSlot, this, arg::_1,
        arg::_2));
    msg_hndlr_->on_find_nodes_request()->connect(std::bind(
        &KademliaMessageHandlerTest::FindNodesRequestSlot,
        this, arg::_1, arg::_2, arg::_3, arg::_4));
    msg_hndlr_->on_find_nodes_response()->connect(std::bind(
        &KademliaMessageHandlerTest::FindNodesResponseSlot, this, arg::_1,
        arg::_2));
  }

  std::vector<std::string> CreateMessages() {
    dht::protobuf::PingRequest p_req;
    dht::protobuf::PingResponse p_rsp;
    dht::protobuf::FindValueRequest fv_req;
    dht::protobuf::FindValueResponse fv_rsp;
    dht::protobuf::FindNodesRequest fn_req;
    dht::protobuf::FindNodesResponse fn_rsp;


    dht::protobuf::Contact contact;
    contact.set_node_id("test");
    std::string public_key;
    asymm::EncodePublicKey(default_public_key_, &public_key);
    contact.set_public_key(public_key);
    p_req.set_ping(RandomString(50 + (RandomUint32() % 50)));
    p_req.mutable_sender()->CopyFrom(contact);
    p_rsp.set_echo(p_req.ping());
    fv_req.set_key("fv_key");
    fv_req.mutable_sender()->CopyFrom(contact);
    fv_rsp.set_result(1);
    fn_req.set_key("fn_key");
    fn_req.mutable_sender()->CopyFrom(contact);
    fn_rsp.set_result(1);


    EXPECT_TRUE(p_req.IsInitialized());
    EXPECT_TRUE(p_rsp.IsInitialized());
    EXPECT_TRUE(fv_req.IsInitialized());
    EXPECT_TRUE(fv_rsp.IsInitialized());
    EXPECT_TRUE(fn_req.IsInitialized());
    EXPECT_TRUE(fn_rsp.IsInitialized());

    std::vector<std::string> messages;
    std::string msg_sig;
    protobuf::WrapperMessage wrap;
    wrap.set_msg_type(kPingRequest);
    wrap.set_payload(p_req.SerializeAsString());
    messages.push_back(std::string(1, kAsymmetricEncrypt)
                       + wrap.SerializeAsString());

    wrap.Clear();
    wrap.set_msg_type(kPingResponse);
    wrap.set_payload(p_rsp.SerializeAsString());
    messages.push_back(std::string(1, kAsymmetricEncrypt)
                       + wrap.SerializeAsString());

    wrap.Clear();
    wrap.set_msg_type(kFindValueRequest);
    wrap.set_payload(fv_req.SerializeAsString());
    messages.push_back(std::string(1, kAsymmetricEncrypt)
                       + wrap.SerializeAsString());

    wrap.Clear();
    wrap.set_msg_type(kFindValueResponse);
    wrap.set_payload(fv_rsp.SerializeAsString());
    messages.push_back(std::string(1, kAsymmetricEncrypt)
                       + wrap.SerializeAsString());

    wrap.Clear();
    wrap.set_msg_type(kFindNodesRequest);
    wrap.set_payload(fn_req.SerializeAsString());
    messages.push_back(std::string(1, kAsymmetricEncrypt)
                       + wrap.SerializeAsString());

    wrap.Clear();
    wrap.set_msg_type(kFindNodesResponse);
    wrap.set_payload(fn_rsp.SerializeAsString());
    messages.push_back(std::string(1, kAsymmetricEncrypt)
                       + wrap.SerializeAsString());
    return messages;
  }

  std::shared_ptr<std::map<MessageType, uint16_t>> invoked_slots() {
    return invoked_slots_;
  }

  void ExecuteThread(std::vector<std::string> messages_copy, int rounds) {
    uint32_t random_sleep((RandomUint32() % 100) + 100);
    for (int a = 0; a < rounds; ++a) {
      Sleep(boost::posix_time::milliseconds(random_sleep));
      for (size_t n = 0; n < messages_copy.size(); ++n) {
        SecurityType security_type = messages_copy[n].at(0);
        protobuf::WrapperMessage wrap;
        wrap.ParseFromString(messages_copy[n].substr(1));
        int message_type = wrap.msg_type();
        std::string payload = wrap.payload();
        transport::Info info;
        std::string *response = new std::string;
        transport::Timeout *timeout = new transport::Timeout;
        std::string message_sig;
        asymm::Sign(boost::lexical_cast<std::string>(message_type) + payload,
                    *msg_hndlr_->private_key_,
                    &message_sig);
        msg_hndlr_->ProcessSerialisedMessage(message_type,
                                             payload,
                                             security_type,
                                             message_sig,
                                             info,
                                             response,
                                             timeout);
      }
    }
  }

 protected:
  asymm::PublicKey default_public_key_;
  std::shared_ptr<MessageHandler> msg_hndlr_;
  MessageHandler msg_hndlr_no_securifier_;
  std::shared_ptr<std::map<MessageType, uint16_t>> invoked_slots_;
  boost::mutex slots_mutex_;
  static asymm::Keys rsa_keypair_;
};

asymm::Keys KademliaMessageHandlerTest::rsa_keypair_;

TEST_F(KademliaMessageHandlerTest, BEH_WrapMessagePingRequest) {
  dht::protobuf::PingRequest ping_rqst;
  ping_rqst.set_ping("ping");
  dht::protobuf::Contact contact;
  contact.set_node_id("test");
  ping_rqst.mutable_sender()->CopyFrom(contact);
  ASSERT_TRUE(ping_rqst.IsInitialized());
  asymm::Keys kp;
  asymm::GenerateKeyPair(&kp);
  std::string result_no_securifier =
      msg_hndlr_no_securifier_.WrapMessage(ping_rqst, kp.public_key);
  ASSERT_EQ("", result_no_securifier);

  std::string function_encrypt =
      msg_hndlr_->WrapMessage(ping_rqst, kp.public_key);
  std::string encode_pub_key;
  asymm::EncodePublicKey(kp.public_key, &encode_pub_key);
  std::string encode_priv_key;
  asymm::EncodePrivateKey(kp.private_key, &encode_priv_key);
  std::string manual_encrypt =
      EncryptMessage<dht::protobuf::PingRequest>(ping_rqst,
                                                 encode_pub_key,
                                                 kPingRequest);
  EXPECT_NE(manual_encrypt, function_encrypt);
//   EXPECT_EQ(manual_encrypt, function_encrypt);

  // decrypt for comparison test
  dht::protobuf::PingRequest decrypted_function_ping =
      GetWrapper<dht::protobuf::PingRequest>(function_encrypt, encode_priv_key);
  dht::protobuf::PingRequest decrypted_manual_ping =
      GetWrapper<dht::protobuf::PingRequest>(manual_encrypt, encode_priv_key);
  ASSERT_EQ(decrypted_manual_ping.ping(), decrypted_function_ping.ping());
  ASSERT_EQ(decrypted_manual_ping.sender().node_id(),
            decrypted_function_ping.sender().node_id());
}

TEST_F(KademliaMessageHandlerTest, BEH_WrapMessageFindValueRequest) {
  dht::protobuf::FindValueRequest value_rqst;
  value_rqst.set_key("request_key");
  dht::protobuf::Contact contact;
  contact.set_node_id("node_id_test");
  value_rqst.mutable_sender()->CopyFrom(contact);
  ASSERT_TRUE(value_rqst.IsInitialized());
  asymm::Keys kp;
  asymm::GenerateKeyPair(&kp);
  std::string result_no_securifier =
      msg_hndlr_no_securifier_.WrapMessage(value_rqst, kp.public_key);
  ASSERT_EQ("", result_no_securifier);

  std::string function_encrypt =
      msg_hndlr_->WrapMessage(value_rqst, kp.public_key);
  std::string encode_pub_key;
  asymm::EncodePublicKey(kp.public_key, &encode_pub_key);
  std::string encode_priv_key;
  asymm::EncodePrivateKey(kp.private_key, &encode_priv_key);
  std::string manual_encrypt =
      EncryptMessage<dht::protobuf::FindValueRequest>(value_rqst,
                                                      encode_pub_key,
                                                      kFindValueRequest);
  EXPECT_NE(manual_encrypt, function_encrypt);
//   EXPECT_EQ(manual_encrypt, function_encrypt);

  // decrypt for comparison test
  dht::protobuf::FindValueRequest decrypted_function_value =
      GetWrapper<dht::protobuf::FindValueRequest>(function_encrypt,
                                                  encode_priv_key);
  dht::protobuf::FindValueRequest decrypted_manual_value =
      GetWrapper<dht::protobuf::FindValueRequest>(manual_encrypt,
                                                  encode_priv_key);
  ASSERT_EQ(decrypted_manual_value.key(), decrypted_function_value.key());
  ASSERT_EQ(decrypted_manual_value.sender().node_id(),
            decrypted_function_value.sender().node_id());
}

TEST_F(KademliaMessageHandlerTest, BEH_WrapMessageFindNodesRequest) {
  dht::protobuf::FindNodesRequest nodes_rqst;
  nodes_rqst.set_key("node_request_key");
  dht::protobuf::Contact contact;
  contact.set_node_id("node_id_test");
  nodes_rqst.mutable_sender()->CopyFrom(contact);
  ASSERT_TRUE(nodes_rqst.IsInitialized());
  asymm::Keys kp;
  asymm::GenerateKeyPair(&kp);
  std::string result_no_securifier =
      msg_hndlr_no_securifier_.WrapMessage(nodes_rqst, kp.public_key);
  ASSERT_EQ("", result_no_securifier);

  std::string function_encrypt =
      msg_hndlr_->WrapMessage(nodes_rqst, kp.public_key);
  std::string encode_pub_key;
  asymm::EncodePublicKey(kp.public_key, &encode_pub_key);
  std::string encode_priv_key;
  asymm::EncodePrivateKey(kp.private_key, &encode_priv_key);
  std::string manual_encrypt =
      EncryptMessage<dht::protobuf::FindNodesRequest>(nodes_rqst,
                                                      encode_pub_key,
                                                      kFindNodesRequest);
  EXPECT_NE(manual_encrypt, function_encrypt);
//   EXPECT_EQ(manual_encrypt, function_encrypt);

  // decrypt for comparison test
  dht::protobuf::FindNodesRequest decrypted_function_value =
      GetWrapper<dht::protobuf::FindNodesRequest>(function_encrypt,
                                                  encode_priv_key);
  dht::protobuf::FindNodesRequest decrypted_manual_value =
      GetWrapper<dht::protobuf::FindNodesRequest>(manual_encrypt,
                                                  encode_priv_key);
  ASSERT_EQ(decrypted_manual_value.key(), decrypted_function_value.key());
  ASSERT_EQ(decrypted_manual_value.sender().node_id(),
            decrypted_function_value.sender().node_id());
}


TEST_F(KademliaMessageHandlerTest, BEH_WrapMessagePingResponse) {
  dht::protobuf::PingResponse response;
  response.set_echo("ping response echo");
  ASSERT_TRUE(response.IsInitialized());
  asymm::Keys kp;
  asymm::GenerateKeyPair(&kp);
  std::string result_no_securifier =
      msg_hndlr_no_securifier_.WrapMessage(response, kp.public_key);
  ASSERT_EQ("", result_no_securifier);
  std::string function_encrypt = msg_hndlr_->WrapMessage(response,
                                                        kp.public_key);
  std::string encode_pub_key;
  asymm::EncodePublicKey(kp.public_key, &encode_pub_key);
  std::string encode_priv_key;
  asymm::EncodePrivateKey(kp.private_key, &encode_priv_key);
  std::string manual_encrypt =
      EncryptMessage<dht::protobuf::PingResponse>(response,
                                                  encode_pub_key,
                                                  kPingResponse);
  EXPECT_NE(manual_encrypt, function_encrypt);
  dht::protobuf::PingResponse decrypted_function_value =
      GetWrapper<dht::protobuf::PingResponse>(function_encrypt,
                                              encode_priv_key);
  dht::protobuf::PingResponse decrypted_manual_value =
      GetWrapper<dht::protobuf::PingResponse>(manual_encrypt,
                                              encode_priv_key);
  ASSERT_EQ(decrypted_manual_value.echo(),
            decrypted_function_value.echo());
}

TEST_F(KademliaMessageHandlerTest, BEH_WrapMessageFindValueResponse) {
  dht::protobuf::FindValueResponse response;
  response.set_result(1);
  ASSERT_TRUE(response.IsInitialized());
  asymm::Keys kp;
  asymm::GenerateKeyPair(&kp);
  std::string result_no_securifier =
      msg_hndlr_no_securifier_.WrapMessage(response, kp.public_key);
  ASSERT_EQ("", result_no_securifier);
  std::string function_encrypt = msg_hndlr_->WrapMessage(response,
                                                        kp.public_key);
  std::string encode_pub_key;
  asymm::EncodePublicKey(kp.public_key, &encode_pub_key);
  std::string encode_priv_key;
  asymm::EncodePrivateKey(kp.private_key, &encode_priv_key);
  std::string manual_encrypt =
      EncryptMessage<dht::protobuf::FindValueResponse>(response,
                                                       encode_pub_key,
                                                       kFindValueResponse);
  EXPECT_NE(manual_encrypt, function_encrypt);
  dht::protobuf::FindValueResponse decrypted_function_value =
      GetWrapper<dht::protobuf::FindValueResponse>(function_encrypt,
                                                   encode_priv_key);
  dht::protobuf::FindValueResponse decrypted_manual_value =
      GetWrapper<dht::protobuf::FindValueResponse>(manual_encrypt,
                                                   encode_priv_key);
  EXPECT_TRUE(decrypted_manual_value.result());
  EXPECT_TRUE(decrypted_function_value.result());
}

TEST_F(KademliaMessageHandlerTest, BEH_WrapMessageFindNodesResponse) {
  dht::protobuf::FindNodesResponse response;
  response.set_result(1);
  ASSERT_TRUE(response.IsInitialized());
  asymm::Keys kp;
  asymm::GenerateKeyPair(&kp);
  std::string result_no_securifier =
      msg_hndlr_no_securifier_.WrapMessage(response, kp.public_key);
  ASSERT_EQ("", result_no_securifier);
  std::string function_encrypt = msg_hndlr_->WrapMessage(response,
                                                        kp.public_key);
  std::string encode_pub_key;
  asymm::EncodePublicKey(kp.public_key, &encode_pub_key);
  std::string encode_priv_key;
  asymm::EncodePrivateKey(kp.private_key, &encode_priv_key);
  std::string manual_encrypt =
      EncryptMessage<dht::protobuf::FindNodesResponse>(response,
                                                       encode_pub_key,
                                                       kFindNodesResponse);
  EXPECT_NE(manual_encrypt, function_encrypt);
  dht::protobuf::FindNodesResponse decrypted_function_value =
      GetWrapper<dht::protobuf::FindNodesResponse>(function_encrypt,
                                                   encode_priv_key);
  dht::protobuf::FindNodesResponse decrypted_manual_value =
      GetWrapper<dht::protobuf::FindNodesResponse>(manual_encrypt,
                                                   encode_priv_key);
  ASSERT_TRUE(decrypted_manual_value.result());
  ASSERT_TRUE(decrypted_function_value.result());
}




TEST_F(KademliaMessageHandlerTest, BEH_ProcessSerialisedMessagePingRqst) {
  InitialiseMap();
  ConnectToHandlerSignals();
  transport::Info info;
  dht::protobuf::Contact contact;
  contact.set_node_id("test");
  std::string encode_pub_key;
  asymm::EncodePublicKey(rsa_keypair_.public_key, &encode_pub_key);
  contact.set_public_key(encode_pub_key);
  std::string message_signature;
  std::string *message_response = new std::string;
  transport::Timeout *timeout = new transport::Timeout;

  int message_type = kPingRequest;
  dht::protobuf::PingRequest request;
  request.set_ping("ping");
  request.mutable_sender()->CopyFrom(contact);
  std::string payload = request.SerializeAsString();
  ASSERT_TRUE(request.IsInitialized());

  msg_hndlr_->ProcessSerialisedMessage(message_type, payload, kNone,
                                      message_signature, info,
                                      message_response, timeout);
  auto it = invoked_slots_->find(kPingRequest);
  int total = (*it).second;
  ASSERT_EQ(0U, total);
  msg_hndlr_->ProcessSerialisedMessage(message_type, payload,
                                       kAsymmetricEncrypt,
                                       message_signature, info,
                                       message_response, timeout);
  it = invoked_slots_->find(kPingRequest);
  total = (*it).second;
  ASSERT_EQ(1U, total);

  msg_hndlr_->ProcessSerialisedMessage(message_type, payload,
                                      kAsymmetricEncrypt,
                                      message_signature, info,
                                      message_response, timeout);
  it = invoked_slots_->find(kPingRequest);
  total = (*it).second;
  ASSERT_EQ(2U, total);
}

TEST_F(KademliaMessageHandlerTest, BEH_ProcessSerialisedMessagePingRsp) {
  InitialiseMap();
  ConnectToHandlerSignals();
  transport::Info info;
  dht::protobuf::Contact contact;
  contact.set_node_id("test");
  std::string message_signature;
  std::string *message_response = new std::string;
  transport::Timeout *timeout = new transport::Timeout;

  int message_type = kPingResponse;
  dht::protobuf::PingResponse response;
  response.set_echo("ping_echo");
  std::string payload = response.SerializeAsString();
  ASSERT_TRUE(response.IsInitialized());

  msg_hndlr_->ProcessSerialisedMessage(message_type, payload, kNone,
                                      message_signature, info,
                                      message_response, timeout);
  auto it = invoked_slots_->find(kPingResponse);
  int total = (*it).second;
  ASSERT_EQ(0U, total);

  msg_hndlr_->ProcessSerialisedMessage(message_type, payload,
                                      kAsymmetricEncrypt,
                                      message_signature, info,
                                      message_response, timeout);
  it = invoked_slots_->find(kPingResponse);
  total = (*it).second;
  ASSERT_EQ(1U, total);
}

TEST_F(KademliaMessageHandlerTest, BEH_ProcessSerialisedMessageFValRqst) {
  InitialiseMap();
  ConnectToHandlerSignals();
  transport::Info info;
  dht::protobuf::Contact contact;
  contact.set_node_id("test");
  std::string encode_pub_key;
  asymm::EncodePublicKey(rsa_keypair_.public_key, &encode_pub_key);
  contact.set_public_key(encode_pub_key);
  std::string message_signature;
  std::string *message_response = new std::string;
  transport::Timeout *timeout = new transport::Timeout;

  int message_type = kFindValueRequest;
  dht::protobuf::FindValueRequest request;
  request.set_key("FindValue_key");
  request.mutable_sender()->CopyFrom(contact);
  std::string payload = request.SerializeAsString();
  ASSERT_TRUE(request.IsInitialized());

  msg_hndlr_->ProcessSerialisedMessage(message_type, payload, kNone,
                                      message_signature, info,
                                      message_response, timeout);
  auto it = invoked_slots_->find(kFindValueRequest);
  int total = (*it).second;
  ASSERT_EQ(0U, total);

  msg_hndlr_->ProcessSerialisedMessage(message_type, payload,
                                      kAsymmetricEncrypt,
                                      message_signature, info,
                                      message_response, timeout);
  it = invoked_slots_->find(kFindValueRequest);
  total = (*it).second;
  ASSERT_EQ(1U, total);
}

TEST_F(KademliaMessageHandlerTest, BEH_ProcessSerialisedMessageFValRsp) {
  InitialiseMap();
  ConnectToHandlerSignals();
  transport::Info info;
  dht::protobuf::Contact contact;
  contact.set_node_id("test");
  std::string message_signature;
  std::string *message_response = new std::string;
  transport::Timeout *timeout = new transport::Timeout;

  int message_type = kFindValueResponse;
  dht::protobuf::FindValueResponse response;
  response.set_result(1);
  std::string payload = response.SerializeAsString();
  ASSERT_TRUE(response.IsInitialized());

  msg_hndlr_->ProcessSerialisedMessage(message_type, payload, kNone,
                                      message_signature, info,
                                      message_response, timeout);
  auto it = invoked_slots_->find(kFindValueResponse);
  int total = (*it).second;
  ASSERT_EQ(0U, total);

  msg_hndlr_->ProcessSerialisedMessage(message_type, payload,
                                      kAsymmetricEncrypt,
                                      message_signature, info,
                                      message_response, timeout);
  it = invoked_slots_->find(kFindValueResponse);
  total = (*it).second;
  ASSERT_EQ(1U, total);
}

TEST_F(KademliaMessageHandlerTest, BEH_ProcessSerialisedMessageFNodeRqst) {
  InitialiseMap();
  ConnectToHandlerSignals();
  transport::Info info;
  dht::protobuf::Contact contact;
  contact.set_node_id("test");
  std::string encode_pub_key;
  asymm::EncodePublicKey(rsa_keypair_.public_key, &encode_pub_key);
  contact.set_public_key(encode_pub_key);
  std::string message_signature;
  std::string *message_response = new std::string;
  transport::Timeout *timeout = new transport::Timeout;

  int message_type = kFindNodesRequest;
  dht::protobuf::FindNodesRequest request;
  request.set_key("FindNodes_key");
  request.mutable_sender()->CopyFrom(contact);
  std::string payload = request.SerializeAsString();
  ASSERT_TRUE(request.IsInitialized());

  msg_hndlr_->ProcessSerialisedMessage(message_type, payload, kNone,
                                      message_signature, info,
                                      message_response, timeout);
  auto it = invoked_slots_->find(kFindNodesRequest);
  int total = (*it).second;
  ASSERT_EQ(0U, total);

  msg_hndlr_->ProcessSerialisedMessage(message_type, payload,
                                      kAsymmetricEncrypt,
                                      message_signature, info,
                                      message_response, timeout);
  it = invoked_slots_->find(kFindNodesRequest);
  total = (*it).second;
  ASSERT_EQ(1U, total);
}

TEST_F(KademliaMessageHandlerTest, BEH_ProcessSerialisedMessageFNodeRsp) {
  InitialiseMap();
  ConnectToHandlerSignals();
  transport::Info info;
  dht::protobuf::Contact contact;
  contact.set_node_id("test");
  std::string message_signature;
  std::string *message_response = new std::string;
  transport::Timeout *timeout = new transport::Timeout;

  int message_type = kFindNodesResponse;
  dht::protobuf::FindNodesResponse response;
  response.set_result(1);
  std::string payload = response.SerializeAsString();
  ASSERT_TRUE(response.IsInitialized());

  msg_hndlr_->ProcessSerialisedMessage(message_type, payload, kNone,
                                      message_signature, info,
                                      message_response, timeout);
  auto it = invoked_slots_->find(kFindNodesResponse);
  int total = (*it).second;
  ASSERT_EQ(0U, total);

  msg_hndlr_->ProcessSerialisedMessage(message_type, payload,
                                      kAsymmetricEncrypt,
                                      message_signature, info,
                                      message_response, timeout);
  it = invoked_slots_->find(kFindNodesResponse);
  total = (*it).second;
  ASSERT_EQ(1U, total);
}

}  // namespace test_service

}  // namespace dht

}  // namespace maidsafe
