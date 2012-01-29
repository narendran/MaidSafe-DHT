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

#ifndef MAIDSAFE_DHT_SERVICE_H_
#define MAIDSAFE_DHT_SERVICE_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "maidsafe/dht/config.h"
#include "maidsafe/dht/contact.h"


namespace maidsafe {

namespace dht {

class DataStore;
class RoutingTable;
class MessageHandler;

namespace protobuf {
class SignedValue;
class PingRequest;
class PingResponse;
class FindValueRequest;
class FindValueResponse;
class FindNodesRequest;
class FindNodesResponse;
class StoreRequest;
class StoreRefreshRequest;
class StoreResponse;
class StoreRefreshResponse;
class DeleteRequest;
class DeleteRefreshRequest;
class DeleteRefreshResponse;
class DeleteResponse;
class DownlistNotification;
}  // namespace protobuf

namespace test {
class ServicesTest;
template <typename T>
class RpcsTest;
}  // namespace test


/** Object handling service requests on a node.
 *  Contains tables of the routing contacts and <value,sig,key> tuples
 *  @class Service */
class Service : public std::enable_shared_from_this<Service> {
 public:
  /** Constructor.  To create a Service, in all cases the routing_table and
   * data_store must be provided.
   *  @param routing_table The routing table contains all contacts.
   *  @param alternative_store Alternative store.
   *  @param private_key Key for validation.
   *  @param[in] k Kademlia constant k.*/
  Service(std::shared_ptr<RoutingTable> routing_table,
          AlternativeStorePtr alternative_store,
          PrivateKeyPtr private_key,
          const uint16_t &k);

  /** Dstructor. */
  ~Service();

  /** Connect to Signals.
   *  @param transport The Transportor to link.
   *  @param message_handler The Message Handler to link. */
  void ConnectToSignals(MessageHandlerPtr message_handler);
  /** Handle Ping request.
   *  The request sender will be added into the routing table
   *  @param[in] info The rank info.
   *  @param[in] request The request.
   *  @param[out] response To response. */
  void Ping(const transport::Info &info,
            const protobuf::PingRequest &request,
            protobuf::PingResponse *response,
            transport::Timeout *timeout);
  /** Handle FindValue request.
   *  The request sender will be added into the routing table
   *  @param[in] info The rank info.
   *  @param[in] request The request.
   *  @param[out] response To response. */
  void FindValue(const transport::Info &info,
                 const protobuf::FindValueRequest &request,
                 protobuf::FindValueResponse *response,
                 transport::Timeout *timeout);
  /** Handle FindNodes request.
   *  The request sender will be added into the routing table
   *  @param[in] info The rank info.
   *  @param[in] request The request.
   *  @param[out] response To response. */
  void FindNodes(const transport::Info &info,
                 const protobuf::FindNodesRequest &request,
                 protobuf::FindNodesResponse *response,
                 transport::Timeout *timeout);
  /** Handle Store request.
   *  The request sender will be added into the routing table
   *  @param[in] info The rank info.
   *  @param[in] request The request.
   *  @param[in] message The message to store.
   *  @param[in] message_signature The signature of the message to store.
   *  @param[out] response The response. */

  /** Set the status to be joined or not joined
   *  @param joined The bool switch. */
  void set_node_joined(bool joined) { node_joined_ = joined; }
  /** Set the node contact
   *  @param contact The node contact. */
  void set_node_contact(const Contact &contact) { node_contact_ = contact; }
  /** Set the PrivateKey
   *  @param priv_key The Private Key. */
  void set_private_key(PrivateKeyPtr priv_key) { private_key_ = priv_key; }

  void set_contact_validation_getter(
      asymm::GetPublicKeyAndValidationFunctor contact_validation_getter) {
    contact_validation_getter_ = contact_validation_getter;
  }

  void set_contact_validator(
      asymm::ValidatePublicKeyFunctor contact_validator) {
    contact_validator_ = contact_validator;
  }

  void set_validate(asymm::ValidateFunctor validate_functor) {
    validate_functor_ = validate_functor;
  }

  friend class test::ServicesTest;
  template <typename T>
  friend class test::RpcsTest;

 private:
  /** Copy Constructor.
   *  @param Service The object to be copied. */
  Service(const Service&);
  /** Assignment overload */
  Service& operator = (const Service&);
  /** Standard parameter checks.  Non-NULL parameters are checked for validity.
   *  @param[in] method_name The name of the method calling this function.
   *  @param[in] key Kademlia key.
   *  @param[in] message Serialised message.
   *  @param[in] message_signature Message signature. */
  bool CheckParameters(const std::string &method_name,
                       const Key *key = NULL,
                       const std::string *message = NULL,
                       const std::string *message_signature = NULL) const;

  void AddContactToRoutingTable(const Contact &contact,
                                const transport::Info &info);

  /** routing table */
  std::shared_ptr<RoutingTable> routing_table_;
  /** alternative store */
  AlternativeStorePtr alternative_store_;
  /** Private Key */
  PrivateKeyPtr private_key_;
  /** bool switch of joined status */
  bool node_joined_;
  /** node contact */
  Contact node_contact_;
    /** k closest to the target */
  const uint16_t k_;
  /** client node id that gets ignored by RT **/
  std::string client_node_id_;
  asymm::GetPublicKeyAndValidationFunctor contact_validation_getter_;
  asymm::ValidatePublicKeyFunctor contact_validator_;
  asymm::ValidateFunctor validate_functor_;
};

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_SERVICE_H_
