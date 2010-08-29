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

/*******************************************************************************
 * NOTE: This header is unlikely to have any breaking changes applied.         *
 *       However, it should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/
/*
* TODO
* 1:  Allow Listening ports to be closed individually and as a group
* 2:  Create managed connection interface
* 3:  Add an Open method for rendezvous connections
* 4:  Create a ping at network level (in UDT this is a connect)
* 5:  Use managed connections for rendezvous
* 6:  Add tcp listen capability, may be another transport
* 7:  Provide a brodcast tcp method " " " " "
* 8:  When a knode can it will start a tcp listener on 80 and 443 and add this
*     to the contact tuple (prononced toople apparently :-) )
* 9:  Thread send including connect
* 10  Use thread pool
* 11: On thread pool filling up move all incoming connecitons to an async
*     connection method until a thread becomes available.
* 12: Complete NAT traversal management (use upnp, nat-pmp and hole punching)
*     allong prioratising of method type.
* 13: Use TCP to beackon on port 5483 when contact with kademlia network lost
* 14: Profile profile and profile. The send recive test should be under 100ms
*     preferrably less than 25ms.
* 15: Decide on how / when to fire the Stats signals
* 16: Provide channel level encryption (diffie Hellman -> AES xfer)
*/

#ifndef MAIDSAFE_TRANSPORT_UDTTRANSPORT_H_
#define MAIDSAFE_TRANSPORT_UDTTRANSPORT_H_

#include <boost/cstdint.hpp>
#include <boost/shared_array.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/thread.hpp>
#include <boost/detail/atomic_count.hpp>
#include <maidsafe/base/threadpool.h>
#include <maidsafe/transport/transport.h>
#include <maidsafe/transport/udtconnection.h>
#include <map>
#include <string>
#include <vector>
#include "maidsafe/transport/udtutils.h"
#include "maidsafe/udt/udt.h"


namespace  bs2 = boost::signals2;
namespace  fs = boost::filesystem;

namespace transport {

class HolePunchingMessage;
// struct IncomingMessages;

namespace test {
class UdtTransportTest_BEH_TRANS_UdtAddRemoveManagedEndpoints_Test;
}  // namespace test

typedef int UdtSocketId;

const int kAddManagedConnectionTimeout(1000);  // milliseconds
const boost::uint16_t kDefaultThreadpoolSize(10);
const int kManagedSocketBufferSize(200);  // bytes

class UdtTransport : public Transport {
 public:
  UdtTransport();
  ~UdtTransport();
  static void CleanUp();
  Port StartListening(const IP &ip,
                      const Port &try_port,
                      TransportCondition *transport_condition);
  bool StopListening(const Port &port);
  bool StopAllListening();
  // Closes all managed connections and stops accepting new incoming ones.
  void StopManagedConnections();
  // Allows new incoming managed connections after StopManagedConnections has
  // been called.
  void ReAllowIncomingManagedConnections();
  // Create a hole to remote endpoint using rendezvous endpoint.
  TransportCondition PunchHole(const IP &remote_ip,
                               const Port &remote_port,
                               const IP &rendezvous_ip,
                               const Port &rendezvous_port);
  SocketId Send(const TransportMessage &transport_message,
                const IP &remote_ip,
                const Port &remote_port,
                const int &response_timeout);
  // Convenience function - calls PunchHole followed by Send.
  void SendWithRendezvous(const TransportMessage &transport_message,
                          const IP &remote_ip,
                          const Port &remote_port,
                          const IP &rendezvous_ip,
                          const Port &rendezvous_port,
                          int &response_timeout,
                          SocketId *socket_id);
  void SendResponse(const TransportMessage &transport_message,
                    const SocketId &socket_id);
  // Used to send a file in response to a request received on socket_id.
  void SendFile(fs::path &path, const SocketId &socket_id);
  // Adds an endpoint that is checked at frequency milliseconds, or which keeps
  // alive the connection if frequency == 0.  Checking persists until
  // RemoveManagedEndpoint called, or endpoint is unavailable.
  // Return value is the socket id or -1 on error.  For frequency == 0 (implies
  // stay connected) the ManagedEndpointId can be used as the SocketId for
  // sending further messages.  For frequency > 0, new connections are
  // regularly made and broken, so ManagedEndpointId cannot be used as SocketId.
  // On failure to connect, retry_count further attempts at retry_frequency (ms)
  // are performed before failure.
  ManagedEndpointId AddManagedEndpoint(
      const IP &remote_ip,
      const Port &remote_port,
      const IP &rendezvous_ip,
      const Port &rendezvous_port,
      const std::string &our_identifier,
      const boost::uint16_t &frequency,
      const boost::uint16_t &retry_count,
      const boost::uint16_t &retry_frequency);
  bool RemoveManagedEndpoint(
      const ManagedEndpointId &managed_endpoint_id);
  friend class UdtConnection;
  friend class
      test::UdtTransportTest_BEH_TRANS_UdtAddRemoveManagedEndpoints_Test;
 private:
  UdtTransport& operator=(const UdtTransport&);
  UdtTransport(const UdtTransport&);
  Port DoStartListening(const IP &ip,
                        const Port &try_port,
                        bool managed_connection_listener,
                        TransportCondition *transport_condition);
  TransportCondition StartManagedEndpointListener(
      const UdtSocketId &initial_peer_socket_id,
      boost::shared_ptr<addrinfo const> peer);
  TransportCondition SetManagedSocketOptions(const UdtSocketId &udt_socket_id);
  UdtSocketId GetNewManagedEndpointSocket(const IP &remote_ip,
                                          const Port &remote_port,
                                          const IP &rendezvous_ip,
                                          const Port &rendezvous_port);
  void AcceptConnection(const Port &port, const UdtSocketId &udt_socket_id);
  void CheckManagedSockets();
  void HandleManagedSocketRequest(const UdtSocketId &udt_socket_id,
                                  const ManagedEndpointMessage &request);
  void HandleManagedSocketResponse(const UdtSocketId &managed_socket_id,
                                   const ManagedEndpointMessage &response);
  bool SetAsynchronous(const UdtSocketId &udt_socket_id);
  // This is only meant to be used as a predicate where
  // managed_endpoint_sockets_mutex_ is already locked.
  bool PendingManagedSocketReplied(const UdtSocketId &udt_socket_id);
  std::map<Port, UdtSocketId> listening_map_;
  std::vector<UdtSocketId> managed_endpoint_sockets_;
  std::map<UdtSocketId, UdtSocketId> pending_managed_endpoint_sockets_;
  volatile bool stop_managed_connections_, managed_connections_stopped_;
  boost::mutex managed_endpoint_sockets_mutex_;
  boost::condition_variable managed_endpoints_cond_var_;
  boost::shared_ptr<addrinfo const> managed_endpoint_listening_addrinfo_;
  Port managed_endpoint_listening_port_;
  boost::shared_ptr<base::Threadpool> listening_threadpool_;
  boost::shared_ptr<base::Threadpool> general_threadpool_;
  boost::shared_ptr<boost::thread> check_connections_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_UDTTRANSPORT_H_
