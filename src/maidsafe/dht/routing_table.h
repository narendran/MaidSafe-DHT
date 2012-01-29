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
/*
 * The purpose of this object is to dynamically manage a routing table.
 * Based on managed connections which require a connection agreement algorithm
 * to ensure connections are fair and calculable. i.e. to accept a connection
 * there has to be a reason to, otherwise connections will imbalance.
 * The algorithm flips the MSB recursively (all the way in a full table to the
 * LSB)  e.g. 010101011 - we would first find node closest to 110101011 then
 * 000101011 then 011101011 and so on. Each flip represents an ever decreasing
 * part of the network (getting closer with more knowledge). For number of nodes
 * per 'bucket' then simply search the next bits that represent bucket size
 * (i.e.) for 4 nodes per bucket search 1[00 -> 11]101011 which will find any
 * nodes in this area.
 * As each bucket is searched and populated there will be a stop which is
 * natural unless the address space is full. At the point this stop happens we
 * go back up again adding more nodes to the buckets (by same method)
 * we can till we have the
 * min nodes in our routing table. (say 64). This balances our RT as fair across
 * the address range as possible, even when almost empty. On start-up of course
 * the algorithm will detect the distance between our nodes will not even allow
 * us to reach a full routing table.
 * This routing table uses only rUDP and managed connections, no other protocol
 * will work.
 * To achieve this we need to be able to manipulate the node class a little
 * more. This node object will be updated to allow this kind of traversal of
 * MSB flipping.
 * All of this is NOT in the DHT API, although 'get all nodes' may be supplied
 * as impl if required, best not to though and let this object internally
 * handle all routing on it's own. There should not be a requirement for
 * any other library to access these internals (AFAIK).
 */

#ifndef MAIDSAFE_DHT_ROUTING_TABLE_H_
#define MAIDSAFE_DHT_ROUTING_TABLE_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "boost/signals2/signal.hpp"

#include "boost/thread/shared_mutex.hpp"
#include "boost/thread/locks.hpp"

#include "maidsafe/dht/contact.h"
#include "maidsafe/dht/node_id.h"
#include "maidsafe/dht/log.h"


namespace bptime = boost::posix_time;


namespace maidsafe {

namespace transport { struct Info; }

namespace dht {

class RoutingTable {
 public:
  void AddNode(Contact &contact);
  Contact Closest(NodeId &node);
 private:
  void TryAddContact(Contact &contact);
  
  std::map<NodeId, Contact>closest_nodes_;
  std::map<NodeId, Contact>routing_table_;
};

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_ROUTING_TABLE_H_
