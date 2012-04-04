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

#include "maidsafe/dht/rpcs_objects.h"

#include "maidsafe/dht/log.h"

namespace maidsafe {

namespace dht {

// ConnectedObjectsList::ObjectsContainer
//     ConnectedObjectsList::objects_container_;
boost::mutex ConnectedObjectsList::mutex_;
boost::condition_variable ConnectedObjectsList::cond_var_;
size_t ConnectedObjectsList::total_count_(0);

ConnectedObjectsList::ConnectedObjectsList()
    : objects_container_(),
      index_(0) {}

ConnectedObjectsList::~ConnectedObjectsList() {
  boost::mutex::scoped_lock lock(mutex_);
  if (!objects_container_.empty()) {
    total_count_ -= objects_container_.size();
    DLOG(WARNING) << "~ConnectedObjectsList - Still "
                  << objects_container_.size() << " objects pending.";
  }
  cond_var_.notify_all();
}

uint32_t ConnectedObjectsList::AddObject(
    const TransportPtr transport,
    const MessageHandlerPtr message_handler) {
  boost::mutex::scoped_lock lock(mutex_);
  while (index_ == 0 || objects_container_.count(index_) > 0)
    ++index_;
//   if (index_ % 50 == 0)
//     DLOG(INFO) << "AddObject - Map has " << objects_container_.size()
//                << " entries, total count is " << total_count_;
  ++total_count_;
  objects_container_.insert(std::make_pair(
      index_, std::make_pair(transport, message_handler)));
  return index_++;
}

bool ConnectedObjectsList::RemoveObject(uint32_t index) {
  boost::mutex::scoped_lock lock(mutex_);
  if (objects_container_.erase(index) == 0)
    return false;
  --total_count_;
  cond_var_.notify_all();
  return true;
}

void ConnectedObjectsList::TryToSend(boost::asio::io_service &asio_service,  // NOLINT
                                     const TransportPtr transport,
                                     const std::string &data,
                                     const transport::Endpoint &endpoint,
                                     const transport::Timeout &timeout) {
  bool can_send(false);
  uint32_t total_count(0);
  {
    boost::mutex::scoped_lock lock(mutex_);
    can_send = cond_var_.timed_wait(lock, kRpcQueueWaitTimeout, [&]()->bool {
      return total_count_ < kMaxParallelRpcs;
    });
    total_count = total_count_;
  }
  if (can_send) {
    transport->Send(data, endpoint, timeout);
  } else {
    DLOG(ERROR) << "TryToSend - Too many concurrent RPCs, total count is "
                << total_count;
    asio_service.post(std::bind(
        [](const TransportPtr transport, const transport::Endpoint &endpoint) {
          (*transport->on_error())(transport::kSendTimeout, endpoint);
        },
        transport,
        endpoint));
  }
}

TransportPtr ConnectedObjectsList::GetTransport(uint32_t index) {
  boost::mutex::scoped_lock lock(mutex_);
  auto it = objects_container_.find(index);
  if (it == objects_container_.end())
    return TransportPtr();
  return (*it).second.first;
}

size_t ConnectedObjectsList::Size() {
  boost::mutex::scoped_lock lock(mutex_);
  return objects_container_.size();
}

}  // namespace dht

}  // namespace maidsafe
