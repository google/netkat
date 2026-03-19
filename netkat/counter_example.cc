// Copyright 2025 The NetKAT authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "netkat/counter_example.h"

#include <vector>

#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "netkat/evaluator.h"
#include "netkat/packet_set.h"
#include "netkat/packet_transformer.h"

namespace netkat {

absl::StatusOr<CounterExample> CounterExample::CreateEquivalenceCounterExample(
    PacketTransformerHandle left_policy, PacketTransformerHandle right_policy,
    PacketTransformerManager& packet_transformer_manager) {
  if (left_policy == right_policy) {
    return absl::InvalidArgumentError(
        "Left and right policies are the same, cannot create a counter "
        "example.");
  }
  return CounterExample(left_policy, right_policy, packet_transformer_manager);
}

CounterExample::CounterExample(
    PacketTransformerHandle left_packet_transformer,
    PacketTransformerHandle right_packet_transformer,
    PacketTransformerManager& packet_transformer_manager)
    : left_packet_transformer_(left_packet_transformer),
      right_packet_transformer_(right_packet_transformer),
      packet_transformer_manager_(packet_transformer_manager) {
  // Compute the transformer that does not drop any packets in the left policy,
  // but does drop packets in the right policy and vice versa.
  PacketTransformerHandle left_diff_right_transformer =
      packet_transformer_manager_.Difference(left_packet_transformer,
                                             right_packet_transformer);
  PacketTransformerHandle right_diff_left_transformer =
      packet_transformer_manager_.Difference(right_packet_transformer,
                                             left_packet_transformer);

  // Compute the sets of input packets that are not dropped by the differences
  // computed above.
  PacketSetHandle fullset =
      packet_transformer_manager_.GetPacketSetManager().FullSet();
  input_packets_in_left_but_not_right_ =
      packet_transformer_manager_.Pull(left_diff_right_transformer, fullset);
  input_packets_in_right_but_not_left_ =
      packet_transformer_manager_.Pull(right_diff_left_transformer, fullset);
}

absl::StatusOr<Packet> CounterExample::GetInputPacketInLeftButNotRight() const {
  std::vector<Packet> input_packets =
      packet_transformer_manager_.GetPacketSetManager().GetConcretePackets(
          input_packets_in_left_but_not_right_);
  if (input_packets.empty()) {
    return absl::NotFoundError("No input packets in left but not right found.");
  }
  return input_packets[0];
}

absl::StatusOr<Packet> CounterExample::GetInputPacketInRightButNotLeft() const {
  std::vector<Packet> input_packets =
      packet_transformer_manager_.GetPacketSetManager().GetConcretePackets(
          input_packets_in_right_but_not_left_);
  if (input_packets.empty()) {
    return absl::NotFoundError("No input packets in right but not left found.");
  }
  return input_packets[0];
}

}  // namespace netkat
