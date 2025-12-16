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

#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "netkat/evaluator.h"
#include "netkat/packet_set.h"
#include "netkat/packet_transformer.h"

namespace netkat {

namespace {

void StableSortOutputPacketsToInputPacket(
    std::vector<std::pair<Packet, OutputPackets>>&
        output_packets_to_input_packet) {
  absl::c_stable_sort(
      output_packets_to_input_packet,
      [](const std::pair<Packet, OutputPackets>& left,
         const std::pair<Packet, OutputPackets>& right) {
        // Create a canonical representation for the left and right Packet by
        // sorting its key-value pairs.
        std::vector<std::pair<std::string, int>> left_packet_vec(
            left.first.begin(), left.first.end());
        absl::c_sort(left_packet_vec);
        std::vector<std::pair<std::string, int>> right_packet_vec(
            right.first.begin(), right.first.end());
        absl::c_sort(right_packet_vec);

        // Compare the canonical representations of the Packets.
        if (left_packet_vec != right_packet_vec) {
          return left_packet_vec < right_packet_vec;
        }

        // If the Packets are identical, compare the OutputPackets.
        // A canonical representation for a set of Packets is a sorted vector
        // of their canonical representations.
        auto create_canonical_rep = [](const OutputPackets& output_packets) {
          std::vector<std::vector<std::pair<std::string, int>>> vec_of_vecs;
          vec_of_vecs.reserve(output_packets.size());
          for (const auto& packet : output_packets) {
            std::vector<std::pair<std::string, int>> packet_vec(packet.begin(),
                                                                packet.end());
            absl::c_sort(packet_vec);
            vec_of_vecs.push_back(std::move(packet_vec));
          }
          absl::c_sort(vec_of_vecs);
          return vec_of_vecs;
        };

        return create_canonical_rep(left.second) <
               create_canonical_rep(right.second);
      });
}

std::vector<std::pair<Packet, OutputPackets>> GetInputPacketToOutputPackets(
    PacketTransformerManager& packet_transformer_manager,
    const PacketTransformerHandle& packet_transformer,
    const PacketSetHandle& input_packet_set) {
  std::vector<std::pair<Packet, OutputPackets>> input_to_output_packets;

  // TODO: b/463710729 - Remove comment once GetConcretePackets returns a
  // comprehensive set of packets.
  // Currently, GetConcretePackets returns a set of packets that are not
  // guaranteed to be exhaustive.
  std::vector<Packet> concrete_packets =
      packet_transformer_manager.GetPacketSetManager().GetConcretePackets(
          input_packet_set);
  input_to_output_packets.reserve(concrete_packets.size());
  for (Packet& input_packet : concrete_packets) {
    input_to_output_packets.push_back(std::make_pair(
        input_packet,
        packet_transformer_manager.Run(packet_transformer, input_packet)));
  }
  StableSortOutputPacketsToInputPacket(input_to_output_packets);
  return input_to_output_packets;
}

}  // namespace

absl::StatusOr<CounterExample> CounterExample::CreateEquivalenceCounterExample(
    PacketTransformerManager* packet_transformer_manager,
    PacketTransformerHandle left_policy, PacketTransformerHandle right_policy) {
  if (left_policy == right_policy) {
    return absl::InvalidArgumentError(
        "Left and right policies are the same, cannot create a counter "
        "example.");
  }
  if (packet_transformer_manager == nullptr) {
    return absl::InvalidArgumentError(
        "Packet transformer manager is null, cannot create a counter example.");
  }
  return CounterExample(packet_transformer_manager, left_policy, right_policy);
}

CounterExample::CounterExample(
    PacketTransformerManager* packet_transformer_manager,
    PacketTransformerHandle left_packet_transformer,
    PacketTransformerHandle right_packet_transformer)
    : packet_transformer_manager_(packet_transformer_manager),
      left_packet_transformer_(left_packet_transformer),
      right_packet_transformer_(right_packet_transformer) {
  // Compute the set of packets that are in L but not R, and vice versa.
  PacketTransformerHandle left_diff_right_transformer =
      packet_transformer_manager_->Difference(left_packet_transformer,
                                              right_packet_transformer);
  PacketTransformerHandle right_diff_left_transformer =
      packet_transformer_manager_->Difference(right_packet_transformer,
                                              left_packet_transformer);

  // Compute the input packet sets to the difference of the left and right
  // policies and vice versa.
  PacketSetHandle fullset =
      packet_transformer_manager_->GetPacketSetManager().FullSet();
  input_packets_in_left_but_not_right_ =
      packet_transformer_manager_->Pull(left_diff_right_transformer, fullset);
  input_packets_in_right_but_not_left_ =
      packet_transformer_manager_->Pull(right_diff_left_transformer, fullset);
}

PacketTransformerHandle CounterExample::GetLeftTransformer() const {
  return left_packet_transformer_;
}
PacketTransformerHandle CounterExample::GetRightTransformer() const {
  return right_packet_transformer_;
}

PacketSetHandle CounterExample::GetInputPacketsInLeftButNotRight() const {
  return input_packets_in_left_but_not_right_;
}
PacketSetHandle CounterExample::GetInputPacketsInRightButNotLeft() const {
  return input_packets_in_right_but_not_left_;
}

PacketSetHandle CounterExample::GetInputPacketsInBoth() const {
  CHECK(packet_transformer_manager_ != nullptr);  // Crash OK
  return packet_transformer_manager_->GetPacketSetManager().Or(
      input_packets_in_left_but_not_right_,
      input_packets_in_right_but_not_left_);
}

std::string CounterExample::GetInputFromLeftButNotRightAsDotOrDie() const {
  CHECK(packet_transformer_manager_ != nullptr);  // Crash OK
  PacketTransformerHandle left_diff_right_transformer =
      packet_transformer_manager_->Difference(left_packet_transformer_,
                                              right_packet_transformer_);
  return packet_transformer_manager_->ToDot(left_diff_right_transformer);
}

std::string CounterExample::GetInputFromRightButNotLeftAsDotOrDie() const {
  CHECK(packet_transformer_manager_ != nullptr);  // Crash OK
  PacketTransformerHandle right_diff_left_transformer =
      packet_transformer_manager_->Difference(right_packet_transformer_,
                                              left_packet_transformer_);
  return packet_transformer_manager_->ToDot(right_diff_left_transformer);
}

std::vector<std::pair<Packet, OutputPackets>>
CounterExample::GetInputPacketToOutputPacketsForLeftDiffRightPoliciesOrDie()
    const {
  CHECK(packet_transformer_manager_ != nullptr);
  PacketTransformerHandle left_diff_right_transformer =
      packet_transformer_manager_->Difference(left_packet_transformer_,
                                              right_packet_transformer_);
  return GetInputPacketToOutputPackets(*packet_transformer_manager_,
                                       left_diff_right_transformer,
                                       input_packets_in_left_but_not_right_);
}

std::vector<std::pair<Packet, OutputPackets>>
CounterExample::GetInputPacketToOutputPacketsForRightDiffLeftPoliciesOrDie()
    const {
  CHECK(packet_transformer_manager_ != nullptr);
  PacketTransformerHandle right_diff_left_transformer =
      packet_transformer_manager_->Difference(right_packet_transformer_,
                                              left_packet_transformer_);
  return GetInputPacketToOutputPackets(*packet_transformer_manager_,
                                       right_diff_left_transformer,
                                       input_packets_in_right_but_not_left_);
}

template <typename Sink>
void AbslStringify(Sink& sink, const CounterExample& counter_example) {
  absl::Format(&sink, "Pull(Left - Right, FullSet):\n%s\n",
               counter_example.GetInputFromLeftButNotRightAsDotOrDie());
  absl::Format(&sink, "Pull(Right - Left, FullSet):\n%s\n",
               counter_example.GetInputFromRightButNotLeftAsDotOrDie());
  if (!counter_example
           .GetInputPacketToOutputPacketsForLeftDiffRightPoliciesOrDie()
           .empty()) {
    absl::Format(&sink,
                 "Input/Output Packet Exists in Left, but not in Right:\n");
  }
  for (const auto& [input, output] :
       counter_example
           .GetInputPacketToOutputPacketsForLeftDiffRightPoliciesOrDie()) {
    absl::Format(&sink, "- Input packet: {%s}\n",
                 absl::StrJoin(input, ",", absl::PairFormatter(": ")));
    for (const auto& output_packet : output) {
      absl::Format(
          &sink, "- Output packet: {%s}\n",
          absl::StrJoin(output_packet, ",", absl::PairFormatter(": ")));
    }
  }
  if (!counter_example
           .GetInputPacketToOutputPacketsForRightDiffLeftPoliciesOrDie()
           .empty()) {
    absl::Format(&sink,
                 "Input/Output Packet Exists in Right, but not in Left:\n");
  }
  for (const auto& [input, output] :
       counter_example
           .GetInputPacketToOutputPacketsForRightDiffLeftPoliciesOrDie()) {
    absl::Format(&sink, "- Input packet: {%s}\n",
                 absl::StrJoin(input, ",", absl::PairFormatter(": ")));
    for (const auto& output_packet : output) {
      absl::Format(
          &sink, "- Output packet: {%s}\n",
          absl::StrJoin(output_packet, ",", absl::PairFormatter(": ")));
    }
  }
}

std::ostream& operator<<(std::ostream& os,
                         const CounterExample& counter_example) {
  return os << absl::StrCat(counter_example);
}

template <typename Sink>
void AbslStringify(Sink& sink,
                   const SuccessOrCounterExample& success_or_counter_example) {
  if (success_or_counter_example.IsSuccess()) {
    absl::Format(&sink, "No counter example found.\n");
  } else {
    absl::Format(&sink, "%v",
                 success_or_counter_example.GetCounterExampleOrDie());
  }
}

std::ostream& operator<<(
    std::ostream& os,
    const SuccessOrCounterExample& success_or_counter_example) {
  return os << absl::StrCat(success_or_counter_example);
}

}  // namespace netkat
