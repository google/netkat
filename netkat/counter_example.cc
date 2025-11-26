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

#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "netkat/evaluator.h"

namespace netkat {

std::string CounterExample::GetInputPacketSetFromLeftDiffRightPolicies() const {
  return input_packet_set_from_left_diff_right_policies_;
}
std::string CounterExample::GetInputPacketSetFromRightDiffLeftPolicies() const {
  return input_packet_set_from_right_diff_left_policies_;
}
std::vector<std::pair<Packet, OutputPackets>>
CounterExample::GetOutputPacketsToInputPacketForLeftDiffRightPolicies() const {
  return output_packets_to_input_packet_for_left_diff_right_policies_;
}
std::vector<std::pair<Packet, OutputPackets>>
CounterExample::GetOutputPacketsToInputPacketForRightDiffLeftPolicies() const {
  return output_packets_to_input_packet_for_right_diff_left_policies_;
}

template <typename Sink>
void AbslStringify(Sink& sink, const CounterExample& counter_example) {
  absl::Format(
      &sink,
      "Pull(Left - Right, FullSet):\n%s\nPull(Right - Left, FullSet):\n%s\n",
      counter_example.GetInputPacketSetFromLeftDiffRightPolicies(),
      counter_example.GetInputPacketSetFromRightDiffLeftPolicies());
  if (!counter_example.GetOutputPacketsToInputPacketForLeftDiffRightPolicies()
           .empty()) {
    absl::Format(&sink,
                 "Input/Output Packet Exists in Left, but not in Right:\n");
  }
  for (const auto& [input, output] :
       counter_example
           .GetOutputPacketsToInputPacketForLeftDiffRightPolicies()) {
    absl::Format(&sink, "- Input packet: {%s}\n",
                 absl::StrJoin(input, ",", absl::PairFormatter(": ")));
    for (const auto& output_packet : output) {
      absl::Format(
          &sink, "- Output packet: {%s}\n",
          absl::StrJoin(output_packet, ",", absl::PairFormatter(": ")));
    }
  }
  if (!counter_example.GetOutputPacketsToInputPacketForRightDiffLeftPolicies()
           .empty()) {
    absl::Format(&sink,
                 "Input/Output Packet Exists in Right, but not in Left:\n");
  }
  for (const auto& [input, output] :
       counter_example
           .GetOutputPacketsToInputPacketForRightDiffLeftPolicies()) {
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

std::ostream& operator<<(
    std::ostream& os,
    const SuccessOrCounterExample& success_or_counter_example) {
  if (success_or_counter_example.IsSuccess()) {
    return os << "No counter example found.\n";
  } else {
    return os << success_or_counter_example.GetCounterExample();
  }
}

}  // namespace netkat
