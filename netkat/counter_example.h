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

#ifndef GOOGLE_NETKAT_NETKAT_COUNTER_EXAMPLE_H_
#define GOOGLE_NETKAT_NETKAT_COUNTER_EXAMPLE_H_

#include <optional>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "netkat/evaluator.h"

namespace netkat {

using OutputPackets = absl::flat_hash_set<Packet>;

// A counter example shows the input/output packets that belong to one policy,
// but not the other.
class CounterExample {
 public:
  explicit CounterExample(
      std::string input_packet_set_from_left_diff_right_policies,
      std::string input_packet_set_from_right_diff_left_policies,
      std::vector<std::pair<Packet, OutputPackets>>
          output_packets_to_input_packet_for_left_diff_right_policies,
      std::vector<std::pair<Packet, OutputPackets>>
          output_packets_to_input_packet_for_right_diff_left_policies)
      : input_packet_set_from_left_diff_right_policies_(
            input_packet_set_from_left_diff_right_policies),
        input_packet_set_from_right_diff_left_policies_(
            input_packet_set_from_right_diff_left_policies),
        output_packets_to_input_packet_for_left_diff_right_policies_(
            output_packets_to_input_packet_for_left_diff_right_policies),
        output_packets_to_input_packet_for_right_diff_left_policies_(
            output_packets_to_input_packet_for_right_diff_left_policies) {}

  // Returns the packet set's dot representation for the counter-example
  // represented by the following:
  // PacketSetHandle := Pull(left policy - right policy, FullSet).
  std::string GetInputPacketSetFromLeftDiffRightPolicies() const;

  // Returns the packet set's dot representation for the counter-example
  // represented by the following:
  // PacketSetHandle := Pull(right policy - left policy, FullSet).
  std::string GetInputPacketSetFromRightDiffLeftPolicies() const;

  // Returns a map from input packets to output packets for the counter-example
  // represented by PacketSetHandle := Pull(left policy - right policy,
  // FullSet).
  std::vector<std::pair<Packet, OutputPackets>>
  GetOutputPacketsToInputPacketForLeftDiffRightPolicies() const;

  // Returns a map from input packets to output packets for the counter-example
  // represented by PacketSetHandle := Pull(right policy - left policy,
  // FullSet).
  std::vector<std::pair<Packet, OutputPackets>>
  GetOutputPacketsToInputPacketForRightDiffLeftPolicies() const;

 private:
  std::string input_packet_set_from_left_diff_right_policies_;
  std::string input_packet_set_from_right_diff_left_policies_;
  std::vector<std::pair<Packet, OutputPackets>>
      output_packets_to_input_packet_for_left_diff_right_policies_;
  std::vector<std::pair<Packet, OutputPackets>>
      output_packets_to_input_packet_for_right_diff_left_policies_;
};

template <typename Sink>
void AbslStringify(Sink& sink, const CounterExample& counter_example);
std::ostream& operator<<(std::ostream& os,
                         const CounterExample& counter_example);

class SuccessOrCounterExample {
 public:
  SuccessOrCounterExample() = default;
  explicit SuccessOrCounterExample(CounterExample counter_example)
      : counter_example_(std::move(counter_example)) {}

  bool IsSuccess() const { return !counter_example_.has_value(); }

  const CounterExample& GetCounterExample() const& {
    DCHECK(counter_example_.has_value());
    return *counter_example_;
  }
  CounterExample& GetCounterExample() & {
    DCHECK(counter_example_.has_value());
    return *counter_example_;
  }
  CounterExample&& GetCounterExample() && {
    DCHECK(counter_example_.has_value());
    return std::move(*counter_example_);
  }

 private:
  std::optional<CounterExample> counter_example_;
};

std::ostream& operator<<(
    std::ostream& os,
    const SuccessOrCounterExample& success_or_counter_example);

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_COUNTER_EXAMPLE_H_
