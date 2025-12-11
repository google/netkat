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
#include "netkat/packet_set.h"
#include "netkat/packet_transformer.h"

namespace netkat {

using OutputPackets = absl::flat_hash_set<Packet>;

// A counter example shows the input/output packets that belong to one policy,
// but not the other.
class CounterExample {
 public:
  explicit CounterExample(
      PacketTransformerManager* packet_transformer_manager,  // NOLINT
      PacketTransformerHandle left_diff_right_transformer,
      PacketTransformerHandle right_diff_left_transformer,
      PacketSetHandle input_from_left_diff_right_policies,
      PacketSetHandle input_from_right_diff_left_policies)
      : packet_transformer_manager_(std::move(packet_transformer_manager)),
        left_diff_right_transformer_(left_diff_right_transformer),
        right_diff_left_transformer_(right_diff_left_transformer),
        input_from_left_diff_right_policies_(
            input_from_left_diff_right_policies),
        input_from_right_diff_left_policies_(
            input_from_right_diff_left_policies) {}

  PacketTransformerHandle GetLeftDiffRightTransformer() const;
  PacketTransformerHandle GetRightDiffLeftTransformer() const;
  PacketSetHandle GetInputFromLeftDiffRightPolicies() const;
  PacketSetHandle GetInputFromRightDiffLeftPolicies() const;

  // Returns the packet set's dot representation for the counter-example
  // represented by the following:
  // PacketSetHandle := Pull(left policy - right policy, FullSet).
  std::string GetInputFromLeftDiffRightPoliciesAsDot() const;

  // Returns the packet set's dot representation for the counter-example
  // represented by the following:
  // PacketSetHandle := Pull(right policy - left policy, FullSet).
  std::string GetInputFromRightDiffLeftPoliciesAsDot() const;

  // Returns a map from input packets to output packets for the counter-example
  // represented by PacketSetHandle := Pull(left policy - right policy,
  // FullSet).
  std::vector<std::pair<Packet, OutputPackets>>
  GetInputPacketToOutputPacketsForLeftDiffRightPoliciesOrDie() const;

  // Returns a map from input packets to output packets for the
  // counter-example represented by PacketSetHandle := Pull(right policy -
  // left policy, FullSet).
  std::vector<std::pair<Packet, OutputPackets>>
  GetInputPacketToOutputPacketsForRightDiffLeftPoliciesOrDie() const;

 private:
  PacketTransformerManager* packet_transformer_manager_;
  PacketTransformerHandle left_diff_right_transformer_;
  PacketTransformerHandle right_diff_left_transformer_;
  PacketSetHandle input_from_left_diff_right_policies_;
  PacketSetHandle input_from_right_diff_left_policies_;
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

  const CounterExample& GetCounterExampleOrDie() const {
    CHECK(counter_example_.has_value());
    return *counter_example_;
  }

 private:
  std::optional<CounterExample> counter_example_;
};

std::ostream& operator<<(
    std::ostream& os,
    const SuccessOrCounterExample& success_or_counter_example);

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_COUNTER_EXAMPLE_H_
