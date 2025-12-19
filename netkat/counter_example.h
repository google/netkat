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
#include <utility>

#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "netkat/evaluator.h"
#include "netkat/packet_set.h"
#include "netkat/packet_transformer.h"

namespace netkat {

using OutputPackets = absl::flat_hash_set<Packet>;

// A counter example contains the difference between two policies and the
// corresponding input/output packets that belong to one policy, but not the
// other and vice versa.
//
// Note: The lifetime of `CounterExample` is dependent on the
// lifetime of the `PacketTransformerManager` that created it.
class CounterExample {
 public:
  // Creates a counter example for the given `left_policy` and `right_policy`.
  // The counter example is defined as:
  //   counter example := Pull(left policy - right policy, FullSet) or
  //   counter example := Pull(right policy - left policy, FullSet).
  //
  // Returns an error if the `packet_transformer_manager` is null or if the
  // `left_policy` and `right_policy` are the same.
  static absl::StatusOr<CounterExample> CreateEquivalenceCounterExample(
      PacketTransformerHandle left_policy, PacketTransformerHandle right_policy,
      PacketTransformerManager* packet_transformer_manager);

  PacketTransformerHandle GetLeftTransformer() const;
  PacketTransformerHandle GetRightTransformer() const;

  // Returns the first arbitrary input packet that produces an output packet
  // when run through the left transformer, but no output packet when run
  // through the right transformer. Will return an error if the packet
  // transformer manager is null or if the packet set is empty.
  // The counterexample packet set is represented by the following:
  // PacketSetHandle := Pull(left policy - right policy, FullSet).
  absl::StatusOr<Packet> GetInputPacketInLeftButNotRight() const;

  // Returns the first arbitrary input packet that produces an output packet
  // when run through the right transformer, but no output packet when run
  // through the left transformer. Will return an error if the packet
  // transformer manager is null or if the packet set is empty.
  // transformer. The counterexample is represented by the following:
  // PacketSetHandle := Pull(right policy - left policy, FullSet).
  absl::StatusOr<Packet> GetInputPacketInRightButNotLeft() const;

 private:
  CounterExample(PacketTransformerHandle left_packet_transformer,
                 PacketTransformerHandle right_packet_transformer,
                 PacketTransformerManager* packet_transformer_manager);

  PacketTransformerHandle left_packet_transformer_;
  PacketTransformerHandle right_packet_transformer_;
  PacketTransformerManager* packet_transformer_manager_;
  PacketSetHandle input_packets_in_left_but_not_right_;
  PacketSetHandle input_packets_in_right_but_not_left_;
};

// A success or counter example is a wrapper around a counter example.
// If the two policies compared in the analysis engine are the same, the
// SuccessOrCounterExample should have no counter example and return true when
// IsSuccess is called. Otherwise, if IsSuccess returns false, then the
// SuccessOrCounterExample will contain a counter example.
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

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_COUNTER_EXAMPLE_H_
