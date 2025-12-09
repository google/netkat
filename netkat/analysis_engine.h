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
//
// -----------------------------------------------------------------------------
// File: analysis_engine.h
// -----------------------------------------------------------------------------
//
// The user-facing API for reasoning about NetKAT policies and predicates.

#ifndef GOOGLE_NETKAT_NETKAT_ANALYSIS_ENGINE_H_
#define GOOGLE_NETKAT_NETKAT_ANALYSIS_ENGINE_H_

#include "netkat/frontend.h"
#include "netkat/packet_transformer.h"

namespace netkat {

// Class for reasoning about NetKAT policies and predicates.
//
// This is a class rather than a namespace of free functions as the class
// maintains state to optimize the speed of repeated calls. The state is not
// intended to have any effect on functional behavior.
//
// TODO: b/398303840 - Persistent use of an `AnalysisEngine` object can incur
// unbounded memory growth. Consider adding some garbage collection mechanism.
//
// TODO: b/446886431 - Boolean returns for `AnalysisEngine` are difficult to
// triage. Consider a more nuanced scheme, such as some description object or
// Status that allows EXPECTs or prod code to print or announce more useful
// information.
class AnalysisEngine {
 public:
  // Checks whether two predicates are "equivalent", meaning they match the same
  // set of packets, meaning `Evaluate(left, packet) == Evaluate(right, packet)`
  // for all packets.
  bool CheckEquivalent(const Predicate& left, const Predicate& right);

  // Checks whether two policies are "equivalent", meaning they have the same
  // packets transformations, meaning Evaluate(left, packet) == Evaluate(right,
  // packet) for all packets.
  bool CheckEquivalent(const Policy& left, const Policy& right);

  // Returns whether any given packet, represented by the set of packets in
  // `packets`, is forwarded by `program`. A packet is considered "forwaded" if
  // it produces some non-zero output packet when the `program` is run on it.
  //
  // More formally, this is equivalent to: filter(packets); program != 0.
  bool ProgramForwardsAnyPacket(const Policy& program,
                                const Predicate& packets);

  // Returns whether all `packets` are forwarded by `program`. A packet is
  // considered "forwarded" if it produces some non-zero output when the
  // `program` is run on it.
  //
  // Note that this excludes the empty set of packets from ever returning that
  // it is forwarded, since it can never produce a non-zero output.
  //
  // More formally, this is equivalent to:
  //   packets != 0 && pull(program, 1) >= packets.
  bool ProgramForwardsAllPackets(const Policy& program,
                                 const Predicate& packets);

  // Returns whether the given `packets` are all dropped by the given `program`.
  // I.e., this returns true if no subset of `packets` is forwarded by
  // `program`.
  bool ProgramDropsAllPackets(const Policy& program, const Predicate& packets) {
    return !ProgramForwardsAnyPacket(program, packets);
  }

  // Returns whether the given `input_packets`, after being pushed through
  // `program`, will produce an output exactly equal to `output_packets`.
  //
  // Equivalent to: push(input_packet, program) == output_packet.
  bool CheckInputProducesExactOutput(const Predicate& input_packets,
                                     const Policy& program,
                                     const Predicate& output_packets);

  // Returns whether the given `input_packets`, after being pushed through
  // `program`, will produce an output lesser than or equal to `output_packets`.
  //
  // Equivalent to: push(input_packet, program) <= output_packet.
  //
  // Note that the empty set is not considered a subset of `output_packets`,
  // unless `output_packets` is also empty. This stops programs that would drop
  // a given input from being considered able to produce any output.
  bool CheckInputProducesAtMostGivenOutput(const Predicate& input_packets,
                                           const Policy& program,
                                           const Predicate& output_packets);

 private:
  PacketTransformerManager packet_transformer_manager_;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_ANALYSIS_ENGINE_H_
