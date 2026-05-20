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

#include "netkat/analysis_engine.h"

#include <vector>

#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "gutil/status.h"
#include "netkat/counter_example.h"
#include "netkat/frontend.h"
#include "netkat/packet.h"
#include "netkat/packet_set.h"
#include "netkat/packet_transformer.h"

namespace netkat {
namespace {
absl::Status SatisfyProperty(PacketSetManager& set_manager,
                             PacketSetHandle packets,
                             PacketSetHandle property) {
  PacketSetHandle violating_set =
      set_manager.And(packets, set_manager.Not(property));

  if (set_manager.IsEmptySet(violating_set)) {
    return absl::OkStatus();
  }

  std::vector<Packet> concrete_packets =
      set_manager.GetConcretePackets(violating_set);
  if (concrete_packets.empty()) {
    return absl::InternalError(
        "Property violated, but could not get any concrete packet from the "
        "violating set.");
  }
  return gutil::InvalidArgumentErrorBuilder()
         << "Property violated by example packet:\n "
         << PacketToString(concrete_packets[0]);
}

}  // namespace

bool AnalysisEngine::CheckEquivalent(const Predicate& left,
                                     const Predicate& right) {
  return packet_transformer_manager_.Compile(Filter(left).ToProto()) ==
         packet_transformer_manager_.Compile(Filter(right).ToProto());
}

SuccessOrCounterExample AnalysisEngine::CheckEquivalent(const Policy& left,
                                                        const Policy& right) {
  PacketTransformerHandle left_packet_transformer =
      packet_transformer_manager_.Compile(left.ToProto());
  PacketTransformerHandle right_packet_transformer =
      packet_transformer_manager_.Compile(right.ToProto());
  if (left_packet_transformer == right_packet_transformer) {
    return SuccessOrCounterExample::Success();
  }
  absl::StatusOr<CounterExample> counter_example =
      CounterExample::CreateEquivalenceCounterExample(
          left_packet_transformer, right_packet_transformer,
          packet_transformer_manager_);
  // This is expected to succeed since we already checked that the policies are
  // not the same and the Analysis Engine owns the PacketTransformerManager, so
  // this cannot be out of scope when creating the CounterExample.
  CHECK_OK(counter_example.status());  // Crash OK
  return SuccessOrCounterExample(*counter_example);
}

absl::Status AnalysisEngine::CheckPacketsSatisfyProperty(
    const Predicate& packets, const Predicate& property) {
  PacketSetManager& set_manager =
      packet_transformer_manager_.GetPacketSetManager();
  PacketSetHandle compiled_packets = set_manager.Compile(packets.ToProto());
  PacketSetHandle compiled_property = set_manager.Compile(property.ToProto());
  return SatisfyProperty(set_manager, compiled_packets, compiled_property);
}

absl::Status AnalysisEngine::CheckOutputSatisfiesProperty(
    const Predicate& input_packets, const Policy& program,
    const Predicate& property) {
  PacketSetManager& set_manager =
      packet_transformer_manager_.GetPacketSetManager();
  PacketSetHandle compiled_input = set_manager.Compile(input_packets.ToProto());
  PacketSetHandle compiled_property = set_manager.Compile(property.ToProto());

  PacketTransformerHandle program_handle =
      packet_transformer_manager_.Compile(program.ToProto());
  PacketSetHandle program_output =
      packet_transformer_manager_.Push(compiled_input, program_handle);
  return SatisfyProperty(set_manager, program_output, compiled_property);
}

bool AnalysisEngine::ProgramForwardsAnyPacket(const Policy& program,
                                              const Predicate& packets) {
  PacketTransformerHandle user_packet_handle =
      packet_transformer_manager_.Filter(packets.ToProto());
  PacketTransformerHandle program_handle =
      packet_transformer_manager_.Compile(program.ToProto());
  return packet_transformer_manager_.Sequence(user_packet_handle,
                                              program_handle) !=
         packet_transformer_manager_.Deny();
}

bool AnalysisEngine::ProgramForwardsAllPackets(const Policy& program,
                                               const Predicate& packets) {
  PacketSetManager& packet_set_manager =
      packet_transformer_manager_.GetPacketSetManager();
  PacketSetHandle user_packet_handle =
      packet_set_manager.Compile(packets.ToProto());

  // We exclude the empty set because it would always be a valid subset of any
  // program. E.g. the empty set would be accepted by the Deny program.
  if (user_packet_handle == packet_set_manager.EmptySet()) return false;

  // TODO: b/446892191 - Consider adding and benchmarking an optimization for
  // packet == True.

  // To ensure all packets are accepted, we must ensure that the set of input
  // packets are under (or equal to) the set of packets that generate a non-zero
  // output from `program`.
  PacketTransformerHandle program_handle =
      packet_transformer_manager_.Compile(program.ToProto());
  PacketSetHandle program_inputs_handle = packet_transformer_manager_.Pull(
      program_handle, packet_set_manager.FullSet());
  return packet_set_manager.Or(program_inputs_handle, user_packet_handle) ==
         program_inputs_handle;
}

bool AnalysisEngine::CheckInputProducesExactOutput(
    const Predicate& input_packets, const Policy& program,
    const Predicate& output_packets) {
  PacketSetManager& set_manager =
      packet_transformer_manager_.GetPacketSetManager();
  PacketSetHandle compiled_input = set_manager.Compile(input_packets.ToProto());
  PacketSetHandle compiled_output =
      set_manager.Compile(output_packets.ToProto());
  PacketSetHandle program_output = packet_transformer_manager_.Push(
      compiled_input, packet_transformer_manager_.Compile(program.ToProto()));
  return program_output == compiled_output;
}

bool AnalysisEngine::CheckInputProducesAtMostGivenOutput(
    const Predicate& input_packets, const Policy& program,
    const Predicate& output_packets) {
  PacketSetManager& set_manager =
      packet_transformer_manager_.GetPacketSetManager();
  PacketSetHandle compiled_input = set_manager.Compile(input_packets.ToProto());
  PacketSetHandle compiled_output =
      set_manager.Compile(output_packets.ToProto());
  PacketSetHandle program_output = packet_transformer_manager_.Push(
      compiled_input, packet_transformer_manager_.Compile(program.ToProto()));

  if (program_output == compiled_output) return true;
  if (program_output == set_manager.EmptySet()) return false;

  return SatisfyProperty(set_manager, program_output, compiled_output).ok();
}

}  // namespace netkat
