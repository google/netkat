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

#include "netkat/frontend.h"
#include "netkat/packet_set.h"
#include "netkat/packet_transformer.h"

namespace netkat {

bool AnalysisEngine::CheckEquivalent(const Predicate& left,
                                     const Predicate& right) {
  return packet_transformer_manager_.Compile(Filter(left).ToProto()) ==
         packet_transformer_manager_.Compile(Filter(right).ToProto());
}

bool AnalysisEngine::CheckEquivalent(const Policy& left, const Policy& right) {
  return packet_transformer_manager_.Compile(left.ToProto()) ==
         packet_transformer_manager_.Compile(right.ToProto());
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

bool AnalysisEngine::CheckInputProducesOutput(const Predicate& input_packets,
                                              const Policy& program,
                                              const Predicate& output_packets) {
  PacketSetManager& set_manager =
      packet_transformer_manager_.GetPacketSetManager();
  PacketSetHandle compiled_input = set_manager.Compile(input_packets.ToProto());
  PacketSetHandle compiled_output =
      set_manager.Compile(output_packets.ToProto());
  PacketTransformerHandle compiled_program =
      packet_transformer_manager_.Compile(program.ToProto());
  PacketSetHandle program_output =
      packet_transformer_manager_.Push(compiled_input, compiled_program);
  return program_output == compiled_output;
}

}  // namespace netkat
