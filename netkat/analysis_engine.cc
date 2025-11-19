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

#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/container/btree_map.h"
#include "netkat/counter_example.h"
#include "netkat/evaluator.h"
#include "netkat/frontend.h"
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

SuccessOrCounterExample GenerateCounterExamples(
    PacketTransformerManager& packet_transformer_manager, const Policy& left,
    const Policy& right) {
  PacketTransformerHandle left_packet_transformer =
      packet_transformer_manager.Compile(left.ToProto());
  PacketTransformerHandle right_packet_transformer =
      packet_transformer_manager.Compile(right.ToProto());
  if (left_packet_transformer == right_packet_transformer) {
    return SuccessOrCounterExample();
  }

  // Compute the set of packets that are in L but not R, and vice versa.
  PacketTransformerHandle left_diff_right_transformer =
      packet_transformer_manager.Difference(left_packet_transformer,
                                            right_packet_transformer);
  PacketTransformerHandle right_diff_left_transformer =
      packet_transformer_manager.Difference(right_packet_transformer,
                                            left_packet_transformer);

  // Compute the input packet sets to the difference of the left and right
  // policies and vice versa.
  PacketSetHandle fullset =
      packet_transformer_manager.GetPacketSetManager().FullSet();
  PacketSetHandle input_packet_set_for_left_diff_right_policies =
      packet_transformer_manager.Pull(left_diff_right_transformer, fullset);
  PacketSetHandle input_packet_set_for_right_diff_left_policies =
      packet_transformer_manager.Pull(right_diff_left_transformer, fullset);

  // Compute the output packets for each input packet for the counter examples.
  std::vector<std::pair<Packet, OutputPackets>>
      output_packets_to_input_packet_for_left_diff_right_policies;

  // TODO: b/463710729 - Remove comment once GetConcretePackets returns a
  // comprehensive set of packets.
  // Currently, GetConcretePackets returns a set of packets that are not
  // guaranteed to be exhaustive.
  std::vector<Packet> input_packets_for_left_diff_right_policies =
      packet_transformer_manager.GetPacketSetManager().GetConcretePackets(
          input_packet_set_for_left_diff_right_policies);
  output_packets_to_input_packet_for_left_diff_right_policies.reserve(
      input_packets_for_left_diff_right_policies.size());
  for (Packet& input_packet : input_packets_for_left_diff_right_policies) {
    output_packets_to_input_packet_for_left_diff_right_policies.push_back(
        std::make_pair(input_packet,
                       packet_transformer_manager.Run(
                           left_diff_right_transformer, input_packet)));
  }
  StableSortOutputPacketsToInputPacket(
      output_packets_to_input_packet_for_left_diff_right_policies);

  std::vector<std::pair<Packet, OutputPackets>>
      output_packets_to_input_packet_for_right_diff_left_policies;

  // TODO: b/463710729 - Remove comment once GetConcretePackets returns a
  // comprehensive set of packets.
  // Currently, GetConcretePackets returns a set of packets that are not
  // guaranteed to be exhaustive.
  std::vector<Packet> input_packets_for_right_diff_left_policies =
      packet_transformer_manager.GetPacketSetManager().GetConcretePackets(
          input_packet_set_for_right_diff_left_policies);
  output_packets_to_input_packet_for_right_diff_left_policies.reserve(
      input_packets_for_right_diff_left_policies.size());
  for (Packet& input_packet : input_packets_for_right_diff_left_policies) {
    output_packets_to_input_packet_for_right_diff_left_policies.push_back(
        std::make_pair(input_packet,
                       packet_transformer_manager.Run(
                           right_diff_left_transformer, input_packet)));
  }
  StableSortOutputPacketsToInputPacket(
      output_packets_to_input_packet_for_right_diff_left_policies);

  return SuccessOrCounterExample(CounterExample(
      packet_transformer_manager.GetPacketSetManager().ToDot(
          input_packet_set_for_left_diff_right_policies),
      packet_transformer_manager.GetPacketSetManager().ToDot(
          input_packet_set_for_right_diff_left_policies),
      output_packets_to_input_packet_for_left_diff_right_policies,
      output_packets_to_input_packet_for_right_diff_left_policies));
}
}  // namespace

bool AnalysisEngine::CheckEquivalent(const Predicate& left,
                                     const Predicate& right) {
  return packet_transformer_manager_.Compile(Filter(left).ToProto()) ==
         packet_transformer_manager_.Compile(Filter(right).ToProto());
}

SuccessOrCounterExample AnalysisEngine::CheckEquivalent(const Policy& left,
                                                        const Policy& right) {
  if (packet_transformer_manager_.Compile(left.ToProto()) ==
      packet_transformer_manager_.Compile(right.ToProto())) {
    return SuccessOrCounterExample();
  }
  return GenerateCounterExamples(packet_transformer_manager_, left, right);
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
