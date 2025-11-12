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

#include <optional>

#include "absl/strings/str_cat.h"
#include "benchmark/benchmark.h"
#include "netkat/netkat.pb.h"
#include "netkat/netkat_proto_constructors.h"
#include "netkat/packet_transformer.h"

namespace netkat {
// Create an arbitrary fixed policy with some relative complexity. In this
// case:
//
//    0 + (filter(a=1); b:=3)*; filter(!((c=1 + b=2) (+) d=3 && e=4))
//
// `id_suffix` will be appended to each match label to generate unique policies.
//
// We use this, rather than fuzztest::Domain, because we want a fixed policy
// that we can consistently benchmark on.
PolicyProto CreateFixedArbitraryPolicyProto(
    std::optional<int> id_suffix = std::nullopt) {
  return UnionProto(
      DenyProto(),
      SequenceProto(
          IterateProto(SequenceProto(
              FilterProto(
                  MatchProto(absl::StrCat("a", id_suffix.value_or(0)), 1)),
              ModificationProto(absl::StrCat("b", id_suffix.value_or(0)), 3))),
          FilterProto(NotProto(XorProto(
              OrProto(MatchProto(absl::StrCat("c", id_suffix.value_or(0)), 1),
                      MatchProto(absl::StrCat("b", id_suffix.value_or(0)), 2)),
              AndProto(
                  MatchProto(absl::StrCat("d", id_suffix.value_or(0)), 3),
                  MatchProto(absl::StrCat("e", id_suffix.value_or(0)), 4)))))));
}

// Benchmarks the first-time cost of compiling a policy that has minimal
// overlapping substructures.
void BM_FirstTimeCompileNonOverlappingPolicy(benchmark::State& state) {
  PolicyProto sub_policy1 = CreateFixedArbitraryPolicyProto(/*id_suffix=*/1);
  PolicyProto sub_policy2 = CreateFixedArbitraryPolicyProto(/*id_suffix=*/2);
  PolicyProto policy = SequenceProto(
      UnionProto(sub_policy1, sub_policy2),
      UnionProto(IterateProto(sub_policy1),
                 IterateProto(SequenceProto(sub_policy1, sub_policy2))));
  for (auto s : state) {
    PacketTransformerManager manager;
    PacketTransformerHandle transformer = manager.Compile(policy);
    benchmark::DoNotOptimize(transformer);
  }
}
BENCHMARK(BM_FirstTimeCompileNonOverlappingPolicy);

// Benchmarks the cost of compiling a policy, with minimal overlapping
// substructures, that has already been compiled once before. Excludes the
// initial cost of compilation.
void BM_ReCompileNonOverlappingPolicy(benchmark::State& state) {
  PolicyProto sub_policy1 = CreateFixedArbitraryPolicyProto(/*id_suffix=*/1);
  PolicyProto sub_policy2 = CreateFixedArbitraryPolicyProto(/*id_suffix=*/2);
  PolicyProto policy = SequenceProto(
      UnionProto(sub_policy1, sub_policy2),
      UnionProto(IterateProto(sub_policy1),
                 IterateProto(SequenceProto(sub_policy1, sub_policy2))));
  PacketTransformerManager manager;
  PacketTransformerHandle transformer = manager.Compile(policy);
  for (auto s : state) {
    transformer = manager.Compile(policy);
    benchmark::DoNotOptimize(transformer);
  }
}
BENCHMARK(BM_ReCompileNonOverlappingPolicy);

// Benchmarks the first-time cost of compiling a policy that has overlapping
// substructures.
void BM_FirstTimeCompileOverlappingPolicy(benchmark::State& state) {
  PolicyProto sub_policy = CreateFixedArbitraryPolicyProto();
  PolicyProto policy = SequenceProto(
      UnionProto(sub_policy, sub_policy),
      UnionProto(IterateProto(sub_policy),
                 IterateProto(SequenceProto(sub_policy, sub_policy))));
  for (auto s : state) {
    PacketTransformerManager manager;
    PacketTransformerHandle transformer = manager.Compile(policy);
    benchmark::DoNotOptimize(transformer);
  }
}
BENCHMARK(BM_FirstTimeCompileOverlappingPolicy);

// Benchmarks the cost of compiling a policy, with overlapping substructures,
// that has already been compiled once before. Excludes the initial cost of
// compilation.
void BM_ReCompileOverlappingPolicy(benchmark::State& state) {
  PolicyProto sub_policy = CreateFixedArbitraryPolicyProto();
  PolicyProto policy = SequenceProto(
      UnionProto(sub_policy, sub_policy),
      UnionProto(IterateProto(sub_policy),
                 IterateProto(SequenceProto(sub_policy, sub_policy))));
  PacketTransformerManager manager;
  PacketTransformerHandle transformer = manager.Compile(policy);
  for (auto s : state) {
    transformer = manager.Compile(policy);
    benchmark::DoNotOptimize(transformer);
  }
}
BENCHMARK(BM_ReCompileOverlappingPolicy);

}  // namespace netkat
