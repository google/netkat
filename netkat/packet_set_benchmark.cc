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
#include "netkat/packet_set.h"

namespace netkat {
// Create an arbitrary fixed policy with some relative complexity. In this
// case:
//
//    0 + 1 && !((a=1 + b=2) (+) c=3 && d=4)
//
// `id_suffix` will be appended to each match label to generate unique policies.
//
// We use this, rather than fuzztest::Domain, because we want a fixed policy
// that we can consistently benchmark on.
PredicateProto CreateFixedArbitraryPredicateProto(
    std::optional<int> id_suffix = std::nullopt) {
  return OrProto(
      FalseProto(),
      AndProto(
          TrueProto(),
          NotProto(XorProto(
              OrProto(MatchProto(absl::StrCat("a", id_suffix.value_or(0)), 1),
                      MatchProto(absl::StrCat("b", id_suffix.value_or(0)), 2)),
              AndProto(
                  MatchProto(absl::StrCat("c", id_suffix.value_or(0)), 3),
                  MatchProto(absl::StrCat("d", id_suffix.value_or(0)), 4))))));
}

// Benchmarks the first-time cost of compiling a predicate that has minimal
// overlapping substructures.
void BM_FirstTimeCompileNonOverlappingPredicate(benchmark::State& state) {
  PredicateProto sub_policy1 =
      AndProto(CreateFixedArbitraryPredicateProto(/*id_suffix=*/1),
               CreateFixedArbitraryPredicateProto(/*id_suffix=*/2));
  PredicateProto sub_policy2 =
      AndProto(CreateFixedArbitraryPredicateProto(/*id_suffix=*/3),
               CreateFixedArbitraryPredicateProto(/*id_suffix=*/4));
  PredicateProto policy = OrProto(sub_policy1, sub_policy2);

  for (auto s : state) {
    PacketSetManager manager;
    PacketSetHandle handle = manager.Compile(policy);
    benchmark::DoNotOptimize(handle);
  }
}
BENCHMARK(BM_FirstTimeCompileNonOverlappingPredicate);

// Benchmarks the cost of compiling a predicate, with minimal overlapping
// substructures, that has already been compiled once before. Excludes the
// initial cost of compilation.
void BM_ReCompileNonOverlappingPredicate(benchmark::State& state) {
  PredicateProto sub_policy1 =
      AndProto(CreateFixedArbitraryPredicateProto(/*id_suffix=*/1),
               CreateFixedArbitraryPredicateProto(/*id_suffix=*/2));
  PredicateProto sub_policy2 =
      AndProto(CreateFixedArbitraryPredicateProto(/*id_suffix=*/3),
               CreateFixedArbitraryPredicateProto(/*id_suffix=*/4));
  PredicateProto policy = OrProto(sub_policy1, sub_policy2);

  PacketSetManager manager;
  PacketSetHandle handle = manager.Compile(policy);
  for (auto s : state) {
    handle = manager.Compile(policy);
    benchmark::DoNotOptimize(handle);
  }
}
BENCHMARK(BM_ReCompileNonOverlappingPredicate);

// Benchmarks the first-time cost of compiling a predicate that has overlapping
// substructures.
void BM_FirstTimeCompileOverlappingPredicate(benchmark::State& state) {
  PredicateProto sub_policy1 = AndProto(CreateFixedArbitraryPredicateProto(),
                                        CreateFixedArbitraryPredicateProto());
  PredicateProto sub_policy2 = AndProto(CreateFixedArbitraryPredicateProto(),
                                        CreateFixedArbitraryPredicateProto());
  PredicateProto policy = OrProto(sub_policy1, sub_policy2);

  for (auto s : state) {
    PacketSetManager manager;
    PacketSetHandle handle = manager.Compile(policy);
    benchmark::DoNotOptimize(handle);
  }
}
BENCHMARK(BM_FirstTimeCompileOverlappingPredicate);

// Benchmarks the cost of compiling a predicate, with overlapping substructures,
// that has already been compiled once before. Excludes the initial cost of
// compilation.
void BM_ReCompileOverlappingPredicate(benchmark::State& state) {
  PredicateProto sub_policy1 = AndProto(CreateFixedArbitraryPredicateProto(),
                                        CreateFixedArbitraryPredicateProto());
  PredicateProto sub_policy2 = AndProto(CreateFixedArbitraryPredicateProto(),
                                        CreateFixedArbitraryPredicateProto());
  PredicateProto policy = OrProto(sub_policy1, sub_policy2);

  PacketSetManager manager;
  PacketSetHandle handle = manager.Compile(policy);
  for (auto s : state) {
    handle = manager.Compile(policy);
    benchmark::DoNotOptimize(handle);
  }
}
BENCHMARK(BM_ReCompileOverlappingPredicate);

}  // namespace netkat
