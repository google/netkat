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

#include <cstddef>
#include <optional>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "benchmark/benchmark.h"
#include "netkat/netkat.pb.h"
#include "netkat/netkat_proto_constructors.h"
#include "netkat/packet_set.h"
#include "netkat/packet_transformer.h"

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
    PacketTransformerManager transformer;
    PacketSetManager& manager = transformer.GetPacketSetManager();
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

  PacketTransformerManager transformer;
  PacketSetManager& manager = transformer.GetPacketSetManager();
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
    PacketTransformerManager transformer;
    PacketSetManager& manager = transformer.GetPacketSetManager();
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

  PacketTransformerManager transformer;
  PacketSetManager& manager = transformer.GetPacketSetManager();
  PacketSetHandle handle = manager.Compile(policy);
  for (auto s : state) {
    handle = manager.Compile(policy);
    benchmark::DoNotOptimize(handle);
  }
}
BENCHMARK(BM_ReCompileOverlappingPredicate);

// Benchmarks the first-time cost of compiling a predicate with a high degree of
// overlapping substructures, exercising memoization.
void BM_FirstTimeCompileAndWithHighOverlappingPredicate(
    benchmark::State& state) {
  // 1. Create base predicates. Using 3 distinct base BDD structures creates
  // significant BDD complexity and overlap when combined in a DAG.
  std::vector<PredicateProto> predicates;
  predicates.reserve(6);
  for (int i = 0; i < 6; ++i) {
    predicates.push_back(
        CreateFixedArbitraryPredicateProto(/*id_suffix=*/i % 3));
  }

  // 2. Combine them into a DAG of predicates. We do this in 6 layers to
  // prevent the exponential growth of the protobuf tree from dwarfing BDD
  // compilation time.
  for (int layer = 0; layer < 6; ++layer) {
    std::vector<PredicateProto> next_layer;
    for (size_t i = 0; i < predicates.size(); ++i) {
      size_t next_idx = (i + 1) % predicates.size();
      // Use AND and OR (which uses AND and NOT internally)
      if (i % 2 == 0) {
        next_layer.push_back(AndProto(predicates[i], predicates[next_idx]));
      } else {
        next_layer.push_back(OrProto(predicates[i], predicates[next_idx]));
      }
    }
    predicates = std::move(next_layer);
  }

  for (auto s : state) {
    PacketTransformerManager transformer;
    PacketSetManager& manager = transformer.GetPacketSetManager();
    PacketSetHandle handle;
    for (auto& predicate : predicates) {
      handle = manager.Compile(predicate);
      benchmark::DoNotOptimize(handle);
    }
  }
}
BENCHMARK(BM_FirstTimeCompileAndWithHighOverlappingPredicate);

// Benchmarks the cost of compiling a predicate with a high degree of
// overlapping substructures, that has already been compiled once before.
// Excludes the initial cost of compilation.
void BM_ReCompileAndWithHighOverlappingPredicate(benchmark::State& state) {
  // 1. Create base predicates. Using 3 distinct base BDD structures creates
  // significant BDD complexity and overlap when combined in a DAG.
  std::vector<PredicateProto> predicates;
  predicates.reserve(6);
  for (int i = 0; i < 6; ++i) {
    predicates.push_back(
        CreateFixedArbitraryPredicateProto(/*id_suffix=*/i % 3));
  }

  // 2. Combine them into a DAG of predicates. We do this in 6 layers to
  // prevent the exponential growth of the protobuf tree from dwarfing BDD
  // compilation time.
  for (int layer = 0; layer < 6; ++layer) {
    std::vector<PredicateProto> next_layer;
    for (size_t i = 0; i < predicates.size(); ++i) {
      size_t next_idx = (i + 1) % predicates.size();
      // Use AND and OR (which uses AND and NOT internally)
      if (i % 2 == 0) {
        next_layer.push_back(AndProto(predicates[i], predicates[next_idx]));
      } else {
        next_layer.push_back(OrProto(predicates[i], predicates[next_idx]));
      }
    }
    predicates = std::move(next_layer);
  }

  PacketTransformerManager transformer;
  PacketSetManager& manager = transformer.GetPacketSetManager();
  PacketSetHandle handle;
  for (auto& predicate : predicates) {
    handle = manager.Compile(predicate);
    benchmark::DoNotOptimize(handle);
  }
  for (auto s : state) {
    for (auto& predicate : predicates) {
      handle = manager.Compile(predicate);
      benchmark::DoNotOptimize(handle);
    }
  }
}
BENCHMARK(BM_ReCompileAndWithHighOverlappingPredicate);

// Benchmarks the cost of applying NOT to the same packet set multiple times.
// This heavily exercises the `not_cache_`.
void BM_NotOnSamePacketSet(benchmark::State& state) {
  PredicateProto proto = CreateFixedArbitraryPredicateProto();
  PacketTransformerManager transformer;
  PacketSetManager& manager = transformer.GetPacketSetManager();
  PacketSetHandle handle = manager.Compile(proto);

  for (auto s : state) {
    PacketSetHandle negated = manager.Not(handle);
    benchmark::DoNotOptimize(negated);
  }
}
BENCHMARK(BM_NotOnSamePacketSet);

// Benchmarks Or operations that share operands. Since Or is implemented via
// And and Not, sharing operands means we repeatedly call Not on the same
// BDD handles, exercising the `not_cache_`.
void BM_OrOperationsSharingOperands(benchmark::State& state) {
  PredicateProto proto1 = CreateFixedArbitraryPredicateProto(/*id_suffix=*/1);
  PredicateProto google::protobuf =
      CreateFixedArbitraryPredicateProto(/*id_suffix=*/2);
  PredicateProto proto3 = CreateFixedArbitraryPredicateProto(/*id_suffix=*/3);

  for (auto s : state) {
    PacketTransformerManager transformer;
    PacketSetManager& manager = transformer.GetPacketSetManager();
    PacketSetHandle h1 = manager.Compile(proto1);
    PacketSetHandle h2 = manager.Compile(google::protobuf);
    PacketSetHandle h3 = manager.Compile(proto3);

    // Or(h1, h2) calls Not(h1), Not(h2), And, Not
    PacketSetHandle or1 = manager.Or(h1, h2);
    // Or(h1, h3) calls Not(h1) [cache hit!], Not(h3), And, Not
    PacketSetHandle or2 = manager.Or(h1, h3);
    // Or(h2, h3) calls Not(h2) [cache hit!], Not(h3) [cache hit!], And, Not
    PacketSetHandle or3 = manager.Or(h2, h3);

    benchmark::DoNotOptimize(or1);
    benchmark::DoNotOptimize(or2);
    benchmark::DoNotOptimize(or3);
  }
}
BENCHMARK(BM_OrOperationsSharingOperands);

}  // namespace netkat
