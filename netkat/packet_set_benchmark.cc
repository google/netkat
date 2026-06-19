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

#include <cstdint>
#include <optional>
#include <utility>

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

// -- Large-scale benchmarks ---------------------------------------------------
//
// The benchmarks above build BDDs of only tens of nodes, so they cannot detect
// effects that only manifest at scale (node arena performance, unique-table
// pressure, algorithmic complexity of the set operations). The benchmarks
// below operate on sets of pseudo-random members of a 16^5 ~= 1M element
// space, encoded over 5 hex-digit fields. Random sets have incompressible
// BDDs, so node counts scale with set size, mimicking large real-world NetKAT
// models.

constexpr int kNumDigits = 5;

// The `i`-th pseudo-random member of the space, under the given `seed`.
// Distinct `i` mostly yield distinct members; collisions just shrink the set.
uint32_t Member(uint32_t i, uint32_t seed) {
  uint64_t state = (i + seed) * 6364136223846793005ULL + 1442695040888963407ULL;
  return static_cast<uint32_t>(state >> 33) & ((1u << (4 * kNumDigits)) - 1);
}

// Matches exactly the packets whose digit fields encode `member`.
PredicateProto MemberPredicate(uint32_t member) {
  PredicateProto pred = MatchProto("f0", member & 15);
  for (int d = 1; d < kNumDigits; ++d) {
    pred = AndProto(std::move(pred),
                    MatchProto(absl::StrCat("f", d), (member >> (4 * d)) & 15));
  }
  return pred;
}

// A balanced Or-tree over members [lo, hi) -- balanced to keep proto/compile
// recursion depth logarithmic.
PredicateProto RandomSetPredicate(uint32_t lo, uint32_t hi, uint32_t seed) {
  if (hi - lo == 1) return MemberPredicate(Member(lo, seed));
  uint32_t mid = lo + (hi - lo) / 2;
  return OrProto(RandomSetPredicate(lo, mid, seed),
                 RandomSetPredicate(mid, hi, seed));
}

// Benchmarks first-time compilation of a large random set, dominated by node
// creation: unique-table hashing and arena appends.
void BM_CompileLargeRandomSet(benchmark::State& state) {
  PredicateProto pred = RandomSetPredicate(0, state.range(0), /*seed=*/1);
  for (auto s : state) {
    PacketSetManager manager;
    PacketSetHandle set = manager.Compile(pred);
    benchmark::DoNotOptimize(set);
  }
}
BENCHMARK(BM_CompileLargeRandomSet)->Arg(1 << 12)->Arg(1 << 15);

// Benchmarks `Not` of a large random set: a full traversal that copies every
// node of the operand (no complement edges yet, see b/382380335).
void BM_NotOfLargeRandomSet(benchmark::State& state) {
  PacketSetManager manager;
  PacketSetHandle set =
      manager.Compile(RandomSetPredicate(0, state.range(0), /*seed=*/1));
  for (auto s : state) {
    PacketSetHandle result = manager.Not(set);
    benchmark::DoNotOptimize(result);
  }
}
BENCHMARK(BM_NotOfLargeRandomSet)->Arg(1 << 12)->Arg(1 << 15);

// Benchmarks `Xor` of two large random sets: a compound operation (two `And`s,
// several `Not`s) that traverses both operands and creates many nodes.
void BM_XorOfLargeRandomSets(benchmark::State& state) {
  PacketSetManager manager;
  PacketSetHandle lhs =
      manager.Compile(RandomSetPredicate(0, state.range(0), /*seed=*/1));
  PacketSetHandle rhs =
      manager.Compile(RandomSetPredicate(0, state.range(0), /*seed=*/2));
  for (auto s : state) {
    PacketSetHandle result = manager.Xor(lhs, rhs);
    benchmark::DoNotOptimize(result);
  }
}
BENCHMARK(BM_XorOfLargeRandomSets)->Arg(1 << 12)->Arg(1 << 15);

}  // namespace netkat
