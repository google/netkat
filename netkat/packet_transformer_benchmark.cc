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
#include "netkat/packet_transformer.h"
#include "netkat/packet_transformer_handle.h"

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

// Benchmarks the first-time cost of compiling a policy with a high degree of
// overlapping substructures, exercising memoization (especially Union and
// Sequence cache).
void BM_FirstTimeCompileUnionOrSequenceWithHighOverlappingPolicy(
    benchmark::State& state) {
  // 1. Create base policies. Using 3 distinct base BDD structures creates
  // significant BDD complexity and overlap when combined in a DAG.
  std::vector<PolicyProto> policies;
  policies.reserve(6);
  for (int i = 0; i < 6; ++i) {
    policies.push_back(CreateFixedArbitraryPolicyProto(/*id_suffix=*/i % 3));
  }

  // 2. Combine them into a DAG of policies. We do this in 6 layers to
  // prevent the exponential growth of the protobuf tree from dwarfing BDD
  // compilation time.
  for (int layer = 0; layer < 6; ++layer) {
    std::vector<PolicyProto> next_layer;
    for (size_t i = 0; i < policies.size(); ++i) {
      size_t next_idx = (i + 1) % policies.size();
      if (i % 2 == 0) {
        next_layer.push_back(SequenceProto(policies[i], policies[next_idx]));
      } else {
        next_layer.push_back(UnionProto(policies[i], policies[next_idx]));
      }
    }
    policies = std::move(next_layer);
  }

  for (auto s : state) {
    PacketTransformerManager manager;
    PacketTransformerHandle handle;
    for (auto& policy : policies) {
      handle = manager.Compile(policy);
      benchmark::DoNotOptimize(handle);
    }
  }
}
BENCHMARK(BM_FirstTimeCompileUnionOrSequenceWithHighOverlappingPolicy);

// Benchmarks the cost of compiling a policy with a high degree of
// overlapping substructures, that has already been compiled once before.
// Excludes the initial cost of compilation.
void BM_ReCompileUnionOrSequenceWithHighOverlappingPolicy(
    benchmark::State& state) {
  std::vector<PolicyProto> policies;
  policies.reserve(6);
  for (int i = 0; i < 6; ++i) {
    policies.push_back(CreateFixedArbitraryPolicyProto(/*id_suffix=*/i % 3));
  }

  for (int layer = 0; layer < 6; ++layer) {
    std::vector<PolicyProto> next_layer;
    for (size_t i = 0; i < policies.size(); ++i) {
      size_t next_idx = (i + 1) % policies.size();
      if (i % 2 == 0) {
        next_layer.push_back(SequenceProto(policies[i], policies[next_idx]));
      } else {
        next_layer.push_back(UnionProto(policies[i], policies[next_idx]));
      }
    }
    policies = std::move(next_layer);
  }

  PacketTransformerManager manager;
  PacketTransformerHandle handle;
  for (auto& policy : policies) {
    handle = manager.Compile(policy);
    benchmark::DoNotOptimize(handle);
  }
  for (auto s : state) {
    for (auto& policy : policies) {
      handle = manager.Compile(policy);
      benchmark::DoNotOptimize(handle);
    }
  }
}
BENCHMARK(BM_ReCompileUnionOrSequenceWithHighOverlappingPolicy);

// Benchmarks the first-time cost of compiling a policy with a high degree of
// overlapping substructures, exercising memoization (especially Difference
// cache).
void BM_FirstTimeCompileDifferenceWithHighOverlappingPolicy(
    benchmark::State& state) {
  // 1. Create base policies. Using 3 distinct base BDD structures creates
  // significant BDD complexity and overlap when combined in a DAG.
  std::vector<PolicyProto> policies;
  policies.reserve(6);
  for (int i = 0; i < 6; ++i) {
    policies.push_back(CreateFixedArbitraryPolicyProto(/*id_suffix=*/i % 3));
  }

  // 2. Combine them into a DAG of policies. We do this in 6 layers to
  // prevent the exponential growth of the protobuf tree from dwarfing BDD
  // compilation time.
  for (int layer = 0; layer < 6; ++layer) {
    std::vector<PolicyProto> next_layer;
    for (size_t i = 0; i < policies.size(); ++i) {
      size_t next_idx = (i + 1) % policies.size();
      if (i % 2 == 0) {
        next_layer.push_back(DifferenceProto(policies[i], policies[next_idx]));
      } else {
        next_layer.push_back(DifferenceProto(policies[next_idx], policies[i]));
      }
    }
    policies = std::move(next_layer);
  }

  for (auto s : state) {
    PacketTransformerManager manager;
    PacketTransformerHandle handle;
    for (auto& policy : policies) {
      handle = manager.Compile(policy);
      benchmark::DoNotOptimize(handle);
    }
  }
}
BENCHMARK(BM_FirstTimeCompileDifferenceWithHighOverlappingPolicy);

// Benchmarks the cost of compiling a policy with a high degree of
// overlapping substructures, that has already been compiled once before.
// Excludes the initial cost of compilation.
void BM_ReCompileDifferenceWithHighOverlappingPolicy(benchmark::State& state) {
  std::vector<PolicyProto> policies;
  policies.reserve(6);
  for (int i = 0; i < 6; ++i) {
    policies.push_back(CreateFixedArbitraryPolicyProto(/*id_suffix=*/i % 3));
  }

  for (int layer = 0; layer < 6; ++layer) {
    std::vector<PolicyProto> next_layer;
    for (size_t i = 0; i < policies.size(); ++i) {
      size_t next_idx = (i + 1) % policies.size();
      if (i % 2 == 0) {
        next_layer.push_back(DifferenceProto(policies[i], policies[next_idx]));
      } else {
        next_layer.push_back(DifferenceProto(policies[next_idx], policies[i]));
      }
    }
    policies = std::move(next_layer);
  }

  PacketTransformerManager manager;
  PacketTransformerHandle handle;
  for (auto& policy : policies) {
    handle = manager.Compile(policy);
    benchmark::DoNotOptimize(handle);
  }
  for (auto s : state) {
    for (auto& policy : policies) {
      handle = manager.Compile(policy);
      benchmark::DoNotOptimize(handle);
    }
  }
}
BENCHMARK(BM_ReCompileDifferenceWithHighOverlappingPolicy);

// Benchmarks the first-time cost of compiling a policy with a high degree of
// overlapping substructures, exercising memoization (especially Iterate cache).
// We use equivalent but structurally different policies to bypass the
// proto-level cache (transformer_by_hash_) and hit the BDD-level
// iterate_cache_.
void BM_FirstTimeCompileIterateWithEquivalentPolicies(benchmark::State& state) {
  // Create a non-trivial base policy.
  PolicyProto base = CreateFixedArbitraryPolicyProto();

  // Create equivalent but structurally different policies.
  PolicyProto p1 = base;
  PolicyProto p2 = SequenceProto(base, AcceptProto());
  PolicyProto p3 = SequenceProto(AcceptProto(), base);
  PolicyProto p4 = UnionProto(base, DenyProto());
  PolicyProto p5 = UnionProto(DenyProto(), base);
  PolicyProto p6 =
      SequenceProto(SequenceProto(base, AcceptProto()), AcceptProto());

  // We want to iterate all of them. They should all compile to the same BDD
  // handle, so subsequent Iterate calls should hit the iterate_cache_.
  std::vector<PolicyProto> iterated_policies = {
      IterateProto(p1), IterateProto(p2), IterateProto(p3),
      IterateProto(p4), IterateProto(p5), IterateProto(p6),
  };

  for (auto s : state) {
    PacketTransformerManager manager;
    for (const auto& policy : iterated_policies) {
      PacketTransformerHandle handle = manager.Compile(policy);
      benchmark::DoNotOptimize(handle);
    }
  }
}
BENCHMARK(BM_FirstTimeCompileIterateWithEquivalentPolicies);

// Benchmarks the cost of compiling a policy with a high degree of
// overlapping substructures, that has already been compiled once before.
// Excludes the initial cost of compilation.
void BM_ReCompileIterateWithEquivalentPolicies(benchmark::State& state) {
  PolicyProto base = CreateFixedArbitraryPolicyProto();
  PolicyProto p1 = base;
  PolicyProto p2 = SequenceProto(base, AcceptProto());
  PolicyProto p3 = SequenceProto(AcceptProto(), base);
  PolicyProto p4 = UnionProto(base, DenyProto());
  PolicyProto p5 = UnionProto(DenyProto(), base);
  PolicyProto p6 =
      SequenceProto(SequenceProto(base, AcceptProto()), AcceptProto());

  std::vector<PolicyProto> iterated_policies = {
      IterateProto(p1), IterateProto(p2), IterateProto(p3),
      IterateProto(p4), IterateProto(p5), IterateProto(p6),
  };

  PacketTransformerManager manager;
  for (const auto& policy : iterated_policies) {
    PacketTransformerHandle handle = manager.Compile(policy);
    benchmark::DoNotOptimize(handle);
  }
  for (auto s : state) {
    for (const auto& policy : iterated_policies) {
      PacketTransformerHandle handle = manager.Compile(policy);
      benchmark::DoNotOptimize(handle);
    }
  }
}
BENCHMARK(BM_ReCompileIterateWithEquivalentPolicies);

}  // namespace netkat
