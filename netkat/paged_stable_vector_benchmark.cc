// Copyright 2026 The NetKAT authors
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
// Benchmarks for `PagedStableVector`, exercising the access patterns of its
// only clients (`PacketSetManager`/`PacketTransformerManager`): indexed reads
// of decision nodes during BDD traversal, and appends of new nodes.
//
// The benchmarks are instantiated with a power-of-two and a non-power-of-two
// page size to quantify the cost of `operator[]`'s index arithmetic: division
// by a non-power-of-two constant compiles to a multiply sequence rather than a
// shift. A flat `std::vector` (no paging, no pointer stability) serves as the
// lower-bound reference.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "benchmark/benchmark.h"
#include "netkat/paged_stable_vector.h"

namespace netkat {
namespace {

// Same size and alignment as `PacketSetManager::DecisionNode`.
struct FakeNode {
  uint64_t a = 0;
  uint64_t b = 0;
  uint64_t c = 0;
};
static_assert(sizeof(FakeNode) == 24);

// The page size of `PacketSetManager::nodes_` at the time of writing:
// a 64 MiB byte budget divided by the node size, yielding a non-power-of-two
// number of elements per page.
constexpr size_t kNonPow2PageSize = (size_t{1} << 26) / sizeof(FakeNode);
static_assert((kNonPow2PageSize & (kNonPow2PageSize - 1)) != 0);

// A power-of-two page size of comparable magnitude (~48 MiB worth of nodes).
constexpr size_t kPow2PageSize = size_t{1} << 21;

template <class Vector>
Vector MakeFilledVector(size_t size) {
  Vector vec;
  for (size_t i = 0; i < size; ++i) {
    vec.push_back(FakeNode{.a = i, .b = i, .c = i});
  }
  return vec;
}

// Returns `size` indices in [0, size) in pseudo-random order, simulating the
// data-dependent node lookups of BDD traversal. Uses a fixed-seed LCG so all
// instantiations see the identical sequence.
std::vector<uint32_t> PseudoRandomIndices(size_t size) {
  std::vector<uint32_t> indices;
  indices.reserve(size);
  uint64_t state = 42;
  for (size_t i = 0; i < size; ++i) {
    state = state * 6364136223846793005ULL + 1442695040888963407ULL;
    indices.push_back(static_cast<uint32_t>((state >> 33) % size));
  }
  return indices;
}

template <class Vector>
void BM_PushBack(benchmark::State& state) {
  const size_t size = state.range(0);
  for (auto s : state) {
    Vector vec = MakeFilledVector<Vector>(size);
    benchmark::DoNotOptimize(vec);
  }
  state.SetItemsProcessed(state.iterations() * size);
}

template <class Vector>
void BM_SequentialRead(benchmark::State& state) {
  const size_t size = state.range(0);
  Vector vec = MakeFilledVector<Vector>(size);
  for (auto s : state) {
    uint64_t sum = 0;
    for (size_t i = 0; i < size; ++i) sum += vec[i].a;
    benchmark::DoNotOptimize(sum);
  }
  state.SetItemsProcessed(state.iterations() * size);
}

template <class Vector>
void BM_RandomRead(benchmark::State& state) {
  const size_t size = state.range(0);
  Vector vec = MakeFilledVector<Vector>(size);
  const std::vector<uint32_t> indices = PseudoRandomIndices(size);
  for (auto s : state) {
    uint64_t sum = 0;
    for (uint32_t index : indices) sum += vec[index].a;
    benchmark::DoNotOptimize(sum);
  }
  state.SetItemsProcessed(state.iterations() * size);
}

// 4M elements ≈ 96 MiB: spans multiple pages and far exceeds L3, like the
// node vectors of large NetKAT models. 256k elements ≈ 6 MiB: fits in L3,
// making the index arithmetic (rather than memory stalls) the bottleneck.
constexpr size_t kSmall = size_t{1} << 18;
constexpr size_t kLarge = size_t{1} << 22;

using NonPow2Vector = PagedStableVector<FakeNode, kNonPow2PageSize>;
using Pow2Vector = PagedStableVector<FakeNode, kPow2PageSize>;
using FlatVector = std::vector<FakeNode>;

BENCHMARK_TEMPLATE(BM_PushBack, NonPow2Vector)->Arg(kSmall)->Arg(kLarge);
BENCHMARK_TEMPLATE(BM_PushBack, Pow2Vector)->Arg(kSmall)->Arg(kLarge);
BENCHMARK_TEMPLATE(BM_PushBack, FlatVector)->Arg(kSmall)->Arg(kLarge);

BENCHMARK_TEMPLATE(BM_SequentialRead, NonPow2Vector)->Arg(kSmall)->Arg(kLarge);
BENCHMARK_TEMPLATE(BM_SequentialRead, Pow2Vector)->Arg(kSmall)->Arg(kLarge);
BENCHMARK_TEMPLATE(BM_SequentialRead, FlatVector)->Arg(kSmall)->Arg(kLarge);

BENCHMARK_TEMPLATE(BM_RandomRead, NonPow2Vector)->Arg(kSmall)->Arg(kLarge);
BENCHMARK_TEMPLATE(BM_RandomRead, Pow2Vector)->Arg(kSmall)->Arg(kLarge);
BENCHMARK_TEMPLATE(BM_RandomRead, FlatVector)->Arg(kSmall)->Arg(kLarge);

}  // namespace
}  // namespace netkat
