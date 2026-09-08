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
// -----------------------------------------------------------------------------
// File: scale_benchmark.cc
// -----------------------------------------------------------------------------
//
// Benchmarks the NetKAT backend on realistically *large* inputs, complementing
// the micro-benchmarks in `packet_set_benchmark.cc` and
// `packet_transformer_benchmark.cc` (which compile small, fixed policies and
// thus mostly measure constant overheads).
//
// The benchmarks are parameterized by input size, so their output also shows
// how the backend *scales*: compare the per-size timings to see whether an
// operation behaves linearly, quadratically, or worse in practice.
//
// Three families of inputs are modeled on common networking workloads:
//  * Forwarding tables: many rules matching a single field (wide decision
//    nodes with one branch per value).
//  * ACLs: rules matching several fields each (deeper decision graphs over
//    multiple fields).
//  * Network reachability: a ring of switches with per-switch forwarding
//    tables, composed with `Iterate` to a fixed point - the workload at the
//    heart of symbolic network verification.

#include <cstdint>
#include <utility>
#include <vector>

#include "benchmark/benchmark.h"
#include "netkat/frontend.h"
#include "netkat/netkat.pb.h"
#include "netkat/packet_set.h"
#include "netkat/packet_transformer.h"

namespace netkat {
namespace {

// Deterministically scrambles `i` into a value in [0, 2^16), so that matched
// values are spread out rather than consecutive. (Knuth's multiplicative
// hash; any fixed bijective-ish scramble would do.)
int ScrambledValue(uint32_t i) {
  return static_cast<int>((i * 2654435761u) >> 16) % (1 << 16);
}

// -- Forwarding tables --------------------------------------------------------

// A forwarding table with `num_entries` exact-match rules on dst_ip, each
// forwarding to one of `num_ports` ports.
Policy ForwardingTable(int num_entries, int num_ports = 32) {
  std::vector<Policy> rules;
  rules.reserve(num_entries);
  for (int i = 0; i < num_entries; ++i) {
    rules.push_back(Sequence(Filter(Match("dst_ip", ScrambledValue(i))),
                             Modify("out_port", i % num_ports)));
  }
  return Union(std::move(rules));
}

void BM_CompileForwardingTable(benchmark::State& state) {
  const int num_entries = state.range(0);
  PolicyProto policy = ForwardingTable(num_entries).ToProto();
  for (auto s : state) {
    PacketTransformerManager manager;
    benchmark::DoNotOptimize(manager.Compile(policy));
  }
  state.SetItemsProcessed(state.iterations() * num_entries);
}
BENCHMARK(BM_CompileForwardingTable)->Arg(64)->Arg(512)->Arg(4096);

// -- ACLs ----------------------------------------------------------------------

// An ACL with `num_rules` rules, each a conjunction over 4 of 5 header fields
// with scrambled values. Models a multi-field classifier; unlike forwarding
// tables, the compiled decision graph branches on several fields per path.
Predicate AclRule(int rule) {
  return Match("src_ip", ScrambledValue(2 * rule)) &&
         Match("dst_ip", ScrambledValue(2 * rule + 1)) &&
         Match("ip_proto", rule % 3) &&
         Match(rule % 2 == 0 ? "dst_port" : "src_port", rule % 1024);
}

Predicate Acl(int num_rules) {
  Predicate acl = Predicate::False();
  for (int i = 0; i < num_rules; ++i) {
    acl = std::move(acl) || AclRule(i);
  }
  return acl;
}

void BM_CompileAclAsPacketSet(benchmark::State& state) {
  const int num_rules = state.range(0);
  PredicateProto acl = Acl(num_rules).ToProto();
  for (auto s : state) {
    PacketSetManager manager;
    benchmark::DoNotOptimize(manager.Compile(acl));
  }
  state.SetItemsProcessed(state.iterations() * num_rules);
}
BENCHMARK(BM_CompileAclAsPacketSet)->Arg(16)->Arg(64)->Arg(256);

// Compiling `permitted && !denied` exercises Not/And on large packet sets.
void BM_CompileAclDifference(benchmark::State& state) {
  const int num_rules = state.range(0);
  // Two ACLs with 50% overlap.
  Predicate permitted = Acl(num_rules);
  Predicate denied = Predicate::False();
  for (int i = num_rules / 2; i < num_rules + num_rules / 2; ++i) {
    denied = std::move(denied) || AclRule(i);
  }
  PredicateProto policy = (std::move(permitted) && !std::move(denied)).ToProto();
  for (auto s : state) {
    PacketSetManager manager;
    benchmark::DoNotOptimize(manager.Compile(policy));
  }
  state.SetItemsProcessed(state.iterations() * num_rules);
}
BENCHMARK(BM_CompileAclDifference)->Arg(16)->Arg(64)->Arg(256);

// -- Network reachability -------------------------------------------------------

// A ring network of `num_switches` switches. Each switch delivers packets
// addressed to it and forwards all other (known) packets clockwise to its
// neighbor. One "step" of the network is the union of all per-switch tables.
Policy RingNetworkStep(int num_switches) {
  std::vector<Policy> switch_policies;
  switch_policies.reserve(num_switches);
  for (int sw = 0; sw < num_switches; ++sw) {
    std::vector<Policy> rules;
    rules.reserve(num_switches);
    for (int dst = 0; dst < num_switches; ++dst) {
      if (dst == sw) {
        // Deliver locally.
        rules.push_back(
            Sequence(Filter(Match("dst_sw", dst)), Modify("delivered", 1)));
      } else {
        // Forward clockwise.
        rules.push_back(Sequence(Filter(Match("dst_sw", dst)),
                                 Modify("sw", (sw + 1) % num_switches)));
      }
    }
    switch_policies.push_back(Sequence(
        Filter(Match("sw", sw) && Match("delivered", 0)),
        Union(std::move(rules))));
  }
  return Union(std::move(switch_policies));
}

// Compiles the reachability transformer of the ring network: all forwarding
// paths of any length, via Iterate. The ring has diameter num_switches - 1,
// so the fixed-point computation must traverse the entire ring.
void BM_CompileRingReachability(benchmark::State& state) {
  const int num_switches = state.range(0);
  PolicyProto reachability =
      Iterate(RingNetworkStep(num_switches)).ToProto();
  for (auto s : state) {
    PacketTransformerManager manager;
    benchmark::DoNotOptimize(manager.Compile(reachability));
  }
  state.SetItemsProcessed(state.iterations() * num_switches);
}
BENCHMARK(BM_CompileRingReachability)->Arg(2)->Arg(4)->Arg(8)->Arg(16)->Arg(32);

// Full end-to-end verification question: "which packets can every switch
// deliver?" Computes the output packet set of the reachability transformer.
void BM_RingReachableOutputs(benchmark::State& state) {
  const int num_switches = state.range(0);
  PolicyProto reachability =
      Iterate(RingNetworkStep(num_switches)).ToProto();
  for (auto s : state) {
    PacketTransformerManager manager;
    PacketTransformerHandle transformer = manager.Compile(reachability);
    benchmark::DoNotOptimize(manager.GetAllPossibleOutputPackets(transformer));
  }
  state.SetItemsProcessed(state.iterations() * num_switches);
}
BENCHMARK(BM_RingReachableOutputs)->Arg(2)->Arg(4)->Arg(8)->Arg(16)->Arg(32);

}  // namespace
}  // namespace netkat
