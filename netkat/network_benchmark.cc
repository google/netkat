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
//
// -----------------------------------------------------------------------------
// File: network_benchmark.cc
// -----------------------------------------------------------------------------
//
// End-to-end benchmarks of the NetKAT backend on realistic network
// verification workloads, drawn from the literature (see
// `benchmark_networks.h`). Each benchmark is parameterized by the size of the
// network, and either measures compilation or, with compilation excluded, a
// typical verification query.

#include <cstddef>
#include <utility>
#include <vector>

#include "absl/types/span.h"
#include "benchmark/benchmark.h"
#include "netkat/benchmark_networks.h"
#include "netkat/field_order.h"
#include "netkat/netkat.pb.h"
#include "netkat/netkat_proto_constructors.h"
#include "netkat/packet_set.h"
#include "netkat/packet_set_handle.h"
#include "netkat/packet_transformer.h"
#include "netkat/packet_transformer_handle.h"

namespace netkat {
namespace {

// -- Fat trees ----------------------------------------------------------------

void SetFatTreeCounters(benchmark::State& state, int k) {
  state.counters["hosts"] = k * k * k / 4;
  state.counters["switches"] = 5 * k * k / 4;
}

// Compiles the end-to-end behavior of a fat tree with `k`-port switches.
void BM_FatTreeCompile(benchmark::State& state) {
  const int k = state.range(0);
  PolicyProto policy = EndToEndPolicy(FatTree({.k = k}));
  for (auto s : state) {
    PacketTransformerManager manager;
    benchmark::DoNotOptimize(manager.Compile(policy));
  }
  SetFatTreeCounters(state, k);
}
BENCHMARK(BM_FatTreeCompile)->DenseRange(4, 16, 4);

// As above, but with multipath routing.
void BM_FatTreeMultipathCompile(benchmark::State& state) {
  const int k = state.range(0);
  PolicyProto policy = EndToEndPolicy(FatTree({.k = k, .multipath = true}));
  for (auto s : state) {
    PacketTransformerManager manager;
    benchmark::DoNotOptimize(manager.Compile(policy));
  }
  SetFatTreeCounters(state, k);
}
BENCHMARK(BM_FatTreeMultipathCompile)->DenseRange(4, 16, 4);

// Computes the set of packets that can be delivered from any host to any host
// of a fat tree, both forward (`Push`) and backward (`Pull`). Excludes
// compilation.
void BM_FatTreeReachability(benchmark::State& state) {
  const int k = state.range(0);
  NetworkModel network = FatTree({.k = k});
  PolicyProto policy = EndToEndPolicy(network);
  for (auto s : state) {
    state.PauseTiming();
    PacketTransformerManager manager;
    PacketSetManager& packet_sets = manager.GetPacketSetManager();
    PacketTransformerHandle end_to_end = manager.Compile(policy);
    PacketSetHandle ingress = packet_sets.Compile(network.ingress);
    PacketSetHandle egress = packet_sets.Compile(network.egress);
    state.ResumeTiming();
    benchmark::DoNotOptimize(
        packet_sets.And(manager.Push(ingress, end_to_end), egress));
    benchmark::DoNotOptimize(
        packet_sets.And(manager.Pull(end_to_end, egress), ingress));
  }
  SetFatTreeCounters(state, k);
}
BENCHMARK(BM_FatTreeReachability)->DenseRange(4, 16, 4);

// Verifies isolation between tenants of a multi-tenant fat tree: that packets
// from hosts of tenant 0 cannot reach hosts of other tenants. Includes
// compilation.
void BM_FatTreeTenantIsolation(benchmark::State& state) {
  const int k = state.range(0);
  FatTreeOptions options = {.k = k, .num_tenants = 4};
  NetworkModel network = FatTree(options);
  PolicyProto policy = EndToEndPolicy(network);
  std::vector<PredicateProto> tenant0_host_locations, other_host_locations;
  for (const FatTreeHost& host : FatTreeHosts(k)) {
    (FatTreeTenant(options, host) == 0 ? tenant0_host_locations
                                       : other_host_locations)
        .push_back(FatTreeHostLocation(k, host));
  }
  PredicateProto tenant0_hosts =
      BalancedOrProto(std::move(tenant0_host_locations));
  PredicateProto other_hosts = BalancedOrProto(std::move(other_host_locations));
  for (auto s : state) {
    PacketTransformerManager manager;
    PacketSetManager& packet_sets = manager.GetPacketSetManager();
    PacketTransformerHandle end_to_end = manager.Compile(policy);
    PacketSetHandle leaked = packet_sets.And(
        manager.Push(packet_sets.Compile(tenant0_hosts), end_to_end),
        packet_sets.Compile(other_hosts));
    if (!packet_sets.IsEmptySet(leaked)) state.SkipWithError("not isolated");
  }
  SetFatTreeCounters(state, k);
}
BENCHMARK(BM_FatTreeTenantIsolation)->DenseRange(4, 12, 4);

// -- Wide area networks -------------------------------------------------------

// Compiles the end-to-end behavior of a WAN with N switches and shortest-path
// routing.
void BM_WanCompile(benchmark::State& state) {
  PolicyProto policy = EndToEndPolicy(ShortestPathWan(state.range(0)).network);
  for (auto s : state) {
    PacketTransformerManager manager;
    benchmark::DoNotOptimize(manager.Compile(policy));
  }
}
BENCHMARK(BM_WanCompile)->RangeMultiplier(2)->Range(16, 256);

// Computes the set of packets that can be delivered between any two switches
// of a WAN, both forward (`Push`) and backward (`Pull`). Excludes compilation.
void BM_WanReachability(benchmark::State& state) {
  NetworkModel network = ShortestPathWan(state.range(0)).network;
  PolicyProto policy = EndToEndPolicy(network);
  for (auto s : state) {
    state.PauseTiming();
    PacketTransformerManager manager;
    PacketSetManager& packet_sets = manager.GetPacketSetManager();
    PacketTransformerHandle end_to_end = manager.Compile(policy);
    PacketSetHandle ingress = packet_sets.Compile(network.ingress);
    PacketSetHandle egress = packet_sets.Compile(network.egress);
    state.ResumeTiming();
    benchmark::DoNotOptimize(
        packet_sets.And(manager.Push(ingress, end_to_end), egress));
    benchmark::DoNotOptimize(
        packet_sets.And(manager.Pull(end_to_end, egress), ingress));
  }
}
BENCHMARK(BM_WanReachability)->RangeMultiplier(2)->Range(16, 256);

// Computes the traffic of a WAN that bypasses a waypoint (e.g. a firewall) at
// its best connected switch. Includes compilation.
void BM_WanWaypointBypass(benchmark::State& state) {
  Wan wan = ShortestPathWan(state.range(0));
  size_t waypoint = 0;
  for (size_t s = 0; s < wan.adjacency.size(); ++s) {
    if (wan.adjacency[s].size() > wan.adjacency[waypoint].size()) waypoint = s;
  }
  PolicyProto policy = EndToEndPolicyAvoiding(wan.network, waypoint);
  for (auto s : state) {
    PacketTransformerManager manager;
    PacketSetManager& packet_sets = manager.GetPacketSetManager();
    PacketTransformerHandle bypassing = manager.Compile(policy);
    benchmark::DoNotOptimize(packet_sets.And(
        manager.Push(packet_sets.Compile(wan.network.ingress), bypassing),
        packet_sets.Compile(wan.network.egress)));
  }
}
BENCHMARK(BM_WanWaypointBypass)->RangeMultiplier(2)->Range(16, 256);

// -- Backbone networks --------------------------------------------------------

// Compiles the end-to-end behavior of a Stanford-style backbone with N routers,
// each with an ACL and longest prefix match routing.
void BM_BackboneCompile(benchmark::State& state) {
  PolicyProto policy = EndToEndPolicy(Backbone(state.range(0)));
  for (auto s : state) {
    PacketTransformerManager manager;
    benchmark::DoNotOptimize(manager.Compile(policy));
  }
}
BENCHMARK(BM_BackboneCompile)->RangeMultiplier(2)->Range(16, 128);

// Computes the set of packets that can be delivered between any two hosts of a
// backbone, both forward (`Push`) and backward (`Pull`). Includes compilation.
void BM_BackboneReachability(benchmark::State& state) {
  NetworkModel network = Backbone(state.range(0));
  PolicyProto policy = EndToEndPolicy(network);
  for (auto s : state) {
    PacketTransformerManager manager;
    PacketSetManager& packet_sets = manager.GetPacketSetManager();
    PacketTransformerHandle end_to_end = manager.Compile(policy);
    PacketSetHandle ingress = packet_sets.Compile(network.ingress);
    PacketSetHandle egress = packet_sets.Compile(network.egress);
    benchmark::DoNotOptimize(
        packet_sets.And(manager.Push(ingress, end_to_end), egress));
    benchmark::DoNotOptimize(
        packet_sets.And(manager.Pull(end_to_end, egress), ingress));
  }
}
BENCHMARK(BM_BackboneReachability)->RangeMultiplier(2)->Range(16, 128);

// -- Access control lists -----------------------------------------------------

// Compiles an N-rule ACL.
void BM_AclCompile(benchmark::State& state) {
  PolicyProto policy = AclPolicy(ClassBenchStyleAclRules(state.range(0)));
  for (auto s : state) {
    PacketTransformerManager manager;
    benchmark::DoNotOptimize(manager.Compile(policy));
  }
}
BENCHMARK(BM_AclCompile)->RangeMultiplier(4)->Range(64, 4096);

// Change impact analysis: computes the packets whose treatment changes when a
// rule is removed from an N-rule ACL. Includes compilation of both versions.
void BM_AclChangeImpact(benchmark::State& state) {
  std::vector<AclRule> rules = ClassBenchStyleAclRules(state.range(0));
  PolicyProto before = AclPolicy(rules);
  rules.erase(rules.begin() + rules.size() / 2);
  PolicyProto after = AclPolicy(rules);
  for (auto s : state) {
    PacketTransformerManager manager;
    PacketTransformerHandle old_acl = manager.Compile(before);
    PacketTransformerHandle new_acl = manager.Compile(after);
    PacketTransformerHandle difference =
        manager.Union(manager.Difference(old_acl, new_acl),
                      manager.Difference(new_acl, old_acl));
    benchmark::DoNotOptimize(
        manager.GetAllInputPacketsThatProduceAnyOutput(difference));
  }
}
BENCHMARK(BM_AclChangeImpact)->RangeMultiplier(4)->Range(64, 4096);

// -- Switch pipelines ---------------------------------------------------------

// Compiles a 4-stage switch pipeline with N routes.
void BM_SwitchPipelineCompile(benchmark::State& state) {
  PolicyProto policy = SaiStyleSwitchPipeline(state.range(0)).Policy();
  for (auto s : state) {
    PacketTransformerManager manager;
    benchmark::DoNotOptimize(manager.Compile(policy));
  }
}
BENCHMARK(BM_SwitchPipelineCompile)->RangeMultiplier(2)->Range(256, 8192);

// Computes the packets forwarded out of port 0, and the packets that are not
// dropped, by a switch pipeline with N routes. Excludes compilation.
void BM_SwitchPipelineAnalysis(benchmark::State& state) {
  PolicyProto policy = SaiStyleSwitchPipeline(state.range(0)).Policy();
  for (auto s : state) {
    state.PauseTiming();
    PacketTransformerManager manager;
    PacketTransformerHandle pipeline = manager.Compile(policy);
    PacketSetHandle port0 = manager.GetPacketSetManager().Match("port", 0);
    state.ResumeTiming();
    benchmark::DoNotOptimize(manager.Pull(pipeline, port0));
    benchmark::DoNotOptimize(
        manager.GetAllInputPacketsThatProduceAnyOutput(pipeline));
  }
}
BENCHMARK(BM_SwitchPipelineAnalysis)->RangeMultiplier(2)->Range(256, 8192);

// -- NAT gateways -------------------------------------------------------------

// Compiles a NAT gateway (load balancing and source NAT) with N flows.
void BM_NatGatewayCompile(benchmark::State& state) {
  PolicyProto policy = NatGatewayWithFlows(state.range(0)).Policy();
  for (auto s : state) {
    PacketTransformerManager manager;
    benchmark::DoNotOptimize(manager.Compile(policy));
  }
}
BENCHMARK(BM_NatGatewayCompile)->RangeMultiplier(4)->Range(256, 16384);

// Verifies that the source NAT of a NAT gateway with N flows is invertible on
// established flows, i.e. that no two flows share a public port, by checking
// `internal_flows; source_nat; inverse_source_nat == internal_flows`. Includes
// compilation.
void BM_NatRoundTrip(benchmark::State& state) {
  NatGateway nat = NatGatewayWithFlows(state.range(0));
  PolicyProto internal_flows = FilterProto(nat.internal_flows);
  for (auto s : state) {
    PacketTransformerManager manager;
    PacketTransformerHandle domain = manager.Compile(internal_flows);
    PacketTransformerHandle round_trip = manager.Sequence(
        manager.Sequence(domain, manager.Compile(nat.source_nat)),
        manager.Compile(nat.inverse_source_nat));
    if (round_trip != domain) state.SkipWithError("not invertible");
  }
}
BENCHMARK(BM_NatRoundTrip)->RangeMultiplier(4)->Range(256, 16384);

// -- Equivalence queries ------------------------------------------------------

// Verifies that a multi-tenant fat tree treats the traffic of tenant 0 like
// the fat tree without tenants, by checking two policies for equivalence (see
// `FatTreeSliceEquivalence`). Includes compilation.
void BM_FatTreeSliceEquivalence(benchmark::State& state) {
  const int k = state.range(0);
  EquivalenceQuery query =
      FatTreeSliceEquivalence({.k = k, .num_tenants = 4}, /*tenant=*/0);
  for (auto s : state) {
    PacketTransformerManager manager;
    if (manager.Compile(query.left) != manager.Compile(query.right)) {
      state.SkipWithError("not equivalent");
    }
  }
  SetFatTreeCounters(state, k);
}
BENCHMARK(BM_FatTreeSliceEquivalence)->DenseRange(4, 12, 4);

// -- Field ordering -----------------------------------------------------------

// Computes the heuristic field order of the end-to-end policy of a WAN with N
// switches, which `Compile` does implicitly.
void BM_HeuristicFieldOrder(benchmark::State& state) {
  PolicyProto policy = EndToEndPolicy(ShortestPathWan(state.range(0)).network);
  for (auto s : state) {
    benchmark::DoNotOptimize(
        HeuristicFieldOrder(absl::MakeConstSpan(&policy, 1)));
  }
}
BENCHMARK(BM_HeuristicFieldOrder)->RangeMultiplier(4)->Range(64, 1024);

}  // namespace
}  // namespace netkat
