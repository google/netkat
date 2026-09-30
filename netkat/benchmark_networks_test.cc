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

// End-to-end tests of the generated benchmark workloads: each workload is
// compiled by the NetKAT backend and checked against its intended semantics.
// This validates the generators, and doubles as an end-to-end test of the
// backend on realistic inputs.

#include "netkat/benchmark_networks.h"

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "netkat/netkat_proto_constructors.h"
#include "netkat/packet.h"
#include "netkat/packet_set.h"
#include "netkat/packet_set_handle.h"
#include "netkat/packet_transformer.h"
#include "netkat/packet_transformer_handle.h"

namespace netkat {
namespace {

using ::testing::IsEmpty;
using ::testing::SizeIs;
using ::testing::UnorderedElementsAre;

// Returns the outputs of running `packet` through `transformer` that are in
// `egress`.
std::vector<Packet> RunToEgress(PacketTransformerManager& manager,
                                PacketTransformerHandle transformer,
                                PacketSetHandle egress, Packet packet) {
  std::vector<Packet> result;
  for (const Packet& output : manager.Run(transformer, packet)) {
    if (manager.GetPacketSetManager().Contains(egress, output)) {
      result.push_back(output);
    }
  }
  return result;
}

// -- Fat trees ----------------------------------------------------------------

Packet FatTreePacket(int k, const FatTreeHost& src, const FatTreeHost& dst) {
  return {{"sw", src.pod * (k / 2) + src.edge},
          {"port", src.host},
          {"dst_pod", dst.pod},
          {"dst_edge", dst.edge},
          {"dst_host", dst.host},
          {"vlan", 0}};
}

void CheckFatTreeDeliversExactlyWithinTenants(const FatTreeOptions& options) {
  const int k = options.k;
  NetworkModel network = FatTree(options);
  PacketTransformerManager manager;
  PacketSetManager& packet_sets = manager.GetPacketSetManager();
  PacketTransformerHandle end_to_end = manager.Compile(EndToEndPolicy(network));
  PacketSetHandle ingress = packet_sets.Compile(network.ingress);
  PacketSetHandle egress = packet_sets.Compile(network.egress);

  for (const FatTreeHost& src : FatTreeHosts(k)) {
    for (const FatTreeHost& dst : FatTreeHosts(k)) {
      SCOPED_TRACE(absl::StrCat("src=", src.pod, ".", src.edge, ".", src.host,
                                " dst=", dst.pod, ".", dst.edge, ".",
                                dst.host));
      Packet packet = FatTreePacket(k, src, dst);
      ASSERT_TRUE(packet_sets.Contains(ingress, packet));
      std::vector<Packet> delivered =
          RunToEgress(manager, end_to_end, egress, packet);
      if (FatTreeTenant(options, src) != FatTreeTenant(options, dst)) {
        EXPECT_THAT(delivered, IsEmpty());
        continue;
      }
      ASSERT_THAT(delivered, SizeIs(1));
      EXPECT_TRUE(packet_sets.Contains(
          packet_sets.Compile(FatTreeHostLocation(k, dst)), delivered[0]));
    }
  }
}

TEST(FatTreeTest, DeliversAllPacketsToTheirDestinationHost) {
  CheckFatTreeDeliversExactlyWithinTenants({.k = 4});
  CheckFatTreeDeliversExactlyWithinTenants({.k = 6});
}

TEST(FatTreeTest, MultipathDeliversAllPacketsToTheirDestinationHost) {
  CheckFatTreeDeliversExactlyWithinTenants({.k = 4, .multipath = true});
}

TEST(FatTreeTest, IsolatesTenants) {
  CheckFatTreeDeliversExactlyWithinTenants({.k = 4, .num_tenants = 3});
  CheckFatTreeDeliversExactlyWithinTenants(
      {.k = 4, .multipath = true, .num_tenants = 2});
}

TEST(FatTreeTest, DropsPacketsToUnknownHosts) {
  const int k = 4;
  NetworkModel network = FatTree({.k = k, .multipath = true});
  PacketTransformerManager manager;
  PacketTransformerHandle end_to_end = manager.Compile(EndToEndPolicy(network));
  PacketSetHandle egress =
      manager.GetPacketSetManager().Compile(network.egress);
  EXPECT_THAT(RunToEgress(manager, end_to_end, egress,
                          FatTreePacket(k, {0, 0, 0}, {1, 0, k})),
              IsEmpty());
  EXPECT_THAT(RunToEgress(manager, end_to_end, egress,
                          FatTreePacket(k, {0, 0, 0}, {1, k, 0})),
              IsEmpty());
  EXPECT_THAT(RunToEgress(manager, end_to_end, egress,
                          FatTreePacket(k, {0, 0, 0}, {k, 0, 0})),
              IsEmpty());
}

TEST(FatTreeTest, SymbolicReachabilityMatchesExpectations) {
  const int k = 4;
  NetworkModel network = FatTree({.k = k});
  PacketTransformerManager manager;
  PacketSetManager& packet_sets = manager.GetPacketSetManager();
  PacketTransformerHandle end_to_end = manager.Compile(EndToEndPolicy(network));
  PacketSetHandle reachable = packet_sets.And(
      manager.Push(packet_sets.Compile(network.ingress), end_to_end),
      packet_sets.Compile(network.egress));
  for (const FatTreeHost& dst : FatTreeHosts(k)) {
    PacketSetHandle at_dst =
        packet_sets.And(packet_sets.Compile(FatTreeHostLocation(k, dst)),
                        packet_sets.Compile(FatTreeHostAddress(dst)));
    EXPECT_FALSE(packet_sets.IsEmptySet(packet_sets.And(reachable, at_dst)));
  }
}

// -- Wide area networks -------------------------------------------------------

TEST(ShortestPathWanTest, HasSymmetricConnectedSparseTopology) {
  for (int seed : {1, 2, 3}) {
    Wan wan = ShortestPathWan(/*num_switches=*/100, seed);
    int num_link_ends = 0;
    for (int s = 0; s < static_cast<int>(wan.adjacency.size()); ++s) {
      num_link_ends += static_cast<int>(wan.adjacency[s].size());
      for (int neighbor : wan.adjacency[s]) {
        EXPECT_NE(neighbor, s);
        EXPECT_EQ(absl::c_count(wan.adjacency[neighbor], s), 1);
      }
    }
    double average_degree = num_link_ends / 100.0;
    EXPECT_GT(average_degree, 2.5);
    EXPECT_LT(average_degree, 3.5);
  }
}

TEST(ShortestPathWanTest, DeliversAllPacketsToTheirDestination) {
  for (int seed : {1, 2}) {
    const int n = 24;
    Wan wan = ShortestPathWan(n, seed);
    PacketTransformerManager manager;
    PacketTransformerHandle end_to_end =
        manager.Compile(EndToEndPolicy(wan.network));
    PacketSetHandle egress =
        manager.GetPacketSetManager().Compile(wan.network.egress);
    for (int src = 0; src < n; ++src) {
      for (int dst = 0; dst < n; ++dst) {
        SCOPED_TRACE(absl::StrCat("seed=", seed, " src=", src, " dst=", dst));
        EXPECT_THAT(RunToEgress(manager, end_to_end, egress,
                                {{"sw", src}, {"port", 0}, {"dst", dst}}),
                    UnorderedElementsAre(
                        Packet{{"sw", dst}, {"port", 0}, {"dst", dst}}));
      }
    }
  }
}

TEST(ShortestPathWanTest, NoPacketToOrFromWaypointAvoidsWaypoint) {
  const int n = 24;
  const int waypoint = 0;
  Wan wan = ShortestPathWan(n);
  PacketTransformerManager manager;
  PacketTransformerHandle avoiding =
      manager.Compile(EndToEndPolicyAvoiding(wan.network, waypoint));
  PacketSetHandle egress =
      manager.GetPacketSetManager().Compile(wan.network.egress);
  int num_delivered = 0;
  for (int other = 0; other < n; ++other) {
    EXPECT_THAT(RunToEgress(manager, avoiding, egress,
                            {{"sw", waypoint}, {"port", 0}, {"dst", other}}),
                IsEmpty());
    EXPECT_THAT(RunToEgress(manager, avoiding, egress,
                            {{"sw", other}, {"port", 0}, {"dst", waypoint}}),
                IsEmpty());
    num_delivered +=
        RunToEgress(manager, avoiding, egress,
                    {{"sw", other}, {"port", 0}, {"dst", (other + 1) % n}})
            .size();
  }
  // Some, but not all, traffic between other switches avoids the waypoint.
  EXPECT_GT(num_delivered, 0);
  EXPECT_LT(num_delivered, n - 2);
}

// -- Backbone networks --------------------------------------------------------

// Returns a packet from a host of router `src` to 10.`dst`.`third_octet`.*,
// which no ACL rule matches (so it is permitted).
Packet BackbonePacket(int src, int dst, int third_octet) {
  return {{"sw", src},
          {"port", 0},
          {"dst_ip0", 10},
          {"dst_ip1", dst},
          {"dst_ip2", third_octet},
          {"src_net", -1},
          {"dst_net", -1},
          {"ip_proto", -1},
          {"l4_src_port", -1},
          {"l4_dst_port", -1}};
}

TEST(BackboneTest, DeliversPacketsToTheOwnerOfTheirDestinationPrefix) {
  const int n = 16;
  NetworkModel network = Backbone(n);
  PacketTransformerManager manager;
  PacketTransformerHandle end_to_end = manager.Compile(EndToEndPolicy(network));
  PacketSetHandle egress =
      manager.GetPacketSetManager().Compile(network.egress);
  for (int src = 0; src < n; ++src) {
    for (int dst = 0; dst < n; ++dst) {
      SCOPED_TRACE(absl::StrCat("src=", src, " dst=", dst));
      // No more specific /24 prefix has third octet 256.
      Packet packet = BackbonePacket(src, dst, /*third_octet=*/256);
      Packet expected = packet;
      expected["sw"] = dst;
      EXPECT_THAT(RunToEgress(manager, end_to_end, egress, packet),
                  UnorderedElementsAre(expected));
    }
  }
}

TEST(BackboneTest, DeliversEachPacketToExactlyOneRouter) {
  const int n = 16;
  NetworkModel network = Backbone(n);
  PacketTransformerManager manager;
  PacketTransformerHandle end_to_end = manager.Compile(EndToEndPolicy(network));
  PacketSetHandle egress =
      manager.GetPacketSetManager().Compile(network.egress);
  int num_rerouted = 0;
  for (int dst = 0; dst < n; ++dst) {
    for (int third_octet = 0; third_octet < 256; ++third_octet) {
      SCOPED_TRACE(absl::StrCat("dst=", dst, " third_octet=", third_octet));
      std::vector<Packet> delivered = RunToEgress(
          manager, end_to_end, egress, BackbonePacket(0, dst, third_octet));
      ASSERT_THAT(delivered, SizeIs(1));
      if (delivered[0].at("sw") != dst) ++num_rerouted;
    }
  }
  // Some more specific prefixes are announced by other routers than the owner
  // of the enclosing /16 prefix.
  EXPECT_GT(num_rerouted, 0);
  EXPECT_LE(num_rerouted, n);
}

TEST(BackboneTest, DropsPacketsOutsideTheBackbonePrefix) {
  NetworkModel network = Backbone(8);
  PacketTransformerManager manager;
  PacketTransformerHandle end_to_end = manager.Compile(EndToEndPolicy(network));
  PacketSetHandle egress =
      manager.GetPacketSetManager().Compile(network.egress);
  Packet packet = BackbonePacket(0, 1, 256);
  packet["dst_ip0"] = 11;
  EXPECT_THAT(RunToEgress(manager, end_to_end, egress, packet), IsEmpty());
}

// -- Access control lists -----------------------------------------------------

bool AclRuleMatches(const AclRule& rule, const Packet& packet) {
  auto matches = [&](const char* field, const std::optional<int>& value) {
    return !value.has_value() || packet.at(field) == *value;
  };
  return matches("src_net", rule.src_net) && matches("dst_net", rule.dst_net) &&
         matches("ip_proto", rule.ip_proto) &&
         matches("l4_src_port", rule.l4_src_port) &&
         matches("l4_dst_port", rule.l4_dst_port);
}

// Returns the output of the ACL `rules` for `packet`, or nullopt if it is
// dropped. Packets that match no rule are dropped iff `default_deny`.
std::optional<Packet> ReferenceAcl(const std::vector<AclRule>& rules,
                                   Packet packet, bool default_deny) {
  for (const AclRule& rule : rules) {
    if (!AclRuleMatches(rule, packet)) continue;
    switch (rule.action) {
      case AclRule::Action::kPermit:
        return packet;
      case AclRule::Action::kDeny:
        return std::nullopt;
      case AclRule::Action::kRedirect:
        packet["port"] = rule.redirect_port;
        return packet;
    }
  }
  if (default_deny) return std::nullopt;
  return packet;
}

// Returns a random packet with header values that are likely to hit rules.
Packet RandomAclPacket(BenchmarkRandom& random) {
  static constexpr int kProtocols[] = {6, 17, 1, 47};
  static constexpr int kPorts[] = {22, 53, 80, 443, 8080, 3389, 1030, 2000};
  return {
      {"src_net", random.Uniform(66)},
      {"dst_net", random.Uniform(258)},
      {"ip_proto", kProtocols[random.Uniform(4)]},
      {"l4_src_port", 1024 + random.Uniform(66)},
      {"l4_dst_port", random.Bernoulli(0.5) ? kPorts[random.Uniform(8)]
                                            : 1024 + random.Uniform(1030)},
      {"port", 0},
  };
}

std::vector<Packet> AsVector(const std::optional<Packet>& packet) {
  if (!packet.has_value()) return {};
  return {*packet};
}

TEST(AclTest, MatchesFirstMatchSemantics) {
  std::vector<AclRule> rules = ClassBenchStyleAclRules(/*num_rules=*/300);
  PacketTransformerManager manager;
  PacketTransformerHandle acl = manager.Compile(AclPolicy(rules));
  BenchmarkRandom random(/*seed=*/42);
  int num_permitted = 0;
  for (int i = 0; i < 3000; ++i) {
    Packet packet = RandomAclPacket(random);
    std::optional<Packet> expected =
        ReferenceAcl(rules, packet, /*default_deny=*/true);
    num_permitted += expected.has_value();
    absl::flat_hash_set<Packet> actual = manager.Run(acl, packet);
    ASSERT_THAT(std::vector<Packet>(actual.begin(), actual.end()),
                testing::ContainerEq(AsVector(expected)));
  }
  // Sanity check that the test exercises both outcomes.
  EXPECT_GT(num_permitted, 100);
  EXPECT_LT(num_permitted, 2900);
}

// -- Switch pipelines ---------------------------------------------------------

std::optional<Packet> ReferencePipeline(const SwitchPipeline& pipeline,
                                        Packet packet) {
  static constexpr const char* kOctetFields[] = {"dst_ip0", "dst_ip1",
                                                 "dst_ip2", "dst_ip3"};
  packet["vrf"] = packet.at("in_port") < kSwitchPipelineNumPorts
                      ? packet.at("in_port") % kSwitchPipelineNumVrfs
                      : 0;
  std::optional<int> nexthop;
  for (const Ipv4Route& route : pipeline.routes) {
    if (route.vrf != packet.at("vrf")) continue;
    bool matches = true;
    for (size_t i = 0; i < route.prefix.size(); ++i) {
      matches &= packet.at(kOctetFields[i]) == route.prefix[i];
    }
    if (matches) {
      nexthop = route.nexthop;
      break;
    }
  }
  if (!nexthop.has_value()) return std::nullopt;
  packet["nexthop"] = *nexthop;
  packet["port"] = *nexthop % kSwitchPipelineNumPorts;
  packet["dst_mac"] = *nexthop;
  return ReferenceAcl(pipeline.acl_rules, packet, /*default_deny=*/false);
}

TEST(SwitchPipelineTest, MatchesReferenceSemantics) {
  SwitchPipeline pipeline = SaiStyleSwitchPipeline(/*num_routes=*/400);
  PacketTransformerManager manager;
  PacketTransformerHandle policy = manager.Compile(pipeline.Policy());
  BenchmarkRandom random(/*seed=*/7);
  int num_dropped = 0;
  for (int i = 0; i < 3000; ++i) {
    Packet packet = RandomAclPacket(random);
    packet["in_port"] = random.Uniform(kSwitchPipelineNumPorts + 2);
    // Choose destinations near existing routes, to exercise longest prefix
    // matching.
    const Ipv4Route& route =
        pipeline
            .routes[random.Uniform(static_cast<int>(pipeline.routes.size()))];
    for (int octet = 0; octet < 4; ++octet) {
      packet[absl::StrCat("dst_ip", octet)] =
          octet < static_cast<int>(route.prefix.size()) && random.Bernoulli(0.9)
              ? route.prefix[octet]
              : random.Uniform(4);
    }
    // The pipeline sets these fields, but we initialize them for the
    // benefit of the reference implementation.
    packet["vrf"] = 0;
    packet["nexthop"] = 0;
    packet["dst_mac"] = 0;
    std::optional<Packet> expected = ReferencePipeline(pipeline, packet);
    num_dropped += !expected.has_value();
    absl::flat_hash_set<Packet> actual = manager.Run(policy, packet);
    ASSERT_THAT(std::vector<Packet>(actual.begin(), actual.end()),
                testing::ContainerEq(AsVector(expected)));
  }
  EXPECT_GT(num_dropped, 0);
  EXPECT_LT(num_dropped, 2900);
}

// -- NAT gateways -------------------------------------------------------------

TEST(NatGatewayTest, LoadBalancesVipTrafficToAllBackends) {
  NatGateway nat = NatGatewayWithFlows(/*num_flows=*/64);
  PacketTransformerManager manager;
  PacketTransformerHandle load_balancing = manager.Compile(nat.load_balancing);
  // VIP 1000 serves either port 80 or port 443; the other port is unaffected.
  int num_load_balanced = 0;
  for (int service_port : {80, 443}) {
    Packet packet = {{"dst_ip", 1000}, {"dst_port", service_port}};
    absl::flat_hash_set<Packet> outputs = manager.Run(load_balancing, packet);
    if (outputs.size() == 1 && *outputs.begin() == packet) continue;
    ++num_load_balanced;
    EXPECT_GE(outputs.size(), 4);
    EXPECT_LE(outputs.size(), 8);
    for (const Packet& output : outputs) {
      EXPECT_GE(output.at("dst_ip"), 1'000'000);
      EXPECT_EQ(output.at("dst_port"), 8080);
    }
  }
  EXPECT_EQ(num_load_balanced, 1);
}

TEST(NatGatewayTest, PassesOtherTrafficUnmodified) {
  NatGateway nat = NatGatewayWithFlows(/*num_flows=*/64);
  PacketTransformerManager manager;
  PacketTransformerHandle policy = manager.Compile(nat.Policy());
  Packet packet = {
      {"src_ip", 5}, {"src_port", 5}, {"dst_ip", 5}, {"dst_port", 80}};
  EXPECT_THAT(manager.Run(policy, packet), UnorderedElementsAre(packet));
}

TEST(NatGatewayTest, TranslatesEstablishedFlowsInvertibly) {
  NatGateway nat = NatGatewayWithFlows(/*num_flows=*/300);
  PacketTransformerManager manager;
  PacketSetManager& packet_sets = manager.GetPacketSetManager();
  PacketTransformerHandle domain =
      manager.Compile(FilterProto(nat.internal_flows));
  PacketTransformerHandle translated =
      manager.Sequence(domain, manager.Compile(nat.source_nat));
  // All established flows get translated to the public address...
  EXPECT_EQ(packet_sets.And(manager.GetAllPossibleOutputPackets(translated),
                            packet_sets.Match("src_ip", kNatPublicIp)),
            manager.GetAllPossibleOutputPackets(translated));
  // ...invertibly.
  EXPECT_EQ(
      manager.Sequence(translated, manager.Compile(nat.inverse_source_nat)),
      domain);
  EXPECT_FALSE(manager.IsDeny(domain));
}

// -- Equivalence queries ------------------------------------------------------

TEST(FatTreeSliceEquivalenceTest, HoldsForAllTenants) {
  FatTreeOptions options = {.k = 4, .num_tenants = 4};
  for (int tenant = 0; tenant < options.num_tenants; ++tenant) {
    EquivalenceQuery query = FatTreeSliceEquivalence(options, tenant);
    PacketTransformerManager manager;
    PacketTransformerHandle left = manager.Compile(query.left);
    EXPECT_EQ(left, manager.Compile(query.right)) << "tenant " << tenant;
    EXPECT_FALSE(manager.IsDeny(left));
  }
}

TEST(FatTreeSliceEquivalenceTest, DistinguishesTenants) {
  FatTreeOptions options = {.k = 4, .num_tenants = 4};
  PacketTransformerManager manager;
  EXPECT_NE(manager.Compile(FatTreeSliceEquivalence(options, 0).left),
            manager.Compile(FatTreeSliceEquivalence(options, 1).right));
}

}  // namespace
}  // namespace netkat
