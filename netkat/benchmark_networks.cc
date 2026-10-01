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

#include "netkat/benchmark_networks.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <iterator>
#include <optional>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "netkat/netkat.pb.h"
#include "netkat/netkat_proto_constructors.h"

namespace netkat {

// -- Common building blocks ---------------------------------------------------

uint64_t BenchmarkRandom::Next() {
  uint64_t z = (state_ += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

int BenchmarkRandom::Uniform(int n) {
  CHECK_GT(n, 0);  // Crash OK.
  return static_cast<int>(Next() % static_cast<uint64_t>(n));
}

bool BenchmarkRandom::Bernoulli(double p) {
  return static_cast<double>(Next() >> 11) * 0x1.0p-53 < p;
}

PolicyProto PrioritizedTableProto(std::vector<TableRule> rules,
                                  PolicyProto default_action) {
  PolicyProto result = std::move(default_action);
  for (auto it = rules.rbegin(); it != rules.rend(); ++it) {
    PredicateProto negated_match = NotProto(it->match);
    result = UnionProto(
        SequenceProto(FilterProto(std::move(it->match)), std::move(it->action)),
        SequenceProto(FilterProto(std::move(negated_match)),
                      std::move(result)));
  }
  return result;
}

namespace {

// Returns `sw=from_switch && port=from_port; sw:=to_switch; port:=to_port`.
PolicyProto LinkProto(int from_switch, int from_port, int to_switch,
                      int to_port) {
  return SequenceProto(FilterProto(AndProto(MatchProto("sw", from_switch),
                                            MatchProto("port", from_port))),
                       SequenceProto(ModificationProto("sw", to_switch),
                                     ModificationProto("port", to_port)));
}

// Returns `operands[0] * ... * operands[n-1]` as a balanced tree, where `*` is
// `combine`, or `empty` if there are no operands.
//
// We build balanced, rather than list-like, trees to keep the nesting depth of
// the resulting protos logarithmic: protobuf copies and destroys messages
// recursively, and so overflows the stack on deeply nested messages.
// Returns `left + right`, simplifying if `left` is the initial `Deny`. Used to
// build per-switch tables incrementally, as is common in practice.
PolicyProto AppendUnion(PolicyProto left, PolicyProto right) {
  if (left.has_filter() && left.filter().has_bool_constant() &&
      !left.filter().bool_constant().value()) {
    return right;
  }
  return UnionProto(std::move(left), std::move(right));
}

template <class Proto, class Combine>
Proto CombineBalancedProtos(std::vector<Proto> operands, Combine combine,
                            Proto empty) {
  if (operands.empty()) return empty;
  while (operands.size() > 1) {
    size_t num_combined = 0;
    for (size_t i = 0; i + 1 < operands.size(); i += 2) {
      operands[num_combined++] =
          combine(std::move(operands[i]), std::move(operands[i + 1]));
    }
    if (operands.size() % 2 == 1) {
      operands[num_combined++] = std::move(operands.back());
    }
    operands.resize(num_combined);
  }
  return std::move(operands.front());
}

}  // namespace

PolicyProto BalancedUnionProto(std::vector<PolicyProto> policies) {
  return CombineBalancedProtos(std::move(policies), UnionProto, DenyProto());
}

PredicateProto BalancedOrProto(std::vector<PredicateProto> predicates) {
  return CombineBalancedProtos(std::move(predicates), OrProto, FalseProto());
}

PredicateProto MatchAnyProto(absl::string_view field,
                             absl::Span<const int> values) {
  std::vector<PredicateProto> matches;
  for (int value : values) matches.push_back(MatchProto(field, value));
  return BalancedOrProto(std::move(matches));
}

PolicyProto EndToEndPolicy(const NetworkModel& network) {
  return SequenceProto(
      IterateProto(SequenceProto(network.forwarding, network.topology)),
      network.forwarding);
}

PolicyProto EndToEndPolicyAvoiding(const NetworkModel& network, int waypoint) {
  PolicyProto forwarding = SequenceProto(
      FilterProto(NotProto(MatchProto("sw", waypoint))), network.forwarding);
  return SequenceProto(
      IterateProto(SequenceProto(forwarding, network.topology)), forwarding);
}

// -- Fat trees ----------------------------------------------------------------

namespace {

// Switch identifiers: edge switches first, then aggregation switches, then
// core switches.
int EdgeSwitch(int k, int pod, int edge) { return pod * (k / 2) + edge; }
int AggregationSwitch(int k, int pod, int aggregation) {
  return k * k / 2 + pod * (k / 2) + aggregation;
}
int CoreSwitch(int k, int core) { return k * k + core; }

// Returns the action forwarding packets along an uplink, i.e. one of the ports
// k/2, ..., k-1. If `multipath`, uses all uplinks. Otherwise, uses the uplink
// determined by the destination host (as in Al-Fares et al.'s two-level
// routing tables), rotated by `rotation`, which is returned as a list of
// suffix rules.
std::vector<TableRule> UplinkRules(const FatTreeOptions& options,
                                   int rotation) {
  const int half = options.k / 2;
  std::vector<TableRule> rules;
  if (options.multipath) {
    std::vector<PolicyProto> all_uplinks;
    all_uplinks.reserve(half);
    for (int i = 0; i < half; ++i) {
      all_uplinks.push_back(ModificationProto("port", half + i));
    }
    rules.push_back({TrueProto(), BalancedUnionProto(std::move(all_uplinks))});
    return rules;
  }
  rules.reserve(half);
  for (int host = 0; host < half; ++host) {
    rules.push_back(
        {MatchProto("dst_host", host),
         ModificationProto("port", half + (host + rotation) % half)});
  }
  return rules;
}

}  // namespace

std::vector<FatTreeHost> FatTreeHosts(int k) {
  std::vector<FatTreeHost> hosts;
  for (int pod = 0; pod < k; ++pod) {
    for (int edge = 0; edge < k / 2; ++edge) {
      for (int host = 0; host < k / 2; ++host) {
        hosts.push_back({.pod = pod, .edge = edge, .host = host});
      }
    }
  }
  return hosts;
}

int FatTreeTenant(const FatTreeOptions& options, const FatTreeHost& host) {
  const int half = options.k / 2;
  return ((host.pod * half + host.edge) * half + host.host) %
         std::max(options.num_tenants, 1);
}

PredicateProto FatTreeHostLocation(int k, const FatTreeHost& host) {
  return AndProto(MatchProto("sw", EdgeSwitch(k, host.pod, host.edge)),
                  MatchProto("port", host.host));
}

PredicateProto FatTreeHostAddress(const FatTreeHost& host) {
  return AndProto(MatchProto("dst_pod", host.pod),
                  AndProto(MatchProto("dst_edge", host.edge),
                           MatchProto("dst_host", host.host)));
}

NetworkModel FatTree(const FatTreeOptions& options) {
  const int k = options.k;
  CHECK(k >= 2 && k % 2 == 0) << k;  // Crash OK.
  const int half = k / 2;
  std::vector<PolicyProto> forwarding, topology;
  std::vector<PredicateProto> host_locations;

  std::vector<int> host_ports;
  host_ports.reserve(half);
  for (int port = 0; port < half; ++port) host_ports.push_back(port);

  for (int pod = 0; pod < k; ++pod) {
    // Edge switches.
    for (int edge = 0; edge < half; ++edge) {
      const int sw = EdgeSwitch(k, pod, edge);
      // Deliver to local hosts, otherwise send up.
      std::vector<TableRule> rules;
      rules.reserve(half);
      for (int host = 0; host < half; ++host) {
        rules.push_back(
            {FatTreeHostAddress({.pod = pod, .edge = edge, .host = host}),
             ModificationProto("port", host)});
      }
      // Drop packets to unknown hosts of this edge switch, rather than looping.
      rules.push_back(
          {AndProto(MatchProto("dst_pod", pod), MatchProto("dst_edge", edge)),
           DenyProto()});
      for (TableRule& rule : UplinkRules(options, /*rotation=*/edge)) {
        rules.push_back(std::move(rule));
      }
      PolicyProto table = PrioritizedTableProto(std::move(rules), DenyProto());

      if (options.num_tenants > 0) {
        // Tag packets arriving from hosts with the tenant of the source host,
        // and only deliver packets to hosts of the tagged tenant.
        PolicyProto tag =
            FilterProto(NotProto(MatchAnyProto("port", host_ports)));
        PredicateProto deliverable =
            NotProto(MatchAnyProto("port", host_ports));
        for (int host = 0; host < half; ++host) {
          const int tenant =
              FatTreeTenant(options, {.pod = pod, .edge = edge, .host = host});
          tag = UnionProto(std::move(tag),
                           SequenceProto(FilterProto(MatchProto("port", host)),
                                         ModificationProto("vlan", tenant)));
          deliverable = OrProto(
              std::move(deliverable),
              AndProto(MatchProto("port", host), MatchProto("vlan", tenant)));
        }
        table = SequenceProto(
            std::move(tag), SequenceProto(std::move(table),
                                          FilterProto(std::move(deliverable))));
      }
      forwarding.push_back(
          SequenceProto(FilterProto(MatchProto("sw", sw)), std::move(table)));
      host_locations.push_back(
          AndProto(MatchProto("sw", sw), MatchAnyProto("port", host_ports)));

      // Links to the aggregation switches of the pod.
      for (int aggregation = 0; aggregation < half; ++aggregation) {
        const int agg = AggregationSwitch(k, pod, aggregation);
        topology.push_back(LinkProto(sw, half + aggregation, agg, edge));
        topology.push_back(LinkProto(agg, edge, sw, half + aggregation));
      }
    }

    // Aggregation switches.
    for (int aggregation = 0; aggregation < half; ++aggregation) {
      const int sw = AggregationSwitch(k, pod, aggregation);
      // Send down to the edge switch of the destination if in this pod,
      // otherwise send up.
      std::vector<TableRule> rules;
      rules.reserve(half);
      for (int edge = 0; edge < half; ++edge) {
        rules.push_back(
            {AndProto(MatchProto("dst_pod", pod), MatchProto("dst_edge", edge)),
             ModificationProto("port", edge)});
      }
      // Drop packets to unknown edge switches of this pod, rather than looping.
      rules.push_back({MatchProto("dst_pod", pod), DenyProto()});
      for (TableRule& rule : UplinkRules(options, /*rotation=*/aggregation)) {
        rules.push_back(std::move(rule));
      }
      forwarding.push_back(
          SequenceProto(FilterProto(MatchProto("sw", sw)),
                        PrioritizedTableProto(std::move(rules), DenyProto())));

      // Links to the core switches.
      for (int i = 0; i < half; ++i) {
        const int core = CoreSwitch(k, aggregation * half + i);
        topology.push_back(LinkProto(sw, half + i, core, pod));
        topology.push_back(LinkProto(core, pod, sw, half + i));
      }
    }
  }

  // Core switches: send down to the pod of the destination.
  for (int core = 0; core < half * half; ++core) {
    PolicyProto table = DenyProto();
    for (int pod = 0; pod < k; ++pod) {
      table = AppendUnion(std::move(table),
                          SequenceProto(FilterProto(MatchProto("dst_pod", pod)),
                                        ModificationProto("port", pod)));
    }
    forwarding.push_back(SequenceProto(
        FilterProto(MatchProto("sw", CoreSwitch(k, core))), std::move(table)));
  }
  PredicateProto at_hosts = BalancedOrProto(std::move(host_locations));
  return {
      .forwarding = BalancedUnionProto(std::move(forwarding)),
      .topology = BalancedUnionProto(std::move(topology)),
      .ingress = at_hosts,
      .egress = at_hosts,
  };
}

// -- Wide area networks -------------------------------------------------------

Wan ShortestPathWan(int num_switches, uint64_t seed) {
  CHECK_GE(num_switches, 2);  // Crash OK.
  BenchmarkRandom random(seed);
  Wan wan;
  std::vector<std::vector<int>>& adjacency = wan.adjacency;
  adjacency.resize(num_switches);
  auto adjacent = [&](int a, int b) {
    return absl::c_linear_search(adjacency[a], b);
  };
  auto connect = [&](int a, int b) {
    adjacency[a].push_back(b);
    adjacency[b].push_back(a);
  };
  // A random recursive tree ensures connectivity; extra random links bring the
  // average degree to ~3.
  for (int s = 1; s < num_switches; ++s) connect(s, random.Uniform(s));
  for (int i = 0; i < num_switches / 2; ++i) {
    int a = random.Uniform(num_switches);
    int b = random.Uniform(num_switches);
    if (a != b && !adjacent(a, b)) connect(a, b);
  }

  auto port_to = [&](int from, int to) {
    auto it = absl::c_find(adjacency[from], to);
    CHECK(it != adjacency[from].end());  // Crash OK.
    return static_cast<int>(it - adjacency[from].begin()) + 1;
  };

  // next_hop[d][s] = the neighbor of `s` on a shortest path to `d`.
  std::vector<std::vector<int>> next_hop(num_switches,
                                         std::vector<int>(num_switches, -1));
  for (int d = 0; d < num_switches; ++d) {
    std::vector<int>& next = next_hop[d];
    next[d] = d;
    std::deque<int> queue = {d};
    while (!queue.empty()) {
      int s = queue.front();
      queue.pop_front();
      for (int neighbor : adjacency[s]) {
        if (next[neighbor] != -1) continue;
        next[neighbor] = s;
        queue.push_back(neighbor);
      }
    }
  }

  std::vector<PolicyProto> forwarding, topology;
  for (int s = 0; s < num_switches; ++s) {
    PolicyProto table = DenyProto();
    for (int d = 0; d < num_switches; ++d) {
      const int port = d == s ? 0 : port_to(s, next_hop[d][s]);
      table = AppendUnion(std::move(table),
                          SequenceProto(FilterProto(MatchProto("dst", d)),
                                        ModificationProto("port", port)));
    }
    forwarding.push_back(
        SequenceProto(FilterProto(MatchProto("sw", s)), std::move(table)));
    for (int neighbor : adjacency[s]) {
      topology.push_back(
          LinkProto(s, port_to(s, neighbor), neighbor, port_to(neighbor, s)));
    }
  }
  wan.network = {
      .forwarding = BalancedUnionProto(std::move(forwarding)),
      .topology = BalancedUnionProto(std::move(topology)),
      .ingress = MatchProto("port", 0),
      .egress = MatchProto("port", 0),
  };
  return wan;
}

// -- Backbone networks --------------------------------------------------------

NetworkModel Backbone(int num_routers, uint64_t seed) {
  Wan wan = ShortestPathWan(num_routers, seed);
  BenchmarkRandom random(seed);

  // port_to[s][d] = the port on which router `s` forwards packets towards
  // router `d` along a shortest path (0 if `s == d`).
  std::vector<std::vector<int>> port_to(num_routers,
                                        std::vector<int>(num_routers, 0));
  for (int d = 0; d < num_routers; ++d) {
    std::vector<int> distance(num_routers, -1);
    distance[d] = 0;
    std::deque<int> queue = {d};
    while (!queue.empty()) {
      int s = queue.front();
      queue.pop_front();
      if (wan.adjacency.size() <= s) continue;
      for (int neighbor : wan.adjacency[s]) {
        if (distance[neighbor] != -1) continue;
        distance[neighbor] = distance[s] + 1;
        queue.push_back(neighbor);
      }
    }
    for (int s = 0; s < num_routers && s < wan.adjacency.size(); ++s) {
      for (int i = 0; i < wan.adjacency[s].size(); ++i) {
        if (distance[wan.adjacency[s][i]] == distance[s] - 1) {
          port_to[s][d] = i + 1;
          break;
        }
      }
    }
  }

  // More specific prefixes 10.`second_octet`.`third_octet`.0/24, announced by
  // `router`.
  struct MoreSpecificPrefix {
    int second_octet;
    int third_octet;
    int router;
  };
  std::vector<MoreSpecificPrefix> more_specific_prefixes;
  more_specific_prefixes.reserve(num_routers);
  for (int i = 0; i < num_routers; ++i) {
    more_specific_prefixes.push_back(
        {.second_octet = random.Uniform(num_routers),
         .third_octet = random.Uniform(256),
         .router = random.Uniform(num_routers)});
  }

  std::vector<PolicyProto> routers;
  for (int s = 0; s < num_routers; ++s) {
    // Longest prefix match, as a prioritized table with longer prefixes first.
    std::vector<TableRule> routes;
    routes.reserve(more_specific_prefixes.size());
    for (const MoreSpecificPrefix& prefix : more_specific_prefixes) {
      routes.push_back(
          {AndProto(MatchProto("dst_ip0", 10),
                    AndProto(MatchProto("dst_ip1", prefix.second_octet),
                             MatchProto("dst_ip2", prefix.third_octet))),
           ModificationProto("port", port_to[s][prefix.router])});
    }
    for (int d = 0; d < num_routers; ++d) {
      routes.push_back(
          {AndProto(MatchProto("dst_ip0", 10), MatchProto("dst_ip1", d)),
           ModificationProto("port", port_to[s][d])});
    }
    PolicyProto routing = PrioritizedTableProto(std::move(routes), DenyProto());

    // An ACL filtering traffic from hosts, which permits unmatched traffic.
    std::vector<TableRule> acl_rules;
    for (const AclRule& rule :
         ClassBenchStyleAclRules(/*num_rules=*/16, /*seed=*/seed + s)) {
      acl_rules.push_back({AclRuleMatch(rule), AclRuleAction(rule)});
    }
    PolicyProto acl = UnionProto(
        SequenceProto(
            FilterProto(MatchProto("port", 0)),
            PrioritizedTableProto(std::move(acl_rules), AcceptProto())),
        FilterProto(NotProto(MatchProto("port", 0))));

    routers.push_back(
        SequenceProto(FilterProto(MatchProto("sw", s)),
                      SequenceProto(std::move(acl), std::move(routing))));
  }
  return {
      .forwarding = BalancedUnionProto(std::move(routers)),
      .topology = std::move(wan.network.topology),
      .ingress = AndProto(MatchProto("port", 0), MatchProto("dst_ip0", 10)),
      .egress = MatchProto("port", 0),
  };
}

// -- Access control lists -----------------------------------------------------

std::vector<AclRule> ClassBenchStyleAclRules(int num_rules, uint64_t seed) {
  BenchmarkRandom random(seed);
  // A few popular values per field, to create realistic overlap.
  static constexpr int kProtocols[] = {6, 6, 6, 17, 17, 1};  // TCP, UDP, ICMP.
  static constexpr int kPopularPorts[] = {22, 53, 80, 443, 8080, 3389};
  std::vector<AclRule> rules;
  rules.reserve(num_rules);
  for (int i = 0; i < num_rules; ++i) {
    AclRule rule;
    // ClassBench-like: destinations are more specific than sources, and most
    // rules match a protocol and destination port.
    if (random.Bernoulli(0.5)) rule.src_net = random.Uniform(64);
    if (random.Bernoulli(0.9) || !rule.src_net.has_value()) {
      rule.dst_net = random.Uniform(256);
    }
    if (random.Bernoulli(0.8)) {
      rule.ip_proto =
          kProtocols[random.Uniform(static_cast<int>(std::size(kProtocols)))];
    }
    if (random.Bernoulli(0.1)) rule.l4_src_port = 1024 + random.Uniform(64);
    if (random.Bernoulli(0.7)) {
      rule.l4_dst_port = random.Bernoulli(0.6)
                             ? kPopularPorts[random.Uniform(
                                   static_cast<int>(std::size(kPopularPorts)))]
                             : 1024 + random.Uniform(1024);
    }
    int action = random.Uniform(10);
    if (action < 5) {
      rule.action = AclRule::Action::kPermit;
    } else if (action < 9) {
      rule.action = AclRule::Action::kDeny;
    } else {
      rule.action = AclRule::Action::kRedirect;
      rule.redirect_port = random.Uniform(kSwitchPipelineNumPorts);
    }
    rules.push_back(rule);
  }
  return rules;
}

PredicateProto AclRuleMatch(const AclRule& rule) {
  PredicateProto result = TrueProto();
  auto add = [&](absl::string_view field, const std::optional<int>& value) {
    if (!value.has_value()) return;
    PredicateProto match = MatchProto(field, *value);
    result = result.has_bool_constant()
                 ? std::move(match)
                 : AndProto(std::move(result), std::move(match));
  };
  add("src_net", rule.src_net);
  add("dst_net", rule.dst_net);
  add("ip_proto", rule.ip_proto);
  add("l4_src_port", rule.l4_src_port);
  add("l4_dst_port", rule.l4_dst_port);
  return result;
}

PolicyProto AclRuleAction(const AclRule& rule) {
  switch (rule.action) {
    case AclRule::Action::kPermit:
      return AcceptProto();
    case AclRule::Action::kDeny:
      return DenyProto();
    case AclRule::Action::kRedirect:
      return ModificationProto("port", rule.redirect_port);
  }
  LOG(FATAL) << "unreachable";  // Crash OK.
}

PolicyProto AclPolicy(absl::Span<const AclRule> rules) {
  std::vector<TableRule> table_rules;
  table_rules.reserve(rules.size());
  for (const AclRule& rule : rules) {
    table_rules.push_back({AclRuleMatch(rule), AclRuleAction(rule)});
  }
  return PrioritizedTableProto(std::move(table_rules), DenyProto());
}

// -- Switch pipelines ---------------------------------------------------------

PolicyProto SwitchPipeline::Policy() const {
  return SequenceProto(
      vrf_assignment,
      SequenceProto(routing, SequenceProto(nexthop_resolution, acl)));
}

SwitchPipeline SaiStyleSwitchPipeline(int num_routes, uint64_t seed) {
  BenchmarkRandom random(seed);
  SwitchPipeline pipeline;

  // Stage 1: VRF assignment by input port.
  {
    std::vector<TableRule> rules;
    rules.reserve(kSwitchPipelineNumPorts);
    for (int port = 0; port < kSwitchPipelineNumPorts; ++port) {
      rules.push_back(
          {MatchProto("in_port", port),
           ModificationProto("vrf", port % kSwitchPipelineNumVrfs)});
    }
    pipeline.vrf_assignment =
        PrioritizedTableProto(std::move(rules), ModificationProto("vrf", 0));
  }

  // Stage 2: longest prefix match routing.
  const int num_nexthops = std::max(8, num_routes / 16);
  {
    // A few popular first octets, so prefixes nest as in real routing tables.
    static constexpr int kFirstOctets[] = {10, 100, 172, 192, 203, 1, 8, 64};
    std::vector<Ipv4Route>& routes = pipeline.routes;
    for (int i = 0; i < num_routes; ++i) {
      Ipv4Route route = {.vrf = random.Uniform(kSwitchPipelineNumVrfs),
                         .nexthop = random.Uniform(num_nexthops)};
      // Prefix length distribution loosely modeled on Internet routing tables:
      // mostly /24s, then /16s, /32s, and /8s.
      int percentile = random.Uniform(100);
      int num_octets = percentile < 60   ? 3
                       : percentile < 85 ? 2
                       : percentile < 95 ? 4
                                         : 1;
      route.prefix.push_back(kFirstOctets[random.Uniform(
          static_cast<int>(std::size(kFirstOctets)))]);
      for (int octet = 1; octet < num_octets; ++octet) {
        // Skewed octet distribution, for more nesting between prefixes.
        route.prefix.push_back(random.Bernoulli(0.5) ? random.Uniform(4)
                                                     : random.Uniform(256));
      }
      routes.push_back(std::move(route));
    }
    for (int vrf = 0; vrf < kSwitchPipelineNumVrfs; ++vrf) {
      routes.push_back({.vrf = vrf, .prefix = {}, .nexthop = vrf});
    }
    // Longest prefix first; stable, so earlier routes win ties.
    absl::c_stable_sort(routes, [](const Ipv4Route& a, const Ipv4Route& b) {
      return a.prefix.size() > b.prefix.size();
    });

    static constexpr absl::string_view kOctetFields[] = {"dst_ip0", "dst_ip1",
                                                         "dst_ip2", "dst_ip3"};
    std::vector<TableRule> rules;
    rules.reserve(routes.size());
    for (const Ipv4Route& route : routes) {
      PredicateProto match = MatchProto("vrf", route.vrf);
      for (size_t octet = 0; octet < route.prefix.size(); ++octet) {
        match = AndProto(std::move(match),
                         MatchProto(kOctetFields[octet], route.prefix[octet]));
      }
      rules.push_back(
          {std::move(match), ModificationProto("nexthop", route.nexthop)});
    }
    pipeline.routing = PrioritizedTableProto(std::move(rules), DenyProto());
  }

  // Stage 3: next hop resolution.
  {
    PolicyProto table = DenyProto();
    for (int nexthop = 0; nexthop < num_nexthops; ++nexthop) {
      table = AppendUnion(
          std::move(table),
          SequenceProto(
              FilterProto(MatchProto("nexthop", nexthop)),
              SequenceProto(
                  ModificationProto("port", nexthop % kSwitchPipelineNumPorts),
                  ModificationProto("dst_mac", nexthop))));
    }
    pipeline.nexthop_resolution = std::move(table);
  }

  // Stage 4: ACL, permitting packets not matched by any rule.
  {
    pipeline.acl_rules =
        ClassBenchStyleAclRules(std::max(1, num_routes / 8), random.Next());
    std::vector<TableRule> rules;
    rules.reserve(pipeline.acl_rules.size());
    for (const AclRule& rule : pipeline.acl_rules) {
      rules.push_back({AclRuleMatch(rule), AclRuleAction(rule)});
    }
    pipeline.acl = PrioritizedTableProto(std::move(rules), AcceptProto());
  }
  return pipeline;
}

// -- NAT gateways -------------------------------------------------------------

namespace {

// Returns the policy of a table whose rules have pairwise disjoint matches
// (e.g. an exact-match table), which processes packets not matched by any rule
// by `default_action`. Since the matches are disjoint, priorities are
// irrelevant, and we encode the table as a balanced union (see
// `BalancedUnionProto`):
//
//   m_0; a_0 + ... + m_n; a_n + !(m_0 || ... || m_n); default_action
PolicyProto DisjointTableProto(std::vector<TableRule> rules,
                               PolicyProto default_action) {
  std::vector<PolicyProto> policies;
  std::vector<PredicateProto> matches;
  policies.reserve(rules.size() + 1);
  matches.reserve(rules.size());
  for (TableRule& rule : rules) {
    matches.push_back(rule.match);
    policies.push_back(SequenceProto(FilterProto(std::move(rule.match)),
                                     std::move(rule.action)));
  }
  policies.push_back(
      SequenceProto(FilterProto(NotProto(BalancedOrProto(std::move(matches)))),
                    std::move(default_action)));
  return BalancedUnionProto(std::move(policies));
}

}  // namespace

PolicyProto NatGateway::Policy() const {
  return SequenceProto(load_balancing, source_nat);
}

NatGateway NatGatewayWithFlows(int num_flows, uint64_t seed) {
  CHECK_GE(num_flows, 1);  // Crash OK.
  BenchmarkRandom random(seed);
  NatGateway nat;

  // Load balancing. Addresses are modeled as integers; VIPs and backends use
  // disjoint ranges.
  constexpr int kVipBase = 1000;
  constexpr int kBackendBase = 1'000'000;
  const int num_vips = std::max(4, num_flows / 64);
  std::vector<TableRule> load_balancing_rules;
  load_balancing_rules.reserve(num_vips);
  for (int vip = 0; vip < num_vips; ++vip) {
    const int service_port = random.Bernoulli(0.5) ? 443 : 80;
    const int num_backends = 4 + random.Uniform(5);
    std::vector<PolicyProto> backends;
    backends.reserve(num_backends);
    for (int backend = 0; backend < num_backends; ++backend) {
      backends.push_back(SequenceProto(
          ModificationProto("dst_ip", kBackendBase + 8 * vip + backend),
          ModificationProto("dst_port", 8080 + vip % 4)));
    }
    load_balancing_rules.push_back(
        {AndProto(MatchProto("dst_ip", kVipBase + vip),
                  MatchProto("dst_port", service_port)),
         BalancedUnionProto(std::move(backends))});
  }
  nat.load_balancing =
      DisjointTableProto(std::move(load_balancing_rules), AcceptProto());

  // Source NAT of established flows (internal host, ephemeral port), each
  // allocated a distinct public port.
  constexpr int kInternalIpBase = 2'000'000;
  constexpr int kMinEphemeralPort = 32768;
  constexpr int kNumEphemeralPorts = 28232;
  const int num_hosts = std::max(16, num_flows / 16);
  absl::flat_hash_set<std::pair<int, int>> flows;
  std::vector<int> public_ports(num_flows);
  for (int i = 0; i < num_flows; ++i) public_ports[i] = 1024 + i;
  for (int i = num_flows - 1; i > 0; --i) {
    std::swap(public_ports[i], public_ports[random.Uniform(i + 1)]);
  }
  std::vector<TableRule> source_nat_rules, inverse_rules;
  std::vector<PredicateProto> internal_flows;
  source_nat_rules.reserve(num_flows);
  inverse_rules.reserve(num_flows);
  internal_flows.reserve(num_flows);
  for (int i = 0; i < num_flows; ++i) {
    int src_ip, src_port;
    do {
      src_ip = kInternalIpBase + random.Uniform(num_hosts);
      src_port = kMinEphemeralPort + random.Uniform(kNumEphemeralPorts);
    } while (!flows.insert({src_ip, src_port}).second);
    PredicateProto internal = AndProto(MatchProto("src_ip", src_ip),
                                       MatchProto("src_port", src_port));
    source_nat_rules.push_back(
        {internal,
         SequenceProto(ModificationProto("src_ip", kNatPublicIp),
                       ModificationProto("src_port", public_ports[i]))});
    inverse_rules.push_back(
        {AndProto(MatchProto("src_ip", kNatPublicIp),
                  MatchProto("src_port", public_ports[i])),
         SequenceProto(ModificationProto("src_ip", src_ip),
                       ModificationProto("src_port", src_port))});
    internal_flows.push_back(std::move(internal));
  }
  nat.source_nat =
      DisjointTableProto(std::move(source_nat_rules), AcceptProto());
  nat.inverse_source_nat =
      DisjointTableProto(std::move(inverse_rules), AcceptProto());
  nat.internal_flows = BalancedOrProto(std::move(internal_flows));
  return nat;
}

// -- Equivalence queries ------------------------------------------------------

EquivalenceQuery FatTreeSliceEquivalence(const FatTreeOptions& options,
                                         int tenant) {
  CHECK_GT(options.num_tenants, 0);  // Crash OK.
  std::vector<PredicateProto> tenant_host_locations;
  for (const FatTreeHost& host : FatTreeHosts(options.k)) {
    if (FatTreeTenant(options, host) == tenant) {
      tenant_host_locations.push_back(FatTreeHostLocation(options.k, host));
    }
  }
  PolicyProto at_tenant_hosts =
      FilterProto(BalancedOrProto(std::move(tenant_host_locations)));
  FatTreeOptions unsliced_options = options;
  unsliced_options.num_tenants = 0;
  return {
      .left = SequenceProto(
          at_tenant_hosts,
          SequenceProto(EndToEndPolicy(FatTree(options)), at_tenant_hosts)),
      .right = SequenceProto(
          at_tenant_hosts,
          SequenceProto(EndToEndPolicy(FatTree(unsliced_options)),
                        SequenceProto(at_tenant_hosts,
                                      ModificationProto("vlan", tenant)))),
  };
}

}  // namespace netkat
