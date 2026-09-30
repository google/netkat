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
// File: benchmark_networks.h
// -----------------------------------------------------------------------------
//
// Generators for realistic, parameterized NetKAT workloads, for benchmarking
// and end-to-end testing of the NetKAT backend. The workloads are modeled on
// those commonly used in the network verification literature:
//
//  * Data center fat trees with two-level routing [Al-Fares et al., "A
//    Scalable, Commodity Data Center Network Architecture", SIGCOMM 2008], as
//    used e.g. in the evaluations of the NetKAT compiler [Smolka et al., "A
//    Fast Compiler for NetKAT", ICFP 2015] and of KATch [Moeller et al.,
//    "KATch: A Fast Symbolic Verifier for NetKAT", PLDI 2024]. Optionally with
//    multipath (ECMP) routing and with VLAN-based tenant isolation ("slicing")
//    [Gutz et al., "Splendid Isolation", HotSDN 2012].
//
//  * Wide area networks with shortest-path destination routing, on random
//    sparse topologies resembling those in the Internet Topology Zoo [Knight
//    et al., JSAC 2011], again as used in the ICFP 2015 and PLDI 2024
//    evaluations.
//
//  * Access control lists with overlapping, prioritized 5-tuple rules in the
//    style of ClassBench [Taylor and Turner, INFOCOM 2005].
//
//  * Multi-stage switch pipelines in the style of the SAI P4 program (VRF
//    assignment, longest prefix match routing, next hop resolution, ACL), as
//    verified e.g. by header space analysis [Kazemian et al., NSDI 2012] and
//    its successors.
//
//  * NAT gateways (load balancing and source NAT), i.e. middleboxes that
//    rewrite many header fields, as verified e.g. by SymNet [Stoenescu et al.,
//    SIGCOMM 2016] and VMN [Panda et al., NSDI 2017].
//
//  * Slice isolation checked as an equivalence query [Gutz et al., "Splendid
//    Isolation", HotSDN 2012]: that a multi-tenant network treats each
//    tenant's traffic like the network without slicing.
//
// All generators are deterministic.

#ifndef GOOGLE_NETKAT_NETKAT_BENCHMARK_NETWORKS_H_
#define GOOGLE_NETKAT_NETKAT_BENCHMARK_NETWORKS_H_

#include <cstdint>
#include <optional>
#include <vector>

#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "netkat/netkat.pb.h"

namespace netkat {

// -- Common building blocks ---------------------------------------------------

// A deterministic, platform-independent pseudo random number generator
// (SplitMix64), so generated workloads are identical across platforms.
class BenchmarkRandom {
 public:
  explicit BenchmarkRandom(uint64_t seed) : state_(seed) {}

  uint64_t Next();

  // Returns a number in [0, n). Requires n > 0.
  int Uniform(int n);

  // Returns true with probability `p`.
  bool Bernoulli(double p);

 private:
  uint64_t state_;
};

// A rule of a prioritized match-action table.
struct TableRule {
  PredicateProto match;
  PolicyProto action;
};

// Returns the policy of a prioritized table with the given `rules`, in order of
// decreasing priority. Packets not matched by any rule are processed by
// `default_action`. Uses the same encoding as `NetkatTable`:
//
//   m_0; a_0 + !m_0; (m_1; a_1 + !m_1; (... default_action))
PolicyProto PrioritizedTableProto(std::vector<TableRule> rules,
                                  PolicyProto default_action);

// Returns `policies[0] + ... + policies[n-1]`, or `Deny` if `policies` is
// empty, as a balanced tree. Balanced, rather than list-like, to keep the
// nesting depth of the proto logarithmic: protobuf copies and destroys messages
// recursively, and so overflows the stack on deeply nested messages.
PolicyProto BalancedUnionProto(std::vector<PolicyProto> policies);

// Returns `predicates[0] || ... || predicates[n-1]`, or `false` if
// `predicates` is empty, as a balanced tree (see above).
PredicateProto BalancedOrProto(std::vector<PredicateProto> predicates);

// Returns the predicate `field=values[0] || ... || field=values[n-1]`, or
// `false` if `values` is empty.
PredicateProto MatchAnyProto(absl::string_view field,
                             absl::Span<const int> values);

// A network in the style of NetKAT: a packet is located at a switch (field
// `sw`) and port (field `port`). The network processes packets by alternating
// between forwarding (applying the switch tables) and topology traversal:
//
//   ingress; (forwarding; topology)*; forwarding; egress
struct NetworkModel {
  // The forwarding behavior of all switches, of the form
  //   SUM_s (sw=s; table_s).
  PolicyProto forwarding;
  // The links of the network, of the form
  //   SUM_{(s,p) -> (s',p')} (sw=s && port=p; sw:=s'; port:=p').
  PolicyProto topology;
  // The packets entering the network, located at host-facing ports.
  PredicateProto ingress;
  // The packets leaving the network, located at host-facing ports.
  PredicateProto egress;
};

// Returns `(forwarding; topology)*; forwarding`, i.e. the end-to-end behavior
// of `network`, excluding ingress and egress filtering.
PolicyProto EndToEndPolicy(const NetworkModel& network);

// Returns `(filter(!sw=waypoint); forwarding; topology)*; filter(!sw=waypoint);
// forwarding`, i.e. the end-to-end behavior of `network` for packets that
// never traverse switch `waypoint`.
PolicyProto EndToEndPolicyAvoiding(const NetworkModel& network, int waypoint);

// -- Fat trees ----------------------------------------------------------------

struct FatTreeOptions {
  // The number of ports per switch. Must be even and >= 2. The fat tree has k
  // pods, k^2/4 core switches, and k^3/4 hosts.
  int k = 4;
  // If true, switches forward packets destined to other pods along all
  // uplinks (nondeterministically), modeling multipath routing. Otherwise,
  // the uplink is chosen deterministically based on the destination host.
  bool multipath = false;
  // If positive, hosts are partitioned into this many tenants, and edge
  // switches tag packets with the `vlan` of the source host's tenant and only
  // deliver packets to hosts of the tenant indicated by their `vlan`.
  int num_tenants = 0;
};

// Identifies a host of a fat tree. Host addresses are hierarchical, in fields
// `dst_pod`, `dst_edge`, `dst_host`, as in the Al-Fares et al. design.
struct FatTreeHost {
  int pod;
  int edge;  // Index of the edge switch within the pod.
  int host;  // Index of the host within the edge switch.
};

NetworkModel FatTree(const FatTreeOptions& options);

// Returns all hosts of the fat tree with the given `k`.
std::vector<FatTreeHost> FatTreeHosts(int k);

// Returns the tenant of `host`, if `options.num_tenants > 0`.
int FatTreeTenant(const FatTreeOptions& options, const FatTreeHost& host);

// Returns the predicate matching packets located at the port connecting to
// `host`.
PredicateProto FatTreeHostLocation(int k, const FatTreeHost& host);

// Returns the predicate matching packets destined to `host`.
PredicateProto FatTreeHostAddress(const FatTreeHost& host);

// -- Wide area networks -------------------------------------------------------

struct Wan {
  NetworkModel network;
  // `adjacency[s]` lists the neighbors of switch `s`. The link to neighbor
  // `adjacency[s][i]` is at port `i + 1`; port 0 connects to hosts.
  std::vector<std::vector<int>> adjacency;
};

// Returns a WAN of `num_switches` switches with a random, connected, sparse
// topology (average degree ~3, as in the Topology Zoo), where each switch
// forwards packets towards their destination switch `dst` along a shortest
// path, and delivers packets destined to itself to port 0.
Wan ShortestPathWan(int num_switches, uint64_t seed = 1);

// -- Backbone networks --------------------------------------------------------

// Returns a backbone network in the style of the Stanford backbone, which is
// widely used in the network verification literature (e.g. by Header Space
// Analysis, NetPlumber, and Atomic Predicates): `num_routers` routers,
// connected as in `ShortestPathWan`, each of which filters traffic from its
// hosts (at port 0) by an ACL (see `ClassBenchStyleAclRules`), and forwards
// traffic by longest prefix match on the destination address, modeled at
// octet granularity in fields `dst_ip0`, `dst_ip1`, and `dst_ip2`. Router `r`
// owns prefix 10.r.0.0/16, and random routers announce `num_routers` more
// specific /24 prefixes (e.g. of multi-homed customers).
NetworkModel Backbone(int num_routers, uint64_t seed = 1);

// -- Access control lists -----------------------------------------------------

// A 5-tuple ACL rule. Absent fields are wildcards.
struct AclRule {
  enum class Action { kPermit, kDeny, kRedirect };

  std::optional<int> src_net;
  std::optional<int> dst_net;
  std::optional<int> ip_proto;
  std::optional<int> l4_src_port;
  std::optional<int> l4_dst_port;
  Action action = Action::kPermit;
  // The port to redirect to, if `action == kRedirect`.
  int redirect_port = 0;
};

// Returns `num_rules` random ACL rules with overlapping matches, with a
// ClassBench-like distribution of wildcards and field values.
std::vector<AclRule> ClassBenchStyleAclRules(int num_rules, uint64_t seed = 1);

PredicateProto AclRuleMatch(const AclRule& rule);
PolicyProto AclRuleAction(const AclRule& rule);

// Returns the policy of an ACL with the given `rules`, in order of decreasing
// priority, which denies packets not matched by any rule.
PolicyProto AclPolicy(absl::Span<const AclRule> rules);

// -- Switch pipelines ---------------------------------------------------------

// An IPv4 route of a VRF. The destination address is modeled at octet
// granularity, in fields `dst_ip0`, ..., `dst_ip3`.
struct Ipv4Route {
  int vrf;
  // The prefix, of length 8 * `prefix.size()`. Empty for the default route.
  std::vector<int> prefix;
  int nexthop;
};

struct SwitchPipeline {
  // Stage 1: assigns a `vrf` based on the `in_port`.
  PolicyProto vrf_assignment;
  // Stage 2: longest prefix match of the destination address in the `vrf`,
  // setting a `nexthop`. Encoded as a prioritized table of the `routes`.
  PolicyProto routing;
  std::vector<Ipv4Route> routes;  // In order of decreasing priority.
  // Stage 3: resolves the `nexthop` to an output `port` and `dst_mac`.
  PolicyProto nexthop_resolution;
  // Stage 4: an ACL.
  PolicyProto acl;
  std::vector<AclRule> acl_rules;  // In order of decreasing priority.

  // Returns the sequential composition of all stages.
  PolicyProto Policy() const;
};

inline constexpr int kSwitchPipelineNumPorts = 32;
inline constexpr int kSwitchPipelineNumVrfs = 4;

// Returns a switch pipeline with `num_routes` random routes (plus a default
// route per VRF), with a realistic distribution of prefix lengths, and an ACL
// with `num_routes / 8` rules.
SwitchPipeline SaiStyleSwitchPipeline(int num_routes, uint64_t seed = 1);

// -- NAT gateways -------------------------------------------------------------

// A NAT gateway in front of a data center, combining a load balancer and a
// source NAT. Established translations are modeled as tables of exact-match
// entries, as in the NAT tables of hardware switches.
struct NatGateway {
  // Forwards packets destined to a virtual IP and service port (`dst_ip`,
  // `dst_port`) to any of the VIP's backends (nondeterministically, modeling
  // ECMP) by rewriting `dst_ip` and `dst_port`. Other packets pass unmodified.
  PolicyProto load_balancing;
  // Rewrites the (`src_ip`, `src_port`) of established internal flows to
  // (`kNatPublicIp`, the public port allocated to the flow). Other packets
  // pass unmodified.
  PolicyProto source_nat;
  // The inverse of `source_nat`: rewrites (`kNatPublicIp`, allocated port)
  // back to the (`src_ip`, `src_port`) of the internal flow. Other packets
  // pass unmodified.
  PolicyProto inverse_source_nat;
  // Matches the (`src_ip`, `src_port`) of established internal flows.
  PredicateProto internal_flows;

  // Returns `load_balancing; source_nat`.
  PolicyProto Policy() const;
};

inline constexpr int kNatPublicIp = 1;

// Returns a NAT gateway with `num_flows` established flows from random
// internal hosts and ephemeral ports, each allocated a distinct public port,
// and `num_flows / 64` (at least 4) VIPs with 4 to 8 backends each.
NatGateway NatGatewayWithFlows(int num_flows, uint64_t seed = 1);

// -- Equivalence queries ------------------------------------------------------

// A pair of policies to check for equivalence.
struct EquivalenceQuery {
  PolicyProto left;
  PolicyProto right;
};

// Returns policies that are equivalent iff the multi-tenant fat tree with the
// given `options` (requires `options.num_tenants > 0`) treats traffic between
// hosts of `tenant` like the fat tree without tenants, except for tagging the
// traffic with the tenant's `vlan`. That is, for T the locations of the
// tenant's hosts:
//
//   T; end_to_end(sliced); T  ==  T; end_to_end(unsliced); T; vlan:=tenant
EquivalenceQuery FatTreeSliceEquivalence(const FatTreeOptions& options,
                                         int tenant);

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_BENCHMARK_NETWORKS_H_
