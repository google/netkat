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

#include "netkat/analysis_engine.h"

#include "gtest/gtest.h"
#include "netkat/frontend.h"

namespace netkat {
namespace {

// We include only a single `CheckEquivalent` test as a smoke test since the
// function is implemented in terms of `SymbolicPacketManager`, which is tested
// thoroughly in its own unit tests.
TEST(AnalysisEngineTest, CheckEquivalentSmokeTests) {
  AnalysisEngine analyzer;

  // Check that true and false are equivalent to themselves but not each other.
  EXPECT_TRUE(analyzer.CheckEquivalent(Predicate::True(), Predicate::True()));
  EXPECT_TRUE(analyzer.CheckEquivalent(Predicate::False(), Predicate::False()));
  EXPECT_FALSE(analyzer.CheckEquivalent(Predicate::True(), Predicate::False()));
  EXPECT_FALSE(analyzer.CheckEquivalent(Predicate::False(), Predicate::True()));

  // Check that some simple predicates are equivalent to themselves but not each
  // other.
  const Predicate p1 = Match("port", 1) && Match("vlan", 10);
  const Predicate p2 = Match("port", 2);
  EXPECT_TRUE(analyzer.CheckEquivalent(p1, p1));
  EXPECT_TRUE(analyzer.CheckEquivalent(p2, p2));
  EXPECT_FALSE(analyzer.CheckEquivalent(p1, p2));
  EXPECT_FALSE(analyzer.CheckEquivalent(p2, p1));

  // Check some properties of negations.
  EXPECT_TRUE(analyzer.CheckEquivalent(!Predicate::True(), Predicate::False()));
  EXPECT_TRUE(analyzer.CheckEquivalent(!Predicate::False(), Predicate::True()));
  EXPECT_TRUE(analyzer.CheckEquivalent(!!p1, p1));

  // Check De Morgan's laws.
  EXPECT_TRUE(analyzer.CheckEquivalent(!(p1 && p2), !p1 || !p2));
  EXPECT_TRUE(analyzer.CheckEquivalent(!(p1 || p2), !p1 && !p2));
}

TEST(AnalysisEngineTest, CheckPolicyEquivalentSmokeTests) {
  AnalysisEngine analyzer;
  // Checks Deny and Accept are equivalent to themselves but not each other.
  EXPECT_TRUE(analyzer.CheckEquivalent(Policy::Deny(), Policy::Deny()));
  EXPECT_TRUE(analyzer.CheckEquivalent(Policy::Accept(), Policy::Accept()));
  EXPECT_FALSE(analyzer.CheckEquivalent(Policy::Accept(), Policy::Deny()));
  EXPECT_FALSE(analyzer.CheckEquivalent(Policy::Deny(), Policy::Accept()));

  // Checks different policies are equivalent to themselves but are not
  // equivalent to each other.
  const Policy p1 = Sequence(Filter(Match("port", 10)), Modify("port", 20));
  const Policy p2 = Sequence(Filter(Match("switch", 42)), Modify("port", 21));
  EXPECT_TRUE(analyzer.CheckEquivalent(p1, p1));
  EXPECT_TRUE(analyzer.CheckEquivalent(p2, p2));
  EXPECT_FALSE(analyzer.CheckEquivalent(p1, p2));
  EXPECT_FALSE(analyzer.CheckEquivalent(p2, p1));

  // Checks Union of Policies are commutative.
  EXPECT_TRUE(analyzer.CheckEquivalent(Union(p1, p2), Union(p2, p1)));

  // Check Union of Policies are associative.
  const Policy p3 = Filter(Match("dst_mac", 30));
  EXPECT_TRUE(analyzer.CheckEquivalent(Union(p1, Union(p2, p3)),
                                       Union(Union(p1, p2), p3)));

  // Some Sequence of Policies are not commutative: modifying the same field
  // with different values in different order would result in different
  // policies.
  const Policy modify_port_1 = Modify("port", 10);
  const Policy modify_port_2 = Modify("port", 20);
  EXPECT_FALSE(
      analyzer.CheckEquivalent(Sequence(modify_port_1, modify_port_2),
                               Sequence(modify_port_2, modify_port_1)));

  // Sequence(p1, p2) can be equivalent to Sequence(p2, p1) depending
  // on what's p1 and p2: e.g., modifying different fields in different order
  // would result in equivalent policies.
  // This is the PA-MOD-MOD-COMM axiom in the NetKAT paper.
  const Policy modify_dst_mac = Modify("dst_mac", 1);
  EXPECT_TRUE(
      analyzer.CheckEquivalent(Sequence(modify_dst_mac, modify_port_1),
                               Sequence(modify_port_1, modify_dst_mac)));
}

// A netkat::Policy representing the given topology
// [Switch 1] -----> [Switch 2] -----> [Switch 3]
// - Packets start from Switch 1 are forwarded to Switch 2 and then to Switch 3.
// - Packets start from Switch 2 are also forwarded to Switch 3.
// - Packets start from non-existing switch are denied.
TEST(AnalysisEngineTest, TopologyTraversalIsAccepted) {
  Policy s1_to_s2 = Sequence(Filter(Match("switch", 1)), Modify("switch", 2));
  Policy s2_to_s3 = Sequence(Filter(Match("switch", 2)), Modify("switch", 3));
  Policy topology = Union(s1_to_s2, s2_to_s3);
  AnalysisEngine analyzer;

  Policy traverse_topo_from_s1 = Sequence(
      Modify("switch", 1), Iterate(topology), Filter(Match("switch", 3)));
  EXPECT_TRUE(
      analyzer.CheckEquivalent(traverse_topo_from_s1, Modify("switch", 3)));

  Policy traverse_topo_from_s2 = Sequence(
      Modify("switch", 2), Iterate(topology), Filter(Match("switch", 3)));
  EXPECT_TRUE(
      analyzer.CheckEquivalent(traverse_topo_from_s2, Modify("switch", 3)));

  Policy traverse_from_non_existing_switch = Sequence(
      Modify("switch", 42), Iterate(topology), Filter(Match("switch", 3)));
  EXPECT_TRUE(analyzer.CheckEquivalent(traverse_from_non_existing_switch,
                                       Policy::Deny()));
}

}  // namespace
}  // namespace netkat
