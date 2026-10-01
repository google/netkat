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

#include "netkat/field_order.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "netkat/netkat.pb.h"
#include "netkat/netkat_proto_constructors.h"

namespace netkat {
namespace {

using ::testing::ElementsAre;
using ::testing::IsEmpty;

// Returns `sw=s; (dst=0; port:=s + dst=1; port:=s+1)`.
PolicyProto SwitchTable(int s) {
  return SequenceProto(
      FilterProto(MatchProto("sw", s)),
      UnionProto(SequenceProto(FilterProto(MatchProto("dst", 0)),
                               ModificationProto("port", s)),
                 SequenceProto(FilterProto(MatchProto("dst", 1)),
                               ModificationProto("port", s + 1))));
}

TEST(FieldsInOrderOfAppearanceTest, EmptyForNoFields) {
  EXPECT_THAT(FieldsInOrderOfAppearance({AcceptProto()}, {TrueProto()}),
              IsEmpty());
}

TEST(FieldsInOrderOfAppearanceTest, ListsFieldsOnceInPreOrder) {
  PolicyProto policy = SequenceProto(
      ModificationProto("c", 1),
      UnionProto(FilterProto(AndProto(MatchProto("a", 1), MatchProto("c", 2))),
                 ModificationProto("b", 1)));
  EXPECT_THAT(FieldsInOrderOfAppearance({policy}, {MatchProto("d", 1)}),
              ElementsAre("c", "a", "b", "d"));
}

TEST(FieldsInOrderOfAppearanceTest, IncludesFieldsOfPullPolicies) {
  PredicateProto pull =
      PullProto(ModificationProto("a", 1), MatchProto("b", 2));
  EXPECT_THAT(FieldsInOrderOfAppearance({}, {pull}), ElementsAre("a", "b"));
}

TEST(HeuristicFieldOrderTest, PutsDispatchingFieldFirst) {
  // `sw` guards entire tables, `dst` only single modifications.
  PolicyProto tables = UnionProto(SwitchTable(0), SwitchTable(1));
  EXPECT_THAT(HeuristicFieldOrder({tables}), ElementsAre("sw", "dst", "port"));
}

TEST(HeuristicFieldOrderTest, OrdersModifiedFieldsByTimeOfModification) {
  // `m` is modified before `b` is tested, and `x` is modified last.
  PolicyProto policy = SequenceProto(
      SequenceProto(FilterProto(MatchProto("a", 1)), ModificationProto("m", 1)),
      SequenceProto(FilterProto(MatchProto("b", 1)),
                    ModificationProto("x", 1)));
  EXPECT_THAT(HeuristicFieldOrder({policy}), ElementsAre("a", "m", "b", "x"));
}

TEST(HeuristicFieldOrderTest, PutsUntestedFieldsAfterTestedFieldsOfSameTime) {
  PolicyProto policy = UnionProto(ModificationProto("a", 1),
                                  SequenceProto(FilterProto(MatchProto("b", 1)),
                                                ModificationProto("c", 1)));
  EXPECT_THAT(HeuristicFieldOrder({policy}), ElementsAre("b", "a", "c"));
}

TEST(HeuristicFieldOrderTest, OrdersFieldsByDataFlow) {
  // `in_port` determines the `vrf`, which the routing stage tests. Although
  // the routing stage tests `vrf` and `dst` far more, `in_port` comes first.
  PolicyProto vrf_assignment =
      UnionProto(SequenceProto(FilterProto(MatchProto("in_port", 1)),
                               ModificationProto("vrf", 1)),
                 SequenceProto(FilterProto(MatchProto("in_port", 2)),
                               ModificationProto("vrf", 2)));
  PolicyProto routing = DenyProto();
  for (int i = 0; i < 10; ++i) {
    routing = UnionProto(
        SequenceProto(FilterProto(AndProto(MatchProto("vrf", i % 2 + 1),
                                           MatchProto("dst", i))),
                      ModificationProto("port", i)),
        routing);
  }
  PolicyProto egress = SequenceProto(FilterProto(MatchProto("port", 1)),
                                     ModificationProto("mac", 1));
  EXPECT_THAT(HeuristicFieldOrder({SequenceProto(
                  SequenceProto(vrf_assignment, routing), egress)}),
              ElementsAre("in_port", "vrf", "dst", "port", "mac"));
}

TEST(HeuristicFieldOrderTest, IgnoresGuardsThatAreNotAlternatives) {
  // `ingress` restricts the tables, but does not dispatch between them.
  PredicateProto ingress =
      OrProto(MatchProto("port", 1), MatchProto("port", 2));
  PolicyProto query = SequenceProto(FilterProto(ingress),
                                    UnionProto(SwitchTable(0), SwitchTable(1)));
  EXPECT_THAT(HeuristicFieldOrder({query}), ElementsAre("sw", "dst", "port"));
}

TEST(HeuristicFieldOrderTest, IgnoresNegatedGuards) {
  // As in a prioritized table: `a=1; x:=1 + !(a=1); (b=1; x:=2 + b=2; x:=3)`.
  // The negated test of `a` guards the larger policy, but does not dispatch.
  PolicyProto rest = UnionProto(
      SequenceProto(FilterProto(MatchProto("b", 1)), ModificationProto("x", 2)),
      SequenceProto(FilterProto(MatchProto("b", 2)),
                    ModificationProto("x", 3)));
  PolicyProto table = UnionProto(
      SequenceProto(FilterProto(MatchProto("a", 1)), ModificationProto("x", 1)),
      SequenceProto(FilterProto(NotProto(MatchProto("a", 1))), rest));
  EXPECT_THAT(HeuristicFieldOrder({table}), ElementsAre("b", "a", "x"));
}

TEST(HeuristicFieldOrderTest, IsInvariantUnderSequenceAssociativity) {
  PolicyProto p = FilterProto(MatchProto("a", 1));
  PolicyProto q =
      SequenceProto(FilterProto(MatchProto("b", 1)), ModificationProto("c", 1));
  PolicyProto r =
      SequenceProto(FilterProto(MatchProto("b", 2)), ModificationProto("c", 2));
  PolicyProto d = ModificationProto("d", 1);
  PolicyProto left = UnionProto(SequenceProto(SequenceProto(p, q), r), d);
  PolicyProto right = UnionProto(SequenceProto(p, SequenceProto(q, r)), d);
  EXPECT_EQ(HeuristicFieldOrder({left}), HeuristicFieldOrder({right}));
  EXPECT_THAT(HeuristicFieldOrder({left}), ElementsAre("a", "b", "c", "d"));
}

TEST(HeuristicFieldOrderTest, IsInvariantUnderUnionCommutativity) {
  PolicyProto p = SequenceProto(
      FilterProto(MatchProto("a", 1)),
      SequenceProto(ModificationProto("c", 1), ModificationProto("d", 1)));
  PolicyProto q =
      SequenceProto(FilterProto(MatchProto("b", 1)), ModificationProto("c", 2));
  EXPECT_EQ(HeuristicFieldOrder({UnionProto(p, q)}),
            HeuristicFieldOrder({UnionProto(q, p)}));
}

TEST(HeuristicFieldOrderTest, HandlesDeeplyNestedPolicies) {
  PolicyProto policy = AcceptProto();
  for (int i = 0; i < 5000; ++i) {
    policy = UnionProto(SequenceProto(FilterProto(MatchProto("a", i)),
                                      ModificationProto("b", i)),
                        std::move(policy));
  }
  EXPECT_THAT(HeuristicFieldOrder({policy}), ElementsAre("a", "b"));
  EXPECT_THAT(FieldsInOrderOfAppearance({policy}), ElementsAre("a", "b"));
}

}  // namespace
}  // namespace netkat
