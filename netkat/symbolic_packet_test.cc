// Copyright 2024 The NetKAT authors
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
// -----------------------------------------------------------------------------

#include "netkat/symbolic_packet.h"

#include <cstdint>
#include <ostream>
#include <utility>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "fuzztest/fuzztest.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/status_matchers.h"  // IWYU pragma: keep
#include "netkat/evaluator.h"
#include "netkat/netkat_proto_constructors.h"
#include "re2/re2.h"

namespace netkat {

// We use a global manager object to exercise statefulness more deeply across
// test cases. This also enables better pretty printing for debugging, see
// `PrintTo`.
SymbolicPacketManager& Manager() {
  static absl::NoDestructor<SymbolicPacketManager> manager;
  return *manager;
}

// The default `SymbolicPacket` pretty printer sucks! It does not have access to
// the graph structure representing the packet, since that is stored in the
// manager object. Thus, it returns opaque strings like "SymbolicPacket<123>".
//
// We define this much better override, which GoogleTest gives precedence to.
void PrintTo(const SymbolicPacket& packet, std::ostream* os) {
  *os << Manager().ToString(packet);
}

namespace {

using ::testing::Ge;
using ::testing::Pair;
using ::testing::SizeIs;
using ::testing::StartsWith;
using ::testing::UnorderedElementsAre;

// After executing all tests, we check once that no invariants are violated, for
// defense in depth. Checking invariants after each test (e.g. using a fixture)
// would likely not scale and seems overkill.
class CheckSymbolicPacketManagerInvariantsOnTearDown
    : public testing::Environment {
 public:
  ~CheckSymbolicPacketManagerInvariantsOnTearDown() override = default;
  void SetUp() override {}
  void TearDown() override { ASSERT_OK(Manager().CheckInternalInvariants()); }
};
testing::Environment* const foo_env = testing::AddGlobalTestEnvironment(
    new CheckSymbolicPacketManagerInvariantsOnTearDown);

TEST(SymbolicPacketManagerTest, EmptySetIsEmptySet) {
  EXPECT_TRUE(Manager().IsEmptySet(Manager().EmptySet()));
  EXPECT_FALSE(Manager().IsFullSet(Manager().EmptySet()));
}

TEST(SymbolicPacketManagerTest, FullSetIsFullSet) {
  EXPECT_TRUE(Manager().IsFullSet(Manager().FullSet()));
  EXPECT_FALSE(Manager().IsEmptySet(Manager().FullSet()));
}

TEST(SymbolicPacketManagerTest, EmptySetDoesNotEqualFullSet) {
  EXPECT_NE(Manager().EmptySet(), Manager().FullSet());
}

TEST(SymbolicPacketManagerTest, AbslStringifyWorksForEmptySet) {
  EXPECT_THAT(absl::StrCat(Manager().EmptySet()), StartsWith("SymbolicPacket"));
}

TEST(SymbolicPacketManagerTest, AbslStringifyWorksForFullSet) {
  EXPECT_THAT(absl::StrCat(Manager().FullSet()), StartsWith("SymbolicPacket"));
}

TEST(SymbolicPacketManagerTest, AbslHashValueWorks) {
  absl::flat_hash_set<SymbolicPacket> set = {
      Manager().EmptySet(),
      Manager().FullSet(),
  };
  EXPECT_EQ(set.size(), 2);
}

TEST(SymbolicPacketManagerTest, TrueCompilesToFullSet) {
  EXPECT_EQ(Manager().Compile(TrueProto()), Manager().FullSet());
}

TEST(SymbolicPacketManagerTest, FalseCompilesToEmptySet) {
  EXPECT_EQ(Manager().Compile(FalseProto()), Manager().EmptySet());
}

// TODO(b/404543304): Remove once golden tests are implemented.
// From Katch paper Fig 3.
TEST(SymbolicPacketManagerTest, SymbolicPacketToDotStringIsCorrect) {
  // p := (a=3 && b=4) || (b!=5 && c=5)
  SymbolicPacket symbolic_packet = Manager().Compile(
      OrProto(AndProto(MatchProto("a", 3), MatchProto("b", 4)),
              AndProto(NotProto(MatchProto("b", 5)), MatchProto("c", 5))));
  std::string dot_string = Manager().ToDot(symbolic_packet);

  absl::flat_hash_set<std::pair<std::string, uint32_t>> labels_to_nodes;
  absl::flat_hash_set<std::pair<uint64_t, uint64_t>> nodes_to_nodes;
  for (const absl::string_view line : absl::StrSplit(dot_string, '\n')) {
    std::string label;
    uint32_t node;
    if (RE2::PartialMatch(line, R"((\d+) \[label=\"([a-zA-Z]+)\")", &node,
                          &label)) {
      labels_to_nodes.insert({label, node});
    }
    uint32_t from, to;
    if (RE2::PartialMatch(line, R"((\d+) -> (\d+))", &from, &to)) {
      nodes_to_nodes.insert({from, to});
    }
  }
  EXPECT_THAT(labels_to_nodes,
              UnorderedElementsAre(Pair("a", 14), Pair("b", 13), Pair("b", 6),
                                   Pair("c", 5), Pair("F", 4294967295),
                                   Pair("T", 4294967294)));

  EXPECT_THAT(nodes_to_nodes,
              UnorderedElementsAre(Pair(14, 13), Pair(14, 6),
                                   Pair(13, 4294967294), Pair(13, 4294967295),
                                   Pair(13, 5), Pair(6, 4294967295), Pair(6, 5),
                                   Pair(5, 4294967294), Pair(5, 4294967295)));
}

void MatchCompilesToMatch(std::string field, int value) {
  EXPECT_EQ(Manager().Compile(MatchProto(field, value)),
            Manager().Match(field, value));
}
FUZZ_TEST(SymbolicPacketManagerTest, MatchCompilesToMatch);

void AndCompilesToAnd(const PredicateProto& left, const PredicateProto& right) {
  EXPECT_EQ(Manager().Compile(AndProto(left, right)),
            Manager().And(Manager().Compile(left), Manager().Compile(right)));
}
FUZZ_TEST(SymbolicPacketManagerTest, AndCompilesToAnd);

void OrCompilesToOr(const PredicateProto& left, const PredicateProto& right) {
  EXPECT_EQ(Manager().Compile(OrProto(left, right)),
            Manager().Or(Manager().Compile(left), Manager().Compile(right)));
}
FUZZ_TEST(SymbolicPacketManagerTest, OrCompilesToOr);

void NotCompilesToNot(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(NotProto(pred)),
            Manager().Not(Manager().Compile(pred)));
}
FUZZ_TEST(SymbolicPacketManagerTest, NotCompilesToNot);

void CompilationPreservesSemantics(const PredicateProto& pred,
                                   const Packet& packet) {
  EXPECT_EQ(Manager().Contains(Manager().Compile(pred), packet),
            Evaluate(pred, packet));
}
FUZZ_TEST(SymbolicPacketManagerTest, CompilationPreservesSemantics);

void GetConcretePacketsReturnsNonEmptyListForNonEmptySet(
    const PredicateProto& pred) {
  SymbolicPacket symbolic_packet = Manager().Compile(pred);
  if (!Manager().IsEmptySet(symbolic_packet)) {
    EXPECT_THAT(Manager().GetConcretePackets(symbolic_packet), SizeIs(Ge(1)));
  }
}
FUZZ_TEST(SymbolicPacketManagerTest,
          GetConcretePacketsReturnsNonEmptyListForNonEmptySet);

void GetConcretePacketsReturnsPacketsInSet(const PredicateProto& pred) {
  SymbolicPacket symbolic_packet = Manager().Compile(pred);
  for (const Packet& concrete_packet :
       Manager().GetConcretePackets(symbolic_packet)) {
    EXPECT_TRUE(Manager().Contains(symbolic_packet, concrete_packet));
  }
}
FUZZ_TEST(SymbolicPacketManagerTest, GetConcretePacketsReturnsPacketsInSet);

TEST(SymbolicPacketManagerTest,
     PacketsFromPacketSetWithMultipleFieldsAreContainedInPacketSet) {
  // p = (a=3 && b=4) || (b!=5 && c=5)
  SymbolicPacket symbolic_packet = Manager().Compile(
      OrProto(AndProto(MatchProto("a", 3), MatchProto("b", 4)),
              AndProto(NotProto(MatchProto("b", 5)), MatchProto("c", 5))));
  std::vector<Packet> concrete_packets =
      Manager().GetConcretePackets(symbolic_packet);
  for (const Packet& concrete_packet : concrete_packets) {
    EXPECT_TRUE(Manager().Contains(symbolic_packet, concrete_packet));
  }
}

void EqualPredicatesCompileToEqualSymbolicPackets(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(pred), Manager().Compile(pred));
}
FUZZ_TEST(SymbolicPacketManagerTest,
          EqualPredicatesCompileToEqualSymbolicPackets);

void NegationCompilesToDifferentSymbolicPacket(const PredicateProto& pred) {
  EXPECT_NE(Manager().Compile(pred), Manager().Compile(NotProto(pred)));
}
FUZZ_TEST(SymbolicPacketManagerTest, NegationCompilesToDifferentSymbolicPacket);

void DoubleNegationCompilesToSameSymbolicPacket(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(pred),
            Manager().Compile(NotProto(NotProto(pred))));
}
FUZZ_TEST(SymbolicPacketManagerTest,
          DoubleNegationCompilesToSameSymbolicPacket);

TEST(SymbolicPacketManagerTest, TrueNotEqualsMatch) {
  EXPECT_NE(Manager().Compile(TrueProto()),
            Manager().Compile(MatchProto("hi", 42)));
}
TEST(SymbolicPacketManagerTest, FalseNotEqualsMatch) {
  EXPECT_NE(Manager().Compile(FalseProto()),
            Manager().Compile(MatchProto("hi", 42)));
}
TEST(SymbolicPacketManagerTest, MatchNotEqualsDifferentMatch) {
  EXPECT_NE(Manager().Compile(MatchProto("hi", 42)),
            Manager().Compile(MatchProto("bye", 42)));
  EXPECT_NE(Manager().Compile(MatchProto("hi", 42)),
            Manager().Compile(MatchProto("hi", 24)));
}
TEST(SymbolicPacketManagerTest, NotTrueEqualsFalse) {
  EXPECT_EQ(Manager().Compile(NotProto(TrueProto())),
            Manager().Compile(FalseProto()));
}

void AndIsIdempotent(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(AndProto(pred, pred)), Manager().Compile(pred));
}
FUZZ_TEST(SymbolicPacketManagerTest, AndIsIdempotent);

void OrIsIdempotent(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(OrProto(pred, pred)), Manager().Compile(pred));
}
FUZZ_TEST(SymbolicPacketManagerTest, OrIsIdempotent);

void PredOrItsNegationIsTrue(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(OrProto(pred, NotProto(pred))),
            Manager().Compile(TrueProto()));
}
FUZZ_TEST(SymbolicPacketManagerTest, PredOrItsNegationIsTrue);

void PredAndItsNegationIsFalse(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(AndProto(pred, NotProto(pred))),
            Manager().Compile(FalseProto()));
}
FUZZ_TEST(SymbolicPacketManagerTest, PredAndItsNegationIsFalse);

void AndTrueIsIdentity(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(AndProto(pred, TrueProto())),
            Manager().Compile(pred));
}
FUZZ_TEST(SymbolicPacketManagerTest, AndTrueIsIdentity);

void OrFalseIsIdentity(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(OrProto(pred, FalseProto())),
            Manager().Compile(pred));
}
FUZZ_TEST(SymbolicPacketManagerTest, OrFalseIsIdentity);

void XorFalseIsIdentity(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(XorProto(pred, FalseProto())),
            Manager().Compile(pred));
}
FUZZ_TEST(SymbolicPacketManagerTest, XorFalseIsIdentity);

void AndFalseIsFalse(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(AndProto(pred, FalseProto())),
            Manager().Compile(FalseProto()));
}
FUZZ_TEST(SymbolicPacketManagerTest, AndFalseIsFalse);

void OrTrueIsTrue(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(OrProto(pred, TrueProto())),
            Manager().Compile(TrueProto()));
}
FUZZ_TEST(SymbolicPacketManagerTest, OrTrueIsTrue);

void XorSelfIsFalse(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(XorProto(pred, pred)),
            Manager().Compile(FalseProto()));
}
FUZZ_TEST(SymbolicPacketManagerTest, XorSelfIsFalse);

void AndIsCommutative(const PredicateProto& a, const PredicateProto& b) {
  EXPECT_EQ(Manager().Compile(AndProto(a, b)),
            Manager().Compile(AndProto(b, a)));
}
FUZZ_TEST(SymbolicPacketManagerTest, AndIsCommutative);

void OrIsCommutative(const PredicateProto& a, const PredicateProto& b) {
  EXPECT_EQ(Manager().Compile(OrProto(a, b)), Manager().Compile(OrProto(b, a)));
}
FUZZ_TEST(SymbolicPacketManagerTest, OrIsCommutative);

void XorIsCommutative(const PredicateProto& a, const PredicateProto& b) {
  EXPECT_EQ(Manager().Compile(XorProto(a, b)),
            Manager().Compile(XorProto(b, a)));
}
FUZZ_TEST(SymbolicPacketManagerTest, XorIsCommutative);

void DistributiveLawsHolds(const PredicateProto& a, const PredicateProto& b,
                           const PredicateProto& c) {
  EXPECT_EQ(Manager().Compile(AndProto(a, OrProto(b, c))),
            Manager().Compile(OrProto(AndProto(a, b), AndProto(a, c))));
  EXPECT_EQ(Manager().Compile(OrProto(a, AndProto(b, c))),
            Manager().Compile(AndProto(OrProto(a, b), OrProto(a, c))));
}
FUZZ_TEST(SymbolicPacketManagerTest, DistributiveLawsHolds);

void DeMorgansLawsHolds(const PredicateProto& a, const PredicateProto& b) {
  EXPECT_EQ(Manager().Compile(NotProto(AndProto(a, b))),
            Manager().Compile(OrProto(NotProto(a), NotProto(b))));
  EXPECT_EQ(Manager().Compile(NotProto(OrProto(a, b))),
            Manager().Compile(AndProto(NotProto(a), NotProto(b))));
}
FUZZ_TEST(SymbolicPacketManagerTest, DeMorgansLawsHolds);

void XorDefinition(const PredicateProto& a, const PredicateProto& b) {
  EXPECT_EQ(Manager().Compile(XorProto(a, b)),
            Manager().Compile(
                OrProto(AndProto(NotProto(a), b), AndProto(a, NotProto(b)))));
}
FUZZ_TEST(SymbolicPacketManagerTest, XorDefinition);

void AndIsAssociative(const PredicateProto& a, const PredicateProto& b,
                      const PredicateProto& c) {
  EXPECT_EQ(Manager().Compile(AndProto(a, AndProto(b, c))),
            Manager().Compile(AndProto(AndProto(a, b), c)));
}
FUZZ_TEST(SymbolicPacketManagerTest, AndIsAssociative);

void OrIsAssociative(const PredicateProto& a, const PredicateProto& b,
                     const PredicateProto& c) {
  EXPECT_EQ(Manager().Compile(OrProto(a, OrProto(b, c))),
            Manager().Compile(OrProto(OrProto(a, b), c)));
}
FUZZ_TEST(SymbolicPacketManagerTest, OrIsAssociative);

void XorIsAssociative(const PredicateProto& a, const PredicateProto& b,
                      const PredicateProto& c) {
  EXPECT_EQ(Manager().Compile(XorProto(a, XorProto(b, c))),
            Manager().Compile(XorProto(XorProto(a, b), c)));
}
FUZZ_TEST(SymbolicPacketManagerTest, XorIsAssociative);

}  // namespace
}  // namespace netkat
