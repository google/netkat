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

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "fuzztest/fuzztest.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/status_matchers.h"
#include "netkat/evaluator.h"
#include "netkat/netkat_proto_constructors.h"

namespace netkat {
namespace {

using ::testing::StartsWith;

// We use a global manager object to exercise statefulness more deeply across
// test cases.
SymbolicPacketManager& Manager() {
  static absl::NoDestructor<SymbolicPacketManager> manager;
  return *manager;
}

// After executing all tests, we check once that no invariants are violated, for
// defense in depth. Checking invariants after each test (e.g. using a fixture)
// would likely not scale and seems overkill.
class CheckSymbolicPacketManagerInvariantsOnTearDown
    : public testing::Environment {
 public:
  ~CheckSymbolicPacketManagerInvariantsOnTearDown() override {}
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

void AndIsCommutative(const PredicateProto& a, const PredicateProto& b) {
  EXPECT_EQ(Manager().Compile(AndProto(a, b)),
            Manager().Compile(AndProto(b, a)));
}
FUZZ_TEST(SymbolicPacketManagerTest, AndIsCommutative);

void OrIsCommutative(const PredicateProto& a, const PredicateProto& b) {
  EXPECT_EQ(Manager().Compile(OrProto(a, b)), Manager().Compile(OrProto(b, a)));
}
FUZZ_TEST(SymbolicPacketManagerTest, OrIsCommutative);

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

}  // namespace
}  // namespace netkat
