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

#include "netkat/packet_set.h"

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
PacketSetManager& Manager() {
  static absl::NoDestructor<PacketSetManager> manager;
  return *manager;
}

// The default `PacketSetHandle` pretty printer sucks! It does not have access
// to the graph structure representing the packet, since that is stored in the
// manager object. Thus, it returns opaque strings like "PacketSetHandle<123>".
//
// We define this much better override, which GoogleTest gives precedence to.
void PrintTo(PacketSetHandle packet, std::ostream* os) {
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
class CheckPacketSetManagerInvariantsOnTearDown : public testing::Environment {
 public:
  ~CheckPacketSetManagerInvariantsOnTearDown() override = default;
  void SetUp() override {}
  void TearDown() override { ASSERT_OK(Manager().CheckInternalInvariants()); }
};
testing::Environment* const foo_env = testing::AddGlobalTestEnvironment(
    new CheckPacketSetManagerInvariantsOnTearDown);

TEST(PacketSetManagerTest, EmptySetIsEmptySet) {
  EXPECT_TRUE(Manager().IsEmptySet(Manager().EmptySet()));
  EXPECT_FALSE(Manager().IsFullSet(Manager().EmptySet()));
}

TEST(PacketSetManagerTest, FullSetIsFullSet) {
  EXPECT_TRUE(Manager().IsFullSet(Manager().FullSet()));
  EXPECT_FALSE(Manager().IsEmptySet(Manager().FullSet()));
}

TEST(PacketSetManagerTest, EmptySetDoesNotEqualFullSet) {
  EXPECT_NE(Manager().EmptySet(), Manager().FullSet());
}

TEST(PacketSetManagerTest, AbslStringifyWorksForEmptySet) {
  EXPECT_THAT(absl::StrCat(Manager().EmptySet()),
              StartsWith("PacketSetHandle"));
}

TEST(PacketSetManagerTest, AbslStringifyWorksForFullSet) {
  EXPECT_THAT(absl::StrCat(Manager().FullSet()), StartsWith("PacketSetHandle"));
}

TEST(PacketSetManagerTest, AbslHashValueWorks) {
  absl::flat_hash_set<PacketSetHandle> set = {
      Manager().EmptySet(),
      Manager().FullSet(),
  };
  EXPECT_EQ(set.size(), 2);
}

TEST(PacketSetManagerTest, TrueCompilesToFullSet) {
  EXPECT_EQ(Manager().Compile(TrueProto()), Manager().FullSet());
}

TEST(PacketSetManagerTest, FalseCompilesToEmptySet) {
  EXPECT_EQ(Manager().Compile(FalseProto()), Manager().EmptySet());
}

void MatchCompilesToMatch(std::string field, int value) {
  EXPECT_EQ(Manager().Compile(MatchProto(field, value)),
            Manager().Match(field, value));
}
FUZZ_TEST(PacketSetManagerTest, MatchCompilesToMatch);

void AndCompilesToAnd(const PredicateProto& left, const PredicateProto& right) {
  EXPECT_EQ(Manager().Compile(AndProto(left, right)),
            Manager().And(Manager().Compile(left), Manager().Compile(right)));
}
FUZZ_TEST(PacketSetManagerTest, AndCompilesToAnd);

void OrCompilesToOr(const PredicateProto& left, const PredicateProto& right) {
  EXPECT_EQ(Manager().Compile(OrProto(left, right)),
            Manager().Or(Manager().Compile(left), Manager().Compile(right)));
}
FUZZ_TEST(PacketSetManagerTest, OrCompilesToOr);

void NotCompilesToNot(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(NotProto(pred)),
            Manager().Not(Manager().Compile(pred)));
}
FUZZ_TEST(PacketSetManagerTest, NotCompilesToNot);

void CompilationPreservesSemantics(const PredicateProto& pred,
                                   const Packet& packet) {
  EXPECT_EQ(Manager().Contains(Manager().Compile(pred), packet),
            Evaluate(pred, packet));
}
FUZZ_TEST(PacketSetManagerTest, CompilationPreservesSemantics);

void GetConcretePacketsReturnsNonEmptyListForNonEmptySet(
    const PredicateProto& pred) {
  PacketSetHandle packet_set = Manager().Compile(pred);
  if (!Manager().IsEmptySet(packet_set)) {
    EXPECT_THAT(Manager().GetConcretePackets(packet_set), SizeIs(Ge(1)));
  }
}
FUZZ_TEST(PacketSetManagerTest,
          GetConcretePacketsReturnsNonEmptyListForNonEmptySet);

void GetConcretePacketsReturnsPacketsInSet(const PredicateProto& pred) {
  PacketSetHandle packet_set = Manager().Compile(pred);
  for (const Packet& packet : Manager().GetConcretePackets(packet_set)) {
    EXPECT_TRUE(Manager().Contains(packet_set, packet));
  }
}
FUZZ_TEST(PacketSetManagerTest, GetConcretePacketsReturnsPacketsInSet);

TEST(PacketSetManagerTest,
     PacketsFromPacketSetWithMultipleFieldsAreContainedInPacketSet) {
  // p = (a=3 && b=4) || (b!=5 && c=5)
  PacketSetHandle packet_set = Manager().Compile(
      OrProto(AndProto(MatchProto("a", 3), MatchProto("b", 4)),
              AndProto(NotProto(MatchProto("b", 5)), MatchProto("c", 5))));
  std::vector<Packet> packets = Manager().GetConcretePackets(packet_set);
  for (const Packet& packet : packets) {
    EXPECT_TRUE(Manager().Contains(packet_set, packet));
  }
}

void EqualPredicatesCompileToEqualPacketSetHandles(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(pred), Manager().Compile(pred));
}
FUZZ_TEST(PacketSetManagerTest, EqualPredicatesCompileToEqualPacketSetHandles);

void NegationCompilesToDifferentPacketSetHandle(const PredicateProto& pred) {
  EXPECT_NE(Manager().Compile(pred), Manager().Compile(NotProto(pred)));
}
FUZZ_TEST(PacketSetManagerTest, NegationCompilesToDifferentPacketSetHandle);

void DoubleNegationCompilesToSamePacketSetHandle(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(pred),
            Manager().Compile(NotProto(NotProto(pred))));
}
FUZZ_TEST(PacketSetManagerTest, DoubleNegationCompilesToSamePacketSetHandle);

TEST(PacketSetManagerTest, TrueNotEqualsMatch) {
  EXPECT_NE(Manager().Compile(TrueProto()),
            Manager().Compile(MatchProto("hi", 42)));
}
TEST(PacketSetManagerTest, FalseNotEqualsMatch) {
  EXPECT_NE(Manager().Compile(FalseProto()),
            Manager().Compile(MatchProto("hi", 42)));
}
TEST(PacketSetManagerTest, MatchNotEqualsDifferentMatch) {
  EXPECT_NE(Manager().Compile(MatchProto("hi", 42)),
            Manager().Compile(MatchProto("bye", 42)));
  EXPECT_NE(Manager().Compile(MatchProto("hi", 42)),
            Manager().Compile(MatchProto("hi", 24)));
}
TEST(PacketSetManagerTest, NotTrueEqualsFalse) {
  EXPECT_EQ(Manager().Compile(NotProto(TrueProto())),
            Manager().Compile(FalseProto()));
}

void AndIsIdempotent(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(AndProto(pred, pred)), Manager().Compile(pred));
}
FUZZ_TEST(PacketSetManagerTest, AndIsIdempotent);

void OrIsIdempotent(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(OrProto(pred, pred)), Manager().Compile(pred));
}
FUZZ_TEST(PacketSetManagerTest, OrIsIdempotent);

void PredOrItsNegationIsTrue(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(OrProto(pred, NotProto(pred))),
            Manager().Compile(TrueProto()));
}
FUZZ_TEST(PacketSetManagerTest, PredOrItsNegationIsTrue);

void PredAndItsNegationIsFalse(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(AndProto(pred, NotProto(pred))),
            Manager().Compile(FalseProto()));
}
FUZZ_TEST(PacketSetManagerTest, PredAndItsNegationIsFalse);

void AndTrueIsIdentity(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(AndProto(pred, TrueProto())),
            Manager().Compile(pred));
}
FUZZ_TEST(PacketSetManagerTest, AndTrueIsIdentity);

void OrFalseIsIdentity(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(OrProto(pred, FalseProto())),
            Manager().Compile(pred));
}
FUZZ_TEST(PacketSetManagerTest, OrFalseIsIdentity);

void XorFalseIsIdentity(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(XorProto(pred, FalseProto())),
            Manager().Compile(pred));
}
FUZZ_TEST(PacketSetManagerTest, XorFalseIsIdentity);

void AndFalseIsFalse(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(AndProto(pred, FalseProto())),
            Manager().Compile(FalseProto()));
}
FUZZ_TEST(PacketSetManagerTest, AndFalseIsFalse);

void OrTrueIsTrue(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(OrProto(pred, TrueProto())),
            Manager().Compile(TrueProto()));
}
FUZZ_TEST(PacketSetManagerTest, OrTrueIsTrue);

void XorSelfIsFalse(const PredicateProto& pred) {
  EXPECT_EQ(Manager().Compile(XorProto(pred, pred)),
            Manager().Compile(FalseProto()));
}
FUZZ_TEST(PacketSetManagerTest, XorSelfIsFalse);

void AndIsCommutative(const PredicateProto& a, const PredicateProto& b) {
  EXPECT_EQ(Manager().Compile(AndProto(a, b)),
            Manager().Compile(AndProto(b, a)));
}
FUZZ_TEST(PacketSetManagerTest, AndIsCommutative);

void OrIsCommutative(const PredicateProto& a, const PredicateProto& b) {
  EXPECT_EQ(Manager().Compile(OrProto(a, b)), Manager().Compile(OrProto(b, a)));
}
FUZZ_TEST(PacketSetManagerTest, OrIsCommutative);

void XorIsCommutative(const PredicateProto& a, const PredicateProto& b) {
  EXPECT_EQ(Manager().Compile(XorProto(a, b)),
            Manager().Compile(XorProto(b, a)));
}
FUZZ_TEST(PacketSetManagerTest, XorIsCommutative);

void DistributiveLawsHolds(const PredicateProto& a, const PredicateProto& b,
                           const PredicateProto& c) {
  EXPECT_EQ(Manager().Compile(AndProto(a, OrProto(b, c))),
            Manager().Compile(OrProto(AndProto(a, b), AndProto(a, c))));
  EXPECT_EQ(Manager().Compile(OrProto(a, AndProto(b, c))),
            Manager().Compile(AndProto(OrProto(a, b), OrProto(a, c))));
}
FUZZ_TEST(PacketSetManagerTest, DistributiveLawsHolds);

void DeMorgansLawsHolds(const PredicateProto& a, const PredicateProto& b) {
  EXPECT_EQ(Manager().Compile(NotProto(AndProto(a, b))),
            Manager().Compile(OrProto(NotProto(a), NotProto(b))));
  EXPECT_EQ(Manager().Compile(NotProto(OrProto(a, b))),
            Manager().Compile(AndProto(NotProto(a), NotProto(b))));
}
FUZZ_TEST(PacketSetManagerTest, DeMorgansLawsHolds);

void XorDefinition(const PredicateProto& a, const PredicateProto& b) {
  EXPECT_EQ(Manager().Compile(XorProto(a, b)),
            Manager().Compile(
                OrProto(AndProto(NotProto(a), b), AndProto(a, NotProto(b)))));
}
FUZZ_TEST(PacketSetManagerTest, XorDefinition);

void AndIsAssociative(const PredicateProto& a, const PredicateProto& b,
                      const PredicateProto& c) {
  EXPECT_EQ(Manager().Compile(AndProto(a, AndProto(b, c))),
            Manager().Compile(AndProto(AndProto(a, b), c)));
}
FUZZ_TEST(PacketSetManagerTest, AndIsAssociative);

void OrIsAssociative(const PredicateProto& a, const PredicateProto& b,
                     const PredicateProto& c) {
  EXPECT_EQ(Manager().Compile(OrProto(a, OrProto(b, c))),
            Manager().Compile(OrProto(OrProto(a, b), c)));
}
FUZZ_TEST(PacketSetManagerTest, OrIsAssociative);

void XorIsAssociative(const PredicateProto& a, const PredicateProto& b,
                      const PredicateProto& c) {
  EXPECT_EQ(Manager().Compile(XorProto(a, XorProto(b, c))),
            Manager().Compile(XorProto(XorProto(a, b), c)));
}
FUZZ_TEST(PacketSetManagerTest, XorIsAssociative);

TEST(PacketSetManagerTest, ExistsOnPacketSetWithSingleFieldReturnsFullSet) {
  const std::string field = "a";
  EXPECT_EQ(Manager().Exists(field, Manager().Compile(MatchProto(field, 3))),
            Manager().FullSet());
}

TEST(PacketSetManagerTest, ExistsOnPacketSetWithNonMatchingFieldReturnsSelf) {
  const std::string field_a = "a";
  const std::string field_b = "b";
  PacketSetHandle packet_set = Manager().Compile(MatchProto(field_b, 3));
  EXPECT_EQ(Manager().Exists(field_a, packet_set), packet_set);
}

TEST(PacketSetManagerTest, ExistOnFieldRemovesPacketFieldProperty) {
  const std::string field = "a";
  constexpr int value = 3;
  // p = (a=3 && b=4) || (b!=5 && c=5)
  PacketSetHandle packet_set = Manager().Compile(
      OrProto(AndProto(MatchProto(field, value), MatchProto("b", 4)),
              AndProto(NotProto(MatchProto("b", 5)), MatchProto("c", 5))));
  PacketSetHandle packet_set_without_field =
      Manager().Exists(field, packet_set);
  Packet packet_with_b4 = Packet{{"b", 4}};
  EXPECT_TRUE(Manager().Contains(packet_set_without_field, packet_with_b4));
  EXPECT_FALSE(Manager().Contains(packet_set, packet_with_b4));

  Packet packet_with_a3_and_b4 = {{field, value}, {"b", 4}};
  EXPECT_TRUE(
      Manager().Contains(packet_set_without_field, packet_with_a3_and_b4));
  EXPECT_TRUE(Manager().Contains(packet_set, packet_with_a3_and_b4));
}

TEST(PacketSetManagerTest, ExistsOnFieldNotInPacketIsIdentity) {
  // p = (a=3 && b=4) || (b!=5 && c=5)
  PacketSetHandle packet_set = Manager().Compile(
      OrProto(AndProto(MatchProto("a", 3), MatchProto("b", 4)),
              AndProto(NotProto(MatchProto("b", 5)), MatchProto("c", 5))));
  EXPECT_EQ(packet_set, Manager().Exists("d", packet_set));
}

void ExistIsIdentityForNonExistentField(const PredicateProto& pred) {
  PacketSetHandle packet_set = Manager().Compile(pred);
  EXPECT_EQ(Manager().Exists("non-existent-field", packet_set), packet_set);
}
FUZZ_TEST(PacketSetManagerTest, ExistIsIdentityForNonExistentField)
    // We restrict to four field value to exclude the non-existent field and
    // increases the likelihood for coverage for predicates/policies that
    // match/modify the same field several times.
    .WithDomains(fuzztest::Arbitrary<PredicateProto>()
                     .WithFieldsAlwaysSet()
                     .WithStringFields(fuzztest::ElementOf<std::string>(
                         {"f", "g", "h", "i"})));

void ExistOnFieldRemovesPacketFieldProperty(const PredicateProto& pred,
                                            int new_value) {
  PacketSetHandle packet_set = Manager().Compile(pred);
  for (const Packet& packet : Manager().GetConcretePackets(packet_set)) {
    // Skip empty packets.
    if (packet.empty()) continue;

    std::string field = packet.begin()->first;

    PacketSetHandle packet_set_without_field =
        Manager().Exists(field, packet_set);
    ASSERT_NE(packet_set_without_field, packet_set);

    Packet packet_without_field = packet;
    packet_without_field.erase(field);

    // Skip packets with the field removed that are empty.
    if (packet_without_field.empty()) continue;

    EXPECT_TRUE(
        Manager().Contains(packet_set_without_field, packet_without_field));
    EXPECT_FALSE(Manager().Contains(packet_set, packet_without_field));

    // Modify the packet to have the field with a different value.
    if (new_value == packet.at(field)) continue;
    Packet packet_with_new_value = packet;
    packet_with_new_value[field] = new_value;
    EXPECT_TRUE(
        Manager().Contains(packet_set_without_field, packet_with_new_value));
    EXPECT_FALSE(Manager().Contains(packet_set, packet_with_new_value));
  }
}
FUZZ_TEST(PacketSetManagerTest, ExistOnFieldRemovesPacketFieldProperty);

}  // namespace
}  // namespace netkat
