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

#include "netkat/packet_transformer.h"

#include <cstdint>
#include <ostream>
#include <utility>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "fuzztest/fuzztest.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/status_matchers.h"  // IWYU pragma: keep
#include "netkat/evaluator.h"
#include "netkat/netkat.pb.h"
#include "netkat/netkat_proto_constructors.h"
#include "netkat/packet_set.h"
#include "re2/re2.h"

namespace netkat {

// We use a global manager object to exercise statefulness more deeply across
// test cases. This also enables better pretty printing for debugging, see
// `PrintTo`.
PacketTransformerManager& Manager() {
  static absl::NoDestructor<PacketTransformerManager> manager;
  return *manager;
}

// The default `PacketTransformerHandle` pretty printer sucks! It does not
// have access to the graph structure representing the packet, since that is
// stored in the manager object. Thus, it returns opaque strings like
// "PacketTransformerHandle<123>".
//
// We define this much better override, which GoogleTest gives precedence to.
void PrintTo(const PacketTransformerHandle& transformer, std::ostream* os) {
  *os << Manager().ToString(transformer);
}

namespace {

using ::testing::ContainerEq;
using ::testing::IsEmpty;
using ::testing::Pair;
using ::testing::StartsWith;
using ::testing::UnorderedElementsAre;

// After executing all tests, we check once that no invariants are violated, for
// defense in depth. Checking invariants after each test (e.g. using a fixture)
// would likely not scale and seems overkill.
class CheckPacketTransformerManagerInvariantsOnTearDown
    : public testing::Environment {
 public:
  ~CheckPacketTransformerManagerInvariantsOnTearDown() override = default;
  void SetUp() override {}
  void TearDown() override { ASSERT_OK(Manager().CheckInternalInvariants()); }
};
testing::Environment* const foo_env = testing::AddGlobalTestEnvironment(
    new CheckPacketTransformerManagerInvariantsOnTearDown);

/*--- Basic tests ------------------------------------------------------------*/

TEST(PacketTransformerManagerTest, DenyIsDeny) {
  EXPECT_TRUE(Manager().IsDeny(Manager().Deny()));
  EXPECT_FALSE(Manager().IsAccept(Manager().Deny()));
}

TEST(PacketTransformerManagerTest, AcceptIsAccept) {
  EXPECT_TRUE(Manager().IsAccept(Manager().Accept()));
  EXPECT_FALSE(Manager().IsDeny(Manager().Accept()));
}

TEST(PacketTransformerManagerTest, DenyDoesNotEqualAccept) {
  EXPECT_NE(Manager().Deny(), Manager().Accept());
}

TEST(PacketTransformerManagerTest, AbslStringifyWorksForDeny) {
  EXPECT_THAT(absl::StrCat(Manager().Deny()),
              StartsWith("PacketTransformerHandle"));
}

TEST(PacketTransformerManagerTest, AbslStringifyWorksForAccept) {
  EXPECT_THAT(absl::StrCat(Manager().Accept()),
              StartsWith("PacketTransformerHandle"));
}

TEST(PacketTransformerManagerTest, AbslHashValueWorks) {
  absl::flat_hash_set<PacketTransformerHandle> set = {
      Manager().Deny(),
      Manager().Accept(),
  };
  EXPECT_EQ(set.size(), 2);
}

TEST(PacketTransformerManagerTest, EmptyPolicyCompilesToDeny) {
  EXPECT_TRUE(Manager().IsDeny(Manager().Compile(PolicyProto())));
}

TEST(PacketTransformerManagerTest, RecordPolicyCompilesToAccept) {
  EXPECT_TRUE(Manager().IsAccept(Manager().Compile(RecordProto())));
}

// packet transformer compile should give the same result as
// PacketSetHandle -> OfPacketSetHandle, if PolicyProto is only a Filter.
void CompileIsSameAsOfCompiledPacketSetHandle(PredicateProto predicate) {
  PacketSetHandle set_1 = Manager().GetPacketSetManager().Compile(predicate);
  EXPECT_EQ(Manager().Compile(FilterProto(predicate)),
            Manager().FromPacketSetHandle(set_1));

  // Using a newly constructed PacketSetManager.
  PacketSetManager packet_set_manager;
  PacketSetHandle set_2 = packet_set_manager.Compile(predicate);
  PacketTransformerManager manager(std::move(packet_set_manager));
  EXPECT_EQ(manager.Compile(FilterProto(predicate)),
            manager.FromPacketSetHandle(set_2));
}
FUZZ_TEST(PacketTransformerManagerTest,
          CompileIsSameAsOfCompiledPacketSetHandle);

/*--- Basic compilation and method consistency checks ------------------------*/

TEST(PacketTransformerManagerTest, AcceptCompilesToAccept) {
  EXPECT_EQ(Manager().Compile(AcceptProto()), Manager().Accept());
}

TEST(PacketTransformerManagerTest, DenyCompilesToDeny) {
  EXPECT_EQ(Manager().Compile(DenyProto()), Manager().Deny());
}

void FilterCompilesToFilter(PredicateProto predicate) {
  EXPECT_EQ(Manager().Compile(FilterProto(predicate)),
            Manager().Filter(predicate));
}
FUZZ_TEST(PacketTransformerManagerTest, FilterCompilesToFilter);

void ModificationCompilesToModification(std::string field, int value) {
  EXPECT_EQ(Manager().Compile(ModificationProto(field, value)),
            Manager().Modification(field, value));
}
FUZZ_TEST(PacketTransformerManagerTest, ModificationCompilesToModification);

void UnionCompilesToUnion(PolicyProto left, PolicyProto right) {
  EXPECT_EQ(Manager().Compile(UnionProto(left, right)),
            Manager().Union(Manager().Compile(left), Manager().Compile(right)));
}
FUZZ_TEST(PacketTransformerManagerTest, UnionCompilesToUnion);

void SequenceCompilesToSequence(PolicyProto left, PolicyProto right) {
  EXPECT_EQ(
      Manager().Compile(SequenceProto(left, right)),
      Manager().Sequence(Manager().Compile(left), Manager().Compile(right)));
}
FUZZ_TEST(PacketTransformerManagerTest, SequenceCompilesToSequence);

void IterateCompilesToIterate(PolicyProto iterable) {
  EXPECT_EQ(Manager().Compile(IterateProto(iterable)),
            Manager().Iterate(Manager().Compile(iterable)));
}
FUZZ_TEST(PacketTransformerManagerTest, IterateCompilesToIterate);

/*--- Kleene algebra axioms and equivalences ---------------------------------*/

void UnionIsAssociative(PolicyProto a, PolicyProto b, PolicyProto c) {
  EXPECT_EQ(Manager().Compile(UnionProto(a, UnionProto(b, c))),
            Manager().Compile(UnionProto(UnionProto(a, b), c)));
}
FUZZ_TEST(PacketTransformerManagerTest, UnionIsAssociative);

void UnionIsCommutative(PolicyProto a, PolicyProto b) {
  EXPECT_EQ(Manager().Compile(UnionProto(a, b)),
            Manager().Compile(UnionProto(b, a)));
}
FUZZ_TEST(PacketTransformerManagerTest, UnionIsCommutative);

void UnionDenyIsIdentity(PolicyProto policy) {
  EXPECT_EQ(Manager().Compile(UnionProto(policy, DenyProto())),
            Manager().Compile(policy));
}
FUZZ_TEST(PacketTransformerManagerTest, UnionDenyIsIdentity);

void UnionIsIdempotent(PolicyProto policy) {
  EXPECT_EQ(Manager().Compile(UnionProto(policy, policy)),
            Manager().Compile(policy));
}
FUZZ_TEST(PacketTransformerManagerTest, UnionIsIdempotent);

void SequenceIsAssociative(PolicyProto a, PolicyProto b, PolicyProto c) {
  EXPECT_EQ(Manager().Compile(SequenceProto(a, SequenceProto(b, c))),
            Manager().Compile(SequenceProto(SequenceProto(a, b), c)));
}
FUZZ_TEST(PacketTransformerManagerTest, SequenceIsAssociative);

void SequenceAcceptIsIdentity(PolicyProto policy) {
  EXPECT_EQ(Manager().Compile(SequenceProto(policy, AcceptProto())),
            Manager().Compile(policy));
  EXPECT_EQ(Manager().Compile(SequenceProto(AcceptProto(), policy)),
            Manager().Compile(policy));
}
FUZZ_TEST(PacketTransformerManagerTest, SequenceAcceptIsIdentity);

void SequenceDenyIsAlwaysDeny(PolicyProto policy) {
  EXPECT_TRUE(
      Manager().IsDeny(Manager().Compile(SequenceProto(policy, DenyProto()))));
  EXPECT_TRUE(
      Manager().IsDeny(Manager().Compile(SequenceProto(DenyProto(), policy))));
}
FUZZ_TEST(PacketTransformerManagerTest, SequenceDenyIsAlwaysDeny);

void DistributiveLawsHold(PolicyProto a, PolicyProto b, PolicyProto c) {
  // Left distribution.
  EXPECT_EQ(
      Manager().Compile(SequenceProto(a, UnionProto(b, c))),
      Manager().Compile(UnionProto(SequenceProto(a, b), SequenceProto(a, c))));
  // Right distribution.
  EXPECT_EQ(
      Manager().Compile(SequenceProto(UnionProto(a, b), c)),
      Manager().Compile(UnionProto(SequenceProto(a, c), SequenceProto(b, c))));
}
FUZZ_TEST(PacketTransformerManagerTest, DistributiveLawsHold);

void IterateUnrollOnce(PolicyProto policy) {
  // Left unroll.
  EXPECT_EQ(Manager().Compile(UnionProto(
                AcceptProto(), SequenceProto(policy, IterateProto(policy)))),
            Manager().Compile(IterateProto(policy)));
  // Right unroll.
  EXPECT_EQ(Manager().Compile(UnionProto(
                AcceptProto(), SequenceProto(IterateProto(policy), policy))),
            Manager().Compile(IterateProto(policy)));
}
FUZZ_TEST(PacketTransformerManagerTest, IterateUnrollOnce);

// This test checks that iterate is the least-fixed point on the left and right
// side of a sequence. I.e. that if there is a term x such that x;y (or y;x) is
// smaller than y, then x* is the smallest such term.
void IterateIsLeastFixedPoint(PolicyProto p, PolicyProto q, PolicyProto r) {
  // Left.
  PolicyProto lfp_left_antecedent = UnionProto(q, SequenceProto(p, r));
  if (Manager().Compile(UnionProto(lfp_left_antecedent, r)) ==
      Manager().Compile(r)) {
    PolicyProto left_lfp = SequenceProto(IterateProto(p), q);
    EXPECT_EQ(Manager().Compile(UnionProto(left_lfp, r)), Manager().Compile(r));
  }
  // Right.
  PolicyProto lfp_right_antecedent = UnionProto(p, SequenceProto(q, r));
  if (Manager().Compile(UnionProto(lfp_right_antecedent, q)) ==
      Manager().Compile(q)) {
    PolicyProto right_lfp = SequenceProto(p, IterateProto(r));
    EXPECT_EQ(Manager().Compile(UnionProto(right_lfp, q)),
              Manager().Compile(q));
  }
}
FUZZ_TEST(PacketTransformerManagerTest, IterateIsLeastFixedPoint);

/*--- Tests with concrete protos ---------------------------------------------*/

TEST(PacketTransformerManagerTest, KatchPaperFig5) {
  // (a=5 + b=2);(b:=1 + c=5)
  PolicyProto p = SequenceProto(
      UnionProto(FilterProto(MatchProto("a", 5)),
                 FilterProto(MatchProto("b", 2))),
      UnionProto(ModificationProto("b", 1), FilterProto(MatchProto("c", 5))));

  // (b=1 + c:=4 + a:=1;b:=1)
  PolicyProto q = UnionProto(
      FilterProto(MatchProto("b", 1)),
      UnionProto(
          ModificationProto("c", 4),
          SequenceProto(ModificationProto("a", 1), ModificationProto("b", 1))));

  PacketTransformerHandle p_transformer = Manager().Compile(p);
  PacketTransformerHandle q_transformer = Manager().Compile(q);
  PacketTransformerHandle sequence_transformer =
      Manager().Compile(SequenceProto(p, q));

  EXPECT_EQ(Manager().Sequence(p_transformer, q_transformer),
            sequence_transformer);
}

TEST(PacketTransformerManagerTest, SequenceOfNonLoopProducerConvergesToDeny) {
  // a=1 ; b:=1 ; a:=0
  PolicyProto a_to_b = SequenceProto(
      FilterProto(MatchProto("a", 1)),
      SequenceProto(ModificationProto("b", 1), ModificationProto("a", 0)));

  // b=1 ; b:=0 ; a:=1
  PolicyProto b_to_a = SequenceProto(
      FilterProto(MatchProto("b", 1)),
      SequenceProto(ModificationProto("b", 0), ModificationProto("a", 1)));

  // !(once=1) ; a:=1 ; once:=1
  PolicyProto b_to_a_once =
      SequenceProto(FilterProto(NotProto(MatchProto("once", 1))),
                    SequenceProto(b_to_a, ModificationProto("once", 1)));

  PacketTransformerHandle a_to_b_and_b_to_a_once_transformer =
      Manager().Compile(UnionProto(a_to_b, b_to_a_once));

  PacketTransformerHandle sequenced_transformer2 = Manager().Sequence(
      a_to_b_and_b_to_a_once_transformer, a_to_b_and_b_to_a_once_transformer);

  // Should converge to Deny if sequenced 4 times.
  PacketTransformerHandle sequenced_transformer4 =
      Manager().Sequence(sequenced_transformer2, sequenced_transformer2);

  EXPECT_TRUE(Manager().IsDeny(sequenced_transformer4))
      << "a_to_b_and_b_to_a_once_transformer:\n"
      << Manager().ToString(a_to_b_and_b_to_a_once_transformer)
      << "\nsequenced_transformer4:\n"
      << Manager().ToString(sequenced_transformer4);
}

TEST(PacketTransformerManagerTest, SequenceOfLoopProducerConvergesToNonDeny) {
  // a=1 ; b:=1 ; a:=0
  PolicyProto a_to_b = SequenceProto(
      FilterProto(MatchProto("a", 1)),
      SequenceProto(ModificationProto("b", 1), ModificationProto("a", 0)));

  // b=1 ; b:=0 ; a:=1
  PolicyProto b_to_a = SequenceProto(
      FilterProto(MatchProto("b", 1)),
      SequenceProto(ModificationProto("b", 0), ModificationProto("a", 1)));

  PacketTransformerHandle a_to_b_and_b_to_a_transformer =
      Manager().Compile(UnionProto(a_to_b, b_to_a));

  PacketTransformerHandle sequenced_transformer2 = Manager().Sequence(
      a_to_b_and_b_to_a_transformer, a_to_b_and_b_to_a_transformer);
  PacketTransformerHandle sequenced_transformer4 =
      Manager().Sequence(sequenced_transformer2, sequenced_transformer2);

  EXPECT_FALSE(Manager().IsDeny(sequenced_transformer4));
  EXPECT_EQ(sequenced_transformer2, sequenced_transformer4)
      << "nsequenced_transformer2:\n"
      << Manager().ToString(sequenced_transformer2)
      << "\nsequenced_transformer4:\n"
      << Manager().ToString(sequenced_transformer4);
}

// Tests that a simple sequence of modification then filter same field with
// different value is Deny.
TEST(PacketTransformerManagerTest, ModifyThenFilterDifferentValueIsDeny) {
  // a:=0 ; a=1
  PolicyProto make_false_then_test =
      SequenceProto(ModificationProto("a", 0), FilterProto(MatchProto("a", 1)));

  EXPECT_TRUE(Manager().IsDeny(Manager().Compile(make_false_then_test)))
      << Manager().ToString(Manager().Compile(make_false_then_test));
}

// Tests that a simple sequence of modification then filter same field with
// same value is Modify.
TEST(PacketTransformerManagerTest, ModifyThenFilterSameValueIsModify) {
  // a:=1 ; a=1
  PolicyProto make_true = ModificationProto("a", 1);
  PolicyProto make_true_then_test =
      SequenceProto(make_true, FilterProto(MatchProto("a", 1)));

  EXPECT_EQ(Manager().Compile(make_true_then_test),
            Manager().Compile(make_true));
}

/*--- Tests with packets -----------------------------------------------------*/

TEST(PacketTransformerManagerTest, RunDenyAndAccept) {
  Packet packet = {{"field", 1}};
  Packet original_packet = packet;
  EXPECT_THAT(Manager().Run(Manager().Deny(), packet), IsEmpty());
  EXPECT_EQ(packet, original_packet);
  EXPECT_THAT(Manager().Run(Manager().Accept(), packet),
              UnorderedElementsAre(packet));
  EXPECT_EQ(packet, original_packet);
}

// We expect that any concrete packet that is `Run` through a `policy` gives the
// same result as when it is `Evaluate`d on that policy.
void RunIsSameAsEvaluate(PolicyProto policy, Packet packet) {
  Packet original_packet = packet;
  EXPECT_THAT(Manager().Run(Manager().Compile(policy), packet),
              ContainerEq(Evaluate(policy, packet)));
  EXPECT_EQ(packet, original_packet);
}
FUZZ_TEST(PacketTransformerManagerTest, RunIsSameAsEvaluate);

TEST(PacketTransformerManagerTest, SimpleSequenceRunTest1) {
  // !(once=1) ; a:=1 ; once:=1
  PacketTransformerHandle match_then_modify_transformer = Manager().Compile(
      SequenceProto(FilterProto(NotProto(MatchProto("once", 1))),
                    SequenceProto(ModificationProto("a", 1),
                                  ModificationProto("once", 1))));

  Packet packet_without_once;
  Packet packet_without_once_copy = packet_without_once;
  Packet packet_with_once_1 = {{"once", 1}};
  Packet packet_with_once_1_copy = packet_with_once_1;
  Packet packet_with_once_0 = {{"once", 0}};
  Packet packet_with_once_0_copy = packet_with_once_0;
  Packet expected_packet = {{"once", 1}, {"a", 1}};
  EXPECT_THAT(Manager().Run(match_then_modify_transformer, packet_without_once),
              UnorderedElementsAre(expected_packet));
  EXPECT_EQ(packet_without_once, packet_without_once_copy);
  EXPECT_THAT(Manager().Run(match_then_modify_transformer, packet_with_once_1),
              IsEmpty());
  EXPECT_EQ(packet_with_once_1, packet_with_once_1_copy);

  EXPECT_THAT(Manager().Run(match_then_modify_transformer, packet_with_once_0),
              UnorderedElementsAre(expected_packet));
  EXPECT_EQ(packet_with_once_0, packet_with_once_0_copy);
}

TEST(PacketTransformerManagerTest, SimpleSequenceAndUnionRunTest2) {
  // a=1 ; a:=0
  PacketTransformerHandle check_a = Manager().Compile(SequenceProto(
      FilterProto(MatchProto("a", 1)), ModificationProto("a", 0)));

  // Does `a:=1` exactly once.
  // !(once=1) ; a:=1 ; once:=1
  PacketTransformerHandle a_once = Manager().Compile(SequenceProto(
      FilterProto(NotProto(MatchProto("once", 1))),
      SequenceProto(ModificationProto("a", 1), ModificationProto("once", 1))));

  PacketTransformerHandle check_a_and_a_once_transformer =
      Manager().Union(check_a, a_once);

  Packet packet_without_fields;
  Packet packet_with_once_0 = {{"once", 0}};
  Packet packet_with_once_1 = {{"once", 1}};
  Packet packet_with_a_0 = {{"a", 0}};
  Packet packet_with_a_1 = {{"a", 1}};
  Packet packet_with_a_1_copy = packet_with_a_1;
  Packet expected_packet_a0 = {{"once", 1}, {"a", 0}};
  Packet expected_packet_a1 = {{"once", 1}, {"a", 1}};

  // Test `check_a_and_a_once_transformer`.
  EXPECT_THAT(
      Manager().Run(check_a_and_a_once_transformer, packet_without_fields),
      UnorderedElementsAre(expected_packet_a1));

  EXPECT_THAT(Manager().Run(check_a_and_a_once_transformer, packet_with_once_0),
              UnorderedElementsAre(expected_packet_a1));
  EXPECT_THAT(Manager().Run(check_a_and_a_once_transformer, packet_with_once_1),
              IsEmpty());

  EXPECT_THAT(Manager().Run(check_a_and_a_once_transformer, packet_with_a_0),
              UnorderedElementsAre(expected_packet_a1));
  EXPECT_THAT(Manager().Run(check_a_and_a_once_transformer, packet_with_a_1),
              UnorderedElementsAre(packet_with_a_0, expected_packet_a1));

  // Run the results through again!
  EXPECT_THAT(Manager().Run(check_a_and_a_once_transformer, expected_packet_a1),
              UnorderedElementsAre(expected_packet_a0));
  EXPECT_THAT(Manager().Run(check_a_and_a_once_transformer, packet_with_a_0),
              UnorderedElementsAre(expected_packet_a1));

  // This should be the same as running the original packets through
  // `sequenced_transformer2`.
  PacketTransformerHandle sequenced_transformer2 = Manager().Sequence(
      check_a_and_a_once_transformer, check_a_and_a_once_transformer);
  // Same result as running `expected_packet_a1` again above:
  EXPECT_THAT(Manager().Run(sequenced_transformer2, packet_without_fields),
              UnorderedElementsAre(expected_packet_a0));
  EXPECT_THAT(Manager().Run(sequenced_transformer2, packet_with_once_0),
              UnorderedElementsAre(expected_packet_a0));
  EXPECT_THAT(Manager().Run(sequenced_transformer2, packet_with_a_0),
              UnorderedElementsAre(expected_packet_a0));

  // Union of results from above.
  EXPECT_THAT(Manager().Run(sequenced_transformer2, packet_with_a_1),
              UnorderedElementsAre(expected_packet_a0, expected_packet_a1));
  EXPECT_EQ(packet_with_a_1, packet_with_a_1_copy);

  // Run it again! Note that `expected_packet_a0` would be created on a third
  // run (from `expected_packet_a1`), so we skip that only do the 4th run with
  // `expected_packet_a0`.
  EXPECT_THAT(Manager().Run(check_a_and_a_once_transformer, expected_packet_a0),
              IsEmpty());

  // Should converge to Deny if sequenced 4 times.
  PacketTransformerHandle sequenced_transformer4 =
      Manager().Sequence(sequenced_transformer2, sequenced_transformer2);

  EXPECT_TRUE(Manager().IsDeny(sequenced_transformer4))
      << "sequenced_transformer4:\n"
      << Manager().ToString(sequenced_transformer4);
}

}  // namespace
}  // namespace netkat
