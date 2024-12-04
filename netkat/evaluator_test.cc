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

#include "netkat/evaluator.h"

#include "absl/container/flat_hash_set.h"
#include "fuzztest/fuzztest.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "netkat/netkat.pb.h"
#include "netkat/netkat_proto_constructors.h"

namespace netkat {
namespace {

using ::fuzztest::Arbitrary;
using ::fuzztest::InRange;
using ::testing::ContainerEq;
using ::testing::IsEmpty;
using ::testing::IsSupersetOf;
using ::testing::UnorderedElementsAre;

/*--- Basic predicate properties ---------------------------------------------*/

void TrueIsTrueOnAnyPackets(Packet packet) {
  EXPECT_TRUE(Evaluate(TrueProto(), packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, TrueIsTrueOnAnyPackets);

void FalseIsFalseOnAnyPackets(Packet packet) {
  EXPECT_FALSE(Evaluate(FalseProto(), packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, FalseIsFalseOnAnyPackets);

void EmptyPredicateIsFalseOnAnyPackets(Packet packet) {
  EXPECT_FALSE(Evaluate(PredicateProto(), packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, EmptyPredicateIsFalseOnAnyPackets);

void NotIsLogicalNot(Packet packet, PredicateProto negand) {
  EXPECT_EQ(Evaluate(NotProto(negand), packet), !Evaluate(negand, packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, NotIsLogicalNot);

void MatchOnlyMatchesPacketsWithCorrectValueAndField(Packet packet,
                                                     std::string field,
                                                     int value) {
  packet[field] = value;
  EXPECT_TRUE(Evaluate(MatchProto(field, value), packet));

  packet[field] = value - 1;
  EXPECT_FALSE(Evaluate(MatchProto(field, value), packet));

  packet.erase(field);
  EXPECT_FALSE(Evaluate(MatchProto(field, value), packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest,
          MatchOnlyMatchesPacketsWithCorrectValueAndField);

void AndIsLogicalAnd(Packet packet, PredicateProto left, PredicateProto right) {
  EXPECT_EQ(Evaluate(AndProto(left, right), packet),
            Evaluate(left, packet) && Evaluate(right, packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, AndIsLogicalAnd);

void OrIsLogicalOr(Packet packet, PredicateProto left, PredicateProto right) {
  EXPECT_EQ(Evaluate(OrProto(left, right), packet),
            Evaluate(left, packet) || Evaluate(right, packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, OrIsLogicalOr);

/*--- Boolean algebra axioms and equivalences --------------------------------*/

void PredOrItsNegationIsTrue(Packet packet, PredicateProto predicate) {
  EXPECT_TRUE(Evaluate(OrProto(predicate, NotProto(predicate)), packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, PredOrItsNegationIsTrue);

void PredAndItsNegationIsFalse(Packet packet, PredicateProto predicate) {
  EXPECT_FALSE(Evaluate(AndProto(predicate, NotProto(predicate)), packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, PredAndItsNegationIsFalse);

void AndIsIdempotent(Packet packet, PredicateProto predicate) {
  EXPECT_EQ(Evaluate(AndProto(predicate, predicate), packet),
            Evaluate(predicate, packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, AndIsIdempotent);

void AndTrueIsIdentity(Packet packet, PredicateProto predicate) {
  EXPECT_EQ(Evaluate(AndProto(predicate, TrueProto()), packet),
            Evaluate(predicate, packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, AndTrueIsIdentity);

void AndFalseIsFalse(Packet packet, PredicateProto predicate) {
  EXPECT_FALSE(Evaluate(AndProto(predicate, FalseProto()), packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, AndFalseIsFalse);

void AndIsCommutative(Packet packet, PredicateProto left,
                      PredicateProto right) {
  EXPECT_EQ(Evaluate(AndProto(left, right), packet),
            Evaluate(AndProto(right, left), packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, AndIsCommutative);

void AndIsAssociative(Packet packet, PredicateProto left, PredicateProto middle,
                      PredicateProto right) {
  EXPECT_EQ(Evaluate(AndProto(AndProto(left, middle), right), packet),
            Evaluate(AndProto(left, AndProto(middle, right)), packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, AndIsAssociative);

void OrIsIdempotent(Packet packet, PredicateProto predicate) {
  EXPECT_EQ(Evaluate(OrProto(predicate, predicate), packet),
            Evaluate(predicate, packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, OrIsIdempotent);

void OrFalseIsIdentity(Packet packet, PredicateProto predicate) {
  EXPECT_EQ(Evaluate(OrProto(predicate, FalseProto()), packet),
            Evaluate(predicate, packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, OrFalseIsIdentity);

void OrTrueIsTrue(Packet packet, PredicateProto predicate) {
  EXPECT_TRUE(Evaluate(OrProto(predicate, TrueProto()), packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, OrTrueIsTrue);

void OrIsCommutative(Packet packet, PredicateProto left, PredicateProto right) {
  EXPECT_EQ(Evaluate(OrProto(left, right), packet),
            Evaluate(OrProto(right, left), packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, OrIsCommutative);

void OrIsAssociative(Packet packet, PredicateProto left, PredicateProto middle,
                     PredicateProto right) {
  EXPECT_EQ(Evaluate(OrProto(OrProto(left, middle), right), packet),
            Evaluate(OrProto(left, OrProto(middle, right)), packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, OrIsAssociative);

void DistributiveLawHolds(Packet packet, PredicateProto first,
                          PredicateProto second, PredicateProto third) {
  // (a || b) && c == (a && c) || (b && c)
  EXPECT_EQ(Evaluate(AndProto(OrProto(first, second), third), packet),
            Evaluate(OrProto(AndProto(first, third), AndProto(second, third)),
                     packet));

  // (a && b) || c == (a || c) && (b || c)
  EXPECT_EQ(Evaluate(OrProto(AndProto(first, second), third), packet),
            Evaluate(AndProto(OrProto(first, third), OrProto(second, third)),
                     packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, DistributiveLawHolds);

void DeMorganHolds(Packet packet, PredicateProto left, PredicateProto right) {
  // Not(a && b) == Not(a) || Not(b)
  EXPECT_EQ(Evaluate(NotProto(AndProto(left, right)), packet),
            Evaluate(OrProto(NotProto(left), NotProto(right)), packet));

  // Not(a || b) == Not(a) && Not(b)
  EXPECT_EQ(Evaluate(NotProto(OrProto(left, right)), packet),
            Evaluate(AndProto(NotProto(left), NotProto(right)), packet));
}
FUZZ_TEST(EvaluatePredicateProtoTest, DeMorganHolds);

/*--- Basic policy properties ------------------------------------------------*/

void LiftedEvaluationIsCorrect(absl::flat_hash_set<Packet> packets,
                               PolicyProto policy) {
  absl::flat_hash_set<Packet> expected_packets;
  for (const Packet& packet : packets) {
    expected_packets.merge(Evaluate(policy, packet));
  }
  EXPECT_THAT(Evaluate(policy, packets), ContainerEq(expected_packets));
}
FUZZ_TEST(EvaluatePolicyProtoTest, LiftedEvaluationIsCorrect);

void RecordIsAccept(Packet packet) {
  EXPECT_THAT(Evaluate(RecordProto(), packet), UnorderedElementsAre(packet));
}
FUZZ_TEST(EvaluatePolicyProtoTest, RecordIsAccept);

void UninitializedPolicyIsDeny(Packet packet) {
  EXPECT_THAT(Evaluate(PolicyProto(), packet), IsEmpty());
}
FUZZ_TEST(EvaluatePolicyProtoTest, UninitializedPolicyIsDeny);

void FilterIsCorrect(Packet packet, PredicateProto predicate) {
  if (Evaluate(predicate, packet)) {
    EXPECT_THAT(Evaluate(FilterProto(predicate), packet),
                UnorderedElementsAre(packet));
  } else {
    EXPECT_THAT(Evaluate(FilterProto(predicate), packet), IsEmpty());
  }
}
FUZZ_TEST(EvaluatePolicyProtoTest, FilterIsCorrect);

void ModifyModifies(Packet packet, std::string field, int value) {
  Packet expected_packet = packet;
  expected_packet[field] = value;
  EXPECT_THAT(Evaluate(ModificationProto(field, value), packet),
              UnorderedElementsAre(expected_packet));
}
FUZZ_TEST(EvaluatePolicyProtoTest, ModifyModifies);

void UnionCombines(Packet packet, PolicyProto left, PolicyProto right) {
  absl::flat_hash_set<Packet> expected_packets = Evaluate(left, packet);
  expected_packets.merge(Evaluate(right, packet));

  EXPECT_THAT(Evaluate(UnionProto(left, right), packet),
              ContainerEq(expected_packets));
}
FUZZ_TEST(EvaluatePolicyProtoTest, UnionCombines);

void SequenceSequences(Packet packet, PolicyProto left, PolicyProto right) {
  absl::flat_hash_set<Packet> expected_packets =
      Evaluate(right, Evaluate(left, packet));

  EXPECT_THAT(Evaluate(SequenceProto(left, right), packet),
              ContainerEq(expected_packets));
}
FUZZ_TEST(EvaluatePolicyProtoTest, SequenceSequences);

PolicyProto UnionUpToNthPower(PolicyProto iterable, int n) {
  PolicyProto union_policy = AcceptProto();
  PolicyProto next_sequence = iterable;
  for (int i = 1; i <= n; ++i) {
    union_policy = UnionProto(union_policy, next_sequence);
    next_sequence = SequenceProto(iterable, next_sequence);
  }
  return union_policy;
}

void IterateIsSupersetOfUnionOfNSequences(Packet packet, PolicyProto iterable,
                                          int n) {
  EXPECT_THAT(Evaluate(IterateProto(iterable), packet),
              IsSupersetOf(Evaluate(UnionUpToNthPower(iterable, n), packet)));
}
FUZZ_TEST(EvaluatePolicyProtoTest, IterateIsSupersetOfUnionOfNSequences)
    .WithDomains(/*packet=*/Arbitrary<Packet>(),
                 /*iterable=*/Arbitrary<PolicyProto>(),
                 /*n=*/InRange(0, 100));

void IterateIsUnionOfNSequencesForSomeN(Packet packet, PolicyProto iterable) {
  absl::flat_hash_set<Packet> iterate_output_packets =
      Evaluate(IterateProto(iterable), packet);

  // Evaluate successively larger unions until we find one that matches all
  // packets in `iterate_packets`.
  absl::flat_hash_set<Packet> union_output_packets;
  int last_size;
  int n = 0;
  do {
    last_size = union_output_packets.size();
    union_output_packets = Evaluate(UnionUpToNthPower(iterable, n++), packet);
  } while (iterate_output_packets != union_output_packets &&
           union_output_packets.size() > last_size);

  EXPECT_THAT(iterate_output_packets, ContainerEq(union_output_packets));
}
FUZZ_TEST(EvaluatePolicyProtoTest, IterateIsUnionOfNSequencesForSomeN);

TEST(EvaluatePolicyProtoTest, SimpleIterateThroughFiltersAndModifies) {
  // f == 0; f:=1 + f == 1; f := 2 + f == 2; f := 3
  PolicyProto iterable = UnionProto(
      SequenceProto(FilterProto(MatchProto("f", 0)), ModificationProto("f", 1)),
      UnionProto(SequenceProto(FilterProto(MatchProto("f", 1)),
                               ModificationProto("f", 2)),
                 SequenceProto(FilterProto(MatchProto("f", 2)),
                               ModificationProto("f", 3))));

  // If the packet contains the field, then the output is the union of the
  // input and the modified packets.
  EXPECT_THAT(Evaluate(IterateProto(iterable), Packet({{"f", 0}})),
              UnorderedElementsAre(Packet({{"f", 0}}), Packet({{"f", 1}}),
                                   Packet({{"f", 2}}), Packet({{"f", 3}})));

  // If the packet doesn't contain the field, then the only output is the
  // input.
  EXPECT_THAT(Evaluate(IterateProto(iterable), Packet()),
              UnorderedElementsAre(Packet()));
}

/*--- Advanced policy properties ---------------------------------------------*/
void ModifyThenMatchIsEquivalentToModify(Packet packet, std::string field,
                                         int value) {
  // f := n;f == n is equivalent to f := n.
  EXPECT_THAT(Evaluate(SequenceProto(ModificationProto(field, value),
                                     FilterProto(MatchProto(field, value))),
                       packet),
              ContainerEq(Evaluate(ModificationProto(field, value), packet)));
}
FUZZ_TEST(EvaluatePolicyProtoTest, ModifyThenMatchIsEquivalentToModify);

// TODO(dilo): Add tests for each of the NetKAT axioms.

}  // namespace
}  // namespace netkat
