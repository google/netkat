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

TEST(EvaluatePredicateProtoTest, TrueIsTrueOnAnyPackets) {
  PredicateProto true_predicate;
  true_predicate.mutable_bool_constant()->set_value(true);

  EXPECT_TRUE(Evaluate(true_predicate, Packet()));
  EXPECT_TRUE(Evaluate(true_predicate, Packet({{"field1", 1}})));
  EXPECT_TRUE(Evaluate(true_predicate,
                       Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));
}

TEST(EvaluatePredicateProtoTest, FalseIsFalseOnAnyPacket) {
  PredicateProto false_predicate;
  false_predicate.mutable_bool_constant()->set_value(false);

  EXPECT_FALSE(Evaluate(false_predicate, Packet()));
  EXPECT_FALSE(Evaluate(false_predicate, Packet({{"field1", 1}})));
  EXPECT_FALSE(Evaluate(false_predicate,
                        Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));
}

TEST(EvaluatePredicateProtoTest, EmptyPredicateIsFalseOnAnyPacket) {
  PredicateProto empty_predicate;

  EXPECT_FALSE(Evaluate(empty_predicate, Packet()));
  EXPECT_FALSE(Evaluate(empty_predicate, Packet({{"field1", 1}})));
  EXPECT_FALSE(Evaluate(empty_predicate,
                        Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));
}

TEST(EvaluatePredicateProtoTest, NotTrueIsFalseOnAnyPackets) {
  PredicateProto not_true_predicate;
  not_true_predicate.mutable_not_op()
      ->mutable_negand()
      ->mutable_bool_constant()
      ->set_value(true);

  EXPECT_FALSE(Evaluate(not_true_predicate, Packet()));
  EXPECT_FALSE(Evaluate(not_true_predicate, Packet({{"field1", 1}})));
  EXPECT_FALSE(Evaluate(not_true_predicate,
                        Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));
}

TEST(EvaluatePredicateProtoTest, NotFalseIsTrueOnAnyPacket) {
  PredicateProto not_false_predicate;
  not_false_predicate.mutable_not_op()
      ->mutable_negand()
      ->mutable_bool_constant()
      ->set_value(false);

  EXPECT_TRUE(Evaluate(not_false_predicate, Packet()));
  EXPECT_TRUE(Evaluate(not_false_predicate, Packet({{"field1", 1}})));
  EXPECT_TRUE(Evaluate(not_false_predicate,
                       Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));
}

TEST(EvaluatePredicateProtoTest, NotNotTrueIsTrueOnAnyPackets) {
  PredicateProto not_not_true_predicate;
  not_not_true_predicate.mutable_not_op()
      ->mutable_negand()
      ->mutable_not_op()
      ->mutable_negand()
      ->mutable_bool_constant()
      ->set_value(true);

  EXPECT_TRUE(Evaluate(not_not_true_predicate, Packet()));
  EXPECT_TRUE(Evaluate(not_not_true_predicate, Packet({{"field1", 1}})));
  EXPECT_TRUE(Evaluate(not_not_true_predicate,
                       Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));
}

TEST(EvaluatePredicateProtoTest, MatchesFieldWithCorrectValue) {
  PredicateProto match_predicate;
  match_predicate.mutable_match()->set_field("field1");
  match_predicate.mutable_match()->set_value(1);

  EXPECT_FALSE(Evaluate(match_predicate, Packet()));
  EXPECT_TRUE(Evaluate(match_predicate, Packet({{"field1", 1}})));
  EXPECT_TRUE(Evaluate(match_predicate,
                       Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));
}

TEST(EvaluatePredicateProtoTest, DoesNotMatchFieldWithWrongValue) {
  PredicateProto match_predicate;
  match_predicate.mutable_match()->set_field("field1");
  match_predicate.mutable_match()->set_value(2);

  EXPECT_FALSE(Evaluate(match_predicate, Packet()));
  EXPECT_FALSE(Evaluate(match_predicate, Packet({{"field1", 1}})));
  EXPECT_FALSE(Evaluate(match_predicate,
                        Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));
}

TEST(EvaluatePredicateProtoTest, AndIsLogicallyCorrect) {
  PredicateProto true_and_true_predicate;
  true_and_true_predicate.mutable_and_op()
      ->mutable_left()
      ->mutable_bool_constant()
      ->set_value(true);
  true_and_true_predicate.mutable_and_op()
      ->mutable_right()
      ->mutable_bool_constant()
      ->set_value(true);

  EXPECT_TRUE(Evaluate(true_and_true_predicate, Packet()));
  EXPECT_TRUE(Evaluate(true_and_true_predicate, Packet({{"field1", 1}})));
  EXPECT_TRUE(Evaluate(true_and_true_predicate,
                       Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));

  PredicateProto false_and_true_predicate;
  false_and_true_predicate.mutable_and_op()
      ->mutable_left()
      ->mutable_bool_constant()
      ->set_value(false);
  false_and_true_predicate.mutable_and_op()
      ->mutable_right()
      ->mutable_bool_constant()
      ->set_value(true);

  EXPECT_FALSE(Evaluate(false_and_true_predicate, Packet()));
  EXPECT_FALSE(Evaluate(false_and_true_predicate, Packet({{"field1", 1}})));
  EXPECT_FALSE(Evaluate(false_and_true_predicate,
                        Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));

  PredicateProto false_and_false_predicate;
  false_and_false_predicate.mutable_and_op()
      ->mutable_left()
      ->mutable_bool_constant()
      ->set_value(false);
  false_and_false_predicate.mutable_and_op()
      ->mutable_right()
      ->mutable_bool_constant()
      ->set_value(false);

  EXPECT_FALSE(Evaluate(false_and_false_predicate, Packet()));
  EXPECT_FALSE(Evaluate(false_and_false_predicate, Packet({{"field1", 1}})));
  EXPECT_FALSE(Evaluate(false_and_false_predicate,
                        Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));
}

TEST(EvaluatePredicateProtoTest, OrIsLogicallyCorrect) {
  PredicateProto true_or_true_predicate;
  true_or_true_predicate.mutable_or_op()
      ->mutable_left()
      ->mutable_bool_constant()
      ->set_value(true);
  true_or_true_predicate.mutable_or_op()
      ->mutable_right()
      ->mutable_bool_constant()
      ->set_value(true);

  EXPECT_TRUE(Evaluate(true_or_true_predicate, Packet()));
  EXPECT_TRUE(Evaluate(true_or_true_predicate, Packet({{"field1", 1}})));
  EXPECT_TRUE(Evaluate(true_or_true_predicate,
                       Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));

  PredicateProto false_or_true_predicate;
  false_or_true_predicate.mutable_or_op()
      ->mutable_left()
      ->mutable_bool_constant()
      ->set_value(false);
  false_or_true_predicate.mutable_or_op()
      ->mutable_right()
      ->mutable_bool_constant()
      ->set_value(true);

  EXPECT_TRUE(Evaluate(false_or_true_predicate, Packet()));
  EXPECT_TRUE(Evaluate(false_or_true_predicate, Packet({{"field1", 1}})));
  EXPECT_TRUE(Evaluate(false_or_true_predicate,
                       Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));

  PredicateProto false_or_false_predicate;
  false_or_false_predicate.mutable_or_op()
      ->mutable_left()
      ->mutable_bool_constant()
      ->set_value(false);
  false_or_false_predicate.mutable_or_op()
      ->mutable_right()
      ->mutable_bool_constant()
      ->set_value(false);

  EXPECT_FALSE(Evaluate(false_or_false_predicate, Packet()));
  EXPECT_FALSE(Evaluate(false_or_false_predicate, Packet({{"field1", 1}})));
  EXPECT_FALSE(Evaluate(false_or_false_predicate,
                        Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));
}

TEST(EvaluatePredicateProtoTest, DeMorganHolds) {
  const Packet kEmptyPacket = Packet();
  const Packet kOneFieldPacket = Packet({{"field1", 1}});
  const Packet kThreeFieldsPacket =
      Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}});

  // Not(a && b) == Not(a) || Not(b)
  for (bool left : {true, false}) {
    for (bool right : {true, false}) {
      PredicateProto not_and_predicate;
      not_and_predicate.mutable_not_op()
          ->mutable_negand()
          ->mutable_and_op()
          ->mutable_left()
          ->mutable_bool_constant()
          ->set_value(left);
      not_and_predicate.mutable_not_op()
          ->mutable_negand()
          ->mutable_and_op()
          ->mutable_right()
          ->mutable_bool_constant()
          ->set_value(right);

      PredicateProto or_not_predicate;
      or_not_predicate.mutable_or_op()
          ->mutable_left()
          ->mutable_not_op()
          ->mutable_negand()
          ->mutable_bool_constant()
          ->set_value(left);
      or_not_predicate.mutable_or_op()
          ->mutable_right()
          ->mutable_not_op()
          ->mutable_negand()
          ->mutable_bool_constant()
          ->set_value(right);

      EXPECT_EQ(Evaluate(not_and_predicate, kEmptyPacket),
                Evaluate(or_not_predicate, kEmptyPacket));
      EXPECT_EQ(Evaluate(not_and_predicate, kOneFieldPacket),
                Evaluate(or_not_predicate, kOneFieldPacket));
      EXPECT_EQ(Evaluate(not_and_predicate, kThreeFieldsPacket),
                Evaluate(or_not_predicate, kThreeFieldsPacket));
    }
  }

  // Not(a || b) == Not(a) && Not(b)
  for (bool left : {true, false}) {
    for (bool right : {true, false}) {
      PredicateProto not_or_predicate;
      not_or_predicate.mutable_not_op()
          ->mutable_negand()
          ->mutable_or_op()
          ->mutable_left()
          ->mutable_bool_constant()
          ->set_value(left);
      not_or_predicate.mutable_not_op()
          ->mutable_negand()
          ->mutable_or_op()
          ->mutable_right()
          ->mutable_bool_constant()
          ->set_value(right);

      PredicateProto and_not_predicate;
      and_not_predicate.mutable_and_op()
          ->mutable_left()
          ->mutable_not_op()
          ->mutable_negand()
          ->mutable_bool_constant()
          ->set_value(left);
      and_not_predicate.mutable_and_op()
          ->mutable_right()
          ->mutable_not_op()
          ->mutable_negand()
          ->mutable_bool_constant()
          ->set_value(right);

      EXPECT_EQ(Evaluate(not_or_predicate, kEmptyPacket),
                Evaluate(and_not_predicate, kEmptyPacket));
      EXPECT_EQ(Evaluate(not_or_predicate, kOneFieldPacket),
                Evaluate(and_not_predicate, kOneFieldPacket));
      EXPECT_EQ(Evaluate(not_or_predicate, kThreeFieldsPacket),
                Evaluate(and_not_predicate, kThreeFieldsPacket));
    }
  }
}

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
