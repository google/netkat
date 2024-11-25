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

#include "gtest/gtest.h"
#include "netkat/netkat.pb.h"

namespace netkat {
namespace {

TEST(EvaluatorTest, TrueIsTrueOnAnyPackets) {
  PredicateProto true_predicate;
  true_predicate.mutable_bool_constant()->set_value(true);

  EXPECT_TRUE(Evaluate(true_predicate, Packet()));
  EXPECT_TRUE(Evaluate(true_predicate, Packet({{"field1", 1}})));
  EXPECT_TRUE(Evaluate(true_predicate,
                       Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));
}

TEST(EvaluatorTest, FalseIsFalseOnAnyPacket) {
  PredicateProto false_predicate;
  false_predicate.mutable_bool_constant()->set_value(false);

  EXPECT_FALSE(Evaluate(false_predicate, Packet()));
  EXPECT_FALSE(Evaluate(false_predicate, Packet({{"field1", 1}})));
  EXPECT_FALSE(Evaluate(false_predicate,
                        Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));
}

TEST(EvaluatorTest, NotTrueIsFalseOnAnyPackets) {
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

TEST(EvaluatorTest, NotFalseIsTrueOnAnyPacket) {
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

TEST(EvaluatorTest, NotNotTrueIsTrueOnAnyPackets) {
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

TEST(EvaluatorTest, MatchesFieldWithCorrectValue) {
  PredicateProto match_predicate;
  match_predicate.mutable_match()->set_field("field1");
  match_predicate.mutable_match()->set_value(1);

  EXPECT_FALSE(Evaluate(match_predicate, Packet()));
  EXPECT_TRUE(Evaluate(match_predicate, Packet({{"field1", 1}})));
  EXPECT_TRUE(Evaluate(match_predicate,
                       Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));
}

TEST(EvaluatorTest, DoesNotMatchFieldWithWrongValue) {
  PredicateProto match_predicate;
  match_predicate.mutable_match()->set_field("field1");
  match_predicate.mutable_match()->set_value(2);

  EXPECT_FALSE(Evaluate(match_predicate, Packet()));
  EXPECT_FALSE(Evaluate(match_predicate, Packet({{"field1", 1}})));
  EXPECT_FALSE(Evaluate(match_predicate,
                        Packet({{"field1", 1}, {"field2", 2}, {"field3", 3}})));
}

TEST(EvaluatorTest, AndIsLogicallyCorrect) {
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

TEST(EvaluatorTest, OrIsLogicallyCorrect) {
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

TEST(EvaluatorTest, DeMorganHolds) {
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

}  // namespace
}  // namespace netkat
