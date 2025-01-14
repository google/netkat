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

#include "netkat/netkat_proto_constructors.h"

#include "absl/strings/string_view.h"
#include "fuzztest/fuzztest.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/proto_matchers.h"
#include "netkat/netkat.pb.h"

namespace netkat {
namespace {

using ::netkat::EqualsProto;

TEST(TrueProtoTest, ReturnsTrueProto) {
  EXPECT_THAT(TrueProto(), EqualsProto(R"pb(bool_constant { value: true })pb"));
}

TEST(FalseProtoTest, ReturnsFalseProto) {
  EXPECT_THAT(FalseProto(),
              EqualsProto(R"pb(bool_constant { value: false })pb"));
}

void MatchProtoReturnsMatch(absl::string_view field, int value) {
  PredicateProto match_proto;
  PredicateProto::Match& match = *match_proto.mutable_match();
  match.set_field(field);
  match.set_value(value);
  EXPECT_THAT(MatchProto(field, value), EqualsProto(match_proto));
}
FUZZ_TEST(MatchProtoTest, MatchProtoReturnsMatch);

void AndProtoReturnsAnd(PredicateProto left, PredicateProto right) {
  PredicateProto and_proto;
  PredicateProto::And& and_op = *and_proto.mutable_and_op();
  *and_op.mutable_left() = left;
  *and_op.mutable_right() = right;
  EXPECT_THAT(AndProto(left, right), EqualsProto(and_proto));
}
FUZZ_TEST(AndProtoTest, AndProtoReturnsAnd);

void OrProtoReturnsOr(PredicateProto left, PredicateProto right) {
  PredicateProto or_proto;
  PredicateProto::Or& or_op = *or_proto.mutable_or_op();
  *or_op.mutable_left() = left;
  *or_op.mutable_right() = right;
  EXPECT_THAT(OrProto(left, right), EqualsProto(or_proto));
}
FUZZ_TEST(OrProtoTest, OrProtoReturnsOr);

void NotProtoReturnsNot(PredicateProto negand) {
  PredicateProto not_proto;
  PredicateProto::Not& not_op = *not_proto.mutable_not_op();
  *not_op.mutable_negand() = negand;
  EXPECT_THAT(NotProto(negand), EqualsProto(not_proto));
}
FUZZ_TEST(NotProtoTest, NotProtoReturnsNot);

// -- Basic Policy constructors ------------------------------------------------

void FilterProtoReturnsFilter(PredicateProto filter) {
  PolicyProto expected_policy;
  *expected_policy.mutable_filter() = filter;
  EXPECT_THAT(FilterProto(filter), EqualsProto(expected_policy));
}
FUZZ_TEST(PolicyProtoTest, FilterProtoReturnsFilter);

void ModificationProtoReturnsModification(std::string field, int value) {
  PolicyProto expected_policy;
  expected_policy.mutable_modification()->set_field(field);
  expected_policy.mutable_modification()->set_value(value);

  EXPECT_THAT(ModificationProto(field, value), EqualsProto(expected_policy));
}
FUZZ_TEST(PolicyProtoTest, ModificationProtoReturnsModification);

TEST(PolicyProtoTest, RecordProtoReturnsRecordPolicy) {
  EXPECT_THAT(RecordProto(), EqualsProto(R"pb(record {})pb"));
}

void SequenceProtoReturnsSequence(PolicyProto left, PolicyProto right) {
  PolicyProto expected_policy;
  *expected_policy.mutable_sequence_op()->mutable_left() = left;
  *expected_policy.mutable_sequence_op()->mutable_right() = right;

  EXPECT_THAT(SequenceProto(left, right), EqualsProto(expected_policy));
}
FUZZ_TEST(PolicyProtoTest, SequenceProtoReturnsSequence);

void UnionProtoReturnsUnion(PolicyProto left, PolicyProto right) {
  PolicyProto expected_policy;
  *expected_policy.mutable_union_op()->mutable_left() = left;
  *expected_policy.mutable_union_op()->mutable_right() = right;

  EXPECT_THAT(UnionProto(left, right), EqualsProto(expected_policy));
}
FUZZ_TEST(PolicyProtoTest, UnionProtoReturnsUnion);

void IterateProtoReturnsIterate(PolicyProto iterable) {
  PolicyProto expected_policy;
  *expected_policy.mutable_iterate_op()->mutable_iterable() = iterable;

  EXPECT_THAT(IterateProto(iterable), EqualsProto(expected_policy));
}
FUZZ_TEST(PolicyProtoTest, IterateProtoReturnsIterate);

// -- Derived Policy tests -----------------------------------------------------

TEST(PolicyProtoTest, DenyProtoFiltersOnFalse) {
  EXPECT_THAT(DenyProto(),
              EqualsProto(R"pb(filter { bool_constant { value: false } })pb"));
}

TEST(PolicyProtoTest, AcceptProtoFiltersOnTrue) {
  EXPECT_THAT(AcceptProto(),
              EqualsProto(R"pb(filter { bool_constant { value: true } })pb"));
}

// -- Short hand tests ---------------------------------------------------------

TEST(AsShorthandStringTest, RecordStringIsCorrect) {
  EXPECT_EQ(AsShorthandString(RecordProto()), "record");
}

TEST(AsShorthandStringTest, UnsetPredicateIsFalse) {
  EXPECT_EQ(AsShorthandString(PredicateProto()), "false");
}

TEST(AsShorthandStringTest, UnsetPolicyIsDeny) {
  EXPECT_EQ(AsShorthandString(PolicyProto()), "deny");
}

void FilterIsJustPredicate(PredicateProto predicate) {
  EXPECT_EQ(AsShorthandString(FilterProto(predicate)),
            AsShorthandString(predicate));
}
FUZZ_TEST(AsShorthandStringTest, FilterIsJustPredicate);

TEST(AsShorthandStringTest, BoolConstantIsCorrect) {
  EXPECT_EQ(AsShorthandString(FalseProto()), "false");
  EXPECT_EQ(AsShorthandString(TrueProto()), "true");
}

TEST(AsShorthandStringTest, AndIsOkay) {
  EXPECT_EQ(AsShorthandString(AndProto(TrueProto(), FalseProto())),
            "(true && false)");
}

TEST(AsShorthandStringTest, SequenceIsOkay) {
  EXPECT_EQ(AsShorthandString(SequenceProto(AcceptProto(), DenyProto())),
            "(true; false)");
}

TEST(AsShorthandStringTest, OrIsOkay) {
  EXPECT_EQ(AsShorthandString(OrProto(TrueProto(), FalseProto())),
            "(true || false)");
}

TEST(AsShorthandStringTest, UnionIsOkay) {
  EXPECT_EQ(AsShorthandString(UnionProto(AcceptProto(), DenyProto())),
            "(true + false)");
}

TEST(AsShorthandStringTest, NegationIsOkay) {
  EXPECT_EQ(AsShorthandString(NotProto(OrProto(TrueProto(), FalseProto()))),
            "!(true || false)");
}

TEST(AsShorthandStringTest, ModifyIsCorrect) {
  EXPECT_EQ(AsShorthandString(ModificationProto("field", 2)), "@field:=2");
}

TEST(AsShorthandStringTest, IterateIsCorrect) {
  EXPECT_EQ(AsShorthandString(IterateProto(AcceptProto())), "(true)*");
}

TEST(AsShorthandStringTest, MixedPolicyOrderIsPreserved) {
  const PredicateProto a = MatchProto("a", 1);
  const PredicateProto b = MatchProto("b", 2);
  const PredicateProto c = MatchProto("c", 3);
  EXPECT_EQ(
      AsShorthandString(IterateProto(UnionProto(
          SequenceProto(SequenceProto(FilterProto(OrProto(OrProto(a, b), c)),
                                      AcceptProto()),
                        RecordProto()),
          SequenceProto(SequenceProto(FilterProto(a), FilterProto(b)),
                        RecordProto())))),
      "((((((@a==1 || @b==2) || @c==3); true); record) + ((@a==1; @b==2); "
      "record)))*");
}

}  // namespace
}  // namespace netkat
