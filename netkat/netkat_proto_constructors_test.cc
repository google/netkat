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
  auto match_proto = PredicateProto();
  auto& match = *match_proto.mutable_match();
  match.set_field(field);
  match.set_value(value);
  EXPECT_THAT(MatchProto(field, value), EqualsProto(match_proto));
}
FUZZ_TEST(AndProtoTest, MatchProtoReturnsMatch);

void AndProtoReturnsAnd(PredicateProto left, PredicateProto right) {
  auto and_proto = PredicateProto();
  auto& and_op = *and_proto.mutable_and_op();
  *and_op.mutable_left() = left;
  *and_op.mutable_right() = right;
  EXPECT_THAT(AndProto(left, right), EqualsProto(and_proto));
}
FUZZ_TEST(AndProtoTest, AndProtoReturnsAnd);

void OrProtoReturnsOr(PredicateProto left, PredicateProto right) {
  auto or_proto = PredicateProto();
  auto& or_op = *or_proto.mutable_or_op();
  *or_op.mutable_left() = left;
  *or_op.mutable_right() = right;
  EXPECT_THAT(OrProto(left, right), EqualsProto(or_proto));
}
FUZZ_TEST(OrProtoTest, OrProtoReturnsOr);

void NotProtoReturnsNot(PredicateProto negand) {
  auto not_proto = PredicateProto();
  auto& not_op = *not_proto.mutable_not_op();
  *not_op.mutable_negand() = negand;
  EXPECT_THAT(NotProto(negand), EqualsProto(not_proto));
}
FUZZ_TEST(NotProtoTest, NotProtoReturnsNot);

}  // namespace
}  // namespace netkat