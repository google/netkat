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
//
// -----------------------------------------------------------------------------
// File: table_test.cc
// -----------------------------------------------------------------------------

#include "netkat/table.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "fuzztest/fuzztest.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/proto_matchers.h"
#include "gutil/status_matchers.h"  // IWYU pragma: keep
#include "netkat/analysis_engine.h"
#include "netkat/frontend.h"
#include "netkat/gtest_utils.h"
#include "netkat/netkat.pb.h"
#include "netkat/netkat_proto_constructors.h"

namespace netkat {
namespace {

using ::gutil::EqualsProto;
using ::gutil::IsOk;
using ::gutil::StatusIs;
using ::testing::HasSubstr;

// TODO: b/416297041 - It would be quite nice to not look at the protos these
// all generate. Instead, we could use the AnalysisEngine to verify correctness.
// At least for tests that don't care what the proto looks like.
//
// Using proto comparison is peeking a bit into the implementation details and
// also requires rule order stability, which may be true but is not required.
// It's also a bit hard to read through...

TEST(NetkatTableTest, EmptyTableIsDefaultAction) {
  EXPECT_THAT(NetkatTable().GetPolicy().ToProto(), EqualsProto(DenyProto()));
  EXPECT_THAT(NetkatTable({}, /*accept_default=*/false).GetPolicy().ToProto(),
              EqualsProto(DenyProto()));
  EXPECT_THAT(NetkatTable({}, /*accept_default=*/true).GetPolicy().ToProto(),
              EqualsProto(AcceptProto()));
}

class NetkatTableTest
    : public ::testing::TestWithParam</*accept_default*/ bool> {
 protected:
  static Policy DefaultPolicy() {
    return GetParam() ? Policy::Accept() : Policy::Deny();
  }

  static bool accept_default() { return GetParam(); }
};

TEST_P(NetkatTableTest, SingleRuleIsAddedCorrectly) {
  NetkatTable table({}, accept_default());
  ASSERT_OK(table.AddRule(/*priority=*/0, Match("port", 0), Modify("vrf", 1)));

  EXPECT_THAT(
      table.GetPolicy().ToProto(),
      EqualsProto(Union(Sequence(Filter(Match("port", 0)), Modify("vrf", 1)),
                        Sequence(Filter(!Match("port", 0)), DefaultPolicy()))
                      .ToProto()));
}

TEST_P(NetkatTableTest, MultipleRulesInSamePriorityAreAddedCorrectly) {
  NetkatTable table({}, accept_default());
  ASSERT_OK(table.AddRule(/*priority=*/0, Match("port", 0), Modify("vrf", 1)));
  ASSERT_OK(table.AddRule(/*priority=*/0, Match("port", 1), Modify("vrf", 2)));

  PolicyProto expected =
      Union(Union(Sequence(Filter(Match("port", 0)), Modify("vrf", 1)),
                  Sequence(Filter(Match("port", 1)), Modify("vrf", 2))),
            Sequence(Filter(!(Match("port", 0) || Match("port", 1))),
                     DefaultPolicy()))
          .ToProto();
  EXPECT_THAT(table.GetPolicy().ToProto(), EqualsProto(expected))
      << AsShorthandString(table.GetPolicy().ToProto())
      << "\n expected: " << AsShorthandString(expected);
}

TEST_P(NetkatTableTest, MultiplePrioritiesAreMergedCorrectly) {
  NetkatTable table({}, accept_default());
  ASSERT_OK(table.AddRule(/*priority=*/0, Match("port", 0), Modify("vrf", 1)));
  ASSERT_OK(table.AddRule(/*priority=*/1, Match("port", 1), Modify("vrf", 2)));

  PolicyProto expected =
      Union(
          Sequence(Filter(Match("port", 1)), Modify("vrf", 2)),
          Sequence(Filter(!Match("port", 1)),
                   Union(Sequence(Filter(Match("port", 0)), Modify("vrf", 1)),
                         Sequence(Filter(!Match("port", 0)), DefaultPolicy()))))
          .ToProto();
  EXPECT_THAT(table.GetPolicy().ToProto(), EqualsProto(expected))
      << AsShorthandString(table.GetPolicy().ToProto())
      << "\n expected: " << AsShorthandString(expected);
}

TEST_P(NetkatTableTest, CustomConstraintViolationIsPropagated) {
  // Create a rule that enforces a maximal priority.
  NetkatTable::TableConstraint priority_limit =
      [](const NetkatTable::PendingRuleInfo& info) {
        if (info.priority > 10)
          return absl::InvalidArgumentError("Bad priority.");
        return absl::OkStatus();
      };

  NetkatTable table({priority_limit}, accept_default());
  ASSERT_OK(table.AddRule(/*priority=*/10, Match("port", 0), Modify("vrf", 1)));
  ASSERT_OK(table.AddRule(/*priority=*/10, Match("port", 1), Modify("vrf", 2)));
  EXPECT_THAT(
      table.AddRule(/*priority=*/11, Match("port", 2), Modify("vrf", 3)),
      StatusIs(absl::StatusCode::kInvalidArgument));

  // Ensure the rule was not actually added.
  PolicyProto expected =
      Union(Union(Sequence(Filter(Match("port", 0)), Modify("vrf", 1)),
                  Sequence(Filter(Match("port", 1)), Modify("vrf", 2))),
            Sequence(Filter(!(Match("port", 0) || Match("port", 1))),
                     DefaultPolicy()))
          .ToProto();
  EXPECT_THAT(table.GetPolicy().ToProto(), EqualsProto(expected))
      << AsShorthandString(table.GetPolicy().ToProto())
      << "\n expected: " << AsShorthandString(expected);
}

INSTANTIATE_TEST_SUITE_P(DefaultTablePolicy, NetkatTableTest,
                         ::testing::Bool());

void RuleWithFilterIsInvalid(PredicateProto predicate) {
  if (predicate.has_bool_constant() &&
      predicate.bool_constant().value() == false) {
    // A False predicate is equivalent to drop, which is the only allowed
    // filter in a rules policy.
    GTEST_SKIP();
  }
  ASSERT_OK_AND_ASSIGN(Predicate pred, Predicate::FromProto(predicate));

  NetkatTable table;
  EXPECT_THAT(table.AddRule(/*priority=*/10, pred, Filter(pred)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}
FUZZ_TEST(NetkatTableTest, RuleWithFilterIsInvalid)
    .WithDomains(netkat_test::ArbitraryValidPredicateProto());

void RuleWithDropActionIsValid(PredicateProto match) {
  ASSERT_OK_AND_ASSIGN(Predicate pred, Predicate::FromProto(match));

  NetkatTable table;
  EXPECT_THAT(table.AddRule(/*priority=*/10, pred, Policy::Deny()), IsOk());
}
FUZZ_TEST(NetkatTableTest, RuleWithDropActionIsValid)
    .WithDomains(netkat_test::ArbitraryValidPredicateProto());

TEST(NetkatTable, NonDeterministicRuleRejected) {
  NetkatTable table;
  ASSERT_OK(table.AddRule(/*priority=*/10, Match("port", 0), Modify("vrf", 1)));

  EXPECT_THAT(
      table.AddRule(/*priority=*/10, Match("vlan", 0), Modify("vrf", 2)),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(NetkatTable, NonDeterministicRuleWithSameActionIsOk) {
  NetkatTable table;
  ASSERT_OK(table.AddRule(/*priority=*/10, Match("port", 0), Modify("vrf", 1)));
  EXPECT_OK(table.AddRule(/*priority=*/10, Match("vlan", 0), Modify("vrf", 1)));
}

TEST(NetkatTable, MergeEmptyTablesIsEmpty) {
  NetkatTable table1, table2;
  ASSERT_OK_AND_ASSIGN(absl::StatusOr<NetkatTable> merged_table,
                       NetkatTable::Merge(table1, table2));
  EXPECT_THAT(merged_table->GetPolicy().ToProto(), EqualsProto(DenyProto()));

  merged_table = NetkatTable::Merge(table2, table1);
  ASSERT_THAT(merged_table, IsOk());
  EXPECT_THAT(merged_table->GetPolicy().ToProto(), EqualsProto(DenyProto()));
}

TEST(NetkatTable, MergeWithEmptyTableIsNoop) {
  NetkatTable table;
  ASSERT_OK(table.AddRule(/*priority=*/10, Match("port", 0), Modify("vrf", 1)));

  NetkatTable empty_table;
  ASSERT_OK_AND_ASSIGN(absl::StatusOr<NetkatTable> merged_table,
                       NetkatTable::Merge(table, empty_table));
  EXPECT_THAT(merged_table->GetPolicy().ToProto(),
              EqualsProto(table.GetPolicy().ToProto()));

  ASSERT_OK_AND_ASSIGN(merged_table, NetkatTable::Merge(empty_table, table));
  ASSERT_THAT(merged_table, IsOk());
  EXPECT_THAT(merged_table->GetPolicy().ToProto(),
              EqualsProto(table.GetPolicy().ToProto()));
}

TEST(NetkatTable, MergeWithSameTableIsSemanticNoop) {
  NetkatTable table;
  ASSERT_OK(table.AddRule(/*priority=*/10, Match("port", 0), Modify("vrf", 1)));

  ASSERT_OK_AND_ASSIGN(absl::StatusOr<NetkatTable> merged_table,
                       NetkatTable::Merge(table, table));

  AnalysisEngine engine;
  EXPECT_TRUE(
      engine.CheckEquivalent(merged_table->GetPolicy(), table.GetPolicy()));
}

TEST(NetkatTable, MergeWithCopiedTableIsEquivalentToMergeWithSameTable) {
  NetkatTable table;
  ASSERT_OK(table.AddRule(/*priority=*/10, Match("port", 0), Modify("vrf", 1)));
  ASSERT_OK(table.AddRule(/*priority=*/11, Match("vlan", 0), Modify("vrf", 2)));
  ASSERT_OK_AND_ASSIGN(absl::StatusOr<NetkatTable> merged_table,
                       NetkatTable::Merge(table, table));

  NetkatTable copy_assign_table = table;
  ASSERT_OK_AND_ASSIGN(
      absl::StatusOr<NetkatTable> copy_assign_merged_table,
      NetkatTable::Merge(copy_assign_table, copy_assign_table));

  NetkatTable copy_ctor_table(table);
  ASSERT_OK_AND_ASSIGN(absl::StatusOr<NetkatTable> copy_ctor_merged_table,
                       NetkatTable::Merge(copy_ctor_table, copy_ctor_table));

  AnalysisEngine engine;
  EXPECT_TRUE(engine.CheckEquivalent(merged_table->GetPolicy(),
                                     copy_assign_merged_table->GetPolicy()));
  EXPECT_TRUE(engine.CheckEquivalent(merged_table->GetPolicy(),
                                     copy_ctor_merged_table->GetPolicy()));
}

TEST(NetkatTable, MergeWithDifferentTablesIsCorrect) {
  NetkatTable table1;
  ASSERT_OK(
      table1.AddRule(/*priority=*/10, Match("port", 0), Modify("vrf", 1)));
  ASSERT_OK(
      table1.AddRule(/*priority=*/10, Match("port", 1), Modify("vrf", 2)));

  NetkatTable table2;
  ASSERT_OK(
      table2.AddRule(/*priority=*/10, Match("port", 2), Modify("vrf", 3)));
  ASSERT_OK(
      table2.AddRule(/*priority=*/10, Match("port", 3), Modify("vrf", 4)));

  ASSERT_OK_AND_ASSIGN(absl::StatusOr<NetkatTable> merged_table,
                       NetkatTable::Merge(table1, table2));

  netkat::Policy expected_policy =
      Union(Sequence(Filter(Match("port", 0)), Modify("vrf", 1)),
            Sequence(Filter(Match("port", 1)), Modify("vrf", 2)),
            Sequence(Filter(Match("port", 2)), Modify("vrf", 3)),
            Sequence(Filter(Match("port", 3)), Modify("vrf", 4)));
  AnalysisEngine engine;
  EXPECT_TRUE(
      engine.CheckEquivalent(merged_table->GetPolicy(), expected_policy));

  ASSERT_OK_AND_ASSIGN(merged_table, NetkatTable::Merge(table2, table1));
  EXPECT_TRUE(
      engine.CheckEquivalent(merged_table->GetPolicy(), expected_policy));
}

TEST(NetkatTable, MergeWithNonDeterminismIsError) {
  NetkatTable table1;
  ASSERT_OK(
      table1.AddRule(/*priority=*/10, Match("port", 0), Modify("vrf", 1)));
  NetkatTable table2;
  ASSERT_OK(
      table2.AddRule(/*priority=*/10, Match("vlan", 0), Modify("vrf", 2)));

  EXPECT_THAT(NetkatTable::Merge(table1, table2),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("collides with existing rule")));
  EXPECT_THAT(NetkatTable::Merge(table2, table1),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("collides with existing rule")));
}

}  // namespace
}  // namespace netkat
