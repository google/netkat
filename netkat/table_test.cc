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
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/proto_matchers.h"
#include "gutil/status_matchers.h"
#include "netkat/frontend.h"
#include "netkat/netkat_proto_constructors.h"

namespace netkat {
namespace {

using ::netkat::EqualsProto;
using ::netkat::StatusIs;

// TODO(anthonyroy): It would be quite nice to not look at the protos these all
// generate. Instead, we could use the AnalysisEngine to verify correctness. At
// least for tests that don't care what the proto looks like.
//
// Using proto comparison is peeking a bit into the implementation details and
// also requires rule order stability, which may be true but is not required.

TEST(NetkatTable, EmptyTableIsDrop) {
  NetkatTable table;
  EXPECT_THAT(table.GetPolicy().ToProto(), EqualsProto(DenyProto()));
}

TEST(NetkatTable, SingleRuleIsAddedCorrectly) {
  NetkatTable table;
  ASSERT_OK(table.AddRule(Match("port", 0), Modify("vrf", 1), /*priority=*/0));

  EXPECT_THAT(
      table.GetPolicy().ToProto(),
      EqualsProto(
          Sequence(Filter(Match("port", 0)), Modify("vrf", 1)).ToProto()));
}

TEST(NetkatTable, MultipleRulesInSamePriorityAreAddedCorrectly) {
  NetkatTable table;
  ASSERT_OK(table.AddRule(Match("port", 0), Modify("vrf", 1), /*priority=*/0));
  ASSERT_OK(table.AddRule(Match("port", 1), Modify("vrf", 2), /*priority=*/0));

  EXPECT_THAT(
      table.GetPolicy().ToProto(),
      EqualsProto(Union(Sequence(Filter(Match("port", 0)), Modify("vrf", 1)),
                        Sequence(Filter(Match("port", 1)), Modify("vrf", 2)))
                      .ToProto()));
}

TEST(NetkatTable, MultiplePrioritiesAreMergedCorrectly) {
  NetkatTable table;
  ASSERT_OK(table.AddRule(Match("port", 0), Modify("vrf", 1), /*priority=*/0));
  ASSERT_OK(table.AddRule(Match("port", 1), Modify("vrf", 2), /*priority=*/1));

  EXPECT_THAT(
      table.GetPolicy().ToProto(),
      EqualsProto(
          Union(Sequence(Filter(Match("port", 1)), Modify("vrf", 2)),
                Sequence(Filter(!Match("port", 1)),
                         Sequence(Filter(Match("port", 0)), Modify("vrf", 1))))
              .ToProto()));
}

TEST(NetkatTable, CustomConstraintViolationIsPropagated) {
  // Create a rule that enforces a maximal priority.
  NetkatTable::TableConstraint priority_limit =
      [](const NetkatTable::PendingRuleInfo& info) {
        if (info.priority > 10)
          return absl::InvalidArgumentError("Bad priority.");
        return absl::OkStatus();
      };

  NetkatTable table({priority_limit});
  ASSERT_OK(table.AddRule(Match("port", 0), Modify("vrf", 1), /*priority=*/10));
  ASSERT_OK(table.AddRule(Match("port", 1), Modify("vrf", 2), /*priority=*/10));
  EXPECT_THAT(
      table.AddRule(Match("port", 2), Modify("vrf", 3), /*priority=*/11),
      StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(
      table.GetPolicy().ToProto(),
      EqualsProto(Union(Sequence(Filter(Match("port", 0)), Modify("vrf", 1)),
                        Sequence(Filter(Match("port", 1)), Modify("vrf", 2)))
                      .ToProto()));
}

// TODO(anthonyroy): Add the tests below.
// TEST(NetkatTable, NonDeterministicRuleRejected)
// TEST(NetkatTable, PolicyConstraintHonoredInGlobalPolicy)

}  // namespace
}  // namespace netkat
