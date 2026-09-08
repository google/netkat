// Copyright 2026 The NetKAT authors
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

#include "netkat/table_builder.h"

#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "netkat/analysis_engine.h"
#include "netkat/frontend.h"
#include "netkat/table.h"

namespace netkat {
namespace {

using ::absl_testing::StatusIs;

TEST(NetkatTableBuilderTest, BuildEmptyTable) {
  NetkatTable table;
  ASSERT_OK(NetkatTableBuilder(table).LogRules().InstallRules());

  AnalysisEngine engine;
  EXPECT_TRUE(
      engine.CheckEquivalent(table.GetPolicy(), Policy::Deny()).IsSuccess());
}

TEST(NetkatTableBuilderTest, BuildTableWithDefaultPolicy) {
  NetkatTable table({}, /*accept_default=*/true);
  ASSERT_OK(NetkatTableBuilder(table).LogRules().InstallRules());

  AnalysisEngine engine;
  EXPECT_TRUE(
      engine.CheckEquivalent(table.GetPolicy(), Policy::Accept()).IsSuccess());
}

TEST(NetkatTableBuilderTest, BuildTableWithRulesAndDefaultPolicy) {
  NetkatTable table({}, /*accept_default=*/true);

  NetkatTable::Rule rule1 = {
      .priority = 0,
      .match = Match("port", 0),
      .action = Modify("vrf", 1),
  };
  NetkatTable::Rule rule2 = {
      .priority = 0,
      .match = Match("port", 1),
      .action = Modify("vrf", 2),
  };

  ASSERT_OK(NetkatTableBuilder(table)
                .AddRule(rule1)
                .AddRule(rule2)
                .LogRules()
                .InstallRules());

  NetkatTable expected_table({}, /*accept_default=*/true);
  ASSERT_OK(expected_table.AddRule(rule1));
  ASSERT_OK(expected_table.AddRule(rule2));

  AnalysisEngine engine;
  EXPECT_TRUE(
      engine.CheckEquivalent(table.GetPolicy(), expected_table.GetPolicy())
          .IsSuccess());
}

TEST(NetkatTableBuilderTest, CustomConstraintPropagatesError) {
  NetkatTable table({[](const NetkatTable::PendingRuleInfo& info) {
    if (info.priority > 10) return absl::InvalidArgumentError("Bad priority.");
    return absl::OkStatus();
  }});
  EXPECT_THAT(NetkatTableBuilder(table)
                  .AddRule({
                      .priority = 11,
                      .match = Match("port", 2),
                      .action = Modify("vrf", 3),
                  })
                  .LogRules()
                  .InstallRules(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(NetkatTableBuilderTest, TableRemainsUnchangedWhenTableBuilderFails) {
  NetkatTable table({[](const NetkatTable::PendingRuleInfo& info) {
    if (info.priority > 10) return absl::InvalidArgumentError("Bad priority.");
    return absl::OkStatus();
  }});
  ASSERT_OK(NetkatTableBuilder(table)
                .AddRule({
                    .priority = 0,
                    .match = Match("port", 1),
                    .action = Modify("vrf", 2),
                })
                .InstallRules());

  NetkatTable expected_table = table;
  ASSERT_THAT(NetkatTableBuilder(table)
                  .AddRule({
                      .priority = 11,
                      .match = Match("port", 2),
                      .action = Modify("vrf", 3),
                  })
                  .LogRules()
                  .InstallRules(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  AnalysisEngine engine;
  EXPECT_TRUE(
      engine.CheckEquivalent(table.GetPolicy(), expected_table.GetPolicy())
          .IsSuccess());
}

TEST(NetkatTableBuilderTest, TableBuilderFromExistingTable) {
  NetkatTable table;
  NetkatTable::Rule rule1 = {
      .priority = 0,
      .match = Match("port", 0),
      .action = Modify("vrf", 1),
  };
  ASSERT_OK(table.AddRule(rule1));

  NetkatTable::Rule rule2 = {
      .priority = 2,
      .match = Match("vrf", 10),
      .action = Modify("vlan_id", 5),
  };
  ASSERT_OK(table.AddRule(rule2));

  NetkatTable expected_table = table;
  NetkatTable::Rule rule3 = {
      .priority = 5,
      .match = Match("vlan_id", 1),
      .action = Modify("out_port", 2),
  };
  ASSERT_OK(expected_table.AddRule(rule3));
  ASSERT_OK(NetkatTableBuilder(table).AddRule(rule3).LogRules().InstallRules());

  AnalysisEngine engine;
  EXPECT_TRUE(
      engine.CheckEquivalent(table.GetPolicy(), expected_table.GetPolicy())
          .IsSuccess());
}

}  // namespace
}  // namespace netkat
