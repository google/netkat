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

#include "netkat/gtest_utils.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "netkat/analysis_engine.h"
#include "netkat/counter_example.h"
#include "netkat/frontend.h"

namespace netkat {
namespace {

using ::netkat::netkat_test::HasCounterExample;
using ::netkat::netkat_test::IsSuccess;
using ::testing::ExplainMatchResult;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::StringMatchResultListener;

TEST(GtestUtilsTest, IsSuccessMatchesOnSuccess) {
  SuccessOrCounterExample success = SuccessOrCounterExample::Success();
  EXPECT_THAT(success, IsSuccess());
  EXPECT_THAT(success, Not(HasCounterExample()));
}

TEST(GtestUtilsTest, IsSuccessFailsOnCounterExample) {
  AnalysisEngine engine;
  Policy left = Filter(Match("port", 1));
  Policy right = Filter(Match("port", 2));

  SuccessOrCounterExample result = engine.CheckEquivalent(left, right);
  ASSERT_FALSE(result.IsSuccess());

  EXPECT_THAT(result, Not(IsSuccess()));
  EXPECT_THAT(result, HasCounterExample());
}

TEST(GtestUtilsTest, IsSuccessExplainsCounterExampleOnFailure) {
  AnalysisEngine engine;
  Policy left = Filter(Match("port", 1));
  Policy right = Filter(Match("port", 2));

  SuccessOrCounterExample result = engine.CheckEquivalent(left, right);

  StringMatchResultListener listener;
  EXPECT_FALSE(ExplainMatchResult(IsSuccess(), result, &listener));
  EXPECT_THAT(listener.str(), HasSubstr("CounterExample:"));
}

TEST(GtestUtilsTest, HasCounterExampleExplainsOnMismatch) {
  SuccessOrCounterExample success = SuccessOrCounterExample::Success();

  StringMatchResultListener listener;
  EXPECT_FALSE(ExplainMatchResult(HasCounterExample(), success, &listener));
  EXPECT_THAT(listener.str(),
              HasSubstr("No CounterExample generated, statement was success."));
}

TEST(GtestUtilsTest, EquivalentPoliciesPassIsSuccess) {
  AnalysisEngine engine;
  Policy p1 = Sequence(Filter(Match("port", 1)), Modify("port", 2));
  Policy p2 = Sequence(Filter(Match("port", 1)), Modify("port", 2));

  EXPECT_THAT(engine.CheckEquivalent(p1, p2), IsSuccess());
}

}  // namespace
}  // namespace netkat
