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
// -----------------------------------------------------------------------------
// To generate the `analysis_engine_counter_example_test.expected` file, run:
//  `bazel run
//  //netkat:analysis_engine_counter_example_diff_test
//  -- --update`

#include <iostream>
#include <string>
#include <vector>

#include "gutil/proto.h"
#include "netkat/analysis_engine.h"
#include "netkat/counter_example.h"
#include "netkat/frontend.h"

namespace netkat {
namespace {

constexpr char kBanner[] =
    "=========================================================================="
    "======\n";
constexpr char kLeftPolicyHeader[] =
    "-- Left Policy -----------------------------------------------------------"
    "------\n";
constexpr char kRightPolicyHeader[] =
    "-- Right Policy ----------------------------------------------------------"
    "------\n";
constexpr char kCounterExampleHeader[] =
    "-- Counter Example -------------------------------------------------------"
    "------\n";

// A test case for the `ValidateTestRun` function.
struct TestCase {
  // Human-readable description of this test case, for documentation.
  std::string description;
  Policy left_policy;
  Policy right_policy;
};

std::vector<TestCase> TestCases() {
  std::vector<TestCase> test_cases;
  test_cases.push_back({
      .description = "left := Deny, right := Deny. No counter example found.",
      .left_policy = Policy::Deny(),
      .right_policy = Policy::Deny(),
  });
  test_cases.push_back({
      .description = "left := Deny, right := Accept. Counter example found.",
      .left_policy = Policy::Deny(),
      .right_policy = Policy::Accept(),
  });
  test_cases.push_back({
      .description = "left := (a=2), right := (b=5).",
      .left_policy = Filter(Match("a", 2)),
      .right_policy = Filter(Match("b", 5)),
  });
  test_cases.push_back({
      .description = "left := (a=5), right := (a=5 && b=2).",
      .left_policy = Filter(Match("a", 5)),
      .right_policy = Filter(Match("a", 5) && Match("b", 2)),
  });
  test_cases.push_back({
      .description = "left := (c=5), right := (c=5) || (d=2).",
      .left_policy = Filter(Match("c", 5)),
      .right_policy = Union(Filter(Match("c", 5)), Filter(Match("d", 2))),
  });
  test_cases.push_back({
      .description = "left := !(c=5), right := (c=5).",
      .left_policy = Filter(!Match("c", 5)),
      .right_policy = Filter(Match("c", 5)),
  });
  test_cases.push_back({
      .description = "left := (f:=42), right := (g:=26).",
      .left_policy = Modify("f", 42),
      .right_policy = Modify("g", 26),
  });

  return test_cases;
}

void main() {
  // This test needs a deterministic field interning order, and thus must start
  // from a fresh manager.
  AnalysisEngine analysis_engine;
  for (const TestCase& test_case : TestCases()) {
    SuccessOrCounterExample success_or_counter_example =
        analysis_engine.CheckEquivalent(test_case.left_policy,
                                        test_case.right_policy);
    std::cout << kBanner << "Test case: " << test_case.description << "\n"
              << kBanner;
    std::cout << kLeftPolicyHeader
              << gutil::PrintTextProto(test_case.left_policy.ToProto());
    std::cout << kRightPolicyHeader
              << gutil::PrintTextProto(test_case.right_policy.ToProto());
    std::cout << kCounterExampleHeader << success_or_counter_example;
  }
}

}  // namespace
}  // namespace netkat

int main() { netkat::main(); }
