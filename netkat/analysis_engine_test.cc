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

#include "netkat/analysis_engine.h"

#include "gtest/gtest.h"
#include "netkat/frontend.h"

namespace netkat {
namespace {

// We include only a single `CheckEquivalent` test as a smoke test since the
// function is implemented in terms of `SymbolicPacketManager`, which is tested
// thoroughly in its own unit tests.
TEST(AnalysisEngineTest, CheckEquivalentSmokeTests) {
  AnalysisEngine analyzer;

  // Check that true and false are equivalent to themselves but not each other.
  EXPECT_TRUE(analyzer.CheckEquivalent(Predicate::True(), Predicate::True()));
  EXPECT_TRUE(analyzer.CheckEquivalent(Predicate::False(), Predicate::False()));
  EXPECT_FALSE(analyzer.CheckEquivalent(Predicate::True(), Predicate::False()));
  EXPECT_FALSE(analyzer.CheckEquivalent(Predicate::False(), Predicate::True()));

  // Check that some simple predicates are equivalent to themselves but not each
  // other.
  const Predicate p1 = Match("port", 1) && Match("vlan", 10);
  const Predicate p2 = Match("port", 2);
  EXPECT_TRUE(analyzer.CheckEquivalent(p1, p1));
  EXPECT_TRUE(analyzer.CheckEquivalent(p2, p2));
  EXPECT_FALSE(analyzer.CheckEquivalent(p1, p2));
  EXPECT_FALSE(analyzer.CheckEquivalent(p2, p1));

  // Check some properties of negations.
  EXPECT_TRUE(analyzer.CheckEquivalent(!Predicate::True(), Predicate::False()));
  EXPECT_TRUE(analyzer.CheckEquivalent(!Predicate::False(), Predicate::True()));
  EXPECT_TRUE(analyzer.CheckEquivalent(!!p1, p1));

  // Check De Morgan's laws.
  EXPECT_TRUE(analyzer.CheckEquivalent(!(p1 && p2), !p1 || !p2));
  EXPECT_TRUE(analyzer.CheckEquivalent(!(p1 || p2), !p1 && !p2));
}

}  // namespace
}  // namespace netkat
