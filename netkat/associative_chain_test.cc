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

#include "netkat/associative_chain.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "fuzztest/fuzztest.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace netkat {
namespace {

using ::testing::ElementsAre;

// A minimal expression type: either a leaf with a name, or a binary
// operation `op` applied to two subexpressions.
struct Expr {
  std::string name;  // For leaves.
  char op = 0;       // For binary operations.
  std::unique_ptr<Expr> left, right;
};

std::unique_ptr<Expr> Leaf(std::string name) {
  return std::make_unique<Expr>(Expr{.name = std::move(name)});
}
std::unique_ptr<Expr> Op(char op, std::unique_ptr<Expr> left,
                         std::unique_ptr<Expr> right) {
  return std::make_unique<Expr>(
      Expr{.op = op, .left = std::move(left), .right = std::move(right)});
}

// Returns the names of the operands of the maximal `op` chain at `root`.
std::vector<std::string> FlattenedNames(const Expr& root, char op) {
  std::vector<std::string> names;
  for (const Expr* operand : FlattenAssociativeChain(
           root,
           [&](const Expr& expr)
               -> std::optional<std::pair<const Expr*, const Expr*>> {
             if (expr.op != op) return std::nullopt;
             return std::make_pair(expr.left.get(), expr.right.get());
           })) {
    names.push_back(operand->op == 0 ? operand->name
                                     : std::string(1, operand->op));
  }
  return names;
}

TEST(FlattenAssociativeChainTest, LeafIsSingleOperand) {
  EXPECT_THAT(FlattenedNames(*Leaf("a"), '+'), ElementsAre("a"));
}

TEST(FlattenAssociativeChainTest, FlattensLeftDeepChain) {
  auto expr =
      Op('+', Op('+', Op('+', Leaf("a"), Leaf("b")), Leaf("c")), Leaf("d"));
  EXPECT_THAT(FlattenedNames(*expr, '+'), ElementsAre("a", "b", "c", "d"));
}

TEST(FlattenAssociativeChainTest, FlattensRightDeepChain) {
  auto expr =
      Op('+', Leaf("a"), Op('+', Leaf("b"), Op('+', Leaf("c"), Leaf("d"))));
  EXPECT_THAT(FlattenedNames(*expr, '+'), ElementsAre("a", "b", "c", "d"));
}

TEST(FlattenAssociativeChainTest, StopsAtOtherOperations) {
  auto expr = Op('+', Op('*', Leaf("a"), Leaf("b")),
                 Op('+', Leaf("c"), Op('*', Leaf("d"), Leaf("e"))));
  EXPECT_THAT(FlattenedNames(*expr, '+'), ElementsAre("*", "c", "*"));
}

TEST(FlattenAssociativeChainTest, SupportsVeryDeepChains) {
  auto expr = Leaf("x");
  for (int i = 0; i < 100000; ++i) {
    expr = Op('+', std::move(expr), Leaf("y"));
  }
  EXPECT_EQ(FlattenedNames(*expr, '+').size(), 100001);
  // Avoid a stack overflow in the recursive destructor.
  while (expr->op != 0) expr = std::move(expr->left);
}

bool IsLongChain(const Expr& root, char op, int min_operands) {
  return IsLongAssociativeChain(
      root,
      [&](const Expr& expr)
          -> std::optional<std::pair<const Expr*, const Expr*>> {
        if (expr.op != op) return std::nullopt;
        return std::make_pair(expr.left.get(), expr.right.get());
      },
      min_operands);
}

TEST(IsLongAssociativeChainTest, DetectsLongLeftAndRightSpines) {
  auto left_deep = Op('+', Op('+', Leaf("a"), Leaf("b")), Leaf("c"));
  auto right_deep = Op('+', Leaf("a"), Op('+', Leaf("b"), Leaf("c")));
  for (const auto* expr : {left_deep.get(), right_deep.get()}) {
    EXPECT_TRUE(IsLongChain(*expr, '+', 2));
    EXPECT_TRUE(IsLongChain(*expr, '+', 3));
    EXPECT_FALSE(IsLongChain(*expr, '+', 4));
    EXPECT_FALSE(IsLongChain(*expr, '*', 2));
  }
}

TEST(IsLongAssociativeChainTest, IgnoresInnerSpines) {
  // ((a + b) + (c + d)): both spines have 3 operands, 4 operands in total.
  auto balanced =
      Op('+', Op('+', Leaf("a"), Leaf("b")), Op('+', Leaf("c"), Leaf("d")));
  EXPECT_TRUE(IsLongChain(*balanced, '+', 3));
  EXPECT_FALSE(IsLongChain(*balanced, '+', 4));
}

TEST(CombineBalancedTest, SingleOperandIsReturnedAsIs) {
  EXPECT_EQ(CombineBalanced(std::vector<std::string>{"a"},
                            [](const std::string& a, const std::string& b) {
                              return a + b;
                            }),
            "a");
}

TEST(CombineBalancedTest, CombinesAsBalancedTree) {
  auto parenthesize = [](const std::string& a, const std::string& b) {
    return "(" + a + b + ")";
  };
  EXPECT_EQ(CombineBalanced(std::vector<std::string>{"a", "b", "c", "d"},
                            parenthesize),
            "((ab)(cd))");
  EXPECT_EQ(CombineBalanced(std::vector<std::string>{"a", "b", "c", "d", "e"},
                            parenthesize),
            "(((ab)(cd))e)");
}

void CombineBalancedPreservesOrder(const std::vector<std::string>& operands) {
  std::string expected;
  for (const std::string& operand : operands) expected += operand;
  EXPECT_EQ(
      CombineBalanced(operands, [](const std::string& a,
                                   const std::string& b) { return a + b; }),
      expected);
}
FUZZ_TEST(CombineBalancedTest, CombineBalancedPreservesOrder)
    .WithDomains(fuzztest::NonEmpty(
        fuzztest::VectorOf(fuzztest::StringOf(fuzztest::InRange('a', 'z')))));

}  // namespace
}  // namespace netkat
