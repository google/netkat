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
// File: associative_chain.h
// -----------------------------------------------------------------------------
//
// Utilities for compiling chains of associative binary operations, such as
// `a || b || c || ...`, as balanced binary trees.
//
// Chains are often built incrementally, resulting in degenerate (list-like)
// expression trees such as `((a || b) || c) || d`. Evaluating such a tree
// bottom-up combines an ever-growing intermediate result with one small
// operand at a time, which takes quadratic time overall for operations like
// set union on BDD-style representations. Evaluating the chain as a balanced
// tree, `(a || b) || (c || d)`, instead takes quasi-linear time.

#ifndef GOOGLE_NETKAT_NETKAT_ASSOCIATIVE_CHAIN_H_
#define GOOGLE_NETKAT_NETKAT_ASSOCIATIVE_CHAIN_H_

#include <cstddef>
#include <initializer_list>
#include <utility>
#include <vector>

#include "absl/log/check.h"

namespace netkat {

// The minimum number of operands along the leftmost or rightmost spine of a
// chain for which it is worth compiling the chain as a balanced tree. Short
// chains are better compiled as is, since that is cheaper to set up and
// preserves the sharing of common sub-chains.
inline constexpr int kMinOperandsToRebalanceAssociativeChain = 16;

// Returns true iff the leftmost or the rightmost spine of the chain of binary
// operations rooted at `root` has at least `min_operands` operands, i.e.
// consists of at least `min_operands - 1` operations. Takes O(`min_operands`)
// time, and does not allocate. See `FlattenAssociativeChain` for the contract
// of `get_operands`.
template <class Expr, class GetOperands>
bool IsLongAssociativeChain(
    const Expr& root, GetOperands&& get_operands,
    int min_operands = kMinOperandsToRebalanceAssociativeChain) {
  for (bool left : {true, false}) {
    int num_operations = 0;
    const Expr* expr = &root;
    while (auto children = get_operands(*expr)) {
      if (++num_operations >= min_operands - 1) return true;
      expr = left ? children->first : children->second;
    }
  }
  return false;
}

// Returns the operands of the maximal chain of binary operations rooted at
// `root`, in left-to-right order. `get_operands(expr)` must return a
// `std::optional<std::pair<const Expr*, const Expr*>>` holding the left and
// right operands of `expr` if `expr` is part of the chain (i.e. an application
// of the binary operation), or `std::nullopt` otherwise.
//
// For example, for the operation `||`, returns `{a, b, c, d}` given
// `((a || b) || c) || d` or `a || (b || (c || d))`.
//
// Uses an explicit stack, and so supports arbitrarily deep chains.
template <class Expr, class GetOperands>
std::vector<const Expr*> FlattenAssociativeChain(const Expr& root,
                                                 GetOperands&& get_operands) {
  std::vector<const Expr*> operands;
  std::vector<const Expr*> stack = {&root};
  while (!stack.empty()) {
    const Expr* expr = stack.back();
    stack.pop_back();
    if (auto children = get_operands(*expr); children.has_value()) {
      // Push the right operand first, so the left operand gets visited first.
      stack.push_back(children->second);
      stack.push_back(children->first);
    } else {
      operands.push_back(expr);
    }
  }
  return operands;
}

// Returns `operands[0] * operands[1] * ... * operands[n-1]`, where `*` is the
// given associative binary operation `combine`, evaluated as a balanced binary
// tree. Preserves the order of the operands, so `combine` need not be
// commutative. Requires `operands` to be non-empty.
template <class T, class Combine>
T CombineBalanced(std::vector<T> operands, Combine&& combine) {
  CHECK(!operands.empty());  // Crash OK.
  while (operands.size() > 1) {
    size_t num_combined = 0;
    for (size_t i = 0; i + 1 < operands.size(); i += 2) {
      operands[num_combined++] = combine(operands[i], operands[i + 1]);
    }
    if (operands.size() % 2 == 1) {
      operands[num_combined++] = std::move(operands.back());
    }
    operands.resize(num_combined);
  }
  return std::move(operands[0]);
}

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_ASSOCIATIVE_CHAIN_H_
