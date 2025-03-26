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
// File: table.cc
// -----------------------------------------------------------------------------
#include "netkat/table.h"

#include <iterator>
#include <utility>
#include <vector>

#include "absl/container/btree_map.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "netkat/frontend.h"

namespace netkat {
namespace {

// Walks the underlying policy in `action` and returns an error if a `Filter`
// policy is present.
//
// TODO(anthonyroy): Can we make this IR-unaware?
absl::Status VerifyActionHasNoPredicate(const Policy& new_action) {
  std::vector<const PolicyProto*> stack = {&new_action.GetProto()};
  while (!stack.empty()) {
    const PolicyProto* policy = stack.back();
    stack.pop_back();

    if (policy->has_filter()) {
      return absl::InvalidArgumentError(
          absl::StrCat("Policy has predicate: ", *policy));
    }

    if (policy->has_iterate_op()) {
      stack.push_back(&policy->iterate_op().iterable());
    } else if (policy->has_sequence_op()) {
      stack.push_back(&policy->sequence_op().left());
      stack.push_back(&policy->sequence_op().right());
    } else if (policy->has_union_op()) {
      stack.push_back(&policy->union_op().left());
      stack.push_back(&policy->union_op().right());
    }
  }
  return absl::OkStatus();
}

// Returns whether or not the new vs old rules maintain determinism. I.e. this
// enforces the p1 && p2 ≡ False OR p1·p2·p1_action ≡ p1·p2·p2_action
// requirement.
//
// TODO(anthonyroy): Finish implementing this once the backend is complete.
absl::Status VerifyRuleDeterminism(const NetkatTable::PendingRuleInfo& info) {
  if (info.current_match == nullptr || info.current_policy == nullptr) {
    return absl::OkStatus();
  }

  // TODO(anthonyroy): Add this once we've completed SymbolicPacket et al.
  // Something like:
  // if (Sympacket(new_match).And(Sympacket(current_match)) == EmptySet)
  //   return OK
  //
  // const bool deterministic =
  //   Sympacket(Sequence(new_match, current_match, new_action)) ==
  //   Sympacket(Sequence(new_match, current_match, current_policy));
  // if (!deterministic) return InvalidArgumentError(...);
  return absl::OkStatus();
}

// Returns the priority-unioned policy based on `GetPolicy`.
Policy GetPolicyInternal(
    absl::btree_map<int, std::pair<Predicate, Policy>> rules) {
  if (rules.empty()) return Policy::Deny();

  // We want to translate the rules in each priority into a statement that is
  // equivalent to:
  //
  //   p1; p1_action + !p1; p2; p2_action + !p1; !p2; p3; p3_action + ...
  //
  // However, that will cause N^2 matches to be generated. Instead, we simplify
  // the expression to:
  //
  //   p1·p1_action + !p1·(p2·p2_action + !p2·(...))
  //
  // TODO(anthonyroy): Will proto unmarshalling limits get in the way here?
  Policy final_policy = std::move(rules.begin()->second.second);
  for (auto it = std::next(rules.begin()); it != rules.end(); ++it) {
    auto& [match, policy] = it->second;
    final_policy = Union(std::move(policy), Sequence(Filter(!std::move(match)),
                                                     std::move(final_policy)));
  }
  return final_policy;
}

}  // namespace

NetkatTable::NetkatTable(std::vector<TableConstraint> constraints)
    : constraints_(std::move(constraints)) {
  // TODO(anthonyroy): Consider an unsafe variant that only performs these
  // checks in DEBUG builds.
  constraints_.push_back([](const PendingRuleInfo& info) {
    return VerifyActionHasNoPredicate(*info.new_action);
  });
  constraints_.push_back(VerifyRuleDeterminism);
}

absl::Status NetkatTable::AddRule(Predicate match, Policy action,
                                  int priority) {
  auto [it, inserted] =
      rules_.try_emplace(priority, std::move(match), std::move(action));

  auto& [current_match, current_action] = it->second;
  PendingRuleInfo info;
  if (inserted) {
    info = {.priority = priority,
            .new_match = &current_match,
            .new_action = &current_action,
            .current_match = nullptr,
            .current_policy = nullptr};
  } else {
    info = {.priority = priority,
            .new_match = &match,
            .new_action = &action,
            .current_match = &current_match,
            .current_policy = &current_action};
  }
  for (TableConstraint& constraint : constraints_) {
    absl::Status status = constraint(info);
    if (!status.ok()) {
      if (inserted) rules_.erase(it);
      return status;
    }
  }

  // If this is the first rule in the priority band, the action does not yet
  // include the match.
  if (inserted) {
    current_action = Sequence(Filter(current_match), std::move(current_action));
    return absl::OkStatus();
  }

  current_match = std::move(current_match) || match;
  current_action = Union(std::move(current_action),
                         Sequence(Filter(std::move(match)), std::move(action)));
  return absl::OkStatus();
}

Policy NetkatTable::GetPolicy() const& { return GetPolicyInternal(rules_); }
Policy NetkatTable::GetPolicy() && {
  return GetPolicyInternal(std::move(rules_));
}

}  // namespace netkat
