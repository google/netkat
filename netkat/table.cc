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

#include <utility>
#include <vector>

#include "absl/container/btree_map.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "gutil/status.h"
#include "netkat/frontend.h"
#include "netkat/netkat.pb.h"
#include "netkat/packet_set.h"
#include "netkat/packet_transformer.h"

namespace netkat {
namespace {

// Walks the underlying policy in `action` and returns an error if a `Filter`
// policy is present.
//
// TODO(anthonyroy): Can we make this IR-unaware? Maybe add it to the backend?
absl::Status VerifyActionHasNoPredicate(const Policy& action) {
  std::vector<const PolicyProto*> stack = {&action.GetProto()};
  while (!stack.empty()) {
    const PolicyProto* policy = stack.back();
    stack.pop_back();

    switch (policy->policy_case()) {
      case PolicyProto::PolicyCase::kIterateOp:
        stack.push_back(&policy->iterate_op().iterable());
        break;
      case PolicyProto::PolicyCase::kUnionOp:
        stack.push_back(&policy->union_op().left());
        stack.push_back(&policy->union_op().right());
        break;
      case PolicyProto::PolicyCase::kSequenceOp:
        stack.push_back(&policy->sequence_op().left());
        stack.push_back(&policy->sequence_op().right());
        break;
      case PolicyProto::PolicyCase::kFilter:
        // Allow the Deny policy.
        if (policy->filter().has_bool_constant() &&
            policy->filter().bool_constant().value() == false) {
          continue;
        }
        return absl::InvalidArgumentError(
            absl::StrCat("Action contains predicate: ", *policy));
      case PolicyProto::PolicyCase::kPushOp:
      case PolicyProto::PolicyCase::kModification:
      case PolicyProto::PolicyCase::kRecord:
        break;
      case PolicyProto::PolicyCase::POLICY_NOT_SET:
        return absl::InvalidArgumentError(
            absl::StrCat("Policy case missing: ", *policy));
    }
  }
  return absl::OkStatus();
}

// Returns whether or not the new vs old rules maintain determinism. I.e. this
// enforces the p1 && p2 ≡ False OR p1; p2; p1_action ≡ p1; p2; p2_action
// requirement.
//
// This is only run against rules of the same priority.
absl::Status VerifyRuleDeterminism(const NetkatTable::PendingRuleInfo& info,
                                   PacketTransformerManager& policy_manager) {
  if (info.existing_match == nullptr || info.existing_policy == nullptr) {
    return absl::OkStatus();
  }

  PacketSetManager& packet_set_manager = policy_manager.GetPacketSetManager();
  PacketSetHandle new_packet =
      packet_set_manager.Compile(info.new_match.GetProto());
  PacketSetHandle old_packet =
      packet_set_manager.Compile(info.existing_match->GetProto());
  PacketSetHandle new_and_old = packet_set_manager.And(new_packet, old_packet);
  if (new_and_old == packet_set_manager.EmptySet()) {
    return absl::OkStatus();
  }

  PacketTransformerHandle new_and_old_policy =
      policy_manager.FromPacketSetHandle(new_and_old);
  PacketTransformerHandle with_new_action = policy_manager.Sequence(
      new_and_old_policy, policy_manager.Compile(info.new_action.GetProto()));
  PacketTransformerHandle with_old_action = policy_manager.Sequence(
      new_and_old_policy,
      policy_manager.Compile(info.existing_policy->GetProto()));
  if (with_new_action != with_old_action) {
    return absl::InvalidArgumentError("New rule collides with existing rule.");
  }
  return absl::OkStatus();
}

// Returns the priority-unioned policy based on `GetPolicy`.
Policy GetPolicyInternal(
    absl::btree_map<int, std::pair<Predicate, Policy>> rules,
    Policy default_action) {
  if (rules.empty()) return default_action;

  // We want to translate the rules in each priority into a statement that is
  // equivalent to:
  //
  //   p1; p1_action + !p1; p2; p2_action + !p1; !p2; p3; p3_action + ...
  //
  // However, that will cause N^2 matches to be generated. Instead, we simplify
  // the expression to:
  //
  //   p1; p1_action + !p1; (p2; p2_action + !p2; (...))
  //
  // Note that rules is in non-descending order, which we want to be the most
  // guarded match.
  //
  // TODO(anthonyroy): Will proto unmarshalling limits get in the way here?
  Policy final_policy = std::move(default_action);
  for (auto it = rules.begin(); it != rules.end(); ++it) {
    auto& [match, policy] = it->second;
    final_policy = Union(std::move(policy), Sequence(Filter(!std::move(match)),
                                                     std::move(final_policy)));
  }
  return final_policy;
}

}  // namespace

NetkatTable::NetkatTable(std::vector<TableConstraint> constraints,
                         bool accept_default)
    : accept_default_(accept_default), constraints_(std::move(constraints)) {
  // TODO(anthonyroy): Consider an unsafe variant that only performs these
  // checks in DEBUG builds.
  constraints_.push_back([](const PendingRuleInfo& info) {
    return VerifyActionHasNoPredicate(info.new_action);
  });
  constraints_.push_back([this](const PendingRuleInfo& info) {
    return VerifyRuleDeterminism(info, policy_manager_);
  });
}

NetkatTable::NetkatTable(const NetkatTable& other)
    : accept_default_(other.accept_default_),
      constraints_(other.constraints_),
      rules_(other.rules_),
      raw_rules_(other.raw_rules_) {}

NetkatTable& NetkatTable::operator=(const NetkatTable& other) {
  if (this == &other) return *this;
  accept_default_ = other.accept_default_;
  constraints_ = other.constraints_;
  rules_ = other.rules_;
  raw_rules_ = other.raw_rules_;
  return *this;
}

absl::Status NetkatTable::AddRule(int priority, Predicate match,
                                  Policy action) {
  auto [it, inserted] =
      rules_.try_emplace(priority, std::move(match), std::move(action));

  auto& [current_match, current_action] = it->second;
  PendingRuleInfo info = {
      .priority = priority,
      .new_match = inserted ? current_match : match,
      .new_action = inserted ? current_action : action,
      .existing_match = inserted ? nullptr : &current_match,
      .existing_policy = inserted ? nullptr : &current_action};
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
    raw_rules_[priority].push_back({current_match, current_action});
    current_action = Sequence(Filter(current_match), std::move(current_action));
    return absl::OkStatus();
  }

  raw_rules_[priority].push_back({match, action});
  current_match = std::move(current_match) || match;
  current_action = Union(std::move(current_action),
                         Sequence(Filter(std::move(match)), std::move(action)));
  return absl::OkStatus();
}

Policy NetkatTable::GetPolicy() const& {
  return GetPolicyInternal(rules_,
                           accept_default_ ? Policy::Accept() : Policy::Deny());
}
Policy NetkatTable::GetPolicy() && {
  return GetPolicyInternal(std::move(rules_),
                           accept_default_ ? Policy::Accept() : Policy::Deny());
}

absl::StatusOr<NetkatTable> NetkatTable::Merge(NetkatTable lhs,
                                               NetkatTable rhs) {
  for (const auto& [priority, rules] : rhs.raw_rules_) {
    for (const auto& [match, action] : rules) {
      RETURN_IF_ERROR(lhs.AddRule(priority, match, action));
    }
  }
  return lhs;
}

}  // namespace netkat
