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
// File: table.h
// -----------------------------------------------------------------------------
//
// This file contains the definition for building match-action tables in
// NetKAT.

#ifndef GOOGLE_NETKAT_NETKAT_TABLE_H_
#define GOOGLE_NETKAT_NETKAT_TABLE_H_

#include <functional>
#include <utility>
#include <vector>

#include "absl/container/btree_map.h"
#include "absl/status/status.h"
#include "netkat/frontend.h"

namespace netkat {

// Represents a prioritized match-action table of some networking switch using
// NetKAT. Rules will be prioritized in descending order. Policy should
// generally limit matches and mutations of packets based on the capabilities of
// the table/switch this intends to reflect.
//
// For any given packet, it is required that it be modified by at most one
// unique action in the table. See `AddRule` for more details.
//
// `TableContraint`s may be added to enforce additional expectations on each
// rule. See `NetkatTable::NetkatTable` for more information.
class NetkatTable {
 public:
  // Returns a NetKAT Table as described above.
  //
  // Additionally, a list of TableConstraints may be provided such that each
  // rule added will be evaluated against each constraint prior to adding.
  //
  // Each constraint will be given the new match/action, the current
  // match/policy of the given priority, or null if this is the first
  // entry, and the priority. A constraint must return an error detailing the
  // cause of the violation or OK if there is none.
  //
  // Note that `current_policy` will be the total policy of the table. E.g. for
  // some (p1_match, p1_action), (p2_match, p2_action) this will be:
  //
  //   p1_match·p1_action + p2_match·p2_action
  //
  // While `current_match` will be the union of the matches. E.g.
  //
  //   p1_match + p2_match
  //
  // Rules will only be added if they conform to all constraints.
  struct PendingRuleInfo {
    // The priority the rule is being added for.
    int priority;

    // Note the new match/action are guaranteed non-null.
    const Predicate* new_match;
    const Policy* new_action;

    const Predicate* current_match;
    const Policy* current_policy;
  };
  using TableConstraint = std::function<absl::Status(const PendingRuleInfo&)>;
  explicit NetkatTable(std::vector<TableConstraint> constraints = {});

  // Adds a match-action into the table, at the given priority. For example, if
  // this were to represent a VRF table then a possible rule would be:
  //
  //   AddRule(Match("ip_tos", kCs4Tos), Modify("vrf", 114), /*priority=*/1136);
  //
  // For any predicate p1 and p2 which share a given priority, it is required
  // that either: no packet matches both p1 and p2 OR p1_action and p2_action
  // mutate the packet equivalently. More formally,
  //
  //   p1 && p2 ≡ False OR p1·p2·p1_action ≡ p1·p2·p2_action
  //
  // This ensures that a packet will always match exactly one rule in the
  // table. Note that it is OK for any given rule to have ambiguity in its
  // action, e.g. setting egress ports.
  //
  // For any predicate p1 and p2 that *does not* share a given priority, the
  // rules will be eventually merged such that higher priority rules are ordered
  // first. See `GetPolicy` for more information.
  //
  // `action` must also not restrict packets further than `match` and should be
  // used exclusively for modifications. I.e., `action` must have no
  // `Predicate`s present in its policy.
  //
  // Finally, the rule is only added if each of the configured
  // `TableConstraint`s are met.
  //
  // TODO(anthonyroy): Consider a more API-friendly way to disallow `action`
  // from being more restrictive than `match`.
  absl::Status AddRule(Predicate match, Policy action, int priority);

  // Returns the resulting unified policy of all added rules in the NetkatTable.
  // The returned policy will emulate a priority based match-action table of a
  // switch. E.g. if p1 priority > p2 priority > p3 priority, the resulting
  // policy will be equiavent to:
  //
  //   p1·p1_action + !p1·p2·p2_action + !p1·!p2·p3·p3_action
  //
  // Note that while priority order is respected, the order in which the rules
  // were added will not necessarily be.
  Policy GetPolicy() const&;
  Policy GetPolicy() &&;

 private:
  // The list of constraints/policies each to-be-added rule must conform to.
  std::vector<TableConstraint> constraints_;

  // The rules in order of priority.
  //
  // For each <predicate, policy> pair, predicate represents the union of each
  // predicate seen at the same priority thus far. E.g.
  //
  //   predicate = p1_match || p2_match || ...
  //
  // The policy represents the true policy of this priority. E.g. for some
  // (p1_match, p1_action), (p2_match, ...), ..., then
  //
  //   policy = p1_match·p1_action + p2_match·p2_action + ...
  //
  // Note that we utilize the predicate to later build the priority-ordered
  // table policy.
  absl::btree_map<int, std::pair<Predicate, Policy>> rules_;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_TABLE_H_
