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
// This file contains the definitions for modeling match-action tables in
// NetKAT. Modeling tables in NetKAT enables reasoning about them using the
// NetKAT framework, e.g. via the `AnalysisEngine`.

#ifndef GOOGLE_NETKAT_NETKAT_TABLE_H_
#define GOOGLE_NETKAT_NETKAT_TABLE_H_

#include <functional>
#include <utility>
#include <vector>

#include "absl/container/btree_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "netkat/frontend.h"
#include "netkat/packet_transformer.h"

namespace netkat {

// Represents a prioritized match-action table of some networking switch using
// NetKAT. Rules will be prioritized in descending order, i.e. higher is better.
// Policy should generally limit matches and mutations of packets based on the
// capabilities of the table/switch this intends to model.
//
// For any given packet, this class requires that it be modified by at most one
// unique action in the table. See `AddRule` for more details.
//
// `TableContraint`s may be added to enforce additional expectations on each
// rule. See the constructor for more information.
class NetkatTable {
 public:
  // Information provided to `TableConstraint` for rule evaluation.
  struct PendingRuleInfo {
    // The priority the rule is being added for.
    int priority;

    // The predicate and policy of the rule to be added. Note that the lifetimes
    // are bound to the given `AddRule` call and should not be held longer than
    // the duration of the callback.
    const Predicate& new_match;
    const Policy& new_action;

    // Represents the union of all matches currently in the table at the given
    // priority. This will be nullptr if this is the first rule to be added in
    // this priority.
    const Predicate* existing_match;

    // Represents the total policy of the table, at this priority.
    //
    // E.g. for some previously added (p1_match, p1_action), (p2_match,
    // p2_action), this will be: p1_match; p1_action + p2_match; p2_action
    const Policy* existing_policy;
  };

  // A functor that represents some constraint to be applied or evaluated
  // against a pending rule of the table. The constraint must return either an
  // error detailing the cause of the violation or OK if there is none.
  using TableConstraint = std::function<absl::Status(const PendingRuleInfo&)>;

  // Returns an empty NetKAT Table as described above.
  //
  // A list of TableConstraints may be provided. Each rule will be evaluated
  // against `constraints` prior to being added. Rules will only be added if
  // they conform to all constraints.
  //
  // `accept_default` will determine what the default action of the table is,
  // i.e. either Accept or Deny. See `GetPolicy` for more information.
  explicit NetkatTable(std::vector<TableConstraint> constraints = {},
                       bool accept_default = false);

  // Copyable and movable. Note that `PacketTransformerManager` is not copyable
  // so we simply create a new one.
  //
  // TODO(anthonyroy): Consider a way to better deal with copy-ability of
  // `PacketTransformerManager`.
  NetkatTable(const NetkatTable&);
  NetkatTable& operator=(const NetkatTable&);
  NetkatTable(NetkatTable&&) = default;
  NetkatTable& operator=(NetkatTable&&) = default;

  // Adds a match-action rule into the table, at the given priority. For
  // example, if this were to represent a VRF table then a possible rule would
  // be:
  //
  //   AddRule(Match("ip_tos", kCs4Tos), Modify("vrf", 114), /*priority=*/1136);
  //
  // For any given (match1,action1) and (match2, action2) which share a given
  // priority, it is required that either: no packet matches both match1 and
  // match2 OR action1 and action2 mutate such a packet equivalently. More
  // formally,
  //
  //   match1 && match2 ≡ False OR
  //   match1; match2; action1 ≡ match1; match2; action2
  //
  // This ensures that a packet will always produce exactly one possible output
  // packet. Note that it is OK for any given rule to have a disjunction in its
  // action, e.g. setting multiple possible output ports for one match.
  //
  // For any two predicates that *do not* share a given priority, the rules will
  // be eventually merged such that higher priority rules are ordered first. See
  // `GetPolicy` for more information.
  //
  // With the exception of the `Deny` policy, `action` must also not restrict
  // packets further than `match` and should be used exclusively for
  // modifications. I.e., `action` must have no `Predicate`s, except `False`,
  // present in its policy.
  //
  // Finally, each rule must meet any and all configured `TableConstraint`s. If
  // a rule fails to meet any of the requirements above it will not be added and
  // an appropriate error will be returned. Otherwise, the rule will be added
  // and an OkStatus returned.
  //
  // TODO(anthonyroy): Consider a more API-friendly way to disallow `action`
  // from being more restrictive than `match`.
  absl::Status AddRule(int priority, Predicate match, Policy action);

  // Returns a unified policy representing all rules in the NetkatTable. The
  // returned policy will emulate a priority based match-action table of a
  // switch. E.g. for rules r1, r2, r3, if priority(r1) > priority(r2) >
  // priority(r3), the resulting policy will be equivalent to:
  //
  //   match(r1); action(r1) +
  //   !match(r1); match(r2); action(r2) +
  //   !match(r1); !match(r2); match(r3); action(r3)
  //
  // If the table is empty, this will return `Policy::Accept()` if
  // `accept_default` is true, else `Policy::Deny()`. Similarly, any packet
  // that does not match any policy in the table will have the same logic
  // applied.
  //
  // TODO(anthonyroy): Consider adding configurability for misses. This assumes
  // the table is explicitly deny/allow-list based. The caveat is that any "on
  // miss" action must be subject to the same constraints as the table is
  // globally.
  Policy GetPolicy() const&;
  Policy GetPolicy() &&;

  // Attempts to merge `rhs` into `lhs`. Returns an error if any rule in
  // `rhs` conflicts with any rule in `lhs`.
  //
  // This may be used to build independent tables and merge them later.
  //
  // Note that only the properties of `lhs` will be used. For example, if
  // merging rules from `lhs` into `rhs` would cause an error but the reverse is
  // OK, this will return OK. Therefore it is recommended to only merge tables
  // with similar constraints.
  //
  // TODO(anthonyroy): Reconsider how to exactly merge. It may be better to
  // require that `lhs` and `rhs` have the same constraints.
  static absl::StatusOr<NetkatTable> Merge(NetkatTable lhs, NetkatTable rhs);

 private:
  // Whether the default action should be Accept or Deny.
  bool accept_default_;

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
  //   policy = p1_match; p1_action + p2_match; p2_action + ...
  //
  // Note that we utilize the predicate to later build the priority-ordered
  // table policy.
  absl::btree_map<int, std::pair<Predicate, Policy>> rules_;

  // The raw rules, in order of priority, as added by `AddRule`.
  // TODO(anthonyroy): Replace/create a MatchAction struct for Predicate+Policy.
  absl::btree_map<int, std::vector<std::pair<Predicate, Policy>>> raw_rules_;

  // Manager for evaluating policy against constraints. E.g. rule determinism.
  PacketTransformerManager policy_manager_;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_TABLE_H_
