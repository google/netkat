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

#include "netkat/packet_transformer.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <new>
#include <optional>
#include <queue>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/container/fixed_array.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/container/inlined_vector.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "gutil/status.h"
#include "netkat/associative_chain.h"
#include "netkat/field_order.h"
#include "netkat/netkat.pb.h"
#include "netkat/packet.h"
#include "netkat/packet_field.h"
#include "netkat/packet_set.h"
#include "netkat/packet_set_handle.h"
#include "netkat/packet_transformer_handle.h"
#include "netkat/sorted_vector_map.h"

namespace netkat {

PacketTransformerManager::PacketTransformerManager()
    : packet_set_manager_(*this) {}

PacketTransformerManager::PacketTransformerManager(
    PacketTransformerManager&& other)
    : nodes_(std::move(other.nodes_)),
      node_storage_(std::move(other.node_storage_)),
      transformer_by_hash_(std::move(other.transformer_by_hash_)),
      union_cache_(std::move(other.union_cache_)),
      sequence_cache_(std::move(other.sequence_cache_)),
      difference_cache_(std::move(other.difference_cache_)),
      iterate_cache_(std::move(other.iterate_cache_)),
      from_packet_set_cache_(std::move(other.from_packet_set_cache_)),
      get_all_possible_outputs_cache_(
          std::move(other.get_all_possible_outputs_cache_)),
      get_all_inputs_cache_(std::move(other.get_all_inputs_cache_)),
      packet_set_manager_(std::move(other.packet_set_manager_)) {
  packet_set_manager_.transformer_ = this;
}

PacketTransformerManager& PacketTransformerManager::operator=(
    PacketTransformerManager&& other) {
  if (this != &other) {
    nodes_ = std::move(other.nodes_);
    node_storage_ = std::move(other.node_storage_);
    transformer_by_hash_ = std::move(other.transformer_by_hash_);
    union_cache_ = std::move(other.union_cache_);
    sequence_cache_ = std::move(other.sequence_cache_);
    difference_cache_ = std::move(other.difference_cache_);
    iterate_cache_ = std::move(other.iterate_cache_);
    from_packet_set_cache_ = std::move(other.from_packet_set_cache_);
    get_all_possible_outputs_cache_ =
        std::move(other.get_all_possible_outputs_cache_);
    get_all_inputs_cache_ = std::move(other.get_all_inputs_cache_);
    packet_set_manager_ = std::move(other.packet_set_manager_);
    packet_set_manager_.transformer_ = this;
  }
  return *this;
}

const PacketTransformerManager::DecisionNode&
PacketTransformerManager::GetNodeOrDie(
    PacketTransformerHandle transformer) const {
  CHECK_LT(transformer.node_index_, nodes_.size());  // Crash ok
  return nodes_[transformer.node_index_];
}

const PacketTransformerManager::ModifyEntry*
PacketTransformerManager::ModifyMapView::find(int modify_value) const {
  const ModifyEntry* it =
      std::lower_bound(begin(), end(), modify_value,
                       [](const ModifyEntry& entry, int modify_value) {
                         return entry.first < modify_value;
                       });
  return it != end() && it->first == modify_value ? it : end();
}

std::optional<PacketTransformerManager::ModifyMapView>
PacketTransformerManager::MatchBranchesView::Find(int match_value) const {
  const MatchBranch* it =
      std::lower_bound(branches_.begin(), branches_.end(), match_value,
                       [](const MatchBranch& branch, int match_value) {
                         return branch.match_value < match_value;
                       });
  if (it == branches_.end() || it->match_value != match_value) {
    return std::nullopt;
  }
  return MapOf(it);
}

template <class T>
T* PacketTransformerManager::NodeStorage::Allocate(size_t n) {
  static_assert(std::is_trivially_destructible_v<T>);
  static_assert(alignof(std::max_align_t) % alignof(T) == 0);
  if (n == 0) return nullptr;
  const size_t size = n * sizeof(T);
  // Large requests get a block of their own, to avoid wasting the remainder of
  // the current block.
  if (size > kBlockSize / 8) {
    blocks_.push_back(std::make_unique_for_overwrite<std::byte[]>(size));
    return reinterpret_cast<T*>(blocks_.back().get());
  }
  const size_t padding =
      (alignof(T) - reinterpret_cast<uintptr_t>(next_) % alignof(T)) %
      alignof(T);
  if (next_ == nullptr || padding + size > remaining_) {
    blocks_.push_back(std::make_unique_for_overwrite<std::byte[]>(kBlockSize));
    next_ = blocks_.back().get();
    remaining_ = kBlockSize;
  } else {
    next_ += padding;
    remaining_ -= padding;
  }
  T* result = reinterpret_cast<T*>(next_);
  next_ += size;
  remaining_ -= size;
  return result;
}

class PacketTransformerManager::MapAtValueCursor {
 public:
  MapAtValueCursor(const PacketTransformerManager& manager,
                   const DecisionNode& node)
      : match_branches_(node.modify_branch_by_field_match()),
        defaults_(node.default_branch_by_field_modification()),
        default_branch_(node.default_branch),
        default_branch_is_deny_(manager.IsDeny(node.default_branch)),
        match_it_(match_branches_.branches().begin()) {}

  // Calls `f(modify_value, branch)` for each entry of the map at `value`, in
  // increasing order of `modify_value`, without materializing the map.
  template <class F>
  void ForEachEntry(int value, F&& f) {
    if (std::optional<ModifyMapView> map = FindMatchBranch(value)) {
      for (const auto& [modify_value, branch] : *map) f(modify_value, branch);
    } else {
      ForEachDefaultEntry(value, f);
    }
  }

  // Returns the map at `value`. To avoid copies, returns a view into the node
  // whenever possible, or else a view of `scratch` (which gets overwritten).
  ModifyMapView Get(int value, ModifyMap& scratch) {
    if (std::optional<ModifyMapView> map = FindMatchBranch(value)) return *map;
    if (default_branch_is_deny_ || defaults_.contains(value)) return defaults_;
    scratch.clear();
    ForEachDefaultEntry(value,
                        [&](int modify_value, PacketTransformerHandle branch) {
                          scratch.insert(scratch.end(), {modify_value, branch});
                        });
    return scratch;
  }

  // Returns the match branch for `value`, or nullopt if there is none.
  std::optional<ModifyMapView> FindMatchBranch(int value) {
    const absl::Span<const MatchBranch> branches = match_branches_.branches();
    if (branches.empty() || value < branches.front().match_value ||
        value > branches.back().match_value) {
      return std::nullopt;
    }
    auto key_less = [](const MatchBranch& branch, int value) {
      return branch.match_value < value;
    };
    if (match_it_ != branches.begin() &&
        (match_it_ - 1)->match_value >= value) {
      // Non-monotone access: search backwards.
      match_it_ =
          std::lower_bound(branches.begin(), match_it_, value, key_less);
    } else {
      // Monotone access: search forwards, linearly for short distances.
      constexpr int kMaxLinearSteps = 8;
      for (int steps = 0;
           match_it_ != branches.end() && match_it_->match_value < value;
           ++steps) {
        if (steps == kMaxLinearSteps) {
          match_it_ =
              std::lower_bound(match_it_, branches.end(), value, key_less);
          break;
        }
        ++match_it_;
      }
    }
    if (match_it_ == branches.end() || match_it_->match_value != value) {
      return std::nullopt;
    }
    return match_branches_.MapOf(match_it_);
  }

  // Calls `f` on each entry of `default_branch_by_field_modification`, plus a
  // mapping from `value` to the default branch, unless the former contains
  // `value` or the latter is Deny.
  template <class F>
  void ForEachDefaultEntry(int value, F&& f) const {
    bool pending = !default_branch_is_deny_;
    for (const auto& [modify_value, branch] : defaults_) {
      if (pending && modify_value >= value) {
        pending = false;
        if (modify_value != value) f(value, default_branch_);
      }
      f(modify_value, branch);
    }
    if (pending) f(value, default_branch_);
  }

 private:
  const MatchBranchesView match_branches_;
  const ModifyMapView defaults_;
  const PacketTransformerHandle default_branch_;
  const bool default_branch_is_deny_;
  // Points to the first match branch whose value is >= the last looked up
  // value.
  const MatchBranch* match_it_;
};

namespace {

// Returns true iff `map` is equal to `other_map` plus the additional entry
// (`value`, `branch`), assuming `value` is not a key of `other_map`.
template <class Map>
bool IsEqualToMapPlusEntry(const Map& map, const Map& other_map, int value,
                           PacketTransformerHandle branch) {
  if (map.size() != other_map.size() + 1) return false;
  auto other_it = other_map.begin();
  for (const auto& entry : map) {
    if (entry.first == value) {
      if (entry.second != branch) return false;
      continue;
    }
    if (other_it == other_map.end() || entry != *other_it) return false;
    ++other_it;
  }
  return true;
}

}  // namespace

// Canonicalizes a decision node and returns a transformer.
PacketTransformerHandle PacketTransformerManager::NodeToTransformer(
    DecisionNodeBuilder&& node) {
  auto is_deny = [&](const auto& entry) { return IsDeny(entry.second); };

  // Remove any default branches pointing to Deny, saving the value.
  absl::InlinedVector<int, 4> deny_values;
  for (const auto& [modify_value, branch] :
       node.default_branch_by_field_modification) {
    if (IsDeny(branch)) deny_values.push_back(modify_value);
  }
  if (!deny_values.empty()) {
    erase_if(node.default_branch_by_field_modification, is_deny);

    // For any value removed above, ensure it is either already in
    // `modify_branch_by_field_match` or add it, pointing to the remaining
    // `default_branch_by_field_modification`.
    for (const int value : deny_values) {
      node.modify_branch_by_field_match.try_emplace(
          value, node.default_branch_by_field_modification);
    }
  }

  // For every match branch, remove any modification branches pointing to Deny,
  // and remove any redundant match branches (i.e. values that carry the same
  // semantics as the default modification and default branch).
  const bool skip_default_branch = IsDeny(node.default_branch);
  auto default_it = node.default_branch_by_field_modification.begin();
  const auto default_end = node.default_branch_by_field_modification.end();
  erase_if(node.modify_branch_by_field_match, [&](auto& entry) {
    auto& [match_value, modification_map] = entry;
    erase_if(modification_map, is_deny);
    while (default_it != default_end && default_it->first < match_value) {
      ++default_it;
    }
    const bool in_default_mods =
        default_it != default_end && default_it->first == match_value;
    if (skip_default_branch || in_default_mods) {
      // Compare the modification map to the default branch modification map,
      // considering the mapping redundant if they are the same.
      return modification_map == node.default_branch_by_field_modification;
    }
    // Otherwise, the mapping is redundant iff it is equal to the default
    // modification map plus a mapping from `match_value` to the default
    // branch.
    return IsEqualToMapPlusEntry(modification_map,
                                 node.default_branch_by_field_modification,
                                 match_value, node.default_branch);
  });

  if (node.modify_branch_by_field_match.empty() &&
      node.default_branch_by_field_modification.empty())
    return node.default_branch;

  // Only if the node is new, we copy it into its flat representation.
  auto [index, inserted] = nodes_.Intern(node, [&] {
    size_t num_modifications = node.default_branch_by_field_modification.size();
    for (const auto& [match_value, map] : node.modify_branch_by_field_match) {
      num_modifications += map.size();
    }
    MatchBranch* match_branches = node_storage_.Allocate<MatchBranch>(
        node.modify_branch_by_field_match.size());
    ModifyEntry* modifications =
        node_storage_.Allocate<ModifyEntry>(num_modifications);
    uint32_t num_match_branches = 0;
    uint32_t modifications_end = 0;
    for (const auto& [match_value, map] : node.modify_branch_by_field_match) {
      for (const ModifyEntry& entry : map) {
        new (&modifications[modifications_end++]) ModifyEntry(entry);
      }
      new (&match_branches[num_match_branches++]) MatchBranch{
          .match_value = match_value, .modifications_end = modifications_end};
    }
    for (const ModifyEntry& entry : node.default_branch_by_field_modification) {
      new (&modifications[modifications_end++]) ModifyEntry(entry);
    }
    return DecisionNode{
        .field = node.field,
        .default_branch = node.default_branch,
        .num_match_branches = num_match_branches,
        .num_modifications = modifications_end,
        .match_branches = match_branches,
        .modifications = modifications,
    };
  });
  LOG_IF(DFATAL,
         inserted && nodes_.size() > PacketTransformerHandle::kMinSentinel)
      << "Internal invariant violated: Proper and sentinel node indices must "
         "be disjoint. This indicates that we allocated more nodes than are "
         "supported (> 2^32 - 2).";
  return PacketTransformerHandle(index);
}

bool PacketTransformerManager::IsDeny(
    PacketTransformerHandle transformer) const {
  return transformer == Deny();
}

bool PacketTransformerManager::IsAccept(
    PacketTransformerHandle transformer) const {
  return transformer == Accept();
}

absl::flat_hash_set<Packet> RunWithNewValueThenReset(
    const PacketTransformerManager& manager,
    PacketTransformerHandle transformer, Packet& packet,
    absl::string_view field, int new_value) {
  // Record the original value of 'field' if it exists in 'packet'.
  std::optional<int> original_value;
  if (auto it = packet.find(field); it != packet.end()) {
    original_value = it->second;
  }

  // Set 'field' to 'new_value' for the duration of the Run call.
  // This will insert if 'field' doesn't exist, or update if it does.
  packet[field] = new_value;

  absl::flat_hash_set<Packet> result = manager.Run(transformer, packet);

  // Restore 'packet' to its original state regarding 'field'.
  if (original_value.has_value()) {
    // Field originally existed, restore its value.
    packet[field] = *original_value;
  } else {
    // Field did not originally exist, so remove the one we added.
    packet.erase(field);
  }
  return result;
}

absl::flat_hash_set<Packet> PacketTransformerManager::Run(
    PacketTransformerHandle transformer, Packet& packet) const {
  if (IsDeny(transformer)) return {};
  if (IsAccept(transformer)) return {packet};

  absl::flat_hash_set<Packet> result;
  const DecisionNode& node = GetNodeOrDie(transformer);
  const std::string& field =
      packet_set_manager_.field_manager_.GetFieldName(node.field);
  // If a field doesn't exist, it does not match any value.
  std::optional<int> initial_field_value;
  if (auto it = packet.find(field); it != packet.end()) {
    initial_field_value = it->second;
  }
  bool matched = false;
  if (initial_field_value.has_value()) {
    // If it exists, see if there is a value match for it and follow every
    // corresponding branch with value modified appropriately.
    if (std::optional<ModifyMapView> mod_map =
            node.modify_branch_by_field_match().Find(*initial_field_value)) {
      matched = true;
      for (const auto& [value, branch] : *mod_map) {
        result.merge(
            RunWithNewValueThenReset(*this, branch, packet, field, value));
      }
    }
  }

  // If the packet was matched by the above then the default branches don't
  // apply and we return.
  if (matched) return result;

  // Otherwise, follow the default branches.
  for (const auto& [value, branch] :
       node.default_branch_by_field_modification()) {
    // If the original packet already had this field with the same value as
    // this modified branch, then we should not also attempt the default
    // branch.
    if (initial_field_value.has_value() && *initial_field_value == value) {
      matched = true;
    }

    result.merge(RunWithNewValueThenReset(*this, branch, packet, field, value));
  }
  if (!matched) result.merge(Run(node.default_branch, packet));
  return result;
}

namespace {

// The operands of a prioritized rule `filter(match); action + filter(!negated_
// match); rest`. For a well-formed rule, `match` and `negated_match` are
// equivalent.
struct PrioritizedRuleOperands {
  const PredicateProto* match;
  const PolicyProto* action;
  const PredicateProto* negated_match;
  const PolicyProto* rest;
};

// Returns the operands of `policy` if it has the syntactic shape of a
// prioritized rule (see above), or `std::nullopt` otherwise.
std::optional<PrioritizedRuleOperands> GetPrioritizedRuleOperands(
    const PolicyProto& policy) {
  if (!policy.has_union_op()) return std::nullopt;
  const PolicyProto& matched = policy.union_op().left();
  const PolicyProto& unmatched = policy.union_op().right();
  if (!matched.has_sequence_op() || !unmatched.has_sequence_op()) {
    return std::nullopt;
  }
  const PolicyProto& match = matched.sequence_op().left();
  const PolicyProto& negated_match = unmatched.sequence_op().left();
  if (!match.has_filter() || !negated_match.has_filter() ||
      !negated_match.filter().has_not_op()) {
    return std::nullopt;
  }
  return PrioritizedRuleOperands{
      .match = &match.filter(),
      .action = &matched.sequence_op().right(),
      .negated_match = &negated_match.filter().not_op().negand(),
      .rest = &unmatched.sequence_op().right(),
  };
}

}  // namespace

std::optional<PacketTransformerHandle>
PacketTransformerManager::CompileIfPrioritizedRules(const PolicyProto& policy) {
  // Check cheaply, without compiling anything, if this is a long cascade.
  int num_rules = 0;
  for (const PolicyProto* rest = &policy;
       num_rules < kMinOperandsToRebalanceAssociativeChain; ++num_rules) {
    std::optional<PrioritizedRuleOperands> rule =
        GetPrioritizedRuleOperands(*rest);
    if (!rule.has_value()) break;
    rest = rule->rest;
  }
  if (num_rules < kMinOperandsToRebalanceAssociativeChain) return std::nullopt;

  // Collect the rules of the cascade. Iterative, so arbitrarily long cascades
  // are supported.
  std::vector<CompiledRule> rules;
  const PolicyProto* rest = &policy;
  while (std::optional<PrioritizedRuleOperands> rule =
             GetPrioritizedRuleOperands(*rest)) {
    PacketSetHandle match = packet_set_manager_.Compile(*rule->match);
    if (packet_set_manager_.Compile(*rule->negated_match) != match) break;
    rules.push_back(
        {.match = match, .action = CompileRecursively(*rule->action)});
    rest = rule->rest;
  }
  if (rules.empty()) return std::nullopt;
  return CompilePrioritizedRules(rules, CompileRecursively(*rest)).first;
}

std::pair<PacketTransformerHandle, PacketSetHandle>
PacketTransformerManager::CompilePrioritizedRules(
    absl::Span<const CompiledRule> rules, PacketTransformerHandle fallthrough) {
  DCHECK(!rules.empty());
  if (rules.size() == 1) {
    const CompiledRule& rule = rules.front();
    return {
        Union(Sequence(FromPacketSetHandle(rule.match), rule.action),
              Sequence(FromPacketSetHandle(packet_set_manager_.Not(rule.match)),
                       fallthrough)),
        rule.match};
  }
  const size_t num_high_priority_rules = rules.size() / 2;
  auto [high_priority_table, high_priority_matches] = CompilePrioritizedRules(
      rules.first(num_high_priority_rules), /*fallthrough=*/Deny());
  auto [low_priority_table, low_priority_matches] = CompilePrioritizedRules(
      rules.subspan(num_high_priority_rules), fallthrough);
  return {Union(high_priority_table,
                Sequence(FromPacketSetHandle(
                             packet_set_manager_.Not(high_priority_matches)),
                         low_priority_table)),
          packet_set_manager_.Or(high_priority_matches, low_priority_matches)};
}

PacketTransformerHandle PacketTransformerManager::Compile(
    const PolicyProto& policy) {
  packet_set_manager_.DeclareFields(
      HeuristicFieldOrder(absl::MakeConstSpan(&policy, 1)));
  return CompileRecursively(policy);
}

PacketTransformerHandle PacketTransformerManager::CompileRecursively(
    const PolicyProto& policy) {
  ProtoHashKey key = {.policy_case = policy.policy_case()};
  switch (policy.policy_case()) {
    case PolicyProto::kFilter:
      return Filter(policy.filter());
    case PolicyProto::kModification: {
      return Modification(policy.modification().field(),
                          policy.modification().value());
    }
    case PolicyProto::kRecord: {
      return Accept();
    }
    case PolicyProto::kSequenceOp: {
      key.lhs_child = CompileRecursively(policy.sequence_op().left());
      key.rhs_child = CompileRecursively(policy.sequence_op().right());
      auto it = transformer_by_hash_.find(key);
      if (it != transformer_by_hash_.end()) return it->second;
      return transformer_by_hash_[key] = Sequence(key.lhs_child, key.rhs_child);
    }
    case PolicyProto::kUnionOp: {
      if (std::optional<PacketTransformerHandle> table =
              CompileIfPrioritizedRules(policy)) {
        return *table;
      }
      auto get_operands = [](const PolicyProto& policy)
          -> std::optional<std::pair<const PolicyProto*, const PolicyProto*>> {
        if (!policy.has_union_op()) return std::nullopt;
        return std::make_pair(&policy.union_op().left(),
                              &policy.union_op().right());
      };
      if (IsLongAssociativeChain(policy, get_operands)) {
        // Compile long chains `p1 + p2 + ... + pn` as balanced trees, to avoid
        // quadratic compile times for degenerate (list-like) chains. See
        // `associative_chain.h`.
        std::vector<PacketTransformerHandle> operands;
        for (const PolicyProto* operand :
             FlattenAssociativeChain(policy, get_operands)) {
          operands.push_back(CompileRecursively(*operand));
        }
        return CombineBalanced(std::move(operands),
                               [this](PacketTransformerHandle left,
                                      PacketTransformerHandle right) {
                                 return Union(left, right);
                               });
      }
      key.lhs_child = CompileRecursively(policy.union_op().left());
      key.rhs_child = CompileRecursively(policy.union_op().right());
      auto it = transformer_by_hash_.find(key);
      if (it != transformer_by_hash_.end()) return it->second;
      return transformer_by_hash_[key] = Union(key.lhs_child, key.rhs_child);
    }
    case PolicyProto::kIterateOp: {
      key.lhs_child = CompileRecursively(policy.iterate_op().iterable());
      auto it = transformer_by_hash_.find(key);
      if (it != transformer_by_hash_.end()) return it->second;
      return transformer_by_hash_[key] = Iterate(key.lhs_child);
    }
    case PolicyProto::kDifferenceOp: {
      key.lhs_child = CompileRecursively(policy.difference_op().left());
      key.rhs_child = CompileRecursively(policy.difference_op().right());
      auto it = transformer_by_hash_.find(key);
      if (it != transformer_by_hash_.end()) return it->second;
      return transformer_by_hash_[key] =
                 Difference(key.lhs_child, key.rhs_child);
    }
    // By convention, uninitialized policies must be treated like the Deny
    // policy.
    case PolicyProto::POLICY_NOT_SET: {
      return Deny();
    }
  }
  LOG(DFATAL) << "Unhandled policy kind: " << policy.policy_case();
  return Deny();
}

PacketTransformerHandle PacketTransformerManager::Deny() const {
  return PacketTransformerHandle(PacketTransformerHandle::kDeny);
}

PacketTransformerHandle PacketTransformerManager::Accept() const {
  return PacketTransformerHandle(PacketTransformerHandle::kAccept);
}

PacketTransformerHandle PacketTransformerManager::FromPacketSetHandle(
    PacketSetHandle packet_set) {
  if (packet_set_manager_.IsEmptySet(packet_set)) return Deny();
  if (packet_set_manager_.IsFullSet(packet_set)) return Accept();

  if (auto it = from_packet_set_cache_.find(packet_set);
      it != from_packet_set_cache_.end()) {
    return it->second;
  }

  const PacketSetManager::DecisionNode& packet_node =
      packet_set_manager_.GetNodeOrDie(packet_set);
  // The branches of nodes reached via complemented handles get complemented.
  const bool complement = PacketSetManager::IsComplemented(packet_set);

  DecisionNodeBuilder transformer_node{
      .field = packet_node.field,
      // This starts out empty and will be populated below.
      .modify_branch_by_field_match = {},
      // Since packet sets are not modified, we don't want any default
      // field modification branches.
      .default_branch_by_field_modification = {},
      .default_branch = FromPacketSetHandle(PacketSetManager::ComplementIf(
          complement, packet_node.default_branch)),
  };

  transformer_node.modify_branch_by_field_match.reserve(
      packet_node.branch_by_field_value.size());
  for (const auto& [value, branch] : packet_node.branch_by_field_value) {
    PacketTransformerHandle transformer_branch =
        FromPacketSetHandle(PacketSetManager::ComplementIf(complement, branch));
    DCHECK(transformer_branch != transformer_node.default_branch);
    ModifyMap mod_map;
    if (!IsDeny(transformer_branch)) {
      mod_map.insert(mod_map.end(), {value, transformer_branch});
    }
    transformer_node.modify_branch_by_field_match.insert(
        transformer_node.modify_branch_by_field_match.end(),
        {value, std::move(mod_map)});
  }

  return from_packet_set_cache_[packet_set] =
             NodeToTransformer(std::move(transformer_node));
}

// TODO(dilo): There are efficiency improvements we could make here, like
// getting rid of predicates entirely and moving to a normalized form.
PacketTransformerHandle PacketTransformerManager::Filter(
    const PredicateProto& predicate) {
  return FromPacketSetHandle(packet_set_manager_.Compile(predicate));
}

PacketTransformerHandle PacketTransformerManager::Modification(
    absl::string_view field, int value) {
  return NodeToTransformer(DecisionNodeBuilder{
      .field = packet_set_manager_.field_manager_.GetOrCreatePacketFieldHandle(
          field),
      .modify_branch_by_field_match = {},
      .default_branch_by_field_modification = {{value, Accept()}},
      .default_branch = Deny(),
  });
}

namespace {

// Returns the map {k -> combine(left[k], right[k]) | k in left or right},
// where missing entries default to `default_value`. Linear time.
template <class Map, class LeftMap, class RightMap, class Combine>
Map CombineModifyBranches(const LeftMap& left, const RightMap& right,
                          Combine&& combine,
                          PacketTransformerHandle default_value) {
  Map result;
  result.reserve(std::max(left.size(), right.size()));
  auto left_it = left.begin();
  auto right_it = right.begin();
  while (left_it != left.end() || right_it != right.end()) {
    if (right_it == right.end() ||
        (left_it != left.end() && left_it->first < right_it->first)) {
      result.insert(result.end(),
                    {left_it->first, combine(left_it->second, default_value)});
      ++left_it;
    } else if (left_it == left.end() || right_it->first < left_it->first) {
      result.insert(result.end(), {right_it->first,
                                   combine(default_value, right_it->second)});
      ++right_it;
    } else {
      result.insert(result.end(), {left_it->first,
                                   combine(left_it->second, right_it->second)});
      ++left_it;
      ++right_it;
    }
  }
  return result;
}

// Specialization of `CombineModifyBranches` for `Union` with `default_value =
// Deny()`. Since `Union(x, Deny()) = x` and `Union(Deny(), y) = y`, entries
// present in only one map can be copied directly without calling `Union`, and
// empty operands short-circuit to a contiguous range copy.
template <class Map, class LeftMap, class RightMap>
Map UnionModifyBranches(PacketTransformerManager& manager, const LeftMap& left,
                        const RightMap& right) {
  if (left.empty()) return Map(right.begin(), right.end());
  if (right.empty()) return Map(left.begin(), left.end());
  Map result;
  result.reserve(std::max(left.size(), right.size()));
  auto left_it = left.begin();
  auto right_it = right.begin();
  while (left_it != left.end() && right_it != right.end()) {
    if (left_it->first < right_it->first) {
      result.insert(result.end(), *left_it);
      ++left_it;
    } else if (right_it->first < left_it->first) {
      result.insert(result.end(), *right_it);
      ++right_it;
    } else {
      result.insert(
          result.end(),
          {left_it->first, manager.Union(left_it->second, right_it->second)});
      ++left_it;
      ++right_it;
    }
  }
  for (; left_it != left.end(); ++left_it) {
    result.insert(result.end(), *left_it);
  }
  for (; right_it != right.end(); ++right_it) {
    result.insert(result.end(), *right_it);
  }
  return result;
}

// Returns the union of the keys of the given sorted maps, in increasing order.
// Uses linear merges, exploiting that the keys of each map are sorted.
template <class... Maps>
absl::InlinedVector<int, 16> MergedKeys(const Maps&... maps) {
  absl::InlinedVector<int, 16> keys, merged;
  auto merge_in = [&](const auto& map) {
    if (map.empty()) return;
    merged.clear();
    merged.reserve(keys.size() + map.size());
    auto it = keys.begin();
    for (const auto& [key, unused] : map) {
      while (it != keys.end() && *it < key) merged.push_back(*it++);
      if (it != keys.end() && *it == key) ++it;
      merged.push_back(key);
    }
    merged.insert(merged.end(), it, keys.end());
    keys.swap(merged);
  };
  (merge_in(maps), ...);
  return keys;
}

// Returns the map {k -> v_1 + ... + v_n | (k, v_1), ..., (k, v_n) in entries},
// where + is `combine`, applied left to right in the order in which the
// entries appear in `entries`. Sorts `entries` (stably) as a side effect.
//
// Compared to accumulating the entries into the map one by one, this avoids
// quadratic insertion costs and repeated binary searches.
template <class Map, class Entries, class Combine>
Map FoldIntoMap(Entries& entries, Combine&& combine) {
  auto key_less = [](const auto& a, const auto& b) {
    return a.first < b.first;
  };
  if (!absl::c_is_sorted(entries, key_less)) {
    absl::c_stable_sort(entries, key_less);
  }
  Map result;
  for (const auto& [key, value] : entries) {
    if (!result.empty() && std::prev(result.end())->first == key) {
      auto& accumulator = std::prev(result.end())->second;
      accumulator = combine(accumulator, value);
    } else {
      result.insert(result.end(), {key, value});
    }
  }
  return result;
}

}  // namespace

template <class F>
PacketTransformerHandle PacketTransformerManager::WithAlignedNodes(
    PacketTransformerHandle left, PacketTransformerHandle right, F&& f) {
  // NOTE: Nodes are pointer-stable, so references to them remain valid even as
  // new nodes are created by `f`.
  if (IsAccept(left)) {
    const DecisionNode& right_node = GetNodeOrDie(right);
    return f(DecisionNode{.field = right_node.field, .default_branch = left},
             right_node);
  }
  if (IsAccept(right)) {
    const DecisionNode& left_node = GetNodeOrDie(left);
    return f(left_node,
             DecisionNode{.field = left_node.field, .default_branch = right});
  }
  const DecisionNode& left_node = GetNodeOrDie(left);
  const DecisionNode& right_node = GetNodeOrDie(right);
  if (left_node.field < right_node.field) {
    return f(left_node,
             DecisionNode{.field = left_node.field, .default_branch = right});
  }
  if (left_node.field > right_node.field) {
    return f(DecisionNode{.field = right_node.field, .default_branch = left},
             right_node);
  }
  return f(left_node, right_node);
}

template <class F>
PacketTransformerHandle PacketTransformerManager::MapBranches(
    const DecisionNode& node, F&& f) {
  DecisionNodeBuilder result_node{
      .field = node.field,
      .default_branch = f(node.default_branch),
  };
  result_node.modify_branch_by_field_match.reserve(
      node.modify_branch_by_field_match().size());
  for (const auto& [value, map] : node.modify_branch_by_field_match()) {
    ModifyMap result_map;
    result_map.reserve(map.size());
    for (const auto& [modify_value, branch] : map) {
      result_map.insert(result_map.end(), {modify_value, f(branch)});
    }
    result_node.modify_branch_by_field_match.insert(
        result_node.modify_branch_by_field_match.end(),
        {value, std::move(result_map)});
  }
  result_node.default_branch_by_field_modification.reserve(
      node.default_branch_by_field_modification().size());
  for (const auto& [modify_value, branch] :
       node.default_branch_by_field_modification()) {
    result_node.default_branch_by_field_modification.insert(
        result_node.default_branch_by_field_modification.end(),
        {modify_value, f(branch)});
  }
  return NodeToTransformer(std::move(result_node));
}

PacketTransformerHandle PacketTransformerManager::SequenceNodes(
    const DecisionNode& left, const DecisionNode& right) {
  DCHECK(left.field == right.field);
  auto union_fn = [this](PacketTransformerHandle left,
                         PacketTransformerHandle right) {
    return Union(left, right);
  };

  DecisionNodeBuilder result_node{
      .field = left.field,
      .default_branch = Sequence(left.default_branch, right.default_branch),
  };

  // The (modify value, branch) pairs contributing to the modification map
  // under construction. Pairs with the same modify value get unioned.
  absl::InlinedVector<std::pair<int, PacketTransformerHandle>, 8> contributions;

  // Construct the possible results of applying the right node to packets
  // gotten by taken default modification branches in the left node. Since
  // these do not depend on the input value of the field, they get reused for
  // every value below at which the left node has no match branch.
  ModifyMap after_left_default_modification;
  if (!left.default_branch_by_field_modification().empty()) {
    MapAtValueCursor right_at_default_value(*this, right);
    for (const auto& [value, left_branch] :
         left.default_branch_by_field_modification()) {
      const PacketTransformerHandle branch = left_branch;
      right_at_default_value.ForEachEntry(
          value, [&](int right_value, PacketTransformerHandle right_branch) {
            contributions.push_back(
                {right_value, Sequence(branch, right_branch)});
          });
    }
    after_left_default_modification =
        FoldIntoMap<ModifyMap>(contributions, union_fn);
  }

  // Add the possible results of taking the default branch (i.e. leaving the
  // field unmodified) in the left node, followed by a default modification
  // branch in the right node.
  //
  // NOTE: Unlike for `modify_branch_by_field_match` below, we must not drop
  // Deny contributions here, as a Deny entry in the default modifications
  // prevents the (non-Deny) default branch from applying to the entry's value.
  if (!right.default_branch_by_field_modification().empty()) {
    ModifyMap after_left_default_branch;
    after_left_default_branch.reserve(
        right.default_branch_by_field_modification().size());
    for (const auto& [right_value, right_branch] :
         right.default_branch_by_field_modification()) {
      after_left_default_branch.insert(
          after_left_default_branch.end(),
          {right_value, Sequence(left.default_branch, right_branch)});
    }
    result_node.default_branch_by_field_modification =
        UnionModifyBranches<ModifyMap>(*this, after_left_default_modification,
                                       after_left_default_branch);
  } else {
    result_node.default_branch_by_field_modification =
        after_left_default_modification;
  }

  // In wide nodes, the same left entries tend to reoccur in the match branches
  // of many values, e.g. when many input switches forward to the same output
  // switch under the same conditions. We memoize their results locally, which
  // is much cheaper than hitting the (large) memoization table of `Sequence`
  // once for each of their right entries.
  const bool use_local_memo = left.modify_branch_by_field_match().size() >= 8;
  // Maps a left entry to the range of `local_memo_results` holding its results.
  absl::flat_hash_map<std::pair<int, PacketTransformerHandle>,
                      std::pair<size_t, size_t>>
      local_memo;
  std::vector<std::pair<int, PacketTransformerHandle>> local_memo_results;

  // When a wide left node transitions to a `left_value` whose match branch in
  // the right node has many entries (e.g. a NAT gateway or tunnel endpoint
  // dispatching on a child field `f`), most (left_branch, right_branch) pairs
  // may have disjoint values on `f` and thus sequence to Deny. Indexing the
  // right match branch's entries by the match values of `f` avoids calling
  // `Sequence` on disjoint pairs.
  struct RightMapChildIndex {
    bool built = false;
    absl::InlinedVector<uint32_t, 4> wildcard_indices;
    std::vector<std::pair<int, uint32_t>> entries_by_child_match;
  };
  absl::flat_hash_map<std::pair<int, PacketFieldHandle>, RightMapChildIndex>
      right_map_indices;
  absl::InlinedVector<uint32_t, 16> candidate_indices;

  // Appends the non-Deny (modify value, branch) pairs resulting from the left
  // entry (`left_value`, `left_branch`) followed by the right node to `out`.
  // (Deny branches would get dropped by `NodeToTransformer` anyway.)
  MapAtValueCursor right_at_value(*this, right);
  auto append_sequenced = [&](int left_value,
                              PacketTransformerHandle left_branch, auto& out) {
    std::optional<ModifyMapView> right_map =
        right_at_value.FindMatchBranch(left_value);
    if (!right_map.has_value()) {
      right_at_value.ForEachDefaultEntry(
          left_value,
          [&](int right_value, PacketTransformerHandle right_branch) {
            PacketTransformerHandle branch =
                Sequence(left_branch, right_branch);
            if (!IsDeny(branch)) out.insert(out.end(), {right_value, branch});
          });
      return;
    }
    if (use_local_memo && right_map->size() >= 64 && !IsAccept(left_branch)) {
      const DecisionNode& left_child = GetNodeOrDie(left_branch);
      if (IsDeny(left_child.default_branch) &&
          left_child.default_branch_by_field_modification().empty() &&
          left_child.num_modifications * 4 <= right_map->size()) {
        const PacketFieldHandle child_field = left_child.field;
        const absl::Span<const ModifyEntry> left_mods(
            left_child.modifications, left_child.num_modifications);
        RightMapChildIndex& index =
            right_map_indices[{left_value, child_field}];
        if (!index.built) {
          index.built = true;
          const ModifyEntry* right_begin = right_map->begin();
          const uint32_t right_size = static_cast<uint32_t>(right_map->size());
          for (uint32_t i = 0; i < right_size; ++i) {
            PacketTransformerHandle right_branch = right_begin[i].second;
            if (IsAccept(right_branch)) {
              index.wildcard_indices.push_back(i);
              continue;
            }
            const DecisionNode& right_child = GetNodeOrDie(right_branch);
            if (right_child.field != child_field ||
                !IsDeny(right_child.default_branch) ||
                !right_child.default_branch_by_field_modification().empty()) {
              index.wildcard_indices.push_back(i);
              continue;
            }
            for (const MatchBranch& branch :
                 right_child.modify_branch_by_field_match().branches()) {
              index.entries_by_child_match.push_back({branch.match_value, i});
            }
          }
          absl::c_sort(index.entries_by_child_match);
        }
        if (!index.entries_by_child_match.empty()) {
          candidate_indices.assign(index.wildcard_indices.begin(),
                                   index.wildcard_indices.end());
          for (const auto& [mod_value, unused] : left_mods) {
            auto it = std::lower_bound(
                index.entries_by_child_match.begin(),
                index.entries_by_child_match.end(), mod_value,
                [](const auto& entry, int v) { return entry.first < v; });
            for (; it != index.entries_by_child_match.end() &&
                   it->first == mod_value;
                 ++it) {
              candidate_indices.push_back(it->second);
            }
          }
          absl::c_sort(candidate_indices);
          candidate_indices.erase(
              std::unique(candidate_indices.begin(), candidate_indices.end()),
              candidate_indices.end());
          const ModifyEntry* right_begin = right_map->begin();
          for (uint32_t i : candidate_indices) {
            const auto& [right_value, right_branch] = right_begin[i];
            PacketTransformerHandle branch =
                Sequence(left_branch, right_branch);
            if (!IsDeny(branch)) out.insert(out.end(), {right_value, branch});
          }
          return;
        }
      }
    }
    for (const auto& [right_value, right_branch] : *right_map) {
      PacketTransformerHandle branch = Sequence(left_branch, right_branch);
      if (!IsDeny(branch)) out.insert(out.end(), {right_value, branch});
    }
  };

  // Returns the result's modification map at a value at which the left node
  // has the match branch `left_map`.
  auto sequence_at_match = [&](ModifyMapView left_map) {
    if (left_map.size() == 1) {
      // Fast path: the contributions are sorted and unique already.
      ModifyMap result;
      const auto& [left_value, left_branch] = *left_map.begin();
      append_sequenced(left_value, left_branch, result);
      return result;
    }
    contributions.clear();
    for (const auto& [left_value, left_branch] : left_map) {
      if (!use_local_memo) {
        append_sequenced(left_value, left_branch, contributions);
        continue;
      }
      auto [it, inserted] = local_memo.try_emplace({left_value, left_branch});
      auto& [begin, end] = it->second;
      if (inserted) {
        begin = local_memo_results.size();
        append_sequenced(left_value, left_branch, local_memo_results);
        end = local_memo_results.size();
      }
      contributions.insert(contributions.end(),
                           local_memo_results.begin() + begin,
                           local_memo_results.begin() + end);
    }
    return FoldIntoMap<ModifyMap>(contributions, union_fn);
  };

  // If the left node's default branch is Deny, then at any value `v` without a
  // match branch in the left node, the left node takes its default
  // modification branches, resulting in `after_left_default_modification`. So
  // does the result, whose default branch is Deny too, without a match branch
  // at `v`.
  if (IsDeny(left.default_branch)) {
    const bool drop_empty_maps =
        result_node.default_branch_by_field_modification.empty();
    if (!drop_empty_maps) {
      result_node.modify_branch_by_field_match.reserve(
          left.modify_branch_by_field_match().size());
    }
    for (const auto& [value, left_map] : left.modify_branch_by_field_match()) {
      ModifyMap map = sequence_at_match(left_map);
      if (drop_empty_maps && map.empty()) continue;
      result_node.modify_branch_by_field_match.insert(
          result_node.modify_branch_by_field_match.end(),
          {value, std::move(map)});
    }
    if (drop_empty_maps && result_node.modify_branch_by_field_match.empty()) {
      return Deny();
    }
    return NodeToTransformer(std::move(result_node));
  }

  // If the left node's default branch is Accept and it has no default
  // modifications (e.g. a negated filter), then at any value `v` without a
  // match branch in the left node, the left node leaves packets unmodified and
  // the right node's match branch (if any) applies verbatim.
  if (IsAccept(left.default_branch) &&
      left.default_branch_by_field_modification().empty()) {
    const auto left_matches = left.modify_branch_by_field_match();
    const auto right_matches = right.modify_branch_by_field_match();
    result_node.modify_branch_by_field_match.reserve(
        std::max(left_matches.size(), right_matches.size()));
    auto left_it = left_matches.begin();
    auto right_it = right_matches.begin();
    while (left_it != left_matches.end() && right_it != right_matches.end()) {
      const auto [left_value, left_map] = *left_it;
      const auto [right_value, right_map] = *right_it;
      if (left_value < right_value) {
        result_node.modify_branch_by_field_match.insert(
            result_node.modify_branch_by_field_match.end(),
            {left_value, sequence_at_match(left_map)});
        ++left_it;
      } else if (right_value < left_value) {
        result_node.modify_branch_by_field_match.insert(
            result_node.modify_branch_by_field_match.end(),
            {right_value, ModifyMap(right_map.begin(), right_map.end())});
        ++right_it;
      } else {
        result_node.modify_branch_by_field_match.insert(
            result_node.modify_branch_by_field_match.end(),
            {left_value, sequence_at_match(left_map)});
        ++left_it;
        ++right_it;
      }
    }
    for (; left_it != left_matches.end(); ++left_it) {
      const auto [left_value, left_map] = *left_it;
      result_node.modify_branch_by_field_match.insert(
          result_node.modify_branch_by_field_match.end(),
          {left_value, sequence_at_match(left_map)});
    }
    for (; right_it != right_matches.end(); ++right_it) {
      const auto [right_value, right_map] = *right_it;
      result_node.modify_branch_by_field_match.insert(
          result_node.modify_branch_by_field_match.end(),
          {right_value, ModifyMap(right_map.begin(), right_map.end())});
    }
    return NodeToTransformer(std::move(result_node));
  }

  // Collect the values at which the result may need a match branch. At any
  // other value `v`, neither node has a match branch and the left node has no
  // default modification branch, so the left node takes its default
  // modification branches, resulting in `after_left_default_modification`,
  // plus its default branch, followed by the right node's default modification
  // branches or default branch. That is precisely the result's behavior
  // without a match branch at `v`.
  const auto all_possible_values = MergedKeys(
      left.modify_branch_by_field_match(), right.modify_branch_by_field_match(),
      left.default_branch_by_field_modification());

  // For every such value, construct the proper new branch.
  MapAtValueCursor left_at_value(*this, left);
  ModifyMap after_left_default_branch_at_value;
  result_node.modify_branch_by_field_match.reserve(all_possible_values.size());
  for (int value : all_possible_values) {
    if (std::optional<ModifyMapView> left_map =
            left_at_value.FindMatchBranch(value)) {
      result_node.modify_branch_by_field_match.insert(
          result_node.modify_branch_by_field_match.end(),
          {value, sequence_at_match(*left_map)});
      continue;
    }

    // The left node takes its default modification branches, which result in
    // `after_left_default_modification`, plus its default branch unless it is
    // shadowed by a default modification branch.
    if (left.default_branch_by_field_modification().contains(value)) {
      result_node.modify_branch_by_field_match.insert(
          result_node.modify_branch_by_field_match.end(),
          {value, after_left_default_modification});
      continue;
    }
    after_left_default_branch_at_value.clear();
    right_at_value.ForEachEntry(
        value, [&](int right_value, PacketTransformerHandle right_branch) {
          after_left_default_branch_at_value.insert(
              after_left_default_branch_at_value.end(),
              {right_value, Sequence(left.default_branch, right_branch)});
        });
    result_node.modify_branch_by_field_match.insert(
        result_node.modify_branch_by_field_match.end(),
        {value,
         UnionModifyBranches<ModifyMap>(*this, after_left_default_modification,
                                        after_left_default_branch_at_value)});
  }

  return NodeToTransformer(std::move(result_node));
}

PacketTransformerHandle PacketTransformerManager::Sequence(
    PacketTransformerHandle left, PacketTransformerHandle right) {
  // Base cases.
  if (IsDeny(left) || IsDeny(right)) return Deny();
  if (IsAccept(left)) return right;
  if (IsAccept(right)) return left;

  // Sequence is NOT commutative, so we do not normalize the keys.
  if (auto it = sequence_cache_.find({left, right});
      it != sequence_cache_.end()) {
    return it->second;
  }

  // If the operands branch on different fields, the operand branching on the
  // larger field neither tests nor modifies the smaller field, and thus can be
  // pushed into the branches of the other operand.
  //
  // NOTE: Nodes are pointer-stable, so references to them remain valid even as
  // new nodes are created.
  const DecisionNode& left_node = GetNodeOrDie(left);
  const DecisionNode& right_node = GetNodeOrDie(right);
  PacketTransformerHandle result;
  if (left_node.field < right_node.field) {
    result = MapBranches(left_node, [&](PacketTransformerHandle branch) {
      return Sequence(branch, right);
    });
  } else if (right_node.field < left_node.field) {
    result = MapBranches(right_node, [&](PacketTransformerHandle branch) {
      return Sequence(left, branch);
    });
  } else {
    result = SequenceNodes(left_node, right_node);
  }
  sequence_cache_.try_emplace({left, right}, result);
  return result;
}

PacketTransformerHandle PacketTransformerManager::UnionNodes(
    const DecisionNode& left, const DecisionNode& right) {
  DCHECK(left.field == right.field);
  DecisionNodeBuilder result_node{
      .field = left.field,
      .default_branch_by_field_modification = UnionModifyBranches<ModifyMap>(
          *this, left.default_branch_by_field_modification(),
          right.default_branch_by_field_modification()),
      .default_branch = Union(left.default_branch, right.default_branch),
  };

  if (IsDeny(result_node.default_branch) &&
      result_node.default_branch_by_field_modification.empty()) {
    const auto left_matches = left.modify_branch_by_field_match();
    const auto right_matches = right.modify_branch_by_field_match();
    result_node.modify_branch_by_field_match.reserve(
        std::max(left_matches.size(), right_matches.size()));
    auto left_it = left_matches.begin();
    auto right_it = right_matches.begin();
    while (left_it != left_matches.end() && right_it != right_matches.end()) {
      const auto [left_value, left_map] = *left_it;
      const auto [right_value, right_map] = *right_it;
      if (left_value < right_value) {
        result_node.modify_branch_by_field_match.insert(
            result_node.modify_branch_by_field_match.end(),
            {left_value, ModifyMap(left_map.begin(), left_map.end())});
        ++left_it;
      } else if (right_value < left_value) {
        result_node.modify_branch_by_field_match.insert(
            result_node.modify_branch_by_field_match.end(),
            {right_value, ModifyMap(right_map.begin(), right_map.end())});
        ++right_it;
      } else {
        result_node.modify_branch_by_field_match.insert(
            result_node.modify_branch_by_field_match.end(),
            {left_value,
             UnionModifyBranches<ModifyMap>(*this, left_map, right_map)});
        ++left_it;
        ++right_it;
      }
    }
    for (; left_it != left_matches.end(); ++left_it) {
      const auto [left_value, left_map] = *left_it;
      result_node.modify_branch_by_field_match.insert(
          result_node.modify_branch_by_field_match.end(),
          {left_value, ModifyMap(left_map.begin(), left_map.end())});
    }
    for (; right_it != right_matches.end(); ++right_it) {
      const auto [right_value, right_map] = *right_it;
      result_node.modify_branch_by_field_match.insert(
          result_node.modify_branch_by_field_match.end(),
          {right_value, ModifyMap(right_map.begin(), right_map.end())});
    }
    return NodeToTransformer(std::move(result_node));
  }

  // Collect every value in mapped in each node.
  const auto all_possible_values = MergedKeys(
      left.modify_branch_by_field_match(), right.modify_branch_by_field_match(),
      left.default_branch_by_field_modification(),
      right.default_branch_by_field_modification());

  // For every value in mapped in each node, construct the proper new branch.
  MapAtValueCursor left_at_value(*this, left);
  MapAtValueCursor right_at_value(*this, right);
  ModifyMap left_scratch, right_scratch;
  result_node.modify_branch_by_field_match.reserve(all_possible_values.size());
  for (int value : all_possible_values) {
    result_node.modify_branch_by_field_match.insert(
        result_node.modify_branch_by_field_match.end(),
        {value, UnionModifyBranches<ModifyMap>(
                    *this, left_at_value.Get(value, left_scratch),
                    right_at_value.Get(value, right_scratch))});
  }

  return NodeToTransformer(std::move(result_node));
}

PacketTransformerHandle PacketTransformerManager::Union(
    PacketTransformerHandle left, PacketTransformerHandle right) {
  // Base cases.
  if (left == right) return left;
  if (IsDeny(right)) return left;
  if (IsDeny(left)) return right;

  // Normalize keys to leverage commutativity.
  if (left > right) std::swap(left, right);
  if (auto it = union_cache_.find({left, right}); it != union_cache_.end()) {
    return it->second;
  }

  PacketTransformerHandle result = WithAlignedNodes(
      left, right, [this](const DecisionNode& left, const DecisionNode& right) {
        return UnionNodes(left, right);
      });
  union_cache_.try_emplace({left, right}, result);
  return result;
}

PacketTransformerHandle PacketTransformerManager::DifferenceNodes(
    const DecisionNode& left, const DecisionNode& right) {
  DCHECK(left.field == right.field);
  DecisionNodeBuilder result_node{
      .field = left.field,
      .default_branch = Difference(left.default_branch, right.default_branch),
  };

  // Since Difference(Deny, x) = Deny, only the left node's entries can
  // contribute to the result. So rather than merging with the right node's
  // maps, which may be much larger (e.g. when subtracting a large set of known
  // transformations from a few new ones, as `Iterate` does), we drive the
  // computation by the left node's entries and look up the corresponding
  // branches of the right node.
  const ModifyMapView right_defaults =
      right.default_branch_by_field_modification();
  const bool right_default_branch_is_deny = IsDeny(right.default_branch);
  // Returns the difference of `left_map` and the right node's map `right_map`
  // at `value`, or of its default map if `right_map` is null.
  auto difference_at = [&](int value, ModifyMapView left_map,
                           std::optional<ModifyMapView> right_map) {
    ModifyMap result;
    const ModifyMapView right_entries = right_map.value_or(right_defaults);
    auto right_it = right_entries.begin();
    for (const auto& [modify_value, left_branch] : left_map) {
      right_it = std::lower_bound(
          right_it, right_entries.end(), modify_value,
          [](const auto& entry, int key) { return entry.first < key; });
      PacketTransformerHandle right_branch = Deny();
      if (right_it != right_entries.end() && right_it->first == modify_value) {
        right_branch = right_it->second;
      } else if (!right_map.has_value() && modify_value == value &&
                 !right_default_branch_is_deny) {
        right_branch = right.default_branch;
      }
      PacketTransformerHandle branch = Difference(left_branch, right_branch);
      // Deny branches get dropped by `NodeToTransformer` anyway.
      if (!IsDeny(branch)) result.insert(result.end(), {modify_value, branch});
    }
    return result;
  };
  // NOTE: Unlike in match branches, Deny entries in default modification
  // branches are meaningful, as they prevent the default branch from applying
  // to their values. So we compute the default modification branches as usual.
  if (!left.default_branch_by_field_modification().empty()) {
    result_node.default_branch_by_field_modification =
        CombineModifyBranches<ModifyMap>(
            left.default_branch_by_field_modification(), right_defaults,
            [this](PacketTransformerHandle left,
                   PacketTransformerHandle right) {
              return Difference(left, right);
            },
            /*default_value=*/Deny());
  }

  // Collect the values at which the result may need a match branch. If the
  // left node's default branch is Deny, then at values `v` without a match
  // branch or default modification branch in the left node, the left node
  // takes its default modification branches only. If `v` has no match branch
  // in the right node either, then the right node's default branch does not
  // apply to their modify values, so the result is the result's default
  // modification map, and the result's default branch is Deny: no match branch
  // is needed. If the left node has no default modification branches, no
  // match branch is needed regardless of the right node.
  absl::InlinedVector<int, 16> all_possible_values;
  if (!IsDeny(left.default_branch)) {
    all_possible_values =
        MergedKeys(left.modify_branch_by_field_match(),
                   right.modify_branch_by_field_match(),
                   left.default_branch_by_field_modification(),
                   right.default_branch_by_field_modification());
  } else if (!left.default_branch_by_field_modification().empty()) {
    all_possible_values =
        MergedKeys(left.modify_branch_by_field_match(),
                   right.modify_branch_by_field_match(),
                   left.default_branch_by_field_modification());
  } else {
    all_possible_values = MergedKeys(left.modify_branch_by_field_match());
  }

  // For every such value, construct the proper new branch.
  MapAtValueCursor left_at_value(*this, left);
  MapAtValueCursor right_at_value(*this, right);
  ModifyMap left_scratch;
  const bool drop_empty_maps =
      IsDeny(result_node.default_branch) &&
      result_node.default_branch_by_field_modification.empty();
  if (!drop_empty_maps) {
    result_node.modify_branch_by_field_match.reserve(
        all_possible_values.size());
  }
  for (int value : all_possible_values) {
    ModifyMap map = difference_at(value, left_at_value.Get(value, left_scratch),
                                  right_at_value.FindMatchBranch(value));
    if (drop_empty_maps && map.empty()) continue;
    result_node.modify_branch_by_field_match.insert(
        result_node.modify_branch_by_field_match.end(),
        {value, std::move(map)});
  }
  if (drop_empty_maps && result_node.modify_branch_by_field_match.empty()) {
    return Deny();
  }

  return NodeToTransformer(std::move(result_node));
}

PacketTransformerHandle PacketTransformerManager::Difference(
    PacketTransformerHandle left, PacketTransformerHandle right) {
  // Base cases.
  if (left == right) return Deny();
  if (IsDeny(left)) return Deny();
  if (IsDeny(right)) return left;

  // Difference is NOT commutative, so we do not normalize the keys.
  if (auto it = difference_cache_.find({left, right});
      it != difference_cache_.end()) {
    return it->second;
  }

  PacketTransformerHandle result = WithAlignedNodes(
      left, right, [this](const DecisionNode& left, const DecisionNode& right) {
        return DifferenceNodes(left, right);
      });
  difference_cache_.try_emplace({left, right}, result);
  return result;
}

PacketTransformerHandle PacketTransformerManager::Iterate(
    PacketTransformerHandle iterable) {
  if (auto it = iterate_cache_.find(iterable); it != iterate_cache_.end()) {
    return it->second;
  }

  // Computes p* = 1 + p + p;p + ... by semi-naive iteration, maintaining the
  // invariant that `approximation` = 1 + p + ... + p^i, and that `delta`
  // consists of the transformations in p^i that are not in any p^j, j < i.
  // Since `Sequence` distributes over `Union`, new transformations in p^(i+1)
  // can only arise from `delta; p`.
  //
  // Compared to repeated squaring (x := x;x), which needs only logarithmically
  // many iterations, this needs linearly many (in the "diameter" of p), but
  // each iteration is much cheaper: `delta` is small, and `iterable` is
  // typically much sparser than p*. E.g. for the hop policy of a network with
  // n switches and small degree d, squaring takes O(n^3) time per iteration on
  // the switch field, whereas this takes O(n^2 * d) time in total.
  //
  // To avoid rebuilding the (ever-growing) approximation in every iteration,
  // we represent it as the union of a logarithmic number of `levels`, where
  // level j is either Deny or the union of 2^j deltas, and merge levels like a
  // binary counter. Since `Difference` is driven by its (small) left operand,
  // subtracting all levels from a new delta is cheap, and each delta takes part
  // in only logarithmically many unions.
  absl::InlinedVector<PacketTransformerHandle, 16> levels;
  auto add_to_approximation = [&](PacketTransformerHandle delta) {
    for (PacketTransformerHandle& level : levels) {
      if (IsDeny(level)) {
        level = delta;
        return;
      }
      delta = Union(level, delta);
      level = Deny();
    }
    levels.push_back(delta);
  };
  PacketTransformerHandle delta = Accept();
  while (!IsDeny(delta)) {
    add_to_approximation(delta);
    delta = Sequence(delta, iterable);
    for (PacketTransformerHandle level : levels) {
      delta = Difference(delta, level);
    }
  }
  PacketTransformerHandle approximation = Deny();
  for (PacketTransformerHandle level : levels) {
    approximation = Union(approximation, level);
  }
  return iterate_cache_[iterable] = approximation;
}

PacketSetHandle PacketTransformerManager::GetAllPossibleOutputPackets(
    PacketTransformerHandle transformer) {
  if (IsAccept(transformer)) return packet_set_manager_.FullSet();
  if (IsDeny(transformer)) return packet_set_manager_.EmptySet();

  if (auto it = get_all_possible_outputs_cache_.find(transformer);
      it != get_all_possible_outputs_cache_.end()) {
    return it->second;
  }

  const DecisionNode& node = GetNodeOrDie(transformer);
  PacketSetHandle default_output =
      GetAllPossibleOutputPackets(node.default_branch);
  auto or_fn = [this](PacketSetHandle a, PacketSetHandle b) {
    return packet_set_manager_.Or(a, b);
  };
  using OutputEntry = std::pair<int, PacketSetHandle>;
  using OutputMap = SortedVectorMap<int, PacketSetHandle,
                                    absl::InlinedVector<OutputEntry, 16>>;

  // Case 2: Output packets that hit an explicit branch and got modified.
  // Implements the `b_B` in the `fwd` function in section C.3 Push and Pull
  // in KATch: A Fast Symbolic Verifier for NetKAT.
  absl::InlinedVector<OutputEntry, 16> entries;
  entries.reserve(node.num_modifications);
  for (const auto& [match_value, branch_by_modify] :
       node.modify_branch_by_field_match()) {
    for (const auto& [modify_value, branch] : branch_by_modify) {
      entries.push_back({modify_value, GetAllPossibleOutputPackets(branch)});
    }
  }
  OutputMap branch_outputs = FoldIntoMap<OutputMap>(entries, or_fn);

  entries.clear();
  entries.reserve(branch_outputs.size() +
                  node.default_branch_by_field_modification().size() +
                  node.modify_branch_by_field_match().size());

  // Case 3: Output packets that do not match on a branch and do not get
  // modified. Implements `b_C` in `fwd`.
  const auto match_branches = node.modify_branch_by_field_match().branches();
  const auto default_mods = node.default_branch_by_field_modification();
  auto match_it = match_branches.begin();
  auto mod_it = default_mods.begin();
  for (const auto& [modify_value, branch_output] : branch_outputs) {
    while (match_it != match_branches.end() &&
           match_it->match_value < modify_value) {
      ++match_it;
    }
    while (mod_it != default_mods.end() && mod_it->first < modify_value) {
      ++mod_it;
    }
    const bool in_match = match_it != match_branches.end() &&
                          match_it->match_value == modify_value;
    const bool in_mod =
        mod_it != default_mods.end() && mod_it->first == modify_value;
    PacketSetHandle output =
        (!in_match && !in_mod)
            ? packet_set_manager_.Or(branch_output, default_output)
            : branch_output;
    entries.push_back({modify_value, output});
  }

  // Case 1: Output packets that hit the default branch and got modified.
  // Implements `b_A` in `fwd`.
  for (const auto& [modify_value, branch] : default_mods) {
    entries.push_back({modify_value, GetAllPossibleOutputPackets(branch)});
  }

  // Case 4: Output packets that got matched on an explicit branch, but did
  // not get modified. Implements `b_D` in `fwd`.
  auto branch_out_it = branch_outputs.begin();
  for (const MatchBranch& match_branch : match_branches) {
    const int match_value = match_branch.match_value;
    while (branch_out_it != branch_outputs.end() &&
           branch_out_it->first < match_value) {
      ++branch_out_it;
    }
    if (branch_out_it == branch_outputs.end() ||
        branch_out_it->first != match_value) {
      entries.push_back({match_value, packet_set_manager_.EmptySet()});
    }
  }

  OutputMap output_by_field_value = FoldIntoMap<OutputMap>(entries, or_fn);

  int num_branches = 0;
  for (const auto& [value, branch] : output_by_field_value) {
    if (branch != default_output) ++num_branches;
  }
  absl::FixedArray<std::pair<int, PacketSetHandle>, 0>
      output_by_field_value_list(num_branches);
  int i = 0;
  for (const auto& [value, branch] : output_by_field_value) {
    // Skips `default_branch` because an invariant of `DecisionNode` is that
    // no branch in `branch_by_field_value` can be a duplicate of the default
    // branch.
    if (branch == default_output) continue;
    output_by_field_value_list[i++] = std::make_pair(value, branch);
  }

  return get_all_possible_outputs_cache_[transformer] =
             packet_set_manager_.NodeToPacket({
                 .field = node.field,
                 .default_branch = default_output,
                 .branch_by_field_value = std::move(output_by_field_value_list),
             });
}

PacketSetHandle PacketTransformerManager::Push(
    PacketSetHandle input_packets, PacketTransformerHandle transformer) {
  return GetAllPossibleOutputPackets(
      Sequence(FromPacketSetHandle(input_packets), transformer));
}

PacketSetHandle
PacketTransformerManager::GetAllInputPacketsThatProduceAnyOutput(
    PacketTransformerHandle transformer) {
  if (IsAccept(transformer)) return packet_set_manager_.FullSet();
  if (IsDeny(transformer)) return packet_set_manager_.EmptySet();

  if (auto it = get_all_inputs_cache_.find(transformer);
      it != get_all_inputs_cache_.end()) {
    return it->second;
  }

  const DecisionNode& node = GetNodeOrDie(transformer);

  // Case 1: Input packets that hit the default branch and got modified.
  // Implements the `d'` in the `bwd` function in section C.3 Push and Pull in
  // KATch: A Fast Symbolic Verifier for NetKAT.
  PacketSetHandle default_branch_output_packets;
  for (const auto& [modify_value, branch] :
       node.default_branch_by_field_modification()) {
    default_branch_output_packets =
        packet_set_manager_.Or(default_branch_output_packets,
                               GetAllInputPacketsThatProduceAnyOutput(branch));
  }

  PacketSetHandle default_branch = packet_set_manager_.Or(
      default_branch_output_packets,
      GetAllInputPacketsThatProduceAnyOutput(node.default_branch));

  // Case 2 (`b_A` in `bwd`: input packets that hit an explicit branch and got
  // modified) and Case 3 (`b_B` in `bwd`: input packets that do not get
  // matched on an explicit branch, but do get modified). Since both sequences
  // are sorted by value, we merge them in a single linear pass.
  const auto match_branches = node.modify_branch_by_field_match();
  const auto default_mods = node.default_branch_by_field_modification();
  const bool include_default_mods =
      default_branch_output_packets != default_branch;
  absl::FixedArray<std::pair<int, PacketSetHandle>, 0>
      branch_by_field_value_list(
          match_branches.size() +
          (include_default_mods ? default_mods.size() : 0));
  int num_branches = 0;
  auto add_branch = [&](int value, PacketSetHandle branch) {
    if (branch != default_branch) {
      branch_by_field_value_list[num_branches++] = {value, branch};
    }
  };
  auto match_it = match_branches.begin();
  auto mod_it =
      include_default_mods ? default_mods.begin() : default_mods.end();
  while (match_it != match_branches.end() || mod_it != default_mods.end()) {
    if (mod_it != default_mods.end() && (match_it == match_branches.end() ||
                                         mod_it->first < (*match_it).first)) {
      add_branch(mod_it->first, default_branch_output_packets);
      ++mod_it;
    } else {
      const auto [match_value, branch_by_modify] = *match_it;
      if (mod_it != default_mods.end() && mod_it->first == match_value) {
        ++mod_it;
      }
      PacketSetHandle union_of_branches;
      for (const auto& [modify_value, branch] : branch_by_modify) {
        union_of_branches = packet_set_manager_.Or(
            union_of_branches, GetAllInputPacketsThatProduceAnyOutput(branch));
      }
      add_branch(match_value, union_of_branches);
      ++match_it;
    }
  }

  return get_all_inputs_cache_[transformer] = packet_set_manager_.NodeToPacket({
             .field = node.field,
             .default_branch = default_branch,
             .branch_by_field_value{
                 branch_by_field_value_list.begin(),
                 branch_by_field_value_list.begin() + num_branches,
             },
         });
}

PacketSetHandle PacketTransformerManager::Pull(
    PacketTransformerHandle transformer, PacketSetHandle output_packets) {
  return GetAllInputPacketsThatProduceAnyOutput(
      Sequence(transformer, FromPacketSetHandle(output_packets)));
}

std::string PacketTransformerManager::ToString(const DecisionNode& node) const {
  std::string result;
  std::vector<PacketTransformerHandle> work_list;

  auto pretty_print_map = [&](absl::string_view field, ModifyMapView map) {
    for (const auto& [value, branch] : map) {
      absl::StrAppendFormat(&result, "    %s := %d -> %v\n", field, value,
                            branch);
      if (!IsAccept(branch) && !IsDeny(branch)) work_list.push_back(branch);
    }
  };

  std::string field = absl::StrFormat(
      "%v:'%s'", node.field,
      absl::CEscape(
          packet_set_manager_.field_manager_.GetFieldName(node.field)));

  for (const auto& [value, modify_map] : node.modify_branch_by_field_match()) {
    absl::StrAppendFormat(&result, "  %s == %d:\n", field, value);
    pretty_print_map(field, modify_map);
  }
  absl::StrAppendFormat(&result, "  %s == *:\n", field);
  pretty_print_map(field, node.default_branch_by_field_modification());
  PacketTransformerHandle fallthrough = node.default_branch;
  absl::StrAppendFormat(&result, "  %s == * -> %v\n", field, fallthrough);
  if (!IsAccept(fallthrough) && !IsDeny(fallthrough))
    work_list.push_back(fallthrough);

  for (const PacketTransformerHandle& branch : work_list) {
    absl::StrAppend(&result, ToString(branch));
  }

  return result;
}

std::string PacketTransformerManager::ToString(
    PacketTransformerHandle transformer) const {
  std::string result;
  std::queue<PacketTransformerHandle> work_list;
  work_list.push(transformer);
  absl::flat_hash_set<PacketTransformerHandle> visited = {transformer};

  auto pretty_print_map = [&](absl::string_view field, ModifyMapView map) {
    for (const auto& [value, branch] : map) {
      absl::StrAppendFormat(&result, "    %s := %d -> %v\n", field, value,
                            branch);
      if (IsAccept(branch) || IsDeny(branch)) continue;
      bool new_branch = visited.insert(branch).second;
      if (new_branch) work_list.push(branch);
    }
  };

  while (!work_list.empty()) {
    PacketTransformerHandle transformer = work_list.front();
    work_list.pop();
    absl::StrAppend(&result, transformer, ":\n");

    if (IsAccept(transformer) || IsDeny(transformer)) continue;

    const DecisionNode& node = GetNodeOrDie(transformer);
    std::string field = absl::StrFormat(
        "%v:'%s'", node.field,
        absl::CEscape(
            packet_set_manager_.field_manager_.GetFieldName(node.field)));
    for (const auto& [value, modify_map] :
         node.modify_branch_by_field_match()) {
      absl::StrAppendFormat(&result, "  %s == %d:\n", field, value);
      pretty_print_map(field, modify_map);
    }
    absl::StrAppendFormat(&result, "  %s == *:\n", field);
    pretty_print_map(field, node.default_branch_by_field_modification());
    PacketTransformerHandle fallthrough = node.default_branch;
    absl::StrAppendFormat(&result, "  %s == * -> %v\n", field, fallthrough);
    if (IsAccept(fallthrough) || IsDeny(fallthrough)) continue;
    bool new_branch = visited.insert(fallthrough).second;
    if (new_branch) work_list.push(fallthrough);
  }
  return result;
}

// Returns a dot string representation of the given
// `packet_transformer`.
std::string PacketTransformerManager::ToDot(
    const PacketTransformerHandle& transformer) const {
  std::string result = "digraph {\n";
  // Applies the default font sizes for GraphViz.
  absl::StrAppend(&result, "  node [fontsize = 14]\n");
  absl::StrAppend(&result, "  edge [fontsize = 12]\n");

  if (IsAccept(transformer)) {
    absl::StrAppendFormat(&result, "  %d [label=\"T\" shape=box]\n",
                          PacketTransformerHandle::kAccept);
    absl::StrAppend(&result, "}\n");
    return result;
  }
  if (IsDeny(transformer)) {
    absl::StrAppendFormat(&result, "  %d [label=\"F\" shape=box]\n",
                          PacketTransformerHandle::kDeny);
    absl::StrAppend(&result, "}\n");
    return result;
  }
  absl::StrAppendFormat(&result, "  %d [label=\"T\" shape=box]\n",
                        PacketTransformerHandle::kAccept);
  absl::StrAppendFormat(&result, "  %d [label=\"F\" shape=box]\n",
                        PacketTransformerHandle::kDeny);
  std::queue<PacketTransformerHandle> work_list;
  work_list.push(transformer);
  absl::flat_hash_set<PacketTransformerHandle> visited = {transformer};

  while (!work_list.empty()) {
    PacketTransformerHandle transformer = work_list.front();
    work_list.pop();

    if (IsAccept(transformer) || IsDeny(transformer)) continue;

    const DecisionNode& node = GetNodeOrDie(transformer);
    std::string field =
        packet_set_manager_.field_manager_.GetFieldName(node.field);
    absl::StrAppendFormat(&result, "  %d [label=\"%s\"]\n",
                          transformer.node_index_, field);
    for (const auto& [value, modify_map] :
         node.modify_branch_by_field_match()) {
      if (modify_map.empty()) {
        absl::StrAppendFormat(
            &result, "  %d -> %d [label=\"%s==%s\"]\n", transformer.node_index_,
            PacketTransformerHandle::kDeny, field, absl::StrCat(value));
      }
      for (const auto& [new_value, branch] : modify_map) {
        absl::StrAppendFormat(&result,
                              "  %d -> %d [label=\"%s==%s; %s:=%d\"]\n",
                              transformer.node_index_, branch.node_index_,
                              field, absl::StrCat(value), field, new_value);
        if (IsAccept(branch) || IsDeny(branch)) continue;
        bool new_branch = visited.insert(branch).second;
        if (new_branch) work_list.push(branch);
      }
    }

    for (const auto& [new_value, branch] :
         node.default_branch_by_field_modification()) {
      absl::StrAppendFormat(
          &result, "  %d -> %d [label=\"%s:=%d\" style=dashed]\n",
          transformer.node_index_, branch.node_index_, field, new_value);
      if (IsAccept(branch) || IsDeny(branch)) continue;
      bool new_branch = visited.insert(branch).second;
      if (new_branch) work_list.push(branch);
    }
    PacketTransformerHandle fallthrough = node.default_branch;
    absl::StrAppendFormat(&result, "  %d -> %d [style=dashed]\n",
                          transformer.node_index_, fallthrough.node_index_);
    if (IsAccept(fallthrough) || IsDeny(fallthrough)) continue;
    bool new_branch = visited.insert(fallthrough).second;
    if (new_branch) work_list.push(fallthrough);
  }
  absl::StrAppend(&result, "}\n");
  return result;
}

absl::Status PacketTransformerManager::CheckInternalInvariants() const {
  // Invariant: Proper and sentinel node indices are disjoint.
  RET_CHECK(nodes_.size() <= PacketTransformerHandle::kMinSentinel);

  // Invariant: Each node is stored exactly once.
  RETURN_IF_ERROR(nodes_.CheckInternalInvariants());

  // Node Invariants.
  for (int i = 0; i < nodes_.size(); ++i) {
    const DecisionNode& node = nodes_[i];
    // Invariant: `modify_branch_by_field_match` or
    // `default_branch_by_field_modification` is non-empty.
    // Maintained by `NodeToTransformer`.
    RET_CHECK(!node.modify_branch_by_field_match().empty() ||
              !node.default_branch_by_field_modification().empty());

    // Invariant: node field is strictly smaller than sub-node fields.
    RET_CHECK(IsAccept(node.default_branch) || IsDeny(node.default_branch) ||
              GetNodeOrDie(node.default_branch).field > node.field)
        << ":\n"
        << ToString(node);

    for (const auto& [match_value, branch_by_modify] :
         node.modify_branch_by_field_match()) {
      for (const auto& [modify_value, branch] : branch_by_modify) {
        // Invariant: Modify branches are not Deny unless `modify_value ==
        // match_value`.
        RET_CHECK(!IsDeny(branch) || modify_value == match_value)
            << ":\n"
            << ToString(node);

        // Invariant: node field is strictly smaller than sub-node fields.
        RET_CHECK(IsAccept(branch) || IsDeny(branch) ||
                  GetNodeOrDie(branch).field > node.field)
            << ":\n"
            << ToString(node);
      }
    }

    for (const auto& [match_value, branch] :
         node.default_branch_by_field_modification()) {
      // Invariant: Default modify branches are not Deny.
      RET_CHECK(!IsDeny(branch));

      // Invariant: node field is strictly smaller than sub-node fields.
      RET_CHECK(IsAccept(branch) || GetNodeOrDie(branch).field > node.field);
    }

    // Invariant: node field is interned by
    // `packet_set_manager_.field_manager_`.
    packet_set_manager_.field_manager_.GetFieldName(node.field);  // No crash.
  }

  return absl::OkStatus();
}

}  // namespace netkat
