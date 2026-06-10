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
#include <cstdint>
#include <limits>
#include <optional>
#include <queue>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/base/no_destructor.h"
#include "absl/container/btree_map.h"
#include "absl/container/fixed_array.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/hash/hash.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "gutil/status.h"
#include "netkat/netkat.pb.h"
#include "netkat/packet.h"
#include "netkat/packet_field.h"
#include "netkat/packet_set.h"

namespace netkat {

// The Deny and Accept transformers are not decision nodes, and thus we cannot
// associate an index into the `nodes_` vector with them. Instead, we represent
// them using sentinel values, chosen maximally to avoid collisions with proper
// indices.
enum SentinelNodeIndex : uint32_t {
  // Encodes the Deny transformer.
  kDeny = std::numeric_limits<uint32_t>::max(),
  // Encodes the Accept transformer.
  kAccept = std::numeric_limits<uint32_t>::max() - 1,
  // The minimum sentinel node index.
  // Smaller values are reserved for proper indices into the `nodes_` vector.
  kMinSentinel = kAccept,
};

PacketTransformerHandle::PacketTransformerHandle()
    : node_index_(SentinelNodeIndex::kDeny) {}

std::string PacketTransformerHandle::ToString() const {
  if (node_index_ == SentinelNodeIndex::kDeny) {
    return "PacketTransformerHandle<deny>";
  } else if (node_index_ == SentinelNodeIndex::kAccept) {
    return "PacketTransformerHandle<accept>";
  } else {
    return absl::StrFormat("PacketTransformerHandle<%d>", node_index_);
  }
}

const PacketTransformerManager::DecisionNode&
PacketTransformerManager::GetNodeOrDie(
    PacketTransformerHandle transformer) const {
  CHECK_LT(transformer.node_index_, nodes_.size());  // Crash ok
  return nodes_[transformer.node_index_];
}

size_t PacketTransformerManager::NodeHash::operator()(
    const DecisionNode* node) const {
  return absl::HashOf(*node);
}

size_t PacketTransformerManager::NodeHash::operator()(
    const DecisionNode& node) const {
  return absl::HashOf(node);
}

// Canonicalizes a decision node and returns a transformer.
PacketTransformerHandle PacketTransformerManager::NodeToTransformer(
    DecisionNode&& node) {
  // Remove any default branches pointing to Deny, saving the value.
  absl::flat_hash_set<int> deny_values;
  for (const auto& [modify_value, branch] :
       node.default_branch_by_field_modification) {
    if (IsDeny(branch)) deny_values.insert(modify_value);
  }
  for (const int value : deny_values) {
    node.default_branch_by_field_modification.erase(value);
  }

  // For any value removed above, ensure it is either already in
  // `modify_branch_by_field_match` or add it, pointing to the remaining
  // `default_branch_by_field_modification`.
  for (const int value : deny_values) {
    if (node.modify_branch_by_field_match.contains(value)) {
      continue;
    }
    node.modify_branch_by_field_match[value] =
        node.default_branch_by_field_modification;
  }

  // For every match branch, remove any modification branches pointing to Deny,
  // unless the match value == the modification value.
  for (auto& [match_value, modification_map] :
       node.modify_branch_by_field_match) {
    deny_values.clear();
    for (const auto& [modify_value, branch] : modification_map) {
      if (IsDeny(branch)) deny_values.insert(modify_value);
    }
    for (const int value : deny_values) {
      modification_map.erase(value);
    }
  }

  // Finally, remove any redundant values in `modify_branch_by_field_match`
  // (i.e. values that carry the same semantics as the default modification
  // and default branch).
  bool skip_default_branch = IsDeny(node.default_branch);
  absl::flat_hash_set<int> redundant_values;
  for (auto& [match_value, modification_map] :
       node.modify_branch_by_field_match) {
    if (skip_default_branch ||
        node.default_branch_by_field_modification.contains(match_value)) {
      // Compare the modification map to the default branch modification map,
      // considering the mapping redundant if they are the same.
      if (modification_map == node.default_branch_by_field_modification) {
        redundant_values.insert(match_value);
      }
    } else {
      // If `value` is in `modification_map` and points to the default branch,
      // then compare the modification map to the default branch modification
      // map after removing the `value` mapping.
      if (!modification_map.contains(match_value) ||
          modification_map.at(match_value) != node.default_branch) {
        continue;
      }
      modification_map.erase(match_value);
      if (modification_map == node.default_branch_by_field_modification) {
        redundant_values.insert(match_value);
      }
      modification_map[match_value] = node.default_branch;
    }
  }

  for (const int value : redundant_values) {
    node.modify_branch_by_field_match.erase(value);
  }

  if (node.modify_branch_by_field_match.empty() &&
      node.default_branch_by_field_modification.empty())
    return node.default_branch;

  // Look up the node by value via the transparent `NodeHash`/`NodeEq`
  // functors; only new nodes get stored (exactly once, in `nodes_`).
  if (auto it = transformer_by_node_.find(node);
      it != transformer_by_node_.end()) {
    return it->second;
  }
  PacketTransformerHandle transformer(nodes_.size());
  nodes_.push_back(std::move(node));
  transformer_by_node_.insert({&nodes_[transformer.node_index_], transformer});
  LOG_IF(DFATAL, nodes_.size() > SentinelNodeIndex::kMinSentinel)
      << "Internal invariant violated: Proper and sentinel node indices must "
         "be disjoint. This indicates that we allocated more nodes than are "
         "supported (> 2^32 - 2).";
  return transformer;
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
  std::string field =
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
    if (auto mod_map_it =
            node.modify_branch_by_field_match.find(*initial_field_value);
        mod_map_it != node.modify_branch_by_field_match.end()) {
      matched = true;
      for (const auto& [value, branch] : mod_map_it->second) {
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
       node.default_branch_by_field_modification) {
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

PacketTransformerHandle PacketTransformerManager::Compile(
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
      key.lhs_child = Compile(policy.sequence_op().left());
      key.rhs_child = Compile(policy.sequence_op().right());
      auto it = transformer_by_hash_.find(key);
      if (it != transformer_by_hash_.end()) return it->second;
      return transformer_by_hash_[key] = Sequence(key.lhs_child, key.rhs_child);
    }
    case PolicyProto::kUnionOp: {
      key.lhs_child = Compile(policy.union_op().left());
      key.rhs_child = Compile(policy.union_op().right());
      auto it = transformer_by_hash_.find(key);
      if (it != transformer_by_hash_.end()) return it->second;
      return transformer_by_hash_[key] = Union(key.lhs_child, key.rhs_child);
    }
    case PolicyProto::kIterateOp: {
      key.lhs_child = Compile(policy.iterate_op().iterable());
      auto it = transformer_by_hash_.find(key);
      if (it != transformer_by_hash_.end()) return it->second;
      return transformer_by_hash_[key] = Iterate(key.lhs_child);
    }
    case PolicyProto::kDifferenceOp: {
      key.lhs_child = Compile(policy.difference_op().left());
      key.rhs_child = Compile(policy.difference_op().right());
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
  return PacketTransformerHandle(SentinelNodeIndex::kDeny);
}

PacketTransformerHandle PacketTransformerManager::Accept() const {
  return PacketTransformerHandle(SentinelNodeIndex::kAccept);
}

PacketTransformerHandle PacketTransformerManager::FromPacketSetHandle(
    PacketSetHandle packet_set) {
  if (packet_set_manager_.IsEmptySet(packet_set)) return Deny();
  if (packet_set_manager_.IsFullSet(packet_set)) return Accept();

  const PacketSetManager::DecisionNode& packet_node =
      packet_set_manager_.GetNodeOrDie(packet_set);

  DecisionNode transformer_node{
      .field = packet_node.field,
      // This starts out empty and will be populated below.
      .modify_branch_by_field_match = {},
      // Since packet sets are not modified, we don't want any default
      // field modification branches.
      .default_branch_by_field_modification = {},
      .default_branch = FromPacketSetHandle(packet_node.default_branch),
  };

  for (const auto& [value, branch] : packet_node.branch_by_field_value) {
    PacketTransformerHandle transformer_branch = FromPacketSetHandle(branch);
    DCHECK(transformer_branch != transformer_node.default_branch);
    transformer_node.modify_branch_by_field_match[value][value] =
        transformer_branch;
  }

  return NodeToTransformer(std::move(transformer_node));
}

// TODO(dilo): There are efficiency improvements we could make here, like
// getting rid of predicates entirely and moving to a normalized form.
PacketTransformerHandle PacketTransformerManager::Filter(
    const PredicateProto& predicate) {
  return FromPacketSetHandle(packet_set_manager_.Compile(predicate));
}

PacketTransformerHandle PacketTransformerManager::Modification(
    absl::string_view field, int value) {
  return NodeToTransformer(DecisionNode{
      .field = packet_set_manager_.field_manager_.GetOrCreatePacketFieldHandle(
          field),
      .modify_branch_by_field_match = {},
      .default_branch_by_field_modification = {{value, Accept()}},
      .default_branch = Deny(),
  });
}

namespace {

// Aliases for the map types of `PacketTransformerManager::DecisionNode`.
using ModifyBranchMap = absl::btree_map<int, PacketTransformerHandle>;
using MatchBranchMap = absl::btree_map<int, ModifyBranchMap>;

const MatchBranchMap& EmptyMatchBranchMap() {
  static const absl::NoDestructor<MatchBranchMap> kEmpty;
  return *kEmpty;
}

const ModifyBranchMap& EmptyModifyBranchMap() {
  static const absl::NoDestructor<ModifyBranchMap> kEmpty;
  return *kEmpty;
}

// Returns true iff `transformer` is the Deny transformer, which by documented
// contract is the default-constructed handle. (Unlike
// `PacketTransformerManager::IsDeny`, this is callable without a manager.)
bool IsDenyHandle(PacketTransformerHandle transformer) {
  return transformer == PacketTransformerHandle();
}

// A cheap, non-owning view of a decision node as seen "at" a field no larger
// than the node's own field: either the node's own maps (if the node branches
// on that field), or the trivial expansion "for every value of the field,
// leave it unmodified and fall through to the node" (if the node branches on
// a strictly larger field, or is Accept). This lets the binary operations
// below combine operands with distinct fields without materializing — and
// then re-interning — the trivial expansion as a `DecisionNode`.
struct DecisionNodeView {
  const MatchBranchMap* modify_branch_by_field_match;
  const ModifyBranchMap* default_branch_by_field_modification;
  PacketTransformerHandle default_branch;
};

// Returns the view of `node` (the decision node of `transformer`, or null if
// `transformer` is Accept) at `field`, which must be <= `node->field`.
//
// `Node` is always `PacketTransformerManager::DecisionNode`; it is a template
// parameter only because that type is private and cannot be named here.
template <typename Node>
DecisionNodeView ViewAtField(PacketFieldHandle field,
                             PacketTransformerHandle transformer,
                             const Node* node) {
  if (node != nullptr && node->field == field) {
    return DecisionNodeView{
        .modify_branch_by_field_match = &node->modify_branch_by_field_match,
        .default_branch_by_field_modification =
            &node->default_branch_by_field_modification,
        .default_branch = node->default_branch,
    };
  }
  return DecisionNodeView{
      .modify_branch_by_field_match = &EmptyMatchBranchMap(),
      .default_branch_by_field_modification = &EmptyModifyBranchMap(),
      .default_branch = transformer,
  };
}

// Returns the smallest field branched on by the given decision nodes, at
// least one of which must be non-null (null encodes Accept, which branches on
// no field). See `ViewAtField` regarding the `Node` template parameter.
template <typename Node>
PacketFieldHandle SmallestField(const Node* left, const Node* right) {
  DCHECK(left != nullptr || right != nullptr);
  if (left == nullptr) return right->field;
  if (right == nullptr) return left->field;
  return std::min(left->field, right->field);
}

// The two operands of a binary combinator, viewed at the smallest field
// branched on by either: an operand that is Accept, or branches on a strictly
// larger field, is viewed as a trivial node at that field.
struct OperandViews {
  PacketFieldHandle field;
  DecisionNodeView left;
  DecisionNodeView right;
};

// Views the operands `left` and `right`, whose decision nodes are `left_node`
// and `right_node` (null encoding Accept; at least one must be non-null), at
// the smallest field branched on by either. See `ViewAtField` regarding the
// `Node` template parameter.
template <typename Node>
OperandViews ViewOperandsAtSmallestField(PacketTransformerHandle left,
                                         const Node* left_node,
                                         PacketTransformerHandle right,
                                         const Node* right_node) {
  const PacketFieldHandle field = SmallestField(left_node, right_node);
  return OperandViews{
      .field = field,
      .left = ViewAtField(field, left, left_node),
      .right = ViewAtField(field, right, right_node),
  };
}

// A cheap, non-owning view of a logical (modify value -> branch) map,
// represented as a base map plus at most one extra entry whose key must not
// be a key of the base map.
class ModifyBranchesView {
 public:
  using Entry = std::pair<int, PacketTransformerHandle>;

  explicit ModifyBranchesView(const ModifyBranchMap& base) : base_(&base) {}
  ModifyBranchesView(const ModifyBranchMap& base, Entry extra)
      : base_(&base), extra_(extra) {
    DCHECK(!base.contains(extra.first));
  }

  // Invokes `fn(modify_value, branch)` for each entry: the base map entries
  // in increasing key order, then the extra entry, if any.
  template <typename Fn>
  void ForEach(Fn&& fn) const {
    for (const auto& [value, branch] : *base_) fn(value, branch);
    if (extra_.has_value()) fn(extra_->first, extra_->second);
  }

  std::optional<PacketTransformerHandle> Find(int value) const {
    if (extra_.has_value() && extra_->first == value) return extra_->second;
    if (auto it = base_->find(value); it != base_->end()) return it->second;
    return std::nullopt;
  }

  bool empty() const { return base_->empty() && !extra_.has_value(); }

 private:
  const ModifyBranchMap* base_;
  std::optional<Entry> extra_;
};

// Returns a view of the logical (modify value -> branch) map that `node`
// applies to packets whose field is equal to `value`: the matching entry of
// `modify_branch_by_field_match` if there is one; otherwise the default
// modifications, plus the unmodified fall-through to `default_branch` (keyed
// by `value`, since the field keeps its value) unless that branch is Deny or
// shadowed by a default modification to `value`.
ModifyBranchesView ModifyBranchesAtValue(const DecisionNodeView& node,
                                         int value) {
  if (auto it = node.modify_branch_by_field_match->find(value);
      it != node.modify_branch_by_field_match->end()) {
    return ModifyBranchesView(it->second);
  }
  const ModifyBranchMap& defaults = *node.default_branch_by_field_modification;
  if (defaults.contains(value) || IsDenyHandle(node.default_branch)) {
    return ModifyBranchesView(defaults);
  }
  return ModifyBranchesView(defaults, {value, node.default_branch});
}

// Combines two (modify value -> branch) maps key-wise into a new map, using
// `combiner(left_branch, right_branch)` for shared keys and substituting
// `default_value` for the missing side otherwise.
template <typename Combiner>
ModifyBranchMap CombineModifyBranches(const ModifyBranchesView& left,
                                      const ModifyBranchesView& right,
                                      Combiner&& combiner,
                                      PacketTransformerHandle default_value) {
  ModifyBranchMap result;
  left.ForEach([&](int value, PacketTransformerHandle left_branch) {
    // Keys arrive in near-sorted order, so the `end()` hint is mostly exact.
    result.try_emplace(
        result.end(), value,
        combiner(left_branch, right.Find(value).value_or(default_value)));
  });
  right.ForEach([&](int value, PacketTransformerHandle right_branch) {
    if (left.Find(value).has_value()) return;
    result.try_emplace(value, combiner(default_value, right_branch));
  });
  return result;
}

// Returns the union of the keys of the given maps, sorted and deduplicated.
template <typename... Maps>
std::vector<int> SortedUniqueKeys(const Maps&... maps) {
  std::vector<int> keys;
  keys.reserve((maps.size() + ... + 0));
  auto append_keys = [&keys](const auto& map) {
    for (const auto& entry : map) keys.push_back(entry.first);
  };
  (append_keys(maps), ...);
  absl::c_sort(keys);
  keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
  return keys;
}

}  // namespace

PacketTransformerHandle PacketTransformerManager::Sequence(
    PacketTransformerHandle left, PacketTransformerHandle right) {
  // Base cases.
  if (IsDeny(left) || IsDeny(right)) return Deny();
  if (IsAccept(left)) return right;
  if (IsAccept(right)) return left;

  // Both operands are decision nodes.
  const auto [field, left_view, right_view] = ViewOperandsAtSmallestField(
      left, &GetNodeOrDie(left), right, &GetNodeOrDie(right));

  // Unions `branch` into `branches[modify_value]`, treating absence as Deny.
  auto union_into = [this](ModifyBranchMap& branches, int modify_value,
                           PacketTransformerHandle branch) {
    auto [it, inserted] = branches.try_emplace(modify_value, branch);
    if (!inserted) it->second = Union(it->second, branch);
  };

  DecisionNode result_node{
      .field = field,
      .default_branch =
          Sequence(left_view.default_branch, right_view.default_branch),
  };

  // Construct the possible results of applying the right node to packets
  // gotten by taken default modification branches in the left node...
  ModifyBranchMap& result_modifications =
      result_node.default_branch_by_field_modification;
  for (const auto& [value, branch] :
       *left_view.default_branch_by_field_modification) {
    ModifyBranchesAtValue(right_view, value)
        .ForEach([&, branch = branch](int modify_value,
                                      PacketTransformerHandle right_branch) {
          union_into(result_modifications, modify_value,
                     Sequence(branch, right_branch));
        });
  }
  // ... and of applying the right node's default modifications to packets
  // falling through the left node unmodified.
  for (const auto& [modify_value, right_branch] :
       *right_view.default_branch_by_field_modification) {
    union_into(result_modifications, modify_value,
               Sequence(left_view.default_branch, right_branch));
  }

  // For every value mapped in either node, construct the proper new branch.
  for (int value :
       SortedUniqueKeys(*left_view.modify_branch_by_field_match,
                        *right_view.modify_branch_by_field_match,
                        *left_view.default_branch_by_field_modification,
                        *right_view.default_branch_by_field_modification,
                        result_modifications)) {
    ModifyBranchesView left_branches_at_value =
        ModifyBranchesAtValue(left_view, value);
    // An empty map is equivalent to a map with a single entry of
    // <value, Deny>, but the latter is not always canonical. However, an
    // empty map won't work correctly for the merges below (an in fact, the
    // whole for-loop would be skipped), so we expand it here if necessary.
    if (left_branches_at_value.empty()) {
      left_branches_at_value =
          ModifyBranchesView(EmptyModifyBranchMap(), {value, Deny()});
    }

    // `value`s arrive in increasing order, so inserting at `end()` is O(1).
    ModifyBranchMap& result_branches =
        result_node.modify_branch_by_field_match
            .try_emplace(result_node.modify_branch_by_field_match.end(), value)
            ->second;
    left_branches_at_value.ForEach([&](int left_value,
                                       PacketTransformerHandle left_branch) {
      ModifyBranchesAtValue(right_view, left_value)
          .ForEach([&](int modify_value, PacketTransformerHandle right_branch) {
            union_into(result_branches, modify_value,
                       Sequence(left_branch, right_branch));
          });
    });
  }

  return NodeToTransformer(std::move(result_node));
}

template <typename Combiner>
PacketTransformerHandle PacketTransformerManager::PointwiseCombine(
    PacketTransformerHandle left, PacketTransformerHandle right,
    Combiner&& combiner) {
  // Neither operand is Deny and at most one is Accept, so at least one is a
  // decision node.
  const auto [field, left_view, right_view] = ViewOperandsAtSmallestField(
      left, IsAccept(left) ? nullptr : &GetNodeOrDie(left), right,
      IsAccept(right) ? nullptr : &GetNodeOrDie(right));

  DecisionNode result_node{
      .field = field,
      .default_branch_by_field_modification = CombineModifyBranches(
          ModifyBranchesView(*left_view.default_branch_by_field_modification),
          ModifyBranchesView(*right_view.default_branch_by_field_modification),
          combiner,
          /*default_value=*/Deny()),
      .default_branch =
          combiner(left_view.default_branch, right_view.default_branch),
  };

  // For every value mapped in either node, construct the proper new branch.
  for (int value :
       SortedUniqueKeys(*left_view.modify_branch_by_field_match,
                        *right_view.modify_branch_by_field_match,
                        *left_view.default_branch_by_field_modification,
                        *right_view.default_branch_by_field_modification)) {
    // `value`s arrive in increasing order, so inserting at `end()` is O(1).
    result_node.modify_branch_by_field_match.try_emplace(
        result_node.modify_branch_by_field_match.end(), value,
        CombineModifyBranches(ModifyBranchesAtValue(left_view, value),
                              ModifyBranchesAtValue(right_view, value),
                              combiner,
                              /*default_value=*/Deny()));
  }

  return NodeToTransformer(std::move(result_node));
}

PacketTransformerHandle PacketTransformerManager::Union(
    PacketTransformerHandle left, PacketTransformerHandle right) {
  // Base cases.
  if (left == right) return left;
  if (IsDeny(right)) return left;
  if (IsDeny(left)) return right;

  return PointwiseCombine(
      left, right,
      [this](PacketTransformerHandle left, PacketTransformerHandle right) {
        return Union(left, right);
      });
}

PacketTransformerHandle PacketTransformerManager::Difference(
    PacketTransformerHandle left, PacketTransformerHandle right) {
  // Base cases.
  if (left == right) return Deny();
  if (IsDeny(left)) return Deny();
  if (IsDeny(right)) return left;

  return PointwiseCombine(
      left, right,
      [this](PacketTransformerHandle left, PacketTransformerHandle right) {
        return Difference(left, right);
      });
}

PacketTransformerHandle PacketTransformerManager::Iterate(
    PacketTransformerHandle iterable) {
  PacketTransformerHandle previous_approximation = Accept();
  PacketTransformerHandle current_approximation = Union(Accept(), iterable);
  // Iterate until we reach a fixed point.
  while (current_approximation != previous_approximation) {
    previous_approximation = current_approximation;
    current_approximation =
        Sequence(previous_approximation, previous_approximation);
  }
  return current_approximation;
}

PacketSetHandle PacketTransformerManager::GetAllPossibleOutputPackets(
    PacketTransformerHandle transformer) {
  if (IsAccept(transformer)) return PacketSetManager().FullSet();
  if (IsDeny(transformer)) return PacketSetManager().EmptySet();

  const DecisionNode& node = GetNodeOrDie(transformer);
  PacketSetHandle default_output =
      GetAllPossibleOutputPackets(node.default_branch);
  absl::flat_hash_map<int, PacketSetHandle> output_by_field_value;
  auto add_to_output_by_field_value = [&](int value, PacketSetHandle output) {
    PacketSetHandle& combined_output = output_by_field_value[value];
    combined_output = packet_set_manager_.Or(combined_output, output);
  };

  // Case 1: Output packets that hit the default branch and got modified.
  // Implements the `b_A` in the `fwd` function in section C.3 Push and Pull
  // in KATch: A Fast Symbolic Verifier for NetKAT.
  for (const auto& [modify_value, branch] :
       node.default_branch_by_field_modification) {
    add_to_output_by_field_value(modify_value,
                                 GetAllPossibleOutputPackets(branch));
  }

  // Case 2: Output packets that hit an explicit branch and got modified.
  // Implements the `b_B` in the `fwd` function in section C.3 Push and Pull
  // in KATch: A Fast Symbolic Verifier for NetKAT.
  absl::flat_hash_set<int> branch_modify_values;
  for (const auto& [match_value, branch_by_modify] :
       node.modify_branch_by_field_match) {
    for (const auto& [modify_value, branch] : branch_by_modify) {
      branch_modify_values.insert(modify_value);
      add_to_output_by_field_value(modify_value,
                                   GetAllPossibleOutputPackets(branch));
    }
  }

  // Case 3: Output packets that does not match on a branch and does not get
  // modified.
  //  Implements the `b_C` in the `fwd` function in section C.3 Push and Pull
  //  in KATch: A Fast Symbolic Verifier for NetKAT.
  for (int modify_value : branch_modify_values) {
    if (!node.modify_branch_by_field_match.contains(modify_value) &&
        !node.default_branch_by_field_modification.contains(modify_value)) {
      add_to_output_by_field_value(modify_value, default_output);
    }
  }

  // Case 4: Output packets that got matched on an explicit branch, but did
  // not get modified. Implements the `b_D` in the `fwd` function in section
  // C.3 Push and Pull in KATch: A Fast Symbolic Verifier for NetKAT.
  for (auto& [match_value, unused] : node.modify_branch_by_field_match) {
    if (!branch_modify_values.contains(match_value)) {
      add_to_output_by_field_value(match_value, PacketSetManager().EmptySet());
    }
  }

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

  // Required to sort `output_by_field_value_list` to ensure that it meets the
  // invariant of the `DecisionNode`'s `branch_by_field_value`.
  absl::c_sort(output_by_field_value_list, [](auto& left, auto& right) {
    return left.first < right.first;
  });

  return packet_set_manager_.NodeToPacket({
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
  if (IsAccept(transformer)) return PacketSetManager().FullSet();
  if (IsDeny(transformer)) return PacketSetManager().EmptySet();

  const DecisionNode& node = GetNodeOrDie(transformer);

  // Case 1: Input packets that hit the default branch and got modified.
  // Implements the `d'` in the `bwd` function in section C.3 Push and Pull in
  // KATch: A Fast Symbolic Verifier for NetKAT.
  PacketSetHandle default_branch_output_packets;
  for (const auto& [modify_value, branch] :
       node.default_branch_by_field_modification) {
    default_branch_output_packets =
        packet_set_manager_.Or(default_branch_output_packets,
                               GetAllInputPacketsThatProduceAnyOutput(branch));
  }

  // Case 2: Input packets that hit an explicit branch and got modified.
  // Implements the `b_A` in the `bwd` function in section C.3 Push and Pull
  // in KATch: A Fast Symbolic Verifier for NetKAT.
  absl::flat_hash_map<int, PacketSetHandle> branch_by_field_value_map;
  for (const auto& [match_value, branch_by_modify] :
       node.modify_branch_by_field_match) {
    PacketSetHandle union_of_branches;
    for (const auto& [modify_value, branch] : branch_by_modify) {
      union_of_branches = packet_set_manager_.Or(
          union_of_branches, GetAllInputPacketsThatProduceAnyOutput(branch));
    }
    branch_by_field_value_map[match_value] = union_of_branches;
  }

  // Case 3: Input packets that do not get matched on an explicit branch, but
  // do get modified.
  //  Implements the `b_B` in the `bwd` function in section C.3 Push and Pull
  //  in KATch: A Fast Symbolic Verifier for NetKAT.
  for (const auto& [modify_value, unused] :
       node.default_branch_by_field_modification) {
    if (!node.modify_branch_by_field_match.contains(modify_value)) {
      branch_by_field_value_map[modify_value] = default_branch_output_packets;
    }
  }

  PacketSetHandle default_branch = packet_set_manager_.Or(
      default_branch_output_packets,
      GetAllInputPacketsThatProduceAnyOutput(node.default_branch));
  int num_branches = 0;
  for (const auto& [value, branch] : branch_by_field_value_map) {
    if (branch != default_branch) num_branches++;
  }
  absl::FixedArray<std::pair<int, PacketSetHandle>, 0>
      branch_by_field_value_list(num_branches);
  int i = 0;
  for (const auto& [value, branch] : branch_by_field_value_map) {
    // Skips `default_branch` because an invariant of `DecisionNode` is that
    // no branch in `branch_by_field_value` can be a duplicate of the default
    // branch.
    if (branch == default_branch) continue;
    branch_by_field_value_list[i++] = std::make_pair(value, branch);
  }

  // Required to sort `branch_by_field_value_list` to ensure that it meets the
  // invariant of the `DecisionNode`'s `branch_by_field_value`.
  absl::c_sort(branch_by_field_value_list, [](auto& left, auto& right) {
    return left.first < right.first;
  });

  return packet_set_manager_.NodeToPacket({
      .field = node.field,
      .default_branch = default_branch,
      .branch_by_field_value = std::move(branch_by_field_value_list),
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

  auto pretty_print_map =
      [&](absl::string_view field,
          const absl::btree_map<int, PacketTransformerHandle>& map) {
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

  for (const auto& [value, modify_map] : node.modify_branch_by_field_match) {
    absl::StrAppendFormat(&result, "  %s == %d:\n", field, value);
    pretty_print_map(field, modify_map);
  }
  absl::StrAppendFormat(&result, "  %s == *:\n", field);
  pretty_print_map(field, node.default_branch_by_field_modification);
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

  auto pretty_print_map =
      [&](absl::string_view field,
          const absl::btree_map<int, PacketTransformerHandle>& map) {
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
    for (const auto& [value, modify_map] : node.modify_branch_by_field_match) {
      absl::StrAppendFormat(&result, "  %s == %d:\n", field, value);
      pretty_print_map(field, modify_map);
    }
    absl::StrAppendFormat(&result, "  %s == *:\n", field);
    pretty_print_map(field, node.default_branch_by_field_modification);
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
                          SentinelNodeIndex::kAccept);
    absl::StrAppend(&result, "}\n");
    return result;
  }
  if (IsDeny(transformer)) {
    absl::StrAppendFormat(&result, "  %d [label=\"F\" shape=box]\n",
                          SentinelNodeIndex::kDeny);
    absl::StrAppend(&result, "}\n");
    return result;
  }
  absl::StrAppendFormat(&result, "  %d [label=\"T\" shape=box]\n",
                        SentinelNodeIndex::kAccept);
  absl::StrAppendFormat(&result, "  %d [label=\"F\" shape=box]\n",
                        SentinelNodeIndex::kDeny);
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
    for (const auto& [value, modify_map] : node.modify_branch_by_field_match) {
      if (modify_map.empty()) {
        absl::StrAppendFormat(&result, "  %d -> %d [label=\"%s==%s\"]\n",
                              transformer.node_index_, SentinelNodeIndex::kDeny,
                              field, absl::StrCat(value));
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
         node.default_branch_by_field_modification) {
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
  RET_CHECK(nodes_.size() <= SentinelNodeIndex::kMinSentinel);

  // Invariant: `transformer_by_node_[p] = s` iff `p == &nodes_[s.node_index_]`.
  for (const auto& [node_ptr, transformer] : transformer_by_node_) {
    RET_CHECK(transformer.node_index_ < nodes_.size());
    RET_CHECK(node_ptr == &nodes_[transformer.node_index_]);
  }
  for (int i = 0; i < nodes_.size(); ++i) {
    const DecisionNode& node = nodes_[i];
    // Look up both by pointer and by value (exercising the transparent
    // functors used by `NodeToTransformer`).
    auto it = transformer_by_node_.find(&node);
    RET_CHECK(it != transformer_by_node_.end());
    RET_CHECK(it->second == PacketTransformerHandle(i));
    it = transformer_by_node_.find(node);
    RET_CHECK(it != transformer_by_node_.end());
    RET_CHECK(it->second == PacketTransformerHandle(i));
  }

  // Node Invariants.
  for (int i = 0; i < nodes_.size(); ++i) {
    const DecisionNode& node = nodes_[i];
    // Invariant: `modify_branch_by_field_match` or
    // `default_branch_by_field_modification` is non-empty.
    // Maintained by `NodeToTransformer`.
    RET_CHECK(!node.modify_branch_by_field_match.empty() ||
              !node.default_branch_by_field_modification.empty());

    // Invariant: node field is strictly smaller than sub-node fields.
    RET_CHECK(IsAccept(node.default_branch) || IsDeny(node.default_branch) ||
              GetNodeOrDie(node.default_branch).field > node.field)
        << ":\n"
        << ToString(node);

    for (const auto& [match_value, branch_by_modify] :
         node.modify_branch_by_field_match) {
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
         node.default_branch_by_field_modification) {
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
