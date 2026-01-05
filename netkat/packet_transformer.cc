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

#include <cstdint>
#include <iterator>
#include <limits>
#include <optional>
#include <queue>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/container/btree_map.h"
#include "absl/container/fixed_array.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/functional/any_invocable.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "gutil/status.h"
#include "netkat/evaluator.h"
#include "netkat/netkat.pb.h"
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

// TODO(dilo): Creating as many map copies as this method facilitates is
// probably going to cause terrible performance, and needs to be revisited.
absl::btree_map<int, PacketTransformerHandle>
PacketTransformerManager::GetMapAtValue(const DecisionNode& node, int value) {
  if (node.modify_branch_by_field_match.contains(value))
    return node.modify_branch_by_field_match.at(value);

  absl::btree_map<int, PacketTransformerHandle> result =
      node.default_branch_by_field_modification;
  if (result.contains(value) || IsDeny(node.default_branch)) return result;

  // Otherwise, add a mapping from `value` to the default branch, then return.
  result[value] = node.default_branch;
  return result;
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
    // TODO(dilo): Consider if this can make use of GetMapAtValue. Perhaps by
    // calling it on a copy of DecisionNode without any
    // `modify_branch_by_field_match` mappings?
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

  auto [it, inserted] = transformer_by_node_.try_emplace(
      node, PacketTransformerHandle(nodes_.size()));
  if (inserted) {
    nodes_.push_back(std::move(node));
    LOG_IF(DFATAL, nodes_.size() > SentinelNodeIndex::kMinSentinel)
        << "Internal invariant violated: Proper and sentinel node indices must "
           "be disjoint. This indicates that we allocated more nodes than are "
           "supported (> 2^32 - 2).";
  }
  return it->second;
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
    case PolicyProto::kIntersectionOp: {
      key.lhs_child = Compile(policy.intersection_op().left());
      key.rhs_child = Compile(policy.intersection_op().right());
      auto it = transformer_by_hash_.find(key);
      if (it != transformer_by_hash_.end()) return it->second;
      return transformer_by_hash_[key] =
                 Intersection(key.lhs_child, key.rhs_child);
    }
    case PolicyProto::kDifferenceOp: {
      key.lhs_child = Compile(policy.difference_op().left());
      key.rhs_child = Compile(policy.difference_op().right());
      auto it = transformer_by_hash_.find(key);
      if (it != transformer_by_hash_.end()) return it->second;
      return transformer_by_hash_[key] =
                 Difference(key.lhs_child, key.rhs_child);
    }
    case PolicyProto::kSymmetricDifferenceOp: {
      key.lhs_child = Compile(policy.symmetric_difference_op().left());
      key.rhs_child = Compile(policy.symmetric_difference_op().right());
      auto it = transformer_by_hash_.find(key);
      if (it != transformer_by_hash_.end()) return it->second;
      return transformer_by_hash_[key] =
                 SymmetricDifference(key.lhs_child, key.rhs_child);
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
absl::btree_map<int, PacketTransformerHandle> CombineModifyBranches(
    const absl::btree_map<int, PacketTransformerHandle>& left,
    const absl::btree_map<int, PacketTransformerHandle>& right,
    absl::AnyInvocable<PacketTransformerHandle(PacketTransformerHandle,
                                               PacketTransformerHandle)>
        combiner,
    PacketTransformerHandle default_value) {
  absl::btree_map<int, PacketTransformerHandle> result;
  for (const auto& [value, branch] : left) {
    if (right.contains(value)) {
      result[value] = combiner(branch, right.at(value));
    } else {
      result[value] = combiner(branch, default_value);
    }
  }
  for (const auto& [value, branch] : right) {
    if (!result.contains(value))
      result[value] = combiner(default_value, branch);
  }
  return result;
}

}  // namespace

PacketTransformerHandle PacketTransformerManager::Sequence(DecisionNode left,
                                                           DecisionNode right) {
  // left.field > right.field: Expand the left node, reducing to the inductive
  // case.
  if (left.field > right.field) {
    PacketFieldHandle first_field = right.field;
    return Sequence(
        DecisionNode{
            .field = first_field,
            .default_branch = NodeToTransformer(std::move(left)),
        },
        std::move(right));
  }

  // left.field < right.field: Expand the right node, reducing to the
  // inductive case.
  if (left.field < right.field) {
    PacketFieldHandle first_field = left.field;
    return Sequence(std::move(left),
                    DecisionNode{
                        .field = first_field,
                        .default_branch = NodeToTransformer(std::move(right)),
                    });
  }

  // left.field == right.field: branch on shared field.
  DCHECK(left.field == right.field);
  DecisionNode result_node{
      .field = left.field,
      .default_branch = Sequence(left.default_branch, right.default_branch),
  };

  // Construct the possible results of applying the right node to packets
  // gotten by taken default modification branches in the left node.
  absl::btree_map<int, PacketTransformerHandle>
      right_applied_to_left_modifications;
  for (const auto& [value, branch] :
       left.default_branch_by_field_modification) {
    absl::btree_map<int, PacketTransformerHandle> right_at_value_with_sequence =
        CombineModifyBranches(
            {}, GetMapAtValue(right, value),
            /*combiner=*/
            [this](PacketTransformerHandle left,
                   PacketTransformerHandle right) {
              return Sequence(left, right);
            },
            /*default_value=*/branch);
    right_applied_to_left_modifications = CombineModifyBranches(
        right_applied_to_left_modifications, right_at_value_with_sequence,
        /*combiner=*/
        [this](PacketTransformerHandle left, PacketTransformerHandle right) {
          return Union(left, right);
        },
        /*default_value=*/Deny());
  }

  result_node.default_branch_by_field_modification = CombineModifyBranches(
      right_applied_to_left_modifications,
      CombineModifyBranches(
          {}, right.default_branch_by_field_modification,
          [this](PacketTransformerHandle left, PacketTransformerHandle right) {
            return Sequence(left, right);
          },
          /*default_value=*/left.default_branch),
      [this](PacketTransformerHandle left, PacketTransformerHandle right) {
        return Union(left, right);
      },
      /*default_value=*/Deny());

  // Collect every value mapped in each node.
  absl::flat_hash_set<int> all_possible_values;
  all_possible_values.reserve(
      left.modify_branch_by_field_match.size() +
      right.modify_branch_by_field_match.size() +
      left.default_branch_by_field_modification.size() +
      right.default_branch_by_field_modification.size() +
      right_applied_to_left_modifications.size());

  absl::c_transform(
      left.modify_branch_by_field_match,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });
  absl::c_transform(
      right.modify_branch_by_field_match,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });
  absl::c_transform(
      left.default_branch_by_field_modification,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });
  absl::c_transform(
      right.default_branch_by_field_modification,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });
  absl::c_transform(
      right_applied_to_left_modifications,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });

  // For every value in mapped in each node, construct the proper new branch.
  for (int value : all_possible_values) {
    auto left_map_at_value = GetMapAtValue(left, value);
    // An empty map is equivalent to a map with a single entry of
    // <value, Deny>, but the latter is not always canonical. However, an
    // empty map won't work correctly for the merges below (an in fact, the
    // whole for-loop would be skipped), so we expand it here if necessary.
    if (left_map_at_value.empty()) left_map_at_value[value] = Deny();

    for (const auto& [left_value, left_spp] : left_map_at_value) {
      result_node.modify_branch_by_field_match[value] = CombineModifyBranches(
          result_node.modify_branch_by_field_match[value],
          CombineModifyBranches(
              {}, GetMapAtValue(right, left_value),
              /*combiner=*/
              [this](PacketTransformerHandle left,
                     PacketTransformerHandle right) {
                return Sequence(left, right);
              },
              /*default_value=*/left_spp),
          /*combiner=*/
          [this](PacketTransformerHandle left, PacketTransformerHandle right) {
            return Union(left, right);
          },
          /*default_value=*/Deny());
    }
  }

  return NodeToTransformer(std::move(result_node));
}

PacketTransformerHandle PacketTransformerManager::Sequence(
    PacketTransformerHandle left, PacketTransformerHandle right) {
  // Base cases.
  if (IsDeny(left) || IsDeny(right)) return Deny();
  if (IsAccept(left)) return right;
  if (IsAccept(right)) return left;

  // If neither node is accept or deny, then sequence the nodes directly.
  return Sequence(GetNodeOrDie(left), GetNodeOrDie(right));
}

PacketTransformerHandle PacketTransformerManager::Union(DecisionNode left,
                                                        DecisionNode right) {
  // left.field > right.field: Expand the left node, reducing to the inductive
  // case.
  if (left.field > right.field) {
    PacketFieldHandle first_field = right.field;
    return Union(
        DecisionNode{
            .field = first_field,
            .default_branch = NodeToTransformer(std::move(left)),
        },
        std::move(right));
  }

  // left.field < right.field: Expand the right node, reducing to the
  // inductive case.
  if (left.field < right.field) {
    PacketFieldHandle first_field = left.field;
    return Union(std::move(left),
                 DecisionNode{
                     .field = first_field,
                     .default_branch = NodeToTransformer(std::move(right)),
                 });
  }

  // left.field == right.field: branch on shared field.
  DCHECK(left.field == right.field);
  DecisionNode result_node{
      .field = left.field,
      .default_branch_by_field_modification = CombineModifyBranches(
          left.default_branch_by_field_modification,
          right.default_branch_by_field_modification,
          /*combiner=*/
          [this](PacketTransformerHandle left, PacketTransformerHandle right) {
            return Union(left, right);
          },
          /*default_value=*/Deny()),
      .default_branch = Union(left.default_branch, right.default_branch),
  };

  // Collect every value in mapped in each node.
  absl::flat_hash_set<int> all_possible_values;
  all_possible_values.reserve(
      left.modify_branch_by_field_match.size() +
      right.modify_branch_by_field_match.size() +
      left.default_branch_by_field_modification.size() +
      right.default_branch_by_field_modification.size());

  absl::c_transform(
      left.modify_branch_by_field_match,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });
  absl::c_transform(
      right.modify_branch_by_field_match,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });
  absl::c_transform(
      left.default_branch_by_field_modification,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });
  absl::c_transform(
      right.default_branch_by_field_modification,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });

  // For every value in mapped in each node, construct the proper new branch.
  // TODO(dilo): Would like to use absl::bind_front here instead of a lambda:
  //   absl::bind_front<PacketTransformerHandle(PacketTransformerHandle,
  //     PacketTransformerHandle)>(
  // &PacketTransformerManager::Union, this),
  for (int value : all_possible_values) {
    result_node.modify_branch_by_field_match[value] = CombineModifyBranches(
        GetMapAtValue(left, value), GetMapAtValue(right, value),
        /*combiner=*/
        [this](PacketTransformerHandle left, PacketTransformerHandle right) {
          return Union(left, right);
        },
        /*default_value=*/Deny());
  }

  return NodeToTransformer(std::move(result_node));
}

PacketTransformerHandle PacketTransformerManager::Union(
    PacketTransformerHandle left, PacketTransformerHandle right) {
  // Base cases.
  if (left == right) return left;
  if (IsDeny(right)) return left;
  if (IsDeny(left)) return right;

  // If either node is accept, then expand it before merging.
  if (IsAccept(left) || IsAccept(right)) {
    const DecisionNode& other_node =
        GetNodeOrDie(IsAccept(left) ? right : left);
    return Union(
        DecisionNode{
            .field = other_node.field,
            .default_branch = Accept(),
        },
        other_node);
  }

  // If neither node is accept or deny, then union the nodes directly.
  return Union(GetNodeOrDie(left), GetNodeOrDie(right));
}

PacketTransformerHandle PacketTransformerManager::Intersection(
    DecisionNode left, DecisionNode right) {
  // left.field > right.field: Expand the left node, reducing to the inductive
  // case.
  if (left.field > right.field) {
    PacketFieldHandle first_field = right.field;
    return Intersection(
        DecisionNode{
            .field = first_field,
            .default_branch = NodeToTransformer(std::move(left)),
        },
        std::move(right));
  }

  // left.field < right.field: Expand the right node, reducing to the inductive
  // case.
  if (left.field < right.field) {
    PacketFieldHandle first_field = left.field;
    return Intersection(
        std::move(left),
        DecisionNode{
            .field = first_field,
            .default_branch = NodeToTransformer(std::move(right)),
        });
  }

  // left.field == right.field: branch on shared field.
  DCHECK(left.field == right.field);
  DecisionNode result_node{
      .field = left.field,
      .default_branch_by_field_modification = CombineModifyBranches(
          left.default_branch_by_field_modification,
          right.default_branch_by_field_modification,
          /*combiner=*/
          [this](PacketTransformerHandle left, PacketTransformerHandle right) {
            return Intersection(left, right);
          },
          /*default_value=*/Deny()),
      .default_branch = Intersection(left.default_branch, right.default_branch),
  };

  // Collect every value in mapped in each node.
  absl::flat_hash_set<int> all_possible_values;
  all_possible_values.reserve(
      left.modify_branch_by_field_match.size() +
      right.modify_branch_by_field_match.size() +
      left.default_branch_by_field_modification.size() +
      right.default_branch_by_field_modification.size());

  absl::c_transform(
      left.modify_branch_by_field_match,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });
  absl::c_transform(
      right.modify_branch_by_field_match,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });
  absl::c_transform(
      left.default_branch_by_field_modification,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });
  absl::c_transform(
      right.default_branch_by_field_modification,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });

  // For every value in mapped in each node, construct the proper new branch.
  // TODO(dilo): Would like to use absl::bind_front here instead of a lambda:
  //   absl::bind_front<PacketTransformerHandle(PacketTransformerHandle,
  //     PacketTransformerHandle)>(
  // &PacketTransformerManager::Intersection, this),
  for (int value : all_possible_values) {
    result_node.modify_branch_by_field_match[value] = CombineModifyBranches(
        GetMapAtValue(left, value), GetMapAtValue(right, value),
        /*combiner=*/
        [this](PacketTransformerHandle left, PacketTransformerHandle right) {
          return Intersection(left, right);
        },
        /*default_value=*/Deny());
  }

  return NodeToTransformer(std::move(result_node));
}

PacketTransformerHandle PacketTransformerManager::Intersection(
    PacketTransformerHandle left, PacketTransformerHandle right) {
  if (left == right) return left;
  if (IsDeny(left) || IsDeny(right)) return Deny();

  if (IsAccept(left) || IsAccept(right)) {
    const DecisionNode& other_node =
        GetNodeOrDie(IsAccept(left) ? right : left);
    return Intersection(
        DecisionNode{
            .field = other_node.field,
            .default_branch = Accept(),
        },
        other_node);
  }

  // If neither node is accept or deny, then intersection the nodes directly.
  return Intersection(GetNodeOrDie(left), GetNodeOrDie(right));
}

PacketTransformerHandle PacketTransformerManager::Difference(
    DecisionNode left, DecisionNode right) {
  // left.field > right.field: Expand the left node, reducing to the inductive
  // case.
  if (left.field > right.field) {
    PacketFieldHandle first_field = right.field;
    return Difference(
        DecisionNode{
            .field = first_field,
            .default_branch = NodeToTransformer(std::move(left)),
        },
        std::move(right));
  }

  // left.field < right.field: Expand the right node, reducing to the
  // inductive case.
  if (left.field < right.field) {
    PacketFieldHandle first_field = left.field;
    return Difference(std::move(left),
                      DecisionNode{
                          .field = first_field,
                          .default_branch = NodeToTransformer(std::move(right)),
                      });
  }

  // left.field == right.field: branch on shared field.
  DCHECK(left.field == right.field);
  DecisionNode result_node{
      .field = left.field,
      .default_branch_by_field_modification = CombineModifyBranches(
          left.default_branch_by_field_modification,
          right.default_branch_by_field_modification,
          /*combiner=*/
          [this](PacketTransformerHandle left, PacketTransformerHandle right) {
            return Difference(left, right);
          },
          /*default_value=*/Deny()),
      .default_branch = Difference(left.default_branch, right.default_branch),
  };

  // Collect every value in mapped in each node.
  absl::flat_hash_set<int> all_possible_values;
  all_possible_values.reserve(
      left.modify_branch_by_field_match.size() +
      right.modify_branch_by_field_match.size() +
      left.default_branch_by_field_modification.size() +
      right.default_branch_by_field_modification.size());

  absl::c_transform(
      left.modify_branch_by_field_match,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });
  absl::c_transform(
      right.modify_branch_by_field_match,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });
  absl::c_transform(
      left.default_branch_by_field_modification,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });
  absl::c_transform(
      right.default_branch_by_field_modification,
      std::inserter(all_possible_values, all_possible_values.end()),
      [](auto pair) { return pair.first; });

  // For every value in mapped in each node, construct the proper new branch.
  for (int value : all_possible_values) {
    result_node.modify_branch_by_field_match[value] = CombineModifyBranches(
        GetMapAtValue(left, value), GetMapAtValue(right, value),
        /*combiner=*/
        [this](PacketTransformerHandle left, PacketTransformerHandle right) {
          return Difference(left, right);
        },
        /*default_value=*/Deny());
  }

  return NodeToTransformer(std::move(result_node));
}

PacketTransformerHandle PacketTransformerManager::Difference(
    PacketTransformerHandle left, PacketTransformerHandle right) {
  // Base cases.
  if (left == right) return Deny();
  if (IsDeny(left)) return Deny();
  if (IsDeny(right)) return left;

  // If either node is accept, then expand it before merging.
  if (IsAccept(left)) {
    const DecisionNode& right_node = GetNodeOrDie(right);
    return Difference(
        DecisionNode{
            .field = right_node.field,
            .default_branch = Accept(),
        },
        right_node);
  }

  if (IsAccept(right)) {
    const DecisionNode& left_node = GetNodeOrDie(left);
    return Difference(left_node, DecisionNode{
                                     .field = left_node.field,
                                     .default_branch = Accept(),
                                 });
  }

  // If neither node is accept or deny, then difference the nodes directly.
  return Difference(GetNodeOrDie(left), GetNodeOrDie(right));
}

PacketTransformerHandle PacketTransformerManager::SymmetricDifference(
    PacketTransformerHandle left, PacketTransformerHandle right) {
  return Union(Difference(left, right), Difference(right, left));
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

  // Invariant: `transformer_by_node_[n] = s` iff `nodes_[s.node_index_] ==
  // n`.
  for (const auto& [node, transformer] : transformer_by_node_) {
    RET_CHECK(transformer.node_index_ < nodes_.size());
    RET_CHECK(nodes_[transformer.node_index_] == node);
  }
  for (int i = 0; i < nodes_.size(); ++i) {
    const DecisionNode& node = nodes_[i];
    auto it = transformer_by_node_.find(node);
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
