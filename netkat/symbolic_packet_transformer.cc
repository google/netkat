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

#include "netkat/symbolic_packet_transformer.h"

#include <cstdint>
#include <iterator>
#include <limits>
#include <queue>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/container/btree_map.h"
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
#include "netkat/interned_field.h"
#include "netkat/netkat.pb.h"
#include "netkat/symbolic_packet.h"

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

SymbolicPacketTransformer::SymbolicPacketTransformer()
    : node_index_(SentinelNodeIndex::kDeny) {}

std::string SymbolicPacketTransformer::ToString() const {
  if (node_index_ == SentinelNodeIndex::kDeny) {
    return "SymbolicPacketTransformer<deny>";
  } else if (node_index_ == SentinelNodeIndex::kAccept) {
    return "SymbolicPacketTransformer<accept>";
  } else {
    return absl::StrFormat("SymbolicPacketTransformer<%d>", node_index_);
  }
}

const SymbolicPacketTransformerManager::DecisionNode&
SymbolicPacketTransformerManager::GetNodeOrDie(
    SymbolicPacketTransformer transformer) const {
  CHECK_LT(transformer.node_index_, nodes_.size());  // Crash ok
  return nodes_[transformer.node_index_];
}

// TODO(dilo): Creating as many map copies as this method facilitates is
// probably going to cause terrible performance, and needs to be revisited.
absl::btree_map<int, SymbolicPacketTransformer>
SymbolicPacketTransformerManager::GetMapAtValue(const DecisionNode& node,
                                                int value) {
  if (node.modify_branch_by_field_match.contains(value))
    return node.modify_branch_by_field_match.at(value);

  absl::btree_map<int, SymbolicPacketTransformer> result =
      node.default_branch_by_field_modification;
  if (result.contains(value) || IsDeny(node.default_branch)) return result;

  // Otherwise, add a mapping from `value` to the default branch, then return.
  result[value] = node.default_branch;
  return result;
}

// Canonicalizes a decision node and returns a transformer.
SymbolicPacketTransformer SymbolicPacketTransformerManager::NodeToTransformer(
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
      node, SymbolicPacketTransformer(nodes_.size()));
  if (inserted) {
    nodes_.push_back(std::move(node));
    LOG_IF(DFATAL, nodes_.size() > SentinelNodeIndex::kMinSentinel)
        << "Internal invariant violated: Proper and sentinel node indices must "
           "be disjoint. This indicates that we allocated more nodes than are "
           "supported (> 2^32 - 2).";
  }
  return it->second;
}

bool SymbolicPacketTransformerManager::IsDeny(
    SymbolicPacketTransformer transformer) const {
  return transformer == Deny();
}

bool SymbolicPacketTransformerManager::IsAccept(
    SymbolicPacketTransformer transformer) const {
  return transformer == Accept();
}

// TODO(b/416560152): Currently, this implementation makes a copy of the packet
// for every subsequent call of Run, recursively. Ideally, there would be a
// clever method of modifying and 'unmodifying' packets in place that also works
// correctly.
absl::flat_hash_set<Packet> SymbolicPacketTransformerManager::Run(
    SymbolicPacketTransformer transformer,
    const Packet& concrete_packet) const {
  if (IsDeny(transformer)) return {};
  if (IsAccept(transformer)) return {concrete_packet};

  absl::flat_hash_set<Packet> result;
  const DecisionNode& node = GetNodeOrDie(transformer);
  std::string field =
      symbolic_packet_manager_.field_manager_.GetFieldName(node.field);
  auto field_it = concrete_packet.find(field);
  // If a field doesn't exist, it does not match any value.
  bool matched = false;
  if (field_it != concrete_packet.end()) {
    // If it exists, see if there is a value match for it and follow every
    // corresponding branch with value modified appropriately.
    if (auto mod_map_it =
            node.modify_branch_by_field_match.find(field_it->second);
        mod_map_it != node.modify_branch_by_field_match.end()) {
      matched = true;
      for (const auto& [value, branch] : mod_map_it->second) {
        Packet modified_packet = concrete_packet;
        modified_packet[field] = value;
        result.merge(Run(branch, modified_packet));
      }
    }
  }

  // If the packet was not matched by the above, run the default modifications.
  if (!matched) {
    for (const auto& [value, branch] :
         node.default_branch_by_field_modification) {
      // If the original packet already had this field with the same value as
      // this modified branch, then we should not also attempt the default
      // branch.
      if (field_it != concrete_packet.end() && field_it->second == value)
        matched = true;
      Packet modified_packet = concrete_packet;
      modified_packet[field] = value;
      result.merge(Run(branch, modified_packet));
    }
    if (!matched) result.merge(Run(node.default_branch, concrete_packet));
  }
  return result;
}

SymbolicPacketTransformer SymbolicPacketTransformerManager::Compile(
    const PolicyProto& policy) {
  switch (policy.policy_case()) {
    case PolicyProto::kFilter:
      return Filter(policy.filter());
    case PolicyProto::kModification:
      return Modification(policy.modification().field(),
                          policy.modification().value());
    case PolicyProto::kRecord:
      return Accept();
    case PolicyProto::kSequenceOp:
      return Sequence(Compile(policy.sequence_op().left()),
                      Compile(policy.sequence_op().right()));
    case PolicyProto::kUnionOp:
      return Union(Compile(policy.union_op().left()),
                   Compile(policy.union_op().right()));
    case PolicyProto::kIterateOp:
      return Iterate(Compile(policy.iterate_op().iterable()));
    case PolicyProto::POLICY_NOT_SET:
      // By convention, uninitialized policies must be treated like the Deny
      // policy.
      return Deny();
  }
  LOG(DFATAL) << "Unhandled policy kind: " << policy.policy_case();
  return Deny();
}

SymbolicPacketTransformer SymbolicPacketTransformerManager::Deny() const {
  return SymbolicPacketTransformer(SentinelNodeIndex::kDeny);
}

SymbolicPacketTransformer SymbolicPacketTransformerManager::Accept() const {
  return SymbolicPacketTransformer(SentinelNodeIndex::kAccept);
}

SymbolicPacketTransformer SymbolicPacketTransformerManager::FromSymbolicPacket(
    SymbolicPacket symbolic_packet) {
  if (symbolic_packet_manager_.IsEmptySet(symbolic_packet)) return Deny();
  if (symbolic_packet_manager_.IsFullSet(symbolic_packet)) return Accept();

  const SymbolicPacketManager::DecisionNode& packet_node =
      symbolic_packet_manager_.GetNodeOrDie(symbolic_packet);

  DecisionNode transformer_node{
      .field = packet_node.field,
      // This starts out empty and will be populated below.
      .modify_branch_by_field_match = {},
      // Since symbolic packets are not modified, we don't want any default
      // field modification branches.
      .default_branch_by_field_modification = {},
      .default_branch = FromSymbolicPacket(packet_node.default_branch),
  };

  for (const auto& [value, branch] : packet_node.branch_by_field_value) {
    SymbolicPacketTransformer transformer_branch = FromSymbolicPacket(branch);
    DCHECK(transformer_branch != transformer_node.default_branch);
    transformer_node.modify_branch_by_field_match[value][value] =
        transformer_branch;
  }

  return NodeToTransformer(std::move(transformer_node));
}

// TODO(dilo): There are efficiency improvements we could make here, like
// getting rid of predicates entirely and moving to a normalized form.
SymbolicPacketTransformer SymbolicPacketTransformerManager::Filter(
    const PredicateProto& predicate) {
  return FromSymbolicPacket(symbolic_packet_manager_.Compile(predicate));
}

SymbolicPacketTransformer SymbolicPacketTransformerManager::Modification(
    absl::string_view field, int value) {
  return NodeToTransformer(DecisionNode{
      .field = symbolic_packet_manager_.field_manager_.GetOrCreateInternedField(
          field),
      .modify_branch_by_field_match = {},
      .default_branch_by_field_modification = {{value, Accept()}},
      .default_branch = Deny(),
  });
}

namespace {
absl::btree_map<int, SymbolicPacketTransformer> CombineModifyBranches(
    const absl::btree_map<int, SymbolicPacketTransformer>& left,
    const absl::btree_map<int, SymbolicPacketTransformer>& right,
    absl::AnyInvocable<SymbolicPacketTransformer(SymbolicPacketTransformer,
                                                 SymbolicPacketTransformer)>
        combiner,
    SymbolicPacketTransformer default_value) {
  absl::btree_map<int, SymbolicPacketTransformer> result;
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

SymbolicPacketTransformer SymbolicPacketTransformerManager::Sequence(
    DecisionNode left, DecisionNode right) {
  // left.field > right.field: Expand the left node, reducing to the inductive
  // case.
  if (left.field > right.field) {
    InternedField first_field = right.field;
    return Sequence(
        DecisionNode{
            .field = first_field,
            .default_branch = NodeToTransformer(std::move(left)),
        },
        std::move(right));
  }

  // left.field < right.field: Expand the right node, reducing to the inductive
  // case.
  if (left.field < right.field) {
    InternedField first_field = left.field;
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

  // Construct the possible results of applying the right node to packets gotten
  // by taken default modification branches in the left node.
  absl::btree_map<int, SymbolicPacketTransformer>
      right_applied_to_left_modifications;
  for (const auto& [value, branch] :
       left.default_branch_by_field_modification) {
    absl::btree_map<int, SymbolicPacketTransformer>
        right_at_value_with_sequence = CombineModifyBranches(
            {}, GetMapAtValue(right, value),
            /*combiner=*/
            [this](SymbolicPacketTransformer left,
                   SymbolicPacketTransformer right) {
              return Sequence(left, right);
            },
            /*default_value=*/branch);
    right_applied_to_left_modifications = CombineModifyBranches(
        right_applied_to_left_modifications, right_at_value_with_sequence,
        /*combiner=*/
        [this](SymbolicPacketTransformer left,
               SymbolicPacketTransformer right) { return Union(left, right); },
        /*default_value=*/Deny());
  }

  result_node.default_branch_by_field_modification = CombineModifyBranches(
      right_applied_to_left_modifications,
      CombineModifyBranches(
          {}, right.default_branch_by_field_modification,
          [this](SymbolicPacketTransformer left,
                 SymbolicPacketTransformer right) {
            return Sequence(left, right);
          },
          /*default_value=*/left.default_branch),
      [this](SymbolicPacketTransformer left, SymbolicPacketTransformer right) {
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
    // <value, Deny>, but the latter is not always canonical. However, an empty
    // map won't work correctly for the merges below (an in fact, the whole
    // for-loop would be skipped), so we expand it here if necessary.
    if (left_map_at_value.empty()) left_map_at_value[value] = Deny();

    for (const auto& [left_value, left_spp] : left_map_at_value) {
      result_node.modify_branch_by_field_match[value] = CombineModifyBranches(
          result_node.modify_branch_by_field_match[value],
          CombineModifyBranches(
              {}, GetMapAtValue(right, left_value),
              /*combiner=*/
              [this](SymbolicPacketTransformer left,
                     SymbolicPacketTransformer right) {
                return Sequence(left, right);
              },
              /*default_value=*/left_spp),
          /*combiner=*/
          [this](SymbolicPacketTransformer left,
                 SymbolicPacketTransformer right) {
            return Union(left, right);
          },
          /*default_value=*/Deny());
    }
  }

  return NodeToTransformer(std::move(result_node));
}

SymbolicPacketTransformer SymbolicPacketTransformerManager::Sequence(
    SymbolicPacketTransformer left, SymbolicPacketTransformer right) {
  // Base cases.
  if (IsDeny(left) || IsDeny(right)) return Deny();
  if (IsAccept(left)) return right;
  if (IsAccept(right)) return left;

  // If neither node is accept or deny, then sequence the nodes directly.
  return Sequence(GetNodeOrDie(left), GetNodeOrDie(right));
}

SymbolicPacketTransformer SymbolicPacketTransformerManager::Union(
    DecisionNode left, DecisionNode right) {
  // left.field > right.field: Expand the left node, reducing to the inductive
  // case.
  if (left.field > right.field) {
    InternedField first_field = right.field;
    return Union(
        DecisionNode{
            .field = first_field,
            .default_branch = NodeToTransformer(std::move(left)),
        },
        std::move(right));
  }

  // left.field < right.field: Expand the right node, reducing to the inductive
  // case.
  if (left.field < right.field) {
    InternedField first_field = left.field;
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
          [this](SymbolicPacketTransformer left,
                 SymbolicPacketTransformer right) {
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
  //   absl::bind_front<SymbolicPacketTransformer(SymbolicPacketTransformer,
  //     SymbolicPacketTransformer)>(
  // &SymbolicPacketTransformerManager::Union, this),
  for (int value : all_possible_values) {
    result_node.modify_branch_by_field_match[value] = CombineModifyBranches(
        GetMapAtValue(left, value), GetMapAtValue(right, value),
        /*combiner=*/
        [this](SymbolicPacketTransformer left,
               SymbolicPacketTransformer right) { return Union(left, right); },
        /*default_value=*/Deny());
  }

  return NodeToTransformer(std::move(result_node));
}

SymbolicPacketTransformer SymbolicPacketTransformerManager::Union(
    SymbolicPacketTransformer left, SymbolicPacketTransformer right) {
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

SymbolicPacketTransformer SymbolicPacketTransformerManager::Iterate(
    SymbolicPacketTransformer iterable) {
  SymbolicPacketTransformer previous_approximation = Accept();
  SymbolicPacketTransformer current_approximation = Union(Accept(), iterable);
  // Iterate until we reach a fixed point.
  while (current_approximation != previous_approximation) {
    previous_approximation = current_approximation;
    current_approximation =
        Sequence(previous_approximation, previous_approximation);
  }
  return current_approximation;
}

// SymbolicPacket SymbolicPacketTransformerManager::Push(
//     SymbolicPacket packet, SymbolicPacketTransformer transformer) const {
//   LOG(DFATAL) << "Push is not implemented yet.";
//   return SymbolicPacket();
// }

// SymbolicPacket SymbolicPacketTransformerManager::Pull(
//     SymbolicPacketTransformer transformer, SymbolicPacket packet) const {
//   LOG(DFATAL) << "Pull is not implemented yet.";
//   return SymbolicPacket();
// }

std::string SymbolicPacketTransformerManager::ToString(
    const DecisionNode& node) const {
  std::string result;
  std::vector<SymbolicPacketTransformer> work_list;

  auto pretty_print_map =
      [&](absl::string_view field,
          const absl::btree_map<int, SymbolicPacketTransformer>& map) {
        for (const auto& [value, branch] : map) {
          absl::StrAppendFormat(&result, "    %s := %d -> %v\n", field, value,
                                branch);
          if (!IsAccept(branch) && !IsDeny(branch)) work_list.push_back(branch);
        }
      };

  std::string field = absl::StrFormat(
      "%v:'%s'", node.field,
      absl::CEscape(
          symbolic_packet_manager_.field_manager_.GetFieldName(node.field)));

  for (const auto& [value, modify_map] : node.modify_branch_by_field_match) {
    absl::StrAppendFormat(&result, "  %s == %d:\n", field, value);
    pretty_print_map(field, modify_map);
  }
  absl::StrAppendFormat(&result, "  %s == *:\n", field);
  pretty_print_map(field, node.default_branch_by_field_modification);
  SymbolicPacketTransformer fallthrough = node.default_branch;
  absl::StrAppendFormat(&result, "  %s == * -> %v\n", field, fallthrough);
  if (!IsAccept(fallthrough) && !IsDeny(fallthrough))
    work_list.push_back(fallthrough);

  for (const SymbolicPacketTransformer& branch : work_list) {
    absl::StrAppend(&result, ToString(branch));
  }

  return result;
}

std::string SymbolicPacketTransformerManager::ToString(
    SymbolicPacketTransformer transformer) const {
  std::string result;
  std::queue<SymbolicPacketTransformer> work_list;
  work_list.push(transformer);
  absl::flat_hash_set<SymbolicPacketTransformer> visited = {transformer};

  auto pretty_print_map =
      [&](absl::string_view field,
          const absl::btree_map<int, SymbolicPacketTransformer>& map) {
        for (const auto& [value, branch] : map) {
          absl::StrAppendFormat(&result, "    %s := %d -> %v\n", field, value,
                                branch);
          if (IsAccept(branch) || IsDeny(branch)) continue;
          bool new_branch = visited.insert(branch).second;
          if (new_branch) work_list.push(branch);
        }
      };

  while (!work_list.empty()) {
    SymbolicPacketTransformer transformer = work_list.front();
    work_list.pop();
    absl::StrAppend(&result, transformer);

    if (IsAccept(transformer) || IsDeny(transformer)) continue;

    const DecisionNode& node = GetNodeOrDie(transformer);
    absl::StrAppend(&result, ":\n");
    std::string field = absl::StrFormat(
        "%v:'%s'", node.field,
        absl::CEscape(
            symbolic_packet_manager_.field_manager_.GetFieldName(node.field)));
    for (const auto& [value, modify_map] : node.modify_branch_by_field_match) {
      absl::StrAppendFormat(&result, "  %s == %d:\n", field, value);
      pretty_print_map(field, modify_map);
    }
    absl::StrAppendFormat(&result, "  %s == *:\n", field);
    pretty_print_map(field, node.default_branch_by_field_modification);
    SymbolicPacketTransformer fallthrough = node.default_branch;
    absl::StrAppendFormat(&result, "  %s == * -> %v\n", field, fallthrough);
    if (IsAccept(fallthrough) || IsDeny(fallthrough)) continue;
    bool new_branch = visited.insert(fallthrough).second;
    if (new_branch) work_list.push(fallthrough);
  }
  return result;
}

// Returns a dot string representation of the given
// `symbolic_packet_transformer`.
std::string SymbolicPacketTransformerManager::ToDot(
    const SymbolicPacketTransformer& transformer) const {
  std::string result = "digraph {\n";
  absl::StrAppendFormat(&result, "  %d [label=\"T\" shape=box]\n",
                        SentinelNodeIndex::kAccept);
  absl::StrAppendFormat(&result, "  %d [label=\"F\" shape=box]\n",
                        SentinelNodeIndex::kDeny);
  std::queue<SymbolicPacketTransformer> work_list;
  work_list.push(transformer);
  absl::flat_hash_set<SymbolicPacketTransformer> visited = {transformer};

  auto dotify_map =
      [&](absl::string_view field, absl::string_view old_value, int node_index,
          const absl::btree_map<int, SymbolicPacketTransformer>& map) {
        for (const auto& [new_value, branch] : map) {
          absl::StrAppendFormat(
              &result, "  %d -> %d [label=\"%s==%s; %s:=%d\"]\n", node_index,
              branch.node_index_, field, old_value, field, new_value);
          if (IsAccept(branch) || IsDeny(branch)) continue;
          bool new_branch = visited.insert(branch).second;
          if (new_branch) work_list.push(branch);
        }
      };

  while (!work_list.empty()) {
    SymbolicPacketTransformer transformer = work_list.front();
    work_list.pop();

    if (IsAccept(transformer) || IsDeny(transformer)) continue;

    const DecisionNode& node = GetNodeOrDie(transformer);
    std::string field =
        symbolic_packet_manager_.field_manager_.GetFieldName(node.field);
    absl::StrAppendFormat(&result, "  %d [label=\"%s\"]\n",
                          transformer.node_index_, field);
    for (const auto& [value, modify_map] : node.modify_branch_by_field_match) {
      dotify_map(field, absl::StrCat(value), transformer.node_index_,
                 modify_map);
    }
    dotify_map(field, "*", transformer.node_index_,
               node.default_branch_by_field_modification);
    SymbolicPacketTransformer fallthrough = node.default_branch;
    absl::StrAppendFormat(&result, "  %d -> %d [style=dashed]\n",
                          transformer.node_index_, fallthrough.node_index_);
    if (IsAccept(fallthrough) || IsDeny(fallthrough)) continue;
    bool new_branch = visited.insert(fallthrough).second;
    if (new_branch) work_list.push(fallthrough);
  }
  absl::StrAppend(&result, "}\n");
  return result;
}

absl::Status SymbolicPacketTransformerManager::CheckInternalInvariants() const {
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
    RET_CHECK(it->second == SymbolicPacketTransformer(i));
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
    // `symbolic_packet_manager_.field_manager_`.
    symbolic_packet_manager_.field_manager_.GetFieldName(
        node.field);  // No crash.
  }

  return absl::OkStatus();
}

}  // namespace netkat
