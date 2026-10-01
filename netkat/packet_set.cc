// Copyright 2024 The NetKAT authors
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

#include "netkat/packet_set.h"

#include <algorithm>
#include <optional>
#include <queue>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/container/fixed_array.h"
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
#include "netkat/packet.h"
#include "netkat/packet_set_handle.h"
#include "netkat/packet_transformer.h"
#include "netkat/packet_transformer_handle.h"

namespace netkat {

PacketSetManager::PacketSetManager(PacketTransformerManager& transformer)
    : transformer_(&transformer) {}

PacketSetHandle PacketSetManager::EmptySet() const {
  return PacketSetHandle(PacketSetHandle::kEmptySet);
}

PacketSetHandle PacketSetManager::FullSet() const {
  return PacketSetHandle(PacketSetHandle::kFullSet);
}

bool PacketSetManager::IsEmptySet(PacketSetHandle packet_set) const {
  return packet_set == EmptySet();
}

bool PacketSetManager::IsFullSet(PacketSetHandle packet_set) const {
  return packet_set == FullSet();
}

const PacketSetManager::DecisionNode& PacketSetManager::GetNodeOrDie(
    PacketSetHandle packet_set) const {
  CHECK_LT(packet_set.node_index_ & ~PacketSetHandle::kComplementBit,
           nodes_.size())
      << "Did you call this function on a leaf node (i.e. FullSet() or "
         "EmptySet())? ";  // Crash ok
  return nodes_[packet_set.node_index_ & ~PacketSetHandle::kComplementBit];
}

PacketSetHandle PacketSetManager::NodeToPacket(DecisionNode&& node) {
  if (node.branch_by_field_value.empty()) return node.default_branch;

  // Canonicalize the node by complementing it (and the resulting handle) if
  // its default branch is complemented.
  const bool complement = IsComplemented(node.default_branch);
  if (complement) {
    node.default_branch = Complement(node.default_branch);
    for (auto& [value, branch] : node.branch_by_field_value) {
      branch = Complement(branch);
    }
  }

// When in debug mode, we check a node's invariants before interning it.
// We could check the invariants of all nodes by calling
// `CheckInternalInvariants`, but that would be redundant and asymptotically
// expensive.
#ifndef NDEBUG
  CHECK(absl::c_is_sorted(node.branch_by_field_value))
      << "Internal invariant violated: branch_by_field_value must be sorted. "
      << ToString(node);
  for (const auto& [value, branch] : node.branch_by_field_value) {
    CHECK(branch != node.default_branch) << ToString(node);
    if (!IsEmptySet(branch) && !IsFullSet(branch)) {
      auto& branch_node = GetNodeOrDie(branch);
      CHECK(branch_node.field > node.field) << absl::StreamFormat(
          "(%v > %v)\n---branch---\n%s\n---node---\n%s", branch_node.field,
          node.field, ToString(branch), ToString(node));
    }
  }
#endif

  auto [index, inserted] = nodes_.Intern(std::move(node));
  LOG_IF(DFATAL, inserted && nodes_.size() > PacketSetHandle::kMinSentinel)
      << "Internal invariant violated: Proper and sentinel node indices must "
         "be disjoint. This indicates that we allocated more nodes than are "
         "supported (> 2^31 - 1).";
  return ComplementIf(complement, PacketSetHandle(index));
}

bool PacketSetManager::Contains(PacketSetHandle packet_set,
                                const Packet& packet) const {
  while (!IsEmptySet(packet_set) && !IsFullSet(packet_set)) {
    const bool complement = IsComplemented(packet_set);
    const DecisionNode& node = GetNodeOrDie(packet_set);
    packet_set = ComplementIf(complement, node.default_branch);
    auto it = packet.find(field_manager_.GetFieldName(node.field));
    if (it == packet.end()) continue;
    // Branches are sorted by value, so we can use binary search.
    auto branch_it = absl::c_lower_bound(
        node.branch_by_field_value, it->second,
        [](const auto& branch, int value) { return branch.first < value; });
    if (branch_it != node.branch_by_field_value.end() &&
        branch_it->first == it->second) {
      packet_set = ComplementIf(complement, branch_it->second);
    }
  }
  return IsFullSet(packet_set);
}

std::string PacketSetManager::ToDot(PacketSetHandle packet_set) const {
  std::string result = "digraph {\n";
  // Applies the default font sizes for GraphViz.
  absl::StrAppend(&result, "  node [fontsize = 14]\n");
  absl::StrAppend(&result, "  edge [fontsize = 12]\n");

  std::queue<PacketSetHandle> work_list;
  work_list.push(packet_set);
  if (IsFullSet(packet_set)) {
    absl::StrAppendFormat(&result, "  %d [label=\"T\" shape=box]\n",
                          PacketSetHandle::kFullSet);
    absl::StrAppend(&result, "}\n");
    return result;
  }
  if (IsEmptySet(packet_set)) {
    absl::StrAppendFormat(&result, "  %d [label=\"F\" shape=box]\n",
                          PacketSetHandle::kEmptySet);
    absl::StrAppend(&result, "}\n");
    return result;
  }
  absl::flat_hash_set<PacketSetHandle> visited = {packet_set};
  // Returns the DOT node ID of the given handle. Complemented handles are
  // printed as separate nodes, so the output reflects the semantics of each
  // node.
  auto dot_id = [&](PacketSetHandle handle) -> std::string {
    if (!IsComplemented(handle) || IsEmptySet(handle)) {
      return absl::StrCat(handle.node_index_);
    }
    return absl::StrFormat("\"!%d\"", Complement(handle).node_index_);
  };
  absl::StrAppendFormat(&result, "  %d [label=\"T\" shape=box]\n",
                        PacketSetHandle::kFullSet);
  absl::StrAppendFormat(&result, "  %d [label=\"F\" shape=box]\n",
                        PacketSetHandle::kEmptySet);

  while (!work_list.empty()) {
    PacketSetHandle packet_set = work_list.front();
    work_list.pop();
    if (IsFullSet(packet_set) || IsEmptySet(packet_set)) continue;

    const bool complement = IsComplemented(packet_set);
    const DecisionNode& node = GetNodeOrDie(packet_set);
    absl::StrAppendFormat(&result, "  %s [label=\"%s\"]\n", dot_id(packet_set),
                          field_manager_.GetFieldName(node.field));

    for (auto [value, branch] : node.branch_by_field_value) {
      branch = ComplementIf(complement, branch);
      absl::StrAppendFormat(&result, "  %s -> %s [label=\"%d\"]\n",
                            dot_id(packet_set), dot_id(branch), value);
      if (IsFullSet(branch) || IsEmptySet(branch)) continue;
      bool new_branch = visited.insert(branch).second;
      if (new_branch) work_list.push(branch);
    }
    PacketSetHandle fallthrough = ComplementIf(complement, node.default_branch);
    absl::StrAppendFormat(&result, "  %s -> %s [style=dashed]\n",
                          dot_id(packet_set), dot_id(fallthrough));
    if (IsFullSet(fallthrough) || IsEmptySet(fallthrough)) continue;
    bool new_branch = visited.insert(fallthrough).second;
    if (new_branch) work_list.push(fallthrough);
  }
  absl::StrAppend(&result, "}\n");
  return result;
}

template <class GetOperands, class Combine>
PacketSetHandle PacketSetManager::CompileAssociativeChain(
    const PredicateProto& pred, ProtoHashKey& key, GetOperands&& get_operands,
    Combine&& combine) {
  if (!IsLongAssociativeChain(pred, get_operands)) {
    auto [left, right] = *get_operands(pred);
    key.lhs_child = Compile(*left);
    key.rhs_child = Compile(*right);
    auto it = packet_set_by_hash_.find(key);
    if (it != packet_set_by_hash_.end()) return it->second;
    return packet_set_by_hash_[key] = combine(key.lhs_child, key.rhs_child);
  }
  std::vector<PacketSetHandle> operands;
  for (const PredicateProto* operand :
       FlattenAssociativeChain(pred, get_operands)) {
    operands.push_back(Compile(*operand));
  }
  return CombineBalanced(std::move(operands), combine);
}

PacketSetHandle PacketSetManager::Compile(const PredicateProto& pred) {
  ProtoHashKey key = {.predicate_case = pred.predicate_case()};
  switch (pred.predicate_case()) {
    case PredicateProto::kPullOp: {
      key.lhs_policy_handle = transformer_->Compile(pred.pull_op().policy());
      key.rhs_child = Compile(pred.pull_op().pred());
      auto it = packet_set_by_hash_.find(key);
      if (it != packet_set_by_hash_.end()) return it->second;
      return packet_set_by_hash_[key] =
                 transformer_->Pull(key.lhs_policy_handle, key.rhs_child);
    }
    case PredicateProto::kBoolConstant: {
      return pred.bool_constant().value() ? FullSet() : EmptySet();
    }
    case PredicateProto::kMatch: {
      return Match(pred.match().field(), pred.match().value());
    }
    case PredicateProto::kAndOp: {
      return CompileAssociativeChain(
          pred, key,
          [](const PredicateProto& pred) -> OptionalOperands {
            if (!pred.has_and_op()) return std::nullopt;
            return std::make_pair(&pred.and_op().left(),
                                  &pred.and_op().right());
          },
          [this](PacketSetHandle left, PacketSetHandle right) {
            return And(left, right);
          });
    }
    case PredicateProto::kOrOp: {
      return CompileAssociativeChain(
          pred, key,
          [](const PredicateProto& pred) -> OptionalOperands {
            if (!pred.has_or_op()) return std::nullopt;
            return std::make_pair(&pred.or_op().left(), &pred.or_op().right());
          },
          [this](PacketSetHandle left, PacketSetHandle right) {
            return Or(left, right);
          });
    }
    case PredicateProto::kNotOp: {
      key.lhs_child = Compile(pred.not_op().negand());
      auto it = packet_set_by_hash_.find(key);
      if (it != packet_set_by_hash_.end()) return it->second;
      return packet_set_by_hash_[key] = Not(key.lhs_child);
    }
    case PredicateProto::kXorOp: {
      return CompileAssociativeChain(
          pred, key,
          [](const PredicateProto& pred) -> OptionalOperands {
            if (!pred.has_xor_op()) return std::nullopt;
            return std::make_pair(&pred.xor_op().left(),
                                  &pred.xor_op().right());
          },
          [this](PacketSetHandle left, PacketSetHandle right) {
            return Xor(left, right);
          });
    }
    // By convention, uninitialized predicates must be treated like `false`.
    case PredicateProto::PREDICATE_NOT_SET: {
      return EmptySet();
    }
  }
  LOG(FATAL) << "Unhandled predicate kind: " << pred.predicate_case();
}

void PacketSetManager::DeclareFields(absl::Span<const std::string> fields) {
  for (const std::string& field : fields) {
    (void)field_manager_.GetOrCreatePacketFieldHandle(field);
  }
}

PacketSetHandle PacketSetManager::Match(absl::string_view field, int value) {
  return NodeToPacket(DecisionNode{
      .field = field_manager_.GetOrCreatePacketFieldHandle(field),
      .default_branch = EmptySet(),
      .branch_by_field_value = {{value, FullSet()}},
  });
}

PacketSetHandle PacketSetManager::Not(PacketSetHandle negand) {
  return Complement(negand);
}

template <class Combine>
PacketSetHandle PacketSetManager::CombineNodes(PacketSetHandle left,
                                               PacketSetHandle right,
                                               Combine&& combine) {
  // NOTE: Nodes are pointer-stable, so these references remain valid even as
  // new nodes get created by recursive calls below.
  const DecisionNode* left_node = &GetNodeOrDie(left);
  const DecisionNode* right_node = &GetNodeOrDie(right);

  // We exploit that `combine` is commutative to canonicalize the order of the
  // arguments, reducing the number of cases by 1.
  if (left_node->field > right_node->field) {
    std::swap(left, right);
    std::swap(left_node, right_node);
  }
  // The branches of nodes reached via complemented handles get complemented.
  const bool complement_left = IsComplemented(left);
  const bool complement_right = IsComplemented(right);
  const PacketSetHandle left_default =
      ComplementIf(complement_left, left_node->default_branch);

  // Case 1: left_node->field < right_node->field: branch on left field.
  absl::InlinedVector<std::pair<int, PacketSetHandle>, 32> branches;
  if (left_node->field < right_node->field) {
    PacketSetHandle default_branch = combine(left_default, right);
    branches.reserve(left_node->branch_by_field_value.size());
    for (const auto& [value, left_branch] : left_node->branch_by_field_value) {
      PacketSetHandle branch =
          combine(ComplementIf(complement_left, left_branch), right);
      if (branch == default_branch) continue;
      branches.push_back({value, branch});
    }
    if (branches.empty()) return default_branch;
    return NodeToPacket(DecisionNode{
        .field = left_node->field,
        .default_branch = default_branch,
        .branch_by_field_value{branches.begin(), branches.end()},
    });
  }

  // Case 2: left_node->field == right_node->field: branch on shared field.
  DCHECK(left_node->field == right_node->field);
  const PacketSetHandle right_default =
      ComplementIf(complement_right, right_node->default_branch);
  PacketSetHandle default_branch = combine(left_default, right_default);
  branches.reserve(std::max(left_node->branch_by_field_value.size(),
                            right_node->branch_by_field_value.size()));
  auto add_branch = [&](int value, PacketSetHandle branch) {
    if (branch == default_branch) return;
    branches.push_back({value, branch});
  };
  auto left_it = left_node->branch_by_field_value.begin();
  auto left_end = left_node->branch_by_field_value.end();
  auto right_it = right_node->branch_by_field_value.begin();
  auto right_end = right_node->branch_by_field_value.end();
  while (left_it != left_end && right_it != right_end) {
    auto [left_value, left_branch] = *left_it;
    auto [right_value, right_branch] = *right_it;
    left_branch = ComplementIf(complement_left, left_branch);
    right_branch = ComplementIf(complement_right, right_branch);
    if (left_value < right_value) {
      add_branch(left_value, combine(left_branch, right_default));
      ++left_it;
    } else if (left_value > right_value) {
      add_branch(right_value, combine(left_default, right_branch));
      ++right_it;
    } else {  // left_value == right_value
      add_branch(left_value, combine(left_branch, right_branch));
      ++left_it;
      ++right_it;
    }
  }
  for (; left_it != left_end; ++left_it) {
    auto [left_value, left_branch] = *left_it;
    add_branch(left_value, combine(ComplementIf(complement_left, left_branch),
                                   right_default));
  }
  for (; right_it != right_end; ++right_it) {
    auto [right_value, right_branch] = *right_it;
    add_branch(right_value, combine(left_default, ComplementIf(complement_right,
                                                               right_branch)));
  }
  if (branches.empty()) return default_branch;
  return NodeToPacket(DecisionNode{
      .field = left_node->field,
      .default_branch = default_branch,
      .branch_by_field_value{branches.begin(), branches.end()},
  });
}

PacketSetHandle PacketSetManager::And(PacketSetHandle left,
                                      PacketSetHandle right) {
  // Base cases.
  if (IsEmptySet(left) || IsFullSet(right) || left == right) return left;
  if (IsEmptySet(right) || IsFullSet(left)) return right;
  if (left == Complement(right)) return EmptySet();

  // Normalize keys to leverage commutativity.
  if (left > right) std::swap(left, right);
  if (auto it = and_cache_.find({left, right}); it != and_cache_.end()) {
    return it->second;
  }

  // Compute result the hard way.
  PacketSetHandle result = CombineNodes(
      left, right,
      [this](PacketSetHandle l, PacketSetHandle r) { return And(l, r); });
  and_cache_.try_emplace({left, right}, result);
  return result;
}

PacketSetHandle PacketSetManager::Or(PacketSetHandle left,
                                     PacketSetHandle right) {
  // By De Morgan's law, sharing the memoization table of `And`.
  return Complement(And(Complement(left), Complement(right)));
}

PacketSetHandle PacketSetManager::Xor(PacketSetHandle left,
                                      PacketSetHandle right) {
  // Since Xor(!a, b) = Xor(a, !b) = !Xor(a, b), we strip the complement bits
  // of the arguments, and complement the result instead.
  const bool complement = IsComplemented(left) != IsComplemented(right);
  left = ComplementIf(IsComplemented(left), left);
  right = ComplementIf(IsComplemented(right), right);

  // Base cases. Note that `EmptySet()` is complemented.
  if (left == right) return ComplementIf(complement, EmptySet());
  if (IsFullSet(left)) return ComplementIf(!complement, right);
  if (IsFullSet(right)) return ComplementIf(!complement, left);

  // Normalize keys to leverage commutativity.
  if (left > right) std::swap(left, right);
  auto it = xor_cache_.find({left, right});
  if (it == xor_cache_.end()) {
    // Compute result the hard way.
    PacketSetHandle result = CombineNodes(
        left, right,
        [this](PacketSetHandle l, PacketSetHandle r) { return Xor(l, r); });
    it = xor_cache_.try_emplace({left, right}, result).first;
  }
  return ComplementIf(complement, it->second);
}

PacketSetHandle PacketSetManager::Exists(absl::string_view field,
                                         PacketSetHandle packet_set) {
  return Exists(field_manager_.GetOrCreatePacketFieldHandle(field), packet_set);
}

PacketSetHandle PacketSetManager::Exists(PacketFieldHandle field,
                                         PacketSetHandle packet_set) {
  if (IsFullSet(packet_set) || IsEmptySet(packet_set)) return packet_set;

  // Since fields are strictly increasing along each path, `field` cannot occur
  // in the sub-graph rooted at a node branching on a larger field.
  const DecisionNode& node = GetNodeOrDie(packet_set);
  if (node.field > field) return packet_set;

  if (auto it = exists_cache_.find({field, packet_set});
      it != exists_cache_.end()) {
    return it->second;
  }

  // Compute result the hard way.
  const bool complement = IsComplemented(packet_set);
  PacketSetHandle result;
  if (node.field == field) {
    // Case 1: This node's field is the one we are removing through an
    // existential: remove the current node and return the OR-ing of all
    // branches.
    result = ComplementIf(complement, node.default_branch);
    for (const auto& [value, branch] : node.branch_by_field_value) {
      if (IsFullSet(result)) break;
      result = Or(result, ComplementIf(complement, branch));
    }
  } else {
    // Case 2: This node does not branch on the relevant field: keep current
    // node and call `Exists` on all branches and exclude a branch if it is the
    // same as the default branch.
    PacketSetHandle default_branch =
        Exists(field, ComplementIf(complement, node.default_branch));
    absl::FixedArray<std::pair<int, PacketSetHandle>> branch_by_field_value(
        node.branch_by_field_value.size());
    int num_branches = 0;
    for (const auto& [value, branch] : node.branch_by_field_value) {
      // Skips `default_branch` because an invariant of `DecisionNode` is that
      // no branch in `branch_by_field_value` can be a duplicate of the default
      // branch.
      PacketSetHandle new_branch =
          Exists(field, ComplementIf(complement, branch));
      if (new_branch == default_branch) continue;
      branch_by_field_value[num_branches++] = std::make_pair(value, new_branch);
    }
    result = NodeToPacket(DecisionNode{
        .field = node.field,
        .default_branch = default_branch,
        .branch_by_field_value{
            branch_by_field_value.begin(),
            branch_by_field_value.begin() + num_branches,
        },
    });
  }
  exists_cache_.try_emplace({field, packet_set}, result);
  return result;
}

std::string PacketSetManager::ToString(PacketSetHandle packet_set) const {
  std::string result;
  std::queue<PacketSetHandle> work_list{{packet_set}};
  absl::flat_hash_set<PacketSetHandle> visited{packet_set};
  while (!work_list.empty()) {
    PacketSetHandle packet_set = work_list.front();
    work_list.pop();
    absl::StrAppend(&result, packet_set, ":\n");

    if (IsFullSet(packet_set) || IsEmptySet(packet_set)) continue;

    // Complemented handles are printed as separate nodes, so the output
    // reflects the semantics of each node.
    const bool complement = IsComplemented(packet_set);
    const DecisionNode& node = GetNodeOrDie(packet_set);
    std::string field =
        absl::StrFormat("%v:'%s'", node.field,
                        absl::CEscape(field_manager_.GetFieldName(node.field)));
    for (auto [value, branch] : node.branch_by_field_value) {
      branch = ComplementIf(complement, branch);
      absl::StrAppendFormat(&result, "  %s == %d -> %v\n", field, value,
                            branch);
      if (IsFullSet(branch) || IsEmptySet(branch)) continue;
      bool new_branch = visited.insert(branch).second;
      if (new_branch) work_list.push(branch);
    }
    PacketSetHandle fallthrough = ComplementIf(complement, node.default_branch);
    absl::StrAppendFormat(&result, "  %s == * -> %v\n", field, fallthrough);
    if (IsFullSet(fallthrough) || IsEmptySet(fallthrough)) continue;
    bool new_branch = visited.insert(fallthrough).second;
    if (new_branch) work_list.push(fallthrough);
  }
  return result;
}

std::string PacketSetManager::ToString(const DecisionNode& node) const {
  std::string result;
  std::vector<PacketSetHandle> work_list;
  std::string field =
      absl::StrFormat("%v:'%s'", node.field,
                      absl::CEscape(field_manager_.GetFieldName(node.field)));
  for (const auto& [value, branch] : node.branch_by_field_value) {
    absl::StrAppendFormat(&result, "  %s == %d -> %v\n", field, value, branch);
    if (!IsFullSet(branch) && !IsEmptySet(branch)) work_list.push_back(branch);
  }
  PacketSetHandle fallthrough = node.default_branch;
  absl::StrAppendFormat(&result, "  %s == * -> %v\n", field, fallthrough);
  if (!IsFullSet(fallthrough) && !IsEmptySet(fallthrough)) {
    work_list.push_back(fallthrough);
  }

  for (PacketSetHandle branch : work_list) {
    absl::StrAppend(&result, ToString(branch));
  }

  return result;
}

absl::Status PacketSetManager::CheckInternalInvariants() const {
  // Invariant: Proper and sentinel node indices are disjoint.
  RET_CHECK(nodes_.size() <= PacketSetHandle::kMinSentinel);

  // Invariant: Each node is stored exactly once.
  RETURN_IF_ERROR(nodes_.CheckInternalInvariants());

  // Node Invariants.
  for (int i = 0; i < nodes_.size(); ++i) {
    const DecisionNode& node = nodes_[i];
    // Invariant: `branch_by_field_value` is non-empty.
    // Maintained by `NodeToPacket`.
    RET_CHECK(!node.branch_by_field_value.empty());

    // Invariant: `default_branch` is not complemented.
    // Maintained by `NodeToPacket`.
    RET_CHECK(!IsComplemented(node.default_branch));

    // Invariant: node field is strictly smaller than sub-node fields.
    RET_CHECK(IsFullSet(node.default_branch) ||
              IsEmptySet(node.default_branch) ||
              GetNodeOrDie(node.default_branch).field > node.field);
    for (const auto& [value, branch] : node.branch_by_field_value) {
      RET_CHECK(IsFullSet(branch) || IsEmptySet(branch) ||
                GetNodeOrDie(branch).field > node.field);

      // Invariant:  Each case in `branch_by_field_value` is !=
      // `default_branch`.
      RET_CHECK(branch != node.default_branch);
    }

    // Invariant: node field is interned by `field_manager_`.
    field_manager_.GetFieldName(node.field);  // No crash.
  }

  return absl::OkStatus();
}

void PacketSetManager::GetConcretePacketsDfs(
    PacketSetHandle packet_set, Packet& current_packet,
    std::vector<Packet>& result) const {
  if (IsEmptySet(packet_set)) return;
  if (IsFullSet(packet_set)) {
    result.push_back(current_packet);
    return;
  }

  const bool complement = IsComplemented(packet_set);
  const DecisionNode& node = GetNodeOrDie(packet_set);
  std::string node_field = field_manager_.GetFieldName(node.field);

  GetConcretePacketsDfs(ComplementIf(complement, node.default_branch),
                        current_packet, result);
  for (const auto& [value, branch] : node.branch_by_field_value) {
    current_packet[node_field] = value;
    GetConcretePacketsDfs(ComplementIf(complement, branch), current_packet,
                          result);
  }
  current_packet.erase(node_field);
}

std::vector<Packet> PacketSetManager::GetConcretePackets(
    PacketSetHandle packet_set) const {
  std::vector<Packet> result;
  Packet current_packet;
  GetConcretePacketsDfs(packet_set, current_packet, result);
  return result;
}

}  // namespace netkat
