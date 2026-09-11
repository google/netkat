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
#include <cstdint>
#include <limits>
#include <queue>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/container/fixed_array.h"
#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "gutil/status.h"
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
  CHECK_LT(packet_set.NodeIndex(), nodes_.size())
      << "Did you call this function on a leaf node (i.e. FullSet() or "
         "EmptySet())? ";  // Crash ok
  return nodes_[packet_set.NodeIndex()];
}

PacketSetHandle PacketSetManager::NodeToPacket(DecisionNode&& node) {
  if (node.branch_by_field_value.empty()) return node.default_branch;

  // Enforce the canonicity rule for complemented edges: the `default_branch` of
  // an interned node must be a regular (non-complemented) edge. If it is not,
  // we intern the complement of `node` -- obtained by complementing all its
  // branches -- and return a complemented edge to it.
  //
  // This is what makes complemented edges canonical: exactly one of any two
  // complementary nodes satisfies the rule, so we never intern both.
  if (node.default_branch.IsComplemented()) {
    node.default_branch = node.default_branch.Complement();
    for (auto& [value, branch] : node.branch_by_field_value) {
      branch = branch.Complement();
    }
    // Complementing is a bijection, so it preserves the `DecisionNode`
    // invariants: the branch values are unchanged (and thus still sorted), and
    // branches that differed from the default branch still do.
    return InternNode(std::move(node)).Complement();
  }
  return InternNode(std::move(node));
}

PacketSetHandle PacketSetManager::InternNode(DecisionNode&& node) {
// When in debug mode, we check a node's invariants before interning it.
// We could check the invariants of all nodes by calling
// `CheckInternalInvariants`, but that would be redundant and asymptotically
// expensive.
#ifndef NDEBUG
  CHECK(!node.branch_by_field_value.empty()) << ToString(node);
  CHECK(!node.default_branch.IsComplemented())
      << "Internal invariant violated: the default branch of an interned node "
         "must be a regular (non-complemented) edge. "
      << ToString(node);
  CHECK(absl::c_is_sorted(node.branch_by_field_value))
      << "Internal invariant violated: branch_by_field_value must be sorted. "
      << ToString(node);
  for (const auto& [value, branch] : node.branch_by_field_value) {
    CHECK(branch != node.default_branch) << ToString(node);
    if (!IsTerminal(branch)) {
      auto& branch_node = GetNodeOrDie(branch);
      CHECK(branch_node.field > node.field) << absl::StreamFormat(
          "(%v > %v)\n---branch---\n%s\n---node---\n%s", branch_node.field,
          node.field, ToString(branch), ToString(node));
    }
  }
#endif

  auto [it, inserted] =
      packet_by_node_.try_emplace(node, PacketSetHandle(nodes_.size()));
  if (inserted) {
    nodes_.push_back(std::move(node));
    LOG_IF(DFATAL, nodes_.size() > PacketSetHandle::kMinSentinel)
        << "Internal invariant violated: Proper and sentinel node indices must "
           "be disjoint. This indicates that we allocated more nodes than are "
           "supported (> 2^31 - 1).";
  }
  return it->second;
}

bool PacketSetManager::Contains(PacketSetHandle packet_set,
                                const Packet& packet) const {
  if (IsEmptySet(packet_set)) return false;
  if (IsFullSet(packet_set)) return true;

  const DecisionNode& node = GetNodeOrDie(packet_set);
  std::string field = field_manager_.GetFieldName(node.field);
  auto it = packet.find(field);
  if (it != packet.end()) {
    for (const auto& [value, branch] : node.branch_by_field_value) {
      if (it->second == value) {
        return Contains(ResolveBranch(packet_set, branch), packet);
      }
    }
  }
  return Contains(ResolveBranch(packet_set, node.default_branch), packet);
}

std::string PacketSetManager::ToDot(PacketSetHandle packet_set) const {
  std::string result = "digraph {\n";
  // Applies the default font sizes for GraphViz.
  absl::StrAppend(&result, "  node [fontsize = 14]\n");
  absl::StrAppend(&result, "  edge [fontsize = 12]\n");

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

  // We draw the graph as it is stored, i.e. we draw each decision node exactly
  // once and mark complemented edges with a dot at their tail, which is the
  // conventional notation. Note that there is a single terminal node ("T"),
  // since the empty set is a complemented edge to the full set.
  absl::StrAppendFormat(&result, "  %d [label=\"T\" shape=box]\n",
                        PacketSetHandle::kFullSet);

  // Appends an edge from the node with index `parent` to the node `branch`
  // points at, marking the edge if `branch` is complemented.
  auto append_edge = [&](uint32_t parent, PacketSetHandle branch,
                         absl::string_view attributes) {
    absl::StrAppendFormat(
        &result, "  %d -> %d [%s%s]\n", parent, branch.NodeIndex(), attributes,
        branch.IsComplemented() ? " arrowtail=odot dir=both" : "");
  };

  // The handle we are asked to draw may itself be a complemented edge. We
  // visualize this using an edge from an anonymous root marker.
  if (packet_set.IsComplemented()) {
    absl::StrAppend(&result, "  root [shape=point]\n");
    absl::StrAppendFormat(&result, "  root -> %d [arrowtail=odot dir=both]\n",
                          packet_set.NodeIndex());
  }

  // Regular (non-complemented) edges to all nodes we still need to draw.
  std::queue<PacketSetHandle> work_list;
  absl::flat_hash_set<PacketSetHandle> visited;
  auto visit = [&](PacketSetHandle branch) {
    if (IsTerminal(branch)) return;
    PacketSetHandle node = PacketSetHandle(branch.NodeIndex());
    if (visited.insert(node).second) work_list.push(node);
  };
  visit(packet_set);

  while (!work_list.empty()) {
    PacketSetHandle current = work_list.front();
    work_list.pop();

    const DecisionNode& node = GetNodeOrDie(current);
    absl::StrAppendFormat(&result, "  %d [label=\"%s\"]\n", current.NodeIndex(),
                          field_manager_.GetFieldName(node.field));

    for (const auto& [value, branch] : node.branch_by_field_value) {
      append_edge(current.NodeIndex(), branch,
                  absl::StrFormat("label=\"%d\"", value));
      visit(branch);
    }
    append_edge(current.NodeIndex(), node.default_branch, "style=dashed");
    visit(node.default_branch);
  }
  absl::StrAppend(&result, "}\n");
  return result;
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
      key.lhs_child = Compile(pred.and_op().left());
      key.rhs_child = Compile(pred.and_op().right());
      auto it = packet_set_by_hash_.find(key);
      if (it != packet_set_by_hash_.end()) return it->second;
      return packet_set_by_hash_[key] = And(key.lhs_child, key.rhs_child);
    }
    case PredicateProto::kOrOp: {
      key.lhs_child = Compile(pred.or_op().left());
      key.rhs_child = Compile(pred.or_op().right());
      auto it = packet_set_by_hash_.find(key);
      if (it != packet_set_by_hash_.end()) return it->second;
      return packet_set_by_hash_[key] = Or(key.lhs_child, key.rhs_child);
    }
    case PredicateProto::kNotOp: {
      // No need to consult `packet_set_by_hash_`: `Not` is O(1).
      return Not(Compile(pred.not_op().negand()));
    }
    case PredicateProto::kXorOp: {
      key.lhs_child = Compile(pred.xor_op().left());
      key.rhs_child = Compile(pred.xor_op().right());
      auto it = packet_set_by_hash_.find(key);
      if (it != packet_set_by_hash_.end()) return it->second;
      return packet_set_by_hash_[key] = Xor(key.lhs_child, key.rhs_child);
    }
    // By convention, uninitialized predicates must be treated like `false`.
    case PredicateProto::PREDICATE_NOT_SET: {
      return EmptySet();
    }
  }
  LOG(FATAL) << "Unhandled predicate kind: " << pred.predicate_case();
}

PacketSetHandle PacketSetManager::Match(absl::string_view field, int value) {
  return NodeToPacket(DecisionNode{
      .field = field_manager_.GetOrCreatePacketFieldHandle(field),
      .default_branch = EmptySet(),
      .branch_by_field_value = {{value, FullSet()}},
  });
}

// NOTE: `Not` is O(1) and defined inline in the header: thanks to complemented
// edges, it merely flips a bit in the handle.

PacketSetHandle PacketSetManager::And(PacketSetHandle left,
                                      PacketSetHandle right) {
  // Base cases.
  if (IsEmptySet(left) || IsFullSet(right) || left == right) return left;
  if (IsEmptySet(right) || IsFullSet(left)) return right;
  // Thanks to complemented edges, we can also recognize `a && !a == false` in
  // O(1), which is a common case, e.g. when `Or`-ing overlapping predicates.
  if (left == Not(right)) return EmptySet();

  // Normalize keys to leverage commutativity.
  std::pair<PacketSetHandle, PacketSetHandle> cache_key =
      std::make_pair(std::min(left, right), std::max(left, right));
  auto it = and_cache_.find(cache_key);
  if (it != and_cache_.end()) {
    return it->second;
  }

  // Compute result the hard way.
  const DecisionNode* left_node = &GetNodeOrDie(left);
  const DecisionNode* right_node = &GetNodeOrDie(right);

  // We exploit that `And` is commutative to canonicalize the order of the
  // arguments, reducing the number of cases by 1.
  if (left_node->field > right_node->field) {
    std::swap(left, right);
    std::swap(left_node, right_node);
  }

  // The branches of a node are stored relative to the regular edge pointing at
  // it, so they must be complemented if we arrived via a complemented edge.
  const bool complement_left = left.IsComplemented();
  const bool complement_right = right.IsComplemented();
  auto left_branch_of = [complement_left](PacketSetHandle branch) {
    return branch.ComplementIf(complement_left);
  };
  auto right_branch_of = [complement_right](PacketSetHandle branch) {
    return branch.ComplementIf(complement_right);
  };

  // Case 1: left_node->field < right_node->field: branch on left field.
  if (left_node->field < right_node->field) {
    PacketSetHandle default_branch =
        And(left_branch_of(left_node->default_branch), right);
    absl::FixedArray<std::pair<int, PacketSetHandle>> branch_by_field_value(
        left_node->branch_by_field_value.size());
    int num_branches = 0;
    for (const auto& [value, left_branch] : left_node->branch_by_field_value) {
      PacketSetHandle branch = And(left_branch_of(left_branch), right);
      if (branch == default_branch) continue;
      branch_by_field_value[num_branches++] = std::make_pair(value, branch);
    }
    return and_cache_[cache_key] = NodeToPacket(DecisionNode{
               .field = left_node->field,
               .default_branch = default_branch,
               .branch_by_field_value{
                   branch_by_field_value.begin(),
                   branch_by_field_value.begin() + num_branches,
               },
           });
  }

  // Case 2: left_node->field == right_node->field: branch on shared field.
  DCHECK(left_node->field == right_node->field);
  PacketSetHandle left_default = left_branch_of(left_node->default_branch);
  PacketSetHandle right_default = right_branch_of(right_node->default_branch);
  PacketSetHandle default_branch = And(left_default, right_default);
  absl::FixedArray<std::pair<int, PacketSetHandle>> branch_by_field_value(
      left_node->branch_by_field_value.size() +
      right_node->branch_by_field_value.size());
  int num_branches = 0;
  auto add_branch = [&](int value, PacketSetHandle branch) {
    if (branch == default_branch) return;
    branch_by_field_value[num_branches++] = std::make_pair(value, branch);
  };
  auto left_it = left_node->branch_by_field_value.begin();
  auto left_end = left_node->branch_by_field_value.end();
  auto right_it = right_node->branch_by_field_value.begin();
  auto right_end = right_node->branch_by_field_value.end();
  while (left_it != left_end && right_it != right_end) {
    auto [left_value, left_branch] = *left_it;
    auto [right_value, right_branch] = *right_it;
    if (left_value < right_value) {
      add_branch(left_value, And(left_branch_of(left_branch), right_default));
      ++left_it;
    } else if (left_value > right_value) {
      add_branch(right_value, And(left_default, right_branch_of(right_branch)));
      ++right_it;
    } else {  // left_value == right_value
      add_branch(left_value, And(left_branch_of(left_branch),
                                 right_branch_of(right_branch)));
      ++left_it;
      ++right_it;
    }
  }
  for (; left_it != left_end; ++left_it) {
    auto [left_value, left_branch] = *left_it;
    add_branch(left_value, And(left_branch_of(left_branch), right_default));
  }
  for (; right_it != right_end; ++right_it) {
    auto [right_value, right_branch] = *right_it;
    add_branch(right_value, And(left_default, right_branch_of(right_branch)));
  }
  return and_cache_[cache_key] = NodeToPacket(DecisionNode{
             .field = left_node->field,
             .default_branch = default_branch,
             .branch_by_field_value{
                 branch_by_field_value.begin(),
                 branch_by_field_value.begin() + num_branches,
             },
         });
}

PacketSetHandle PacketSetManager::Or(PacketSetHandle left,
                                     PacketSetHandle right) {
  // Apply De Morgan's law: a || b == !(!a && !b).
  //
  // Thanks to complemented edges, the three `Not`s are free (O(1)), so this is
  // strictly better than implementing `Or` directly: it recycles the
  // `And`-memoization table instead of maintaining a second one.
  return Not(And(Not(left), Not(right)));
}

PacketSetHandle PacketSetManager::Xor(PacketSetHandle left,
                                      PacketSetHandle right) {
  // a (+) b == (!a && b) || (a && !b).
  return Or(And(Not(left), right), And(left, Not(right)));
}

PacketSetHandle PacketSetManager::Exists(absl::string_view field,
                                         PacketSetHandle packet) {
  if (IsFullSet(packet) || IsEmptySet(packet)) return packet;

  // Compute result the hard way.
  const DecisionNode& node = GetNodeOrDie(packet);

  // Case 1: This node's field is the one we are removing through an
  // existential: remove the current node and return the OR-ing of all branches.
  if (node.field == field_manager_.GetOrCreatePacketFieldHandle(field)) {
    PacketSetHandle result = ResolveBranch(packet, node.default_branch);
    for (const auto& [field_value, branch] : node.branch_by_field_value) {
      result = Or(result, ResolveBranch(packet, branch));
    }
    return result;
  }

  // Case 2: This node does not branch on the relevant field: keep current
  // node and call `Exists` on all branches and exclude a branch if it is the
  // same as the default branch.
  PacketSetHandle default_branch =
      Exists(field, ResolveBranch(packet, node.default_branch));
  int num_branches = 0;
  for (const auto& [value, branch] : node.branch_by_field_value) {
    if (Exists(field, ResolveBranch(packet, branch)) != default_branch) {
      ++num_branches;
    }
  }
  absl::FixedArray<std::pair<int, PacketSetHandle>, 0>
      non_default_branches_by_field_value(num_branches);
  int i = 0;
  for (const auto& [value, branch] : node.branch_by_field_value) {
    // Skips `default_branch` because an invariant of `DecisionNode` is that no
    // branch in `branch_by_field_value` can be a duplicate of the default
    // branch.
    PacketSetHandle non_default_branch =
        Exists(field, ResolveBranch(packet, branch));
    if (non_default_branch == default_branch) continue;
    non_default_branches_by_field_value[i++] =
        std::make_pair(value, non_default_branch);
  }

  return NodeToPacket(DecisionNode{
      .field = node.field,
      .default_branch = default_branch,
      .branch_by_field_value = std::move(non_default_branches_by_field_value),
  });
}

std::string PacketSetManager::ToString(PacketSetHandle packet_set) const {
  std::string result;
  std::queue<PacketSetHandle> work_list{{packet_set}};
  absl::flat_hash_set<PacketSetHandle> visited{packet_set};
  while (!work_list.empty()) {
    PacketSetHandle packet_set = work_list.front();
    work_list.pop();
    absl::StrAppend(&result, packet_set, ":\n");

    if (IsTerminal(packet_set)) continue;

    const DecisionNode& node = GetNodeOrDie(packet_set);
    std::string field =
        absl::StrFormat("%v:'%s'", node.field,
                        absl::CEscape(field_manager_.GetFieldName(node.field)));
    // NOTE: We print the branches of `packet_set`, i.e. we resolve complemented
    // edges, rather than printing the branches as they are stored.
    for (const auto& [value, stored_branch] : node.branch_by_field_value) {
      PacketSetHandle branch = ResolveBranch(packet_set, stored_branch);
      absl::StrAppendFormat(&result, "  %s == %d -> %v\n", field, value,
                            branch);
      if (IsTerminal(branch)) continue;
      bool new_branch = visited.insert(branch).second;
      if (new_branch) work_list.push(branch);
    }
    PacketSetHandle fallthrough =
        ResolveBranch(packet_set, node.default_branch);
    absl::StrAppendFormat(&result, "  %s == * -> %v\n", field, fallthrough);
    if (IsTerminal(fallthrough)) continue;
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

  // Invariant: `packet_by_node_[n] = s` iff `nodes_[s.NodeIndex()] == n`.
  for (const auto& [node, packet] : packet_by_node_) {
    // Invariant: Interned nodes are pointed at by regular edges.
    RET_CHECK(!packet.IsComplemented());
    RET_CHECK(packet.NodeIndex() < nodes_.size());
    RET_CHECK(nodes_[packet.NodeIndex()] == node);
  }
  for (int i = 0; i < nodes_.size(); ++i) {
    const DecisionNode& node = nodes_[i];
    auto it = packet_by_node_.find(node);
    RET_CHECK(it != packet_by_node_.end());
    RET_CHECK(it->second == PacketSetHandle(i));
  }

  // Node Invariants.
  for (int i = 0; i < nodes_.size(); ++i) {
    const DecisionNode& node = nodes_[i];
    // Invariant: `branch_by_field_value` is non-empty.
    // Maintained by `NodeToPacket`.
    RET_CHECK(!node.branch_by_field_value.empty());

    // Invariant: The default branch is a regular (non-complemented) edge. This
    // is the canonicity rule for complemented edges, see `NodeToPacket`.
    RET_CHECK(!node.default_branch.IsComplemented());

    // Invariant: node field is strictly smaller than sub-node fields.
    RET_CHECK(IsTerminal(node.default_branch) ||
              GetNodeOrDie(node.default_branch).field > node.field);
    for (const auto& [value, branch] : node.branch_by_field_value) {
      RET_CHECK(IsTerminal(branch) || GetNodeOrDie(branch).field > node.field);

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

  const DecisionNode& node = GetNodeOrDie(packet_set);
  std::string node_field = field_manager_.GetFieldName(node.field);

  GetConcretePacketsDfs(ResolveBranch(packet_set, node.default_branch),
                        current_packet, result);
  for (const auto& [value, branch] : node.branch_by_field_value) {
    current_packet[node_field] = value;
    GetConcretePacketsDfs(ResolveBranch(packet_set, branch), current_packet,
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
