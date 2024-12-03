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
// -----------------------------------------------------------------------------

#include "netkat/symbolic_packet.h"

#include <cstdint>
#include <deque>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "gutil/status.h"
#include "netkat/evaluator.h"

namespace netkat {

// The empty and full set of packets cannot be represented as decision nodes,
// and thus we cannot associate an index into the `nodes_` vector with them.
// Instead, we represent them using sentinel values, chosen maximally to avoid
// collisions with proper indices.
enum SentinelNodeIndex : uint32_t {
  kEmptySet = std::numeric_limits<uint32_t>::max(),
  kFullSet = std::numeric_limits<uint32_t>::max() - 1,
};

SymbolicPacket::SymbolicPacket() : node_index_(SentinelNodeIndex::kEmptySet) {}

std::string SymbolicPacket::ToString() const {
  if (node_index_ == SentinelNodeIndex::kEmptySet) {
    return "SymbolicPacket<empty>";
  } else if (node_index_ == SentinelNodeIndex::kFullSet) {
    return "SymbolicPacket<full>";
  } else {
    return absl::StrFormat("SymbolicPacket<%d>", node_index_);
  }
}

// The symbolic packet representing the empty set of packets.
SymbolicPacket SymbolicPacketManager::EmptySet() {
  return SymbolicPacket(SentinelNodeIndex::kEmptySet);
}

// The symbolic packet representing the set of all packets.
SymbolicPacket SymbolicPacketManager::FullSet() {
  return SymbolicPacket(SentinelNodeIndex::kFullSet);
}

// Returns true iff this symbolic packet represents the empty set of
bool SymbolicPacketManager::IsEmptySet(SymbolicPacket packet) const {
  return packet == EmptySet();
}

// Returns true iff this symbolic packet represents the set of all packets.
bool SymbolicPacketManager::IsFullSet(SymbolicPacket packet) const {
  return packet == FullSet();
}

const SymbolicPacketManager::DecisionNode& SymbolicPacketManager::GetNodeOrDie(
    SymbolicPacket packet) const {
  CHECK_LT(packet.node_index_, nodes_.size());  // Crash ok
  return nodes_[packet.node_index_];
}

std::string SymbolicPacketManager::GetFieldNameOrDie(Field field) const {
  CHECK_LT(field.index_, fields_.size());  // Crash ok
  return fields_[field.index_];
}

Field SymbolicPacketManager::GetField(absl::string_view field_name) {
  auto [it, inserted] =
      field_by_name_.try_emplace(field_name, Field(fields_.size()));
  if (inserted) fields_.push_back(std::string(field_name));
  return it->second;
}

SymbolicPacket SymbolicPacketManager::NodeToPacket(DecisionNode&& node) {
  if (node.branch_by_field_value.empty()) return node.default_branch;

// When in debug mode, we check key invariants before creating a new node, to
// ease debugging.
#ifndef NDEBUG
  for (const auto& [value, branch] : node.branch_by_field_value) {
    CHECK(branch != node.default_branch) << PrettyPrint(node);
    if (!IsEmptySet(branch) && !IsFullSet(branch)) {
      auto& branch_node = GetNodeOrDie(branch);
      CHECK(branch_node.field > node.field) << absl::StreamFormat(
          "(%v > %v)\n---branch---\n%s\n---node---\n%s", branch_node.field,
          node.field, PrettyPrint(branch), PrettyPrint(node));
    }
  }
#endif

  auto [it, inserted] =
      packet_by_node_.try_emplace(node, SymbolicPacket(nodes_.size()));
  if (inserted) nodes_.push_back(std::move(node));
  return it->second;
}

bool SymbolicPacketManager::Contains(SymbolicPacket symbolic_packet,
                                     Packet concrete_packet) const {
  if (IsEmptySet(symbolic_packet)) return false;
  if (IsFullSet(symbolic_packet)) return true;

  const DecisionNode& node = GetNodeOrDie(symbolic_packet);
  std::string field = GetFieldNameOrDie(node.field);
  auto it = concrete_packet.find(field);
  if (it != concrete_packet.end()) {
    for (const auto& [value, branch] : node.branch_by_field_value) {
      if (it->second == value) return Contains(branch, concrete_packet);
    }
  }
  return Contains(node.default_branch, concrete_packet);
}

SymbolicPacket SymbolicPacketManager::Compile(const PredicateProto& pred) {
  switch (pred.predicate_case()) {
    case PredicateProto::kBoolConstant:
      return pred.bool_constant().value() ? FullSet() : EmptySet();
    case PredicateProto::kMatch:
      return Match(pred.match().field(), pred.match().value());
    case PredicateProto::kAndOp:
      return And(Compile(pred.and_op().left()), Compile(pred.and_op().right()));
    case PredicateProto::kOrOp:
      return Or(Compile(pred.or_op().left()), Compile(pred.or_op().right()));
    case PredicateProto::kNotOp:
      return Not(Compile(pred.not_op().negand()));
    // By convention, uninitialized predicates must be treated like `false`.
    case PredicateProto::PREDICATE_NOT_SET:
      return EmptySet();
  }
  LOG(FATAL) << "Unhandled predicate kind: " << pred.predicate_case();
}

SymbolicPacket SymbolicPacketManager::Match(absl::string_view field,
                                            int value) {
  return NodeToPacket(DecisionNode{
      .field = GetField(field),
      .default_branch = EmptySet(),
      .branch_by_field_value = {{value, FullSet()}},
  });
}

// TODO(smolkaj): Use complement edges.
SymbolicPacket SymbolicPacketManager::Not(SymbolicPacket negand) {
  // Base cases.
  if (IsEmptySet(negand)) return FullSet();
  if (IsFullSet(negand)) return EmptySet();

  // Compute result the hard way.
  const DecisionNode& negand_node = GetNodeOrDie(negand);
  DecisionNode result_node{
      .field = negand_node.field,
      .default_branch = Not(negand_node.default_branch),
      .branch_by_field_value{negand_node.branch_by_field_value.size()},
  };

  for (int i = 0; i < negand_node.branch_by_field_value.size(); ++i) {
    auto [value, branch] = negand_node.branch_by_field_value[i];
    SymbolicPacket negated_branch = Not(branch);
    DCHECK(branch != negand_node.default_branch);
    DCHECK(negated_branch != result_node.default_branch);
    result_node.branch_by_field_value[i] =
        std::make_pair(value, negated_branch);
  }

  return NodeToPacket(std::move(result_node));
}

SymbolicPacket SymbolicPacketManager::And(SymbolicPacket left,
                                          SymbolicPacket right) {
  // Base cases.
  if (IsEmptySet(left) || IsFullSet(right) || left == right) return left;
  if (IsEmptySet(right) || IsFullSet(left)) return right;

  // Compute result the hard way.
  const DecisionNode* left_node = &GetNodeOrDie(left);
  const DecisionNode* right_node = &GetNodeOrDie(right);

  // We exploit that `And` is commutative to canonicalize the order of the
  // arguments, reducing the number of cases by 1.
  if (left_node->field > right_node->field) {
    std::swap(left, right);
    std::swap(left_node, right_node);
  }

  // Case 1: left_node->field < right_node->field: branch on left field.
  if (left_node->field < right_node->field) {
    SymbolicPacket default_branch = And(left_node->default_branch, right);
    std::vector<std::pair<int, SymbolicPacket>> branch_by_field_value;
    branch_by_field_value.reserve(left_node->branch_by_field_value.size());
    for (const auto& [value, left_branch] : left_node->branch_by_field_value) {
      SymbolicPacket branch = And(left_branch, right);
      if (branch == default_branch) continue;
      branch_by_field_value.push_back(std::make_pair(value, branch));
    }
    return NodeToPacket(DecisionNode{
        .field = left_node->field,
        .default_branch = default_branch,
        .branch_by_field_value{
            branch_by_field_value.begin(),
            branch_by_field_value.end(),
        },
    });
  }

  // Case 2: left_node->field == right_node->field: branch on shared field.
  DCHECK(left_node->field == right_node->field);
  SymbolicPacket default_branch =
      And(left_node->default_branch, right_node->default_branch);
  std::vector<std::pair<int, SymbolicPacket>> branch_by_field_value;
  branch_by_field_value.reserve(left_node->branch_by_field_value.size() +
                                right_node->branch_by_field_value.size());
  auto add_branch = [&](int value, SymbolicPacket branch) {
    if (branch == default_branch) return;
    branch_by_field_value.push_back(std::make_pair(value, branch));
  };
  auto left_it = left_node->branch_by_field_value.begin();
  auto left_end = left_node->branch_by_field_value.end();
  auto right_it = right_node->branch_by_field_value.begin();
  auto right_end = right_node->branch_by_field_value.end();
  while (left_it != left_end && right_it != right_end) {
    auto [left_value, left_branch] = *left_it;
    auto [right_value, right_branch] = *right_it;
    if (left_value < right_value) {
      add_branch(left_value, And(left_branch, right_node->default_branch));
      ++left_it;
    } else if (left_value > right_value) {
      add_branch(right_value, And(left_node->default_branch, right_branch));
      ++right_it;
    } else {  // left_value == right_value
      add_branch(left_value, And(left_branch, right_branch));
      ++left_it;
      ++right_it;
    }
  }
  for (; left_it != left_end; ++left_it) {
    auto [left_value, left_branch] = *left_it;
    add_branch(left_value, And(left_branch, right_node->default_branch));
  }
  for (; right_it != right_end; ++right_it) {
    auto [right_value, right_branch] = *right_it;
    add_branch(right_value, And(left_node->default_branch, right_branch));
  }
  return NodeToPacket(DecisionNode{
      .field = left_node->field,
      .default_branch = default_branch,
      .branch_by_field_value{
          branch_by_field_value.begin(),
          branch_by_field_value.end(),
      },
  });
}

SymbolicPacket SymbolicPacketManager::Or(SymbolicPacket left,
                                         SymbolicPacket right) {
  // Apply De Morgan's law: a || b == !(!a && !b).
  // TODO(smolkaj): Implement complement edges so this becomes efficient.
  return Not(And(Not(left), Not(right)));
}

std::string SymbolicPacketManager::PrettyPrint(SymbolicPacket packet) const {
  std::string result;
  std::deque<SymbolicPacket> work_list = {packet};
  absl::flat_hash_set<SymbolicPacket> visited = {packet};
  while (!work_list.empty()) {
    SymbolicPacket packet = work_list.front();
    work_list.pop_front();
    absl::StrAppend(&result, packet);

    if (IsFullSet(packet) || IsEmptySet(packet)) continue;

    const DecisionNode& node = GetNodeOrDie(packet);
    absl::StrAppend(&result, ":\n");
    std::string field = absl::StrFormat(
        "%v:'%s'", node.field, absl::CEscape(GetFieldNameOrDie(node.field)));
    for (const auto& [value, branch] : node.branch_by_field_value) {
      absl::StrAppendFormat(&result, "  %s == %d -> %v\n", field, value,
                            branch);
      if (IsFullSet(branch) || IsEmptySet(branch)) continue;
      bool new_branch = visited.insert(branch).second;
      if (new_branch) work_list.push_back(branch);
    }
    SymbolicPacket fallthrough = node.default_branch;
    absl::StrAppendFormat(&result, "  %s == * -> %v\n", field, fallthrough);
    if (IsFullSet(fallthrough) || IsEmptySet(fallthrough)) continue;
    bool new_branch = visited.insert(fallthrough).second;
    if (new_branch) work_list.push_back(fallthrough);
  }
  return result;
}

std::string SymbolicPacketManager::PrettyPrint(const DecisionNode& node) const {
  std::string result;
  std::vector<SymbolicPacket> work_list;
  std::string field = absl::StrFormat(
      "%v:'%s'", node.field, absl::CEscape(GetFieldNameOrDie(node.field)));
  for (const auto& [value, branch] : node.branch_by_field_value) {
    absl::StrAppendFormat(&result, "  %s == %d -> %v\n", field, value, branch);
    if (!IsFullSet(branch) || !IsEmptySet(branch)) work_list.push_back(branch);
  }
  SymbolicPacket fallthrough = node.default_branch;
  absl::StrAppendFormat(&result, "  %s == * -> %v\n", field, fallthrough);
  if (!IsFullSet(fallthrough) && !IsEmptySet(fallthrough)) {
    work_list.push_back(fallthrough);
  }

  for (const SymbolicPacket& branch : work_list) {
    absl::StrAppend(&result, PrettyPrint(branch));
  }

  return result;
}

absl::Status SymbolicPacketManager::CheckInternalInvariants() const {
  // Invariant: `packet_by_node_[n] = s` iff `nodes_[s.node_index_] == n`.
  for (const auto& [node, packet] : packet_by_node_) {
    RET_CHECK(packet.node_index_ < nodes_.size());
    RET_CHECK(nodes_[packet.node_index_] == node);
  }
  for (int i = 0; i < nodes_.size(); ++i) {
    const DecisionNode& node = nodes_[i];
    auto it = packet_by_node_.find(node);
    RET_CHECK(it != packet_by_node_.end());
    RET_CHECK(it->second == SymbolicPacket(i));
  }

  // Invariant: `field_by_name_[n] = f` iff `fields_[f.index_] == n`.
  for (const auto& [field_name, field] : field_by_name_) {
    RET_CHECK(field.index_ < fields_.size());
    RET_CHECK(fields_[field.index_] == field_name);
  }
  for (int i = 0; i < fields_.size(); ++i) {
    const std::string& field_name = fields_[i];
    auto it = field_by_name_.find(field_name);
    RET_CHECK(it != field_by_name_.end());
    RET_CHECK(it->second == Field(i));
  }

  // Node Invariants.
  for (const DecisionNode& node : nodes_) {
    // Invariant: `branch_by_field_value` is non-empty.
    // Maintained by `NodeToPacket`.
    RET_CHECK(!node.branch_by_field_value.empty());

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
  }

  return absl::OkStatus();
}

}  // namespace netkat
