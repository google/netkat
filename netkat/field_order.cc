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

#include "netkat/field_order.h"

#include <algorithm>
#include <compare>  // IWYU pragma: keep
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/types/span.h"
#include "netkat/netkat.pb.h"

namespace netkat {
namespace {

using Node = std::variant<const PolicyProto*, const PredicateProto*>;

// Pushes the children of `node` onto `stack`, in reverse order, so that they
// are popped from left to right.
void PushChildren(Node node, std::vector<Node>& stack) {
  if (auto* policy = std::get_if<const PolicyProto*>(&node)) {
    const PolicyProto& p = **policy;
    switch (p.policy_case()) {
      case PolicyProto::kFilter:
        stack.push_back(&p.filter());
        break;
      case PolicyProto::kSequenceOp:
        stack.push_back(&p.sequence_op().right());
        stack.push_back(&p.sequence_op().left());
        break;
      case PolicyProto::kUnionOp:
        stack.push_back(&p.union_op().right());
        stack.push_back(&p.union_op().left());
        break;
      case PolicyProto::kIterateOp:
        stack.push_back(&p.iterate_op().iterable());
        break;
      case PolicyProto::kDifferenceOp:
        stack.push_back(&p.difference_op().right());
        stack.push_back(&p.difference_op().left());
        break;
      case PolicyProto::kModification:
      case PolicyProto::kRecord:
      case PolicyProto::POLICY_NOT_SET:
        break;
    }
    return;
  }
  const PredicateProto& p = *std::get<const PredicateProto*>(node);
  switch (p.predicate_case()) {
    case PredicateProto::kAndOp:
      stack.push_back(&p.and_op().right());
      stack.push_back(&p.and_op().left());
      break;
    case PredicateProto::kOrOp:
      stack.push_back(&p.or_op().right());
      stack.push_back(&p.or_op().left());
      break;
    case PredicateProto::kNotOp:
      stack.push_back(&p.not_op().negand());
      break;
    case PredicateProto::kXorOp:
      stack.push_back(&p.xor_op().right());
      stack.push_back(&p.xor_op().left());
      break;
    case PredicateProto::kPullOp:
      stack.push_back(&p.pull_op().pred());
      stack.push_back(&p.pull_op().policy());
      break;
    case PredicateProto::kMatch:
    case PredicateProto::kBoolConstant:
    case PredicateProto::PREDICATE_NOT_SET:
      break;
  }
}

// Returns the roots of the given policies and predicates, in reverse order.
std::vector<Node> Roots(absl::Span<const PolicyProto> policies,
                        absl::Span<const PredicateProto> predicates) {
  std::vector<Node> roots;
  for (auto it = predicates.rbegin(); it != predicates.rend(); ++it) {
    roots.push_back(&*it);
  }
  for (auto it = policies.rbegin(); it != policies.rend(); ++it) {
    roots.push_back(&*it);
  }
  return roots;
}

// Returns the field of `node` if it is a match or modification.
const std::string* FieldOf(Node node) {
  if (auto* policy = std::get_if<const PolicyProto*>(&node)) {
    if ((*policy)->has_modification()) {
      return &(*policy)->modification().field();
    }
    return nullptr;
  }
  const PredicateProto& p = *std::get<const PredicateProto*>(node);
  return p.has_match() ? &p.match().field() : nullptr;
}

constexpr int64_t kNever = std::numeric_limits<int64_t>::max();

// How a field is used by a policy, for `HeuristicFieldOrder`.
struct FieldUses {
  std::string name;
  int64_t first_test_time = kNever;
  int64_t first_modification_time = kNever;
  int64_t num_tests = 0;
  // The total size of the policies guarded by positive tests of the field in
  // alternatives (see `HeuristicFieldOrder`), by time of the test. Unsorted,
  // and the same time may occur more than once.
  std::vector<std::pair<int64_t, int64_t>> guard_weight_by_time;
};

// Analyzes how the given policies and predicates use fields, where "time"
// counts the modifications that a packet may have undergone so far: `p; q`
// runs `q` after `p`, `p + q` runs `p` and `q` at the same time, and `p*` runs
// its first iteration at the same time as `p*`. Tests are instantaneous.
//
// Runs in linear time, with an explicit stack, since policies can be deeply
// nested.
class FieldUseAnalysis {
 public:
  FieldUseAnalysis(absl::Span<const PolicyProto> policies,
                   absl::Span<const PredicateProto> predicates) {
    for (const PolicyProto& policy : policies) Analyze(policy);
    for (const PredicateProto& predicate : predicates) {
      RecordTests(predicate, /*time=*/0, /*guarded_element=*/std::nullopt);
    }
  }

  // The fields, in order of first appearance (in a left-to-right, pre-order
  // traversal).
  const std::vector<FieldUses>& fields() const { return fields_; }

 private:
  int FieldId(const std::string& name) {
    // Policies typically have few fields, which are faster to find by linear
    // search than by hashing.
    if (fields_.size() <= kMaxFieldsForLinearSearch) {
      for (size_t i = 0; i < fields_.size(); ++i) {
        if (fields_[i].name == name) return i;
      }
      if (fields_.size() < kMaxFieldsForLinearSearch) {
        fields_.push_back({.name = name});
        return fields_.size() - 1;
      }
      // Switch to hashing.
      for (size_t i = 0; i < fields_.size(); ++i) {
        field_ids_[fields_[i].name] = i;
      }
    }
    auto [it, inserted] = field_ids_.try_emplace(name, fields_.size());
    if (inserted) fields_.push_back({.name = name});
    return it->second;
  }

  // Records the tests of `predicate` at `time`, and returns the size of
  // `predicate`. If the predicate is a filter guarding the rest of a chain in
  // an alternative (starting after element `guarded_element`), records its
  // positive tests as pending guards, whose guarded size is determined once
  // the chain is complete.
  int64_t RecordTests(const PredicateProto& predicate, int64_t time,
                      std::optional<size_t> guarded_element) {
    int64_t size = 0;
    test_stack_.clear();
    test_stack_.push_back({&predicate, true});
    while (!test_stack_.empty()) {
      auto [p, positive] = test_stack_.back();
      test_stack_.pop_back();
      ++size;
      switch (p->predicate_case()) {
        case PredicateProto::kMatch: {
          const int field = FieldId(p->match().field());
          if (fields_.size() <= field) break;
          FieldUses& uses = fields_[field];
          uses.first_test_time = std::min(uses.first_test_time, time);
          ++uses.num_tests;
          if (positive && guarded_element.has_value()) {
            pending_guards_.push_back({field, time, *guarded_element});
          }
          break;
        }
        case PredicateProto::kAndOp:
          test_stack_.push_back({&p->and_op().right(), positive});
          test_stack_.push_back({&p->and_op().left(), positive});
          break;
        case PredicateProto::kOrOp:
          test_stack_.push_back({&p->or_op().right(), positive});
          test_stack_.push_back({&p->or_op().left(), positive});
          break;
        case PredicateProto::kNotOp:
          test_stack_.push_back({&p->not_op().negand(), !positive});
          break;
        case PredicateProto::kXorOp:
          // Tests under `Xor` occur both positively and negatively.
          test_stack_.push_back({&p->xor_op().right(), false});
          test_stack_.push_back({&p->xor_op().left(), false});
          break;
        case PredicateProto::kPullOp: {
          // For simplicity, we treat all fields of the pulled policy as tested
          // (without guarding anything) at `time`.
          std::vector<Node> pull_stack = {&p->pull_op().policy()};
          while (!pull_stack.empty()) {
            Node node = pull_stack.back();
            pull_stack.pop_back();
            ++size;
            if (const std::string* field_name = FieldOf(node)) {
              const int field = FieldId(*field_name);
              if (fields_.size() > field) {
                FieldUses& uses = fields_[field];
                uses.first_test_time = std::min(uses.first_test_time, time);
                ++uses.num_tests;
              }
            }
            PushChildren(node, pull_stack);
          }
          test_stack_.push_back({&p->pull_op().pred(), false});
          break;
        }
        case PredicateProto::kBoolConstant:
        case PredicateProto::PREDICATE_NOT_SET:
          break;
      }
    }
    return size;
  }

  void RecordModification(const std::string& field_name, int64_t time) {
    FieldUses& uses = fields_[FieldId(field_name)];
    uses.first_modification_time = std::min(uses.first_modification_time, time);
  }

  // A policy being analyzed. Sequences are flattened into chains
  // `p1; ...; pn`, in which each filter `pi` guards `p(i+1); ...; pn`.
  struct Frame {
    const PolicyProto* policy;
    // For chains, the current time; otherwise, the start time.
    int64_t time;
    // Whether the policy is an alternative, i.e. an operand of a union.
    bool is_alternative;
    int stage = 0;
    int64_t size = 1;
    int64_t left_end_time = 0;
    // For chains: the elements are `chain_elements_[elements_begin, ...)`,
    // `index` is the next element to analyze, and the frame's pending guards
    // are `pending_guards_[pending_guards_begin, ...)`.
    size_t elements_begin = 0;
    size_t index = 0;
    size_t pending_guards_begin = 0;
  };

  Frame MakeFrame(const PolicyProto& policy, int64_t time,
                  bool is_alternative) {
    Frame frame = {
        .policy = &policy, .time = time, .is_alternative = is_alternative};
    if (!policy.has_sequence_op()) return frame;
    frame.elements_begin = frame.index = chain_elements_.size();
    frame.pending_guards_begin = pending_guards_.size();
    flatten_stack_.clear();
    flatten_stack_.push_back(&policy);
    while (!flatten_stack_.empty()) {
      const PolicyProto* element = flatten_stack_.back();
      flatten_stack_.pop_back();
      if (element->has_sequence_op()) {
        flatten_stack_.push_back(&element->sequence_op().right());
        flatten_stack_.push_back(&element->sequence_op().left());
      } else {
        chain_elements_.push_back(element);
      }
    }
    element_sizes_.resize(chain_elements_.size());
    return frame;
  }

  // Completes the chain of `frame`: resolves its pending guards, and returns
  // its size.
  int64_t CompleteChain(const Frame& frame) {
    // Turns element sizes into suffix sizes.
    const size_t num_elements = chain_elements_.size() - frame.elements_begin;
    int64_t suffix_size = 0;
    for (size_t i = chain_elements_.size(); i-- > frame.elements_begin;) {
      const int64_t element_size = element_sizes_[i];
      element_sizes_[i] = suffix_size;
      suffix_size += element_size;
    }
    for (size_t i = frame.pending_guards_begin; i < pending_guards_.size();
         ++i) {
      const PendingGuard& guard = pending_guards_[i];
      if (fields_.size() <= guard.field) continue;
      std::vector<std::pair<int64_t, int64_t>>& guard_weight_by_time =
          fields_[guard.field].guard_weight_by_time;
      if (guard_weight_by_time.empty() ||
          guard_weight_by_time.back().first != guard.time) {
        guard_weight_by_time.push_back({guard.time, 0});
      }
      guard_weight_by_time.back().second += element_sizes_[guard.element];
    }
    pending_guards_.resize(frame.pending_guards_begin);
    chain_elements_.resize(frame.elements_begin);
    element_sizes_.resize(frame.elements_begin);
    // Accounts for the `num_elements - 1` sequence nodes.
    return suffix_size + num_elements - 1;
  }

  void Analyze(const PolicyProto& root) {
    std::vector<Frame> stack;
    stack.push_back(MakeFrame(root, 0, /*is_alternative=*/false));
    // The end time and size of the last completed frame.
    int64_t end_time = 0;
    int64_t size = 0;
    while (!stack.empty()) {
      Frame& frame = stack.back();
      const PolicyProto& p = *frame.policy;
      if (p.has_sequence_op()) {
        if (frame.stage == 1) {  // Returning from `chain_elements_[index]`.
          frame.stage = 0;
          frame.time = end_time;
          if (element_sizes_.size() > frame.index) {
            element_sizes_[frame.index++] = size;
          }
        }
        if (frame.index >= chain_elements_.size() ||
            frame.index >= element_sizes_.size()) {
          end_time = frame.time;
          size = CompleteChain(frame);
          stack.pop_back();
          continue;
        }
        const PolicyProto& element = *chain_elements_[frame.index];
        if (element.has_filter()) {
          std::optional<size_t> guarded_element;
          if (frame.is_alternative) guarded_element = frame.index;
          element_sizes_[frame.index] =
              1 + RecordTests(element.filter(), frame.time, guarded_element);
          ++frame.index;
        } else if (element.has_modification()) {
          RecordModification(element.modification().field(), frame.time);
          element_sizes_[frame.index] = 1;
          ++frame.time;
          ++frame.index;
        } else {
          frame.stage = 1;
          const int64_t time = frame.time;
          stack.push_back(MakeFrame(element, time, /*is_alternative=*/false));
        }
        continue;
      }
      const int64_t start_time = frame.time;
      switch (p.policy_case()) {
        case PolicyProto::kFilter:
          size = 1 + RecordTests(p.filter(), start_time,
                                 /*guarded_element=*/std::nullopt);
          end_time = start_time;
          stack.pop_back();
          break;
        case PolicyProto::kModification:
          RecordModification(p.modification().field(), start_time);
          size = 1;
          end_time = start_time + 1;
          stack.pop_back();
          break;
        case PolicyProto::kUnionOp:
        case PolicyProto::kDifferenceOp: {
          const bool is_union = p.has_union_op();
          const PolicyProto& left =
              is_union ? p.union_op().left() : p.difference_op().left();
          const PolicyProto& right =
              is_union ? p.union_op().right() : p.difference_op().right();
          if (frame.stage == 0) {
            frame.stage = 1;
            stack.push_back(MakeFrame(left, start_time, is_union));
          } else if (frame.stage == 1) {
            frame.stage = 2;
            frame.size += size;
            frame.left_end_time = end_time;
            stack.push_back(MakeFrame(right, start_time, is_union));
          } else {
            size += frame.size;
            end_time = std::max(end_time, frame.left_end_time);
            stack.pop_back();
          }
          break;
        }
        case PolicyProto::kIterateOp:
          if (frame.stage == 0) {
            frame.stage = 1;
            stack.push_back(MakeFrame(p.iterate_op().iterable(), start_time,
                                      /*is_alternative=*/false));
          } else {
            size += 1;
            end_time = std::max(end_time, start_time);
            stack.pop_back();
          }
          break;
        case PolicyProto::kSequenceOp:  // Handled above.
        case PolicyProto::kRecord:
        case PolicyProto::POLICY_NOT_SET:
          size = 1;
          end_time = start_time;
          stack.pop_back();
          break;
      }
    }
  }

  struct PendingGuard {
    int field;
    int64_t time;
    size_t element;  // The index of the guarding filter in `chain_elements_`.
  };

  static constexpr size_t kMaxFieldsForLinearSearch = 16;
  std::vector<FieldUses> fields_;
  // Only used once there are more than `kMaxFieldsForLinearSearch` fields.
  absl::flat_hash_map<std::string, int> field_ids_;
  // The elements of the chains being analyzed, and their sizes.
  std::vector<const PolicyProto*> chain_elements_;
  std::vector<int64_t> element_sizes_;
  std::vector<PendingGuard> pending_guards_;
  // Scratch space.
  std::vector<std::pair<const PredicateProto*, bool>> test_stack_;
  std::vector<const PolicyProto*> flatten_stack_;
};

}  // namespace

std::vector<std::string> FieldsInOrderOfAppearance(
    absl::Span<const PolicyProto> policies,
    absl::Span<const PredicateProto> predicates) {
  std::vector<std::string> fields;
  absl::flat_hash_map<std::string, int> seen;
  std::vector<Node> stack = Roots(policies, predicates);
  while (!stack.empty()) {
    Node node = stack.back();
    stack.pop_back();
    if (const std::string* field = FieldOf(node);
        field != nullptr && seen.try_emplace(*field, fields.size()).second) {
      fields.push_back(*field);
    }
    PushChildren(node, stack);
  }
  return fields;
}

// We order fields by two principles.
//
// First, by data flow: we order fields by the time at which they are first
// used (tested or modified), i.e. in the order in which the stages of a
// pipeline `p1; p2; ...` process them. For example, in `in_port=1; vrf:=1;
// (vrf=1; dst=2; ...)`, `in_port` determines how the packet is processed
// downstream, and the later tests of `vrf` are resolved by the preceding
// modification. Similarly, in a network `(forwarding; topology)*`, the
// topology's tests of `port` are resolved by the forwarding's modifications
// of `port`. Ordering fields that are only modified by the time of their
// modification (rather than, say, last) lets the rest of the pipeline be
// shared between different values of the field.
//
// Second, among fields first used at the same time, we order fields by how
// much of the policy they "dispatch" on. A test `f=v` in a filter of a
// sequence `f=v; p` selects the continuation `p`, and testing `f` early splits
// the policy into independent parts, keeping the decision diagrams of the
// parts from being interleaved with each other. For example, in a network
// `sw=1; t1 + sw=2; t2 + ...`, testing `sw` first results in one decision
// diagram per switch table `ti`, while testing `sw` last results in the
// tables' diagrams being merged and then split again at every leaf.
//
// Concretely, we define the "guard weight" of a field as the total size of
// the policies guarded by positive tests of the field in alternatives `f=v; p`
// of unions, which occur no later than the field's first modification (later
// tests are resolved by modifications, as above). A filter that is not an
// alternative, e.g. the `ingress` of a query `ingress; p; egress`, restricts
// `p`, but does not select between different policies. A test is positive if
// it occurs under an even number of negations (and not under a `Xor`), since a
// negated test `!(f=v); p` does not select `p` by `f`, but only excludes one
// value. This makes the weight robust to the encoding of prioritized tables as
// `m1; a1 + !m1; (m2; a2 + !m2; (...))`, in which `!m1` guards the rest of the
// table.
//
// We break remaining ties by the number of tests of the field, and then by
// order of appearance.
//
// Up to the final tie breaker, both principles only depend on the semantically
// relevant structure of the policy: the order of sequential composition, but
// not the order of the operands of `+`, `&&`, or `||`, or the associativity of
// `;`.
std::vector<std::string> HeuristicFieldOrder(
    absl::Span<const PolicyProto> policies,
    absl::Span<const PredicateProto> predicates) {
  FieldUseAnalysis analysis(policies, predicates);
  const std::vector<FieldUses>& fields = analysis.fields();

  struct Key {
    int64_t time;
    int64_t negated_guard_weight;
    int64_t negated_num_tests;
    size_t appearance;
    auto operator<=>(const Key&) const = default;
  };
  std::vector<Key> keys;
  keys.reserve(fields.size());
  for (size_t i = 0; i < fields.size(); ++i) {
    const FieldUses& uses = fields[i];
    int64_t guard_weight = 0;
    for (auto [time, weight] : uses.guard_weight_by_time) {
      if (time <= uses.first_modification_time) guard_weight += weight;
    }
    keys.push_back({
        .time = std::min(uses.first_test_time, uses.first_modification_time),
        .negated_guard_weight = -guard_weight,
        .negated_num_tests = -uses.num_tests,
        .appearance = i,
    });
  }
  std::sort(keys.begin(), keys.end());
  std::vector<std::string> order;
  order.reserve(keys.size());
  for (const Key& key : keys) order.push_back(fields[key.appearance].name);
  return order;
}

}  // namespace netkat
