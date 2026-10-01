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
// File: packet_transformer.h
// -----------------------------------------------------------------------------
//
// Defines `PacketTransformerManager`, the companion class to
// `PacketTransformerHandle` following the manager-handle pattern described in
// `manager_handle_pattern.md`. Together, they provide a compact and efficient
// representation of record-free policies allowing for fast semantic equality
// checks. Semantically, a `PacketTransformerHandle` represents a function that
// maps packets to packet sets.
//
// This is a low level library designed for maximum efficiency, rather than a
// high level library designed for safety and convenience.
//
// The implementation is based on the paper "KATch: A Fast Symbolic Verifier for
// NetKAT" and is closely related to Binary Decision Diagrams (BDDs), see
// https://en.wikipedia.org/wiki/Binary_decision_diagram.
//
// -----------------------------------------------------------------------------
//
// CAUTION: This implementation has NOT yet been optimized for performance.

#ifndef GOOGLE_NETKAT_NETKAT_PACKET_TRANSFORMER_H_
#define GOOGLE_NETKAT_NETKAT_PACKET_TRANSFORMER_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/container/inlined_vector.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "netkat/interned_vector.h"
#include "netkat/netkat.pb.h"
#include "netkat/packet.h"
#include "netkat/packet_field.h"
#include "netkat/packet_set.h"
#include "netkat/packet_set_handle.h"
#include "netkat/packet_transformer_handle.h"
#include "netkat/sorted_vector_map.h"

namespace netkat {

// An "arena" in which `PacketTransformerHandle`s can be created and
// manipulated, following the manager-handle pattern (see
// `manager_handle_pattern.md`).
//
// This class defines the majority of operations on `PacketTransformerHandle`s
// and owns all the memory associated with the handles returned by the class's
// methods.
//
// CAUTION: Using a `PacketTransformerHandle` returned by one
// `PacketTransformerManager` object with a different manager is
// undefined behavior. `PacketSetHandles` and `PacketTransformerHandles`
// returned by this class are not invalidated on move.

class PacketTransformerManager {
 public:
  PacketTransformerManager();

  // The class is move-only: not copyable, but movable.
  // `PacketSetHandles` and `PacketTransformerHandles` returned by this class
  // are not invalidated on move.
  PacketTransformerManager(const PacketTransformerManager&) = delete;
  PacketTransformerManager& operator=(const PacketTransformerManager&) = delete;
  PacketTransformerManager(PacketTransformerManager&& other);
  PacketTransformerManager& operator=(PacketTransformerManager&& other);

  // Returns the `PacketSetManager` used by this object to compile
  // predicates.
  PacketSetManager& GetPacketSetManager() { return packet_set_manager_; }
  const PacketSetManager& GetPacketSetManager() const {
    return packet_set_manager_;
  }

  // Returns true iff this transformer represents the Deny policy.
  bool IsDeny(PacketTransformerHandle transformer) const;

  // Returns true iff this transformer represents the Accept policy.
  bool IsAccept(PacketTransformerHandle transformer) const;

  // Returns the set of possible packets obtained by running the given
  // `packet` through the policy represented by `transformer`.
  // NOTE: The `packet` will be returned unmodified.
  absl::flat_hash_set<Packet> Run(PacketTransformerHandle transformer,
                                  Packet& packet) const;

  // Compiles the given `PolicyProto` into a `PacketTransformerHandle` that
  // represents the application of that policy to a set of packets.
  // Note: Will remove any Record operations in `policy`, replacing them with
  // the Accept policy.
  //
  // Fields of `policy` that are not yet in use are first declared in the order
  // given by `HeuristicFieldOrder` (see `PacketSetManager::DeclareFields`). To
  // use a different order, declare the fields before compiling. Workloads that
  // also compile predicates (e.g. `Push(ingress, policy)`) generally perform
  // best if the policy is compiled first.
  PacketTransformerHandle Compile(const PolicyProto& policy);

  // The packet transformer representing the Deny policy (i.e. the
  // policy that denies all packets). We say a transformer `T` "denies" a packet
  // `p` iff `T(p)` is empty.
  PacketTransformerHandle Deny() const;

  // The packet transformer representing the Accept policy (i.e. the
  // policy that accepts all packets). We say a transformer `T` "accepts" a
  // packet `p` iff `p \in T(p)`.
  PacketTransformerHandle Accept() const;

  // Creates a `PacketTransformerHandle` that accepts a packet iff it is
  // contained in `packet_set`. `packet_set` must be created/owned by
  // this manager. This is equivalent to Filter on the predicate corresponding
  // to `packet_set`.
  PacketTransformerHandle FromPacketSetHandle(PacketSetHandle packet_set);

  // Returns the transformer that only accepts packets matching `predicate`.
  PacketTransformerHandle Filter(const PredicateProto& predicate);

  // Returns the transformer that sets the `field` of packets to `value`.
  PacketTransformerHandle Modification(absl::string_view field, int value);

  // Returns the transformer that applies the `left` transformer, then the
  // `right` transformer.
  PacketTransformerHandle Sequence(PacketTransformerHandle left,
                                   PacketTransformerHandle right);

  // Returns the transformer that non-deterministically applies the `left`
  // transformer *OR* the `right` transformer.
  PacketTransformerHandle Union(PacketTransformerHandle left,
                                PacketTransformerHandle right);

  // Returns the transformer that non-deterministically applies the `iterable`
  // transformer in sequence 0 or more times.
  PacketTransformerHandle Iterate(PacketTransformerHandle iterable);

  // Returns a human-readable string representation of the given `transformer`,
  // intended for debugging.
  [[nodiscard]] std::string ToString(PacketTransformerHandle transformer) const;

  // Returns a dot string representation of the given `packet_set`.
  std::string ToDot(const PacketTransformerHandle& transformer) const;

  // Computes the set of all possible outputs the given `transformer` can
  // produce. Equivalent to `Push(manager::FullSet(), transformer)`.
  PacketSetHandle GetAllPossibleOutputPackets(
      PacketTransformerHandle transformer);

  // Computes the set of possible input packets that when run through the given
  // transformer produce a non-empty set of outputs. Equivalent to
  // `Pull(transformer, manager::FullSet())`.
  PacketSetHandle GetAllInputPacketsThatProduceAnyOutput(
      PacketTransformerHandle transformer);

  // Returns set of output packets obtained by applying the given `transformer`
  // to the given `input_packets`.
  PacketSetHandle Push(PacketSetHandle input_packets,
                       PacketTransformerHandle transformer);

  // Returns the set of input packets obtained by applying the given
  // `transformer` in reverse on the given `output_packets`. More formally,
  // returns the set of input packets that produce one or more output packets
  // contained in `output_packets`.
  PacketSetHandle Pull(PacketTransformerHandle transformer,
                       PacketSetHandle output_packets);

  // TODO(b/398373935): There are many additional operations supported by this
  // data structure, but not currently implemented. Add them as needed. Examples
  // below include Intersection, Difference, and SymmetricDifference.

  // Returns the transformer that describes the packets produced by both the
  // `left` and the `right` transformers, but not either alone.
  PacketTransformerHandle Intersection(PacketTransformerHandle left,
                                       PacketTransformerHandle right) = delete;

  // Returns the transformer that describes the packets produced by the `left`
  // transformer, but not the `right` transformer.
  PacketTransformerHandle Difference(PacketTransformerHandle left,
                                     PacketTransformerHandle right);

  // Returns the transformer that describes the packets produced by the `left`
  // transformer or the `right` transformer, but not both.
  PacketTransformerHandle SymmetricDifference(
      PacketTransformerHandle left, PacketTransformerHandle right) = delete;

  // Dynamically checks all class invariants. Exposed for testing only.
  absl::Status CheckInternalInvariants() const;

 private:
  // Internally, this class represents packet transformers
  // as nodes in a directed acyclic graph (DAG). Each node branches based on the
  // input value of a single packet field, and then on the possible output
  // values of that field. Each branch end-point is another packet set
  // transformer, which in turn is either the Accept/Deny policy, or represented
  // by another node in the graph.
  //
  // The graph is "ordered", "reduced", and contains no "isomorphic subgraphs":
  //
  // * Ordered: Along each path through the graph, fields increase strictly
  //   monotonically (with respect to `<` defined on `PacketFieldHandle`s).
  // * Reduced: Intutively, there exist no redundant branches or nodes.
  //   This intuition is formalized in the paper "KATch: A Fast Symbolic
  //   Verifier for NetKAT".
  // * No isomorphic subgraphs: Nodes are interned by the class, ensuring that
  //   structurally identical nodes are guaranteed to be stored by the class
  //   only once. Together with the other two properties, this implies that each
  //   node stored by the class represents a unique policy.
  //
  // This representation is closely related to Binary Decision Diagrams (BDDs),
  // see https://en.wikipedia.org/wiki/Binary_decision_diagram. This variant of
  // BDDs is described in the paper "KATch: A Fast Symbolic Verifier for
  // NetKAT".

  // A decision node in the packet transformer DAG. The node branches
  // on the value of a single `field`, and (the consequent of) each branch is a
  // `PacketTransformerHandle` corresponding to either another decision node
  // or the full/empty set. Semantically, represents a cascading conditional of
  // the form:
  //
  //   if      (field == value_1) then
  //     non-deterministically set field -> value_1_1 then branch_1_1
  //     non-deterministically set field -> value_1_2 then branch_1_2
  //     ...
  //   else if (field == value_2) then
  //     non-deterministically set field -> value_2_1 then branch_2_1
  //     non-deterministically set field -> value_2_2 then branch_2_2
  //   ...
  //   // Default case when no value matches.
  //   else
  //     non-deterministically set field -> value_d_1 then branch_d_1
  //     non-deterministically set field -> value_d_2 then branch_d_2
  //     non-deterministically LEAVE field UNMODIFIED then default_branch
  //
  // Nodes are stored in a compact, immutable, flat representation (see
  // `DecisionNode` below), and constructed as `DecisionNodeBuilder`s.

  // An entry of a modification map: a value that a field gets modified to, and
  // the transformer that is applied after the modification.
  using ModifyEntry = std::pair<int, PacketTransformerHandle>;

  // A map from values that a field gets modified to, to the transformer that is
  // applied after the modification. Used to build decision nodes.
  //
  // CHOICE OF DATA STRUCTURE:
  // The vast majority of these maps are tiny (often just a single entry), and
  // all set operations build them in sorted order. We thus use a flat, sorted
  // vector, with 2 entries stored inline to avoid heap allocations for the
  // common case, at no extra memory cost.
  using ModifyMap = SortedVectorMap<int, PacketTransformerHandle,
                                    absl::InlinedVector<ModifyEntry, 2>>;

  // A mutable decision node, used to construct `DecisionNode`s.
  struct DecisionNodeBuilder {
    // The packet field whose value this decision node branches on.
    //
    // INVARIANTS:
    // * Strictly smaller (`<`) than the fields of other decision nodes
    //   reachable from this node.
    // * Interned by `field_manager_`.
    PacketFieldHandle field;

    // The "if" branches of the decision node, "keyed" by the value they branch
    // on. Each element of the map is a (match_value, Map)-pair encoding
    // "if (field == match_value) then non-deterministically choose a
    // (modify_value, branch) pair from `Map`, modify field to modify_value and
    // follow branch".
    //
    // INVARIANTS:
    // 1. Maintained by `NodeToTransformer`: `modify_branch_by_field_match` and
    //    `default_branch_by_field_modification` below are not both empty.
    //    (If they were both empty, the decision node gets replaced by
    //    `default_branch`.)
    // 2. For every v, v', and b such that (v,(v',b)) is in
    //    `modify_branch_by_field_match`, either v == v' or b is not Deny.
    SortedVectorMap<int, ModifyMap> modify_branch_by_field_match;

    // The "else" branch of this decision node, "keyed" by the value they modify
    // the field to (or not keyed at all for the `default_branch`).
    //
    // INVARIANTS:
    // 1. For every v and b such that (v,b) is in
    //    `default_branch_by_field_modification`, b is not Deny.
    ModifyMap default_branch_by_field_modification;
    PacketTransformerHandle default_branch;

    // Hashing, see https://abseil.io/docs/cpp/guides/hash. Consistent with the
    // hashing of the equivalent `DecisionNode`.
    template <typename H>
    friend H AbslHashValue(H h, const DecisionNodeBuilder& node) {
      return H::combine(std::move(h), node.field, node.default_branch,
                        node.default_branch_by_field_modification,
                        node.modify_branch_by_field_match);
    }
  };

  // A read-only view of a modification map, i.e. of a sequence of
  // `ModifyEntry`s sorted by strictly increasing modify value.
  class ModifyMapView {
   public:
    ModifyMapView() = default;
    explicit ModifyMapView(absl::Span<const ModifyEntry> entries)
        : entries_(entries) {}
    // Implicit, so that `ModifyMap`s can be passed where views are expected.
    ModifyMapView(const ModifyMap& map)  // NOLINT
        : entries_(map.begin(), map.size()) {}

    const ModifyEntry* begin() const { return entries_.data(); }
    const ModifyEntry* end() const { return entries_.data() + entries_.size(); }
    size_t size() const { return entries_.size(); }
    bool empty() const { return entries_.empty(); }

    // Returns a pointer to the entry with the given `modify_value`, or `end()`.
    const ModifyEntry* find(int modify_value) const;
    bool contains(int modify_value) const {
      return find(modify_value) != end();
    }

    friend bool operator==(ModifyMapView a, ModifyMapView b) {
      return std::equal(a.begin(), a.end(), b.begin(), b.end());
    }

    // Hashing, see https://abseil.io/docs/cpp/guides/hash. Consistent with the
    // hashing of the equivalent `ModifyMap`.
    template <typename H>
    friend H AbslHashValue(H h, ModifyMapView map) {
      for (const auto& [modify_value, branch] : map) {
        h = H::combine(std::move(h), modify_value, branch);
      }
      return H::combine(std::move(h), map.size());
    }

   private:
    absl::Span<const ModifyEntry> entries_;
  };

  // A match branch of a `DecisionNode`, i.e. a match value together with (the
  // end of the range of) its modification map.
  struct MatchBranch {
    int match_value;
    // The modification map of this branch is stored at the positions
    // [begin, `modifications_end`) of `DecisionNode::modifications`, where
    // `begin` is the `modifications_end` of the preceding match branch (or 0).
    uint32_t modifications_end;
  };

  // A read-only view of the match branches of a `DecisionNode`, i.e. of a map
  // from match values to modification maps, sorted by strictly increasing
  // match value. Iterates over (match value, `ModifyMapView`) pairs.
  class MatchBranchesView {
   public:
    class Iterator {
     public:
      using iterator_category = std::input_iterator_tag;
      using value_type = std::pair<int, ModifyMapView>;
      using difference_type = std::ptrdiff_t;
      using pointer = void;
      using reference = value_type;

      Iterator() = default;
      Iterator(const MatchBranch* branch, const ModifyEntry* modifications,
               uint32_t modifications_begin)
          : branch_(branch),
            modifications_(modifications),
            modifications_begin_(modifications_begin) {}

      value_type operator*() const {
        return {branch_->match_value,
                ModifyMapView(absl::MakeConstSpan(
                    modifications_ + modifications_begin_,
                    branch_->modifications_end - modifications_begin_))};
      }
      Iterator& operator++() {
        modifications_begin_ = branch_->modifications_end;
        ++branch_;
        return *this;
      }
      Iterator operator++(int) {
        Iterator result = *this;
        ++*this;
        return result;
      }
      friend bool operator==(const Iterator& a, const Iterator& b) {
        return a.branch_ == b.branch_;
      }

     private:
      const MatchBranch* branch_ = nullptr;
      const ModifyEntry* modifications_ = nullptr;
      uint32_t modifications_begin_ = 0;
    };

    MatchBranchesView(absl::Span<const MatchBranch> branches,
                      const ModifyEntry* modifications)
        : branches_(branches), modifications_(modifications) {}

    Iterator begin() const {
      return Iterator(branches_.data(), modifications_, 0);
    }
    Iterator end() const {
      return Iterator(branches_.data() + branches_.size(), modifications_, 0);
    }
    size_t size() const { return branches_.size(); }
    bool empty() const { return branches_.empty(); }

    // The match branches, sorted by strictly increasing match value.
    absl::Span<const MatchBranch> branches() const { return branches_; }

    // Returns the modification map of the given `branch`, which must be an
    // element of `branches()`.
    ModifyMapView MapOf(const MatchBranch* branch) const {
      const uint32_t begin =
          branch == branches_.data() ? 0 : (branch - 1)->modifications_end;
      return ModifyMapView(absl::MakeConstSpan(
          modifications_ + begin, branch->modifications_end - begin));
    }

    // Returns the modification map at the given `match_value`, if any.
    std::optional<ModifyMapView> Find(int match_value) const;
    bool contains(int match_value) const {
      return Find(match_value).has_value();
    }

    // Hashing, see https://abseil.io/docs/cpp/guides/hash. Consistent with the
    // hashing of the equivalent `SortedVectorMap<int, ModifyMap>`.
    template <typename H>
    friend H AbslHashValue(H h, const MatchBranchesView& view) {
      for (const auto& [match_value, map] : view) {
        h = H::combine(std::move(h), match_value, map);
      }
      return H::combine(std::move(h), view.size());
    }

   private:
    absl::Span<const MatchBranch> branches_;
    const ModifyEntry* modifications_;
  };

  // A decision node, as stored by the manager: an immutable, flat
  // representation of an (equivalent) `DecisionNodeBuilder`, see there for
  // semantics and invariants.
  //
  // CHOICE OF DATA STRUCTURE:
  // Decision nodes are the most numerous objects of the manager, and are
  // accessed in random order, so a compact representation with few pointer
  // indirections pays off: All modification maps of a node are stored
  // contiguously, in memory owned by `node_storage_`, avoiding one heap
  // allocation per map (and the associated memory overhead). The match values
  // are stored densely, so they can be searched without touching the maps.
  struct DecisionNode {
    PacketFieldHandle field;
    PacketTransformerHandle default_branch;
    uint32_t num_match_branches = 0;
    // The total number of modifications, including default modifications.
    uint32_t num_modifications = 0;
    // `num_match_branches` match branches, sorted by increasing match value.
    const MatchBranch* match_branches = nullptr;
    // `num_modifications` entries: the modification maps of the match
    // branches, in order, followed by the default modifications.
    const ModifyEntry* modifications = nullptr;

    MatchBranchesView modify_branch_by_field_match() const {
      return MatchBranchesView(
          absl::MakeConstSpan(match_branches, num_match_branches),
          modifications);
    }
    ModifyMapView default_branch_by_field_modification() const {
      const uint32_t begin =
          num_match_branches == 0
              ? 0
              : match_branches[num_match_branches - 1].modifications_end;
      return ModifyMapView(absl::MakeConstSpan(modifications + begin,
                                               num_modifications - begin));
    }

    friend bool operator==(const DecisionNode& a, const DecisionNode& b) {
      return a.field == b.field && a.default_branch == b.default_branch &&
             a.default_branch_by_field_modification() ==
                 b.default_branch_by_field_modification() &&
             MatchBranchesAreEqual(a.modify_branch_by_field_match(),
                                   b.modify_branch_by_field_match());
    }
    friend bool operator==(const DecisionNode& a,
                           const DecisionNodeBuilder& b) {
      return a.field == b.field && a.default_branch == b.default_branch &&
             a.default_branch_by_field_modification() ==
                 ModifyMapView(b.default_branch_by_field_modification) &&
             MatchBranchesAreEqual(a.modify_branch_by_field_match(),
                                   b.modify_branch_by_field_match);
    }

    // Hashing, see https://abseil.io/docs/cpp/guides/hash. Consistent with the
    // hashing of the equivalent `DecisionNodeBuilder`.
    template <typename H>
    friend H AbslHashValue(H h, const DecisionNode& node) {
      return H::combine(std::move(h), node.field, node.default_branch,
                        node.default_branch_by_field_modification(),
                        node.modify_branch_by_field_match());
    }

   private:
    // Returns true iff `left` is equal to `right`, a `MatchBranchesView` or a
    // `SortedVectorMap<int, ModifyMap>`.
    template <class Map>
    static bool MatchBranchesAreEqual(const MatchBranchesView& left,
                                      const Map& right) {
      if (left.size() != right.size()) return false;
      auto right_it = right.begin();
      for (const auto& [match_value, map] : left) {
        const auto& [right_match_value, right_map] = *right_it;
        if (match_value != right_match_value ||
            map != ModifyMapView(right_map)) {
          return false;
        }
        ++right_it;
      }
      return true;
    }
  };

  // Protect against regressions in memory layout, as it affects performance.
  static_assert(sizeof(DecisionNode) == 32);
  static_assert(alignof(DecisionNode) == 8);

  // Append-only storage for the match branches and modifications of
  // `DecisionNode`s, allocated in large blocks, providing pointer stability.
  class NodeStorage {
   public:
    // Returns uninitialized storage for `n` `T`s, or null if `n` is 0. `T`
    // must be trivially destructible, as the `T`s are never destroyed.
    template <class T>
    T* Allocate(size_t n);

   private:
    static constexpr size_t kBlockSize = 1 << 20;
    std::vector<std::unique_ptr<std::byte[]>> blocks_;
    std::byte* next_ = nullptr;
    size_t remaining_ = 0;
  };

  // A key for efficiently hashing a `PolicyProto` to a
  // `PacketTransformerHandle`. This works as a recursive hash, such that we
  // only internally compile unique messages exactly once.
  struct ProtoHashKey {
    // The `PolicyProto` oneof case.
    int policy_case;

    // The left child, if `policy_case` is a operation. In the case
    // `policy_case` is unary, e.g. Iterate, this will be the child.
    PacketTransformerHandle lhs_child;

    // The right child, if `policy_case` is a operation. In the case
    // `policy_case` is unary, e.g. Iterate, this will be defaulted.
    PacketTransformerHandle rhs_child;

    friend auto operator<=>(const ProtoHashKey& a,
                            const ProtoHashKey& b) = default;

    template <typename H>
    friend H AbslHashValue(H h, const ProtoHashKey& key) {
      return H::combine(std::move(h), key.policy_case, key.lhs_child,
                        key.rhs_child);
    }
  };

  PacketTransformerHandle NodeToTransformer(DecisionNodeBuilder&& node);

  // A rule of a prioritized table, compiled: packets in `match` are processed
  // by `action`.
  struct CompiledRule {
    PacketSetHandle match;
    PacketTransformerHandle action;
  };

  // Like `Compile`, but does not declare fields.
  PacketTransformerHandle CompileRecursively(const PolicyProto& policy);

  // If `policy` is a long cascade of prioritized rules, i.e. of the form
  //
  //   filter(m_1); a_1 + filter(!m_1); (... (filter(m_n); a_n +
  //                                          filter(!m_n); fallthrough))
  //
  // as produced e.g. by `NetkatTable`, compiles it by divide and conquer (see
  // `CompilePrioritizedRules` below) and returns the result. Otherwise, returns
  // `std::nullopt`.
  std::optional<PacketTransformerHandle> CompileIfPrioritizedRules(
      const PolicyProto& policy);

  // Returns the first-match composition of the given `rules`, in order of
  // decreasing priority, where packets matched by no rule are processed by
  // `fallthrough`, as well as the union of the matches of all rules. Requires
  // `rules` to be non-empty.
  //
  // Compiling the cascade from the inside out, rule by rule, takes quadratic
  // time, since each step rebuilds the ever-growing table compiled so far.
  // Instead, we use that
  //
  //   T(r_1, ..., r_n; f) = T(r_1, ..., r_k; 0) +
  //                         filter(!(m_1 || ... || m_k)); T(r_k+1, ..., r_n; f)
  //
  // and split the rules in half at each step, for quasi-linear time.
  std::pair<PacketTransformerHandle, PacketSetHandle> CompilePrioritizedRules(
      absl::Span<const CompiledRule> rules,
      PacketTransformerHandle fallthrough);

  // Returns the `DecisionNode` corresponding to the given
  // `PacketTransformerHandle`, or crashes if the `transformer` is
  // `Deny()` or `Accept()`.
  //
  // Unless there is a bug in the implementation of this class, this function
  // is NOT expected to be called with these special transformers that crash.
  const DecisionNode& GetNodeOrDie(PacketTransformerHandle transformer) const;

  [[nodiscard]] std::string ToString(const DecisionNode& node) const;

  // The page size of the `nodes_` vector: 64 MiB or ~ 67 MB.
  // Chosen large enough to reduce the cost of dynamic allocation, and small
  // enough to avoid excessive memory overhead.
  static constexpr size_t kPageSize = (1 << 26) / sizeof(DecisionNode);

  // Calls `f(left_node, right_node)` on two decision nodes that branch on the
  // same field and are semantically equivalent to `left` and `right`,
  // respectively, and returns the result. Nodes branching on a larger field
  // and `Accept()` are expanded as needed to align the fields.
  //
  // Requires: `left` and `right` are not `Deny()` and not both `Accept()`.
  template <class F>
  PacketTransformerHandle WithAlignedNodes(PacketTransformerHandle left,
                                           PacketTransformerHandle right,
                                           F&& f);

  // Returns the transformer gotten from `node` by replacing each of its
  // branches `b` with `f(b)`.
  template <class F>
  PacketTransformerHandle MapBranches(const DecisionNode& node, F&& f);

  // Helper functions implementing the eponymous operations on decision nodes
  // that branch on the same field.
  PacketTransformerHandle UnionNodes(const DecisionNode& left,
                                     const DecisionNode& right);
  PacketTransformerHandle SequenceNodes(const DecisionNode& left,
                                        const DecisionNode& right);
  PacketTransformerHandle DifferenceNodes(const DecisionNode& left,
                                          const DecisionNode& right);

  // Provides the maps of possible modification values to branches for packets
  // whose `node.field` has a given input value, for a sequence of values.
  // Optimized for increasing sequences of values, which are served using a
  // monotone cursor rather than repeated binary searches. Defined in the .cc.
  class MapAtValueCursor;

  // The decision nodes forming the BDD-style DAG representation of packets.
  // `PacketTransformerHandle::node_index_` indexes into this vector.
  //
  // The vector doubles as a so called "unique table", ensuring each node is
  // stored only once, and thus has a unique
  // `PacketTransformerHandle::node_index_`.
  //
  // We use a custom vector class that provides pointer stability, allowing us
  // to create new nodes while traversing the graph. The class also avoids
  // expensive relocations, and stores each node only once (rather than in both
  // a vector and a hash map).
  InternedVector<DecisionNode, kPageSize> nodes_;

  // The storage for the maps of `nodes_`.
  NodeStorage node_storage_;

  // A map of a given `PolicyProto` to a `PacketTransformerHandle`.
  //
  // This reflects a hash-consing of the proto to the already hash-consed
  // handle. This allows `Compile` to quickly deduce if a policy is new or
  // already exists.
  absl::flat_hash_map<ProtoHashKey, PacketTransformerHandle>
      transformer_by_hash_;

  // A memoization table for the `Union` operation.
  // Maps a pair of (normalized) argument handles to their computed union
  // handle.
  absl::flat_hash_map<
      std::pair<PacketTransformerHandle, PacketTransformerHandle>,
      PacketTransformerHandle>
      union_cache_;

  // A memoization table for the `Sequence` operation.
  // Maps a pair of argument handles to their computed sequence handle.
  absl::flat_hash_map<
      std::pair<PacketTransformerHandle, PacketTransformerHandle>,
      PacketTransformerHandle>
      sequence_cache_;

  // A memoization table for the `Difference` operation.
  // Maps a pair of argument handles to their computed difference handle.
  absl::flat_hash_map<
      std::pair<PacketTransformerHandle, PacketTransformerHandle>,
      PacketTransformerHandle>
      difference_cache_;

  // A memoization table for the `Iterate` operation.
  // Maps an argument handle to its computed iteration handle.
  absl::flat_hash_map<PacketTransformerHandle, PacketTransformerHandle>
      iterate_cache_;

  // A memoization table for the `FromPacketSetHandle` operation.
  // Maps a packet set handle to its corresponding packet transformer handle.
  absl::flat_hash_map<PacketSetHandle, PacketTransformerHandle>
      from_packet_set_cache_;

  // A memoization table for the `GetAllPossibleOutputPackets` operation.
  // Maps a transformer handle to its computed output packet set handle.
  absl::flat_hash_map<PacketTransformerHandle, PacketSetHandle>
      get_all_possible_outputs_cache_;

  // A memoization table for the `GetAllInputPacketsThatProduceAnyOutput`
  // operation. Maps a transformer handle to its computed input packet set
  // handle.
  absl::flat_hash_map<PacketTransformerHandle, PacketSetHandle>
      get_all_inputs_cache_;

  // INVARIANT: All `DecisionNode` fields are interned by this manager's
  // PacketFieldManager.
  PacketSetManager packet_set_manager_;

  friend class PacketTransformerManagerTestPeer;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_PACKET_TRANSFORMER_H_
