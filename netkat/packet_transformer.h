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
// Defines `PacketTransformerHandle` and its companion class
// `PacketTransformerManager` following the manager-class pattern described in
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
#include <optional>
#include <string>
#include <utility>

#include "absl/container/btree_map.h"
#include "absl/container/fixed_array.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "netkat/netkat.pb.h"
#include "netkat/packet.h"
#include "netkat/packet_field.h"
#include "netkat/packet_set.h"
#include "netkat/paged_stable_vector.h"

namespace netkat {

// A "packet transformer" is a lightweight handle (32 bits) that
// represents a record-free policy (or functions from packets to sets of output
// packets). Handles can only be created by a `PacketTransformerManager`
// object, which owns the graph-based representation of the set. The
// representation can efficiently encode typical large and even infinite sets
// seen in practice.
//
// The APIs of this object are almost entirely defined as methods of the
// companion class `PacketTransformerManager` following the
// manager-handle pattern, see `manager_handle_pattern.md`.
//
// CAUTION: Each `PacketTransformerHandle` is implicitly associated with the
// manager object that created it; using it with a different manager has
// undefined behavior.
//
// This data structure enjoys the following powerful *canonicity property*: two
// packet transformers represent the policy if and only if they have
// the same memory representation. Since the memory representation is just 32
// bits, semantic policy equality is cheap: O(1)!
//
// Compared to NetKAT policies, packet transformers have a few
// advantages:
// * Cheap to store, copy, hash, and compare: O(1)
// * Cheap to check semantic equality: O(1)
class [[nodiscard]] PacketTransformerHandle {
 public:
  // Default constructor: the Deny policy.
  PacketTransformerHandle();

  // Two packet transformers compare equal iff they represent the same
  // record-free policy (semantically). That is, two policies are equal iff they
  // are semantically equivalent when Record is replaced by Accept. Comparison
  // is O(1), thanks to interning/hash-consing.
  friend auto operator<=>(PacketTransformerHandle a,
                          PacketTransformerHandle b) = default;

  // Hashing, see https://abseil.io/docs/cpp/guides/hash.
  template <typename H>
  friend H AbslHashValue(H h, PacketTransformerHandle transformer) {
    return H::combine(std::move(h), transformer.node_index_);
  }

  // Formatting, see https://abseil.io/docs/cpp/guides/abslstringify.
  // NOTE: These functions do not produce particularly useful output. Instead,
  // use `PacketTransformerManager::ToString(transformer)` whenever
  // possible.
  template <typename Sink>
  friend void AbslStringify(Sink& sink, PacketTransformerHandle transformer) {
    absl::Format(&sink, "%s", transformer.ToString());
  }
  std::string ToString() const;

 private:
  // An index into the `nodes_` vector of the `PacketTransformerManager`
  // object associated with this `PacketTransformerHandle`. The semantics of
  // this packet transformer is entirely determined by the node
  // `nodes_[node_index_]`. The index is otherwise arbitrary and meaningless.
  //
  // We use a 32-bit index as a tradeoff between minimizing memory usage and
  // maximizing the number of `PacketTransformerHandle`s that can be created,
  // both aspects that impact how well we scale to large NetKAT models.
  uint32_t node_index_;
  explicit PacketTransformerHandle(uint32_t node_index)
      : node_index_(node_index) {}
  friend class PacketTransformerManager;
};

// Protect against regressions in the memory layout, as it affects performance.
static_assert(sizeof(PacketTransformerHandle) <= 4);

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
  PacketTransformerManager() = default;
  explicit PacketTransformerManager(PacketSetManager&& manager)
      : packet_set_manager_(std::move(manager)) {};

  // The class is move-only: not copyable, but movable.
  // `PacketSetHandles` and `PacketTransformerHandles` returned by this class
  // are not invalidated on move.
  PacketTransformerManager(const PacketTransformerManager&) = delete;
  PacketTransformerManager& operator=(const PacketTransformerManager&) = delete;
  PacketTransformerManager(PacketTransformerManager&&) = default;
  PacketTransformerManager& operator=(PacketTransformerManager&&) = default;

  // Returns the `PacketSetManager` used by this object to compile
  // predicates.
  PacketSetManager& GetPacketSetManager() { return packet_set_manager_; }

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
  // CHOICE OF DATA STRUCTURE:
  // Logically, a node is a map of maps, match value -> (modify value ->
  // branch), plus a map of default modifications, modify value -> branch. We
  // store all of this in two flat, sorted arrays to optimize memory layout
  // (contiguous, compact, flat), exploiting that nodes are immutable once
  // interned. This makes the hashing, equality comparison, and copying done
  // by the unique table (`transformer_by_node_`) cheap scans over contiguous
  // memory, and shrinks node storage. A mutation-friendly map-based
  // representation exists separately as `DecisionNodeBuilder`, used only
  // transiently while constructing nodes.
  struct DecisionNode {
    // A single "set field to `first`, then continue with `second`" entry.
    using ModifyEntry = std::pair<int, PacketTransformerHandle>;

    // The packet field whose value this decision node branches on.
    //
    // INVARIANTS:
    // * Strictly smaller (`<`) than the fields of other decision nodes
    //   reachable from this node.
    // * Interned by `field_manager_`.
    PacketFieldHandle field;

    // The "leave field unmodified" consequent of the "else" branch.
    PacketTransformerHandle default_branch;

    // The "if" branches of the decision node. `matches[i]` is a
    // (match_value, end_offset) pair encoding "if (field == match_value) then
    // non-deterministically choose a ModifyEntry from `MatchModifies(i)`,
    // modify field to its modify value and follow its branch". The end offsets
    // delimit the per-match ranges of `modifies`: `MatchModifies(i)` is
    // `modifies[matches[i-1].end_offset, matches[i].end_offset)`.
    // A match with an empty ModifyEntry range denies all packets whose field
    // equals its match value.
    //
    // INVARIANTS:
    // 1. Maintained by `NodeToTransformer`: `matches` and `DefaultModifies()`
    //    are not both empty. (If they were both empty, the decision node gets
    //    replaced by `default_branch`.)
    // 2. For every entry (v', b) in `MatchModifies(i)` with match value v,
    //    either v == v' or b is not Deny.
    // 3. Sorted by strictly increasing match value; end offsets are
    //    non-decreasing and bounded by `modifies.size()`.
    absl::FixedArray<std::pair<int, uint32_t>,
                     /*use_heap_allocation_above_size=*/0>
        matches;

    // The ModifyEntry ranges of all matches, in match order, followed by the
    // "else" modifications (see `DefaultModifies()`): entries encoding "if no
    // match value applies, non-deterministically set field -> entry.first and
    // follow entry.second".
    //
    // INVARIANTS:
    // 1. Each per-match range and the default range is sorted by strictly
    //    increasing modify value, without duplicates.
    // 2. For every entry (v, b) in `DefaultModifies()`, b is not Deny.
    absl::FixedArray<ModifyEntry, /*use_heap_allocation_above_size=*/0>
        modifies;

    // The ModifyEntry range of `matches[i]`.
    absl::Span<const ModifyEntry> MatchModifies(size_t i) const {
      uint32_t begin = i == 0 ? 0 : matches[i - 1].second;
      return absl::MakeConstSpan(modifies.data() + begin,
                                 matches[i].second - begin);
    }

    // A single "if (field == value)" branch: the match value together with
    // its ModifyEntry range.
    struct Match {
      int value;
      absl::Span<const ModifyEntry> modifies;
    };

    // Iterates the "if" branches as `Match` views, in order of strictly
    // increasing match value. Allows range-for loops over the branches
    // without manual index bookkeeping.
    class MatchIterator {
     public:
      MatchIterator(const DecisionNode* node, size_t index)
          : node_(node), index_(index) {}
      Match operator*() const {
        return {node_->matches[index_].first, node_->MatchModifies(index_)};
      }
      MatchIterator& operator++() {
        ++index_;
        return *this;
      }
      friend bool operator==(const MatchIterator& a,
                             const MatchIterator& b) = default;

     private:
      const DecisionNode* node_;
      size_t index_;
    };
    struct MatchRange {
      const DecisionNode* node;
      MatchIterator begin() const { return {node, 0}; }
      MatchIterator end() const { return {node, node->matches.size()}; }
    };
    MatchRange Matches() const { return {this}; }

    // The ModifyEntry range of the "else" branch.
    absl::Span<const ModifyEntry> DefaultModifies() const {
      uint32_t begin = matches.empty() ? 0 : matches.back().second;
      return absl::MakeConstSpan(modifies.data() + begin,
                                 modifies.size() - begin);
    }

    // Returns the index into `matches` with the given match value, if any.
    std::optional<size_t> FindMatch(int match_value) const {
      auto it = std::lower_bound(
          matches.begin(), matches.end(), match_value,
          [](const auto& match, int value) { return match.first < value; });
      if (it == matches.end() || it->first != match_value) return std::nullopt;
      return it - matches.begin();
    }

    // Returns true iff `entries` (sorted by modify value) contains an entry
    // with the given modify value.
    static bool ContainsModifyValue(absl::Span<const ModifyEntry> entries,
                                    int modify_value) {
      auto it = std::lower_bound(entries.begin(), entries.end(), modify_value,
                                 [](const ModifyEntry& entry, int value) {
                                   return entry.first < value;
                                 });
      return it != entries.end() && it->first == modify_value;
    }

    friend auto operator<=>(const DecisionNode& a,
                            const DecisionNode& b) = default;

    // NOTE: Hashing is deliberately NOT defined on this struct. The unique
    // table must hash flat nodes and `DecisionNodeBuilder`s identically, so
    // there is a single hash definition for both: `NodeHash`.
  };

  // Protect against regressions in memory layout, as it affects performance.
  static_assert(sizeof(DecisionNode) == 40);
  static_assert(alignof(DecisionNode) == 8);

  // A mutable, map-based representation of a `DecisionNode`, used only
  // transiently while constructing nodes (by the combinators and the golden
  // test runner's canonicalizing copy). Finished builders are canonicalized,
  // flattened into `DecisionNode`s, and interned by `NodeToTransformer`. The
  // members mirror `DecisionNode`; see there for semantics and invariants.
  struct DecisionNodeBuilder {
    PacketFieldHandle field;

    // Match value -> (modify value -> branch). See `DecisionNode::matches`.
    absl::btree_map<int, absl::btree_map<int, PacketTransformerHandle>>
        modify_branch_by_field_match;

    // Modify value -> branch. See `DecisionNode::DefaultModifies()`.
    absl::btree_map<int, PacketTransformerHandle>
        default_branch_by_field_modification;
    PacketTransformerHandle default_branch;
  };

  // Invokes `match(match_value, end_offset)` for each match header and then
  // `modify(modify_value, branch)` for each modify entry of the given node or
  // builder, in the canonical flat order of `DecisionNode::matches` and
  // `DecisionNode::modifies`. Stops and returns false as soon as a callback
  // returns false; returns true if all elements were visited.
  //
  // This is the single definition of a node's flat element sequence:
  // `Flatten`, `NodeHash`, and `NodeEq` are all written against it, which
  // keeps the two node representations consistent by construction.
  template <typename MatchFn, typename ModifyFn>
  static bool ForEachFlatEntry(const DecisionNode& node, MatchFn&& match,
                               ModifyFn&& modify);
  template <typename MatchFn, typename ModifyFn>
  static bool ForEachFlatEntry(const DecisionNodeBuilder& builder,
                               MatchFn&& match, ModifyFn&& modify);

  // Transparent hash and equality functors for the unique table
  // (`transformer_by_node_`), which is keyed by stable `DecisionNode*`
  // pointers into `nodes_` (so each node is stored only once). Lookups work
  // directly with a `DecisionNodeBuilder` — without flattening it — keeping
  // the hot path of `NodeToTransformer`, re-deriving a node that already
  // exists, free of allocations; flattening only happens for genuinely new
  // nodes. Both functors are stateless: keys are pointers, and the pages
  // holding the nodes are stable across moves of the manager.
  //
  // INVARIANT: A builder and its flattened node are treated identically:
  // `NodeHash()(b) == NodeHash()(&Flatten(b))` and `NodeEq()(&Flatten(b), b)`.
  // Maintained by defining both functors in terms of `ForEachFlatEntry`;
  // checked by `CheckInternalInvariants`.
  struct NodeHash {
    using is_transparent = void;
    size_t operator()(const DecisionNode* node) const;
    size_t operator()(const DecisionNodeBuilder& builder) const;

   private:
    // Adapter implementing both overloads: hashes the canonical flat element
    // sequence (via `ForEachFlatEntry`) in a single streaming pass, so flat
    // nodes and builders with the same logical content hash identically.
    template <typename NodeOrBuilder>
    struct FlatSequenceView {
      const NodeOrBuilder& node;

      // Hashing, see https://abseil.io/docs/cpp/guides/hash.
      template <typename H>
      friend H AbslHashValue(H h, const FlatSequenceView& view) {
        size_t num_matches = 0;
        size_t num_modifies = 0;
        h = H::combine(std::move(h), view.node.field,
                       view.node.default_branch);
        ForEachFlatEntry(
            view.node,
            [&](int match_value, uint32_t end_offset) {
              h = H::combine(std::move(h), match_value, end_offset);
              ++num_matches;
              return true;
            },
            [&](int modify_value, PacketTransformerHandle branch) {
              h = H::combine(std::move(h), modify_value, branch);
              ++num_modifies;
              return true;
            });
        return H::combine(std::move(h), num_matches, num_modifies);
      }
    };
  };
  struct NodeEq {
    using is_transparent = void;
    bool operator()(const DecisionNode* a, const DecisionNode* b) const {
      return a == b || *a == *b;
    }
    bool operator()(const DecisionNode* a, const DecisionNodeBuilder& b) const;
    bool operator()(const DecisionNodeBuilder& a, const DecisionNode* b) const {
      return (*this)(b, a);
    }
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

  // Shared implementation of `Union` and `Difference`, which differ only in
  // their base cases and the operation applied to corresponding branches:
  // combines `left` and `right` by applying `combiner` — which must be the
  // handle-level operation itself, e.g. `Union` — to corresponding branches.
  // Both operands must be Accept or decision nodes (i.e., the base cases must
  // already have been handled).
  template <typename Combiner>
  PacketTransformerHandle PointwiseCombine(PacketTransformerHandle left,
                                           PacketTransformerHandle right,
                                           Combiner&& combiner);

  // Conversions between the interned (flat) and builder (map-based)
  // representations of decision nodes. `ToBuilder` is only used by
  // `CheckInternalInvariants`, to validate `NodeHash`/`NodeEq` consistency.
  static DecisionNode Flatten(DecisionNodeBuilder&& builder);
  static DecisionNodeBuilder ToBuilder(const DecisionNode& node);

  // The decision nodes forming the BDD-style DAG representation of packets.
  // `PacketTransformerHandle::node_index_` indexes into this vector.
  //
  // We use a custom vector class that provides pointer stability, allowing us
  // to create new nodes while traversing the graph. The class also avoids
  // expensive relocations.
  PagedStableVector<DecisionNode, kPageSize> nodes_;

  // A so called "unique table" to ensure each node is only added to `nodes_`
  // once, and thus has a unique `PacketTransformerHandle::node_index`.
  // Keyed by pointers into `nodes_` (stable, see `PagedStableVector`), so
  // nodes are not stored twice. The transparent `NodeHash`/`NodeEq` functors
  // support lookup by `DecisionNodeBuilder` without flattening, see their
  // documentation.
  //
  // INVARIANT: `transformer_by_node_[p] = s` iff `p == &nodes_[s.node_index_]`.
  absl::flat_hash_map<const DecisionNode*, PacketTransformerHandle, NodeHash,
                      NodeEq>
      transformer_by_node_;

  // A map of a given `PolicyProto` to a `PacketTransformerHandle`.
  //
  // This reflects a hash-consing of the proto to the already hash-consed
  // handle. This allows `Compile` to quickly deduce if a policy is new or
  // already exists.
  absl::flat_hash_map<ProtoHashKey, PacketTransformerHandle>
      transformer_by_hash_;

  // INVARIANT: All `DecisionNode` fields are interned by this manager's
  // PacketFieldManager.
  PacketSetManager packet_set_manager_;

  friend class PacketTransformerManagerTestPeer;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_PACKET_TRANSFORMER_H_
