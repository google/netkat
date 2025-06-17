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

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/container/btree_map.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "netkat/evaluator.h"
#include "netkat/netkat.pb.h"
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

  // TODO(dilo): Describe Push and Pull functions.
  // WARNING: Unimplemented and currently crashes.
  PacketSetHandle Push(PacketSetHandle packet_set,
                       PacketTransformerHandle transformer) const = delete;
  PacketSetHandle Pull(PacketTransformerHandle transformer,
                       PacketSetHandle packet_set) const = delete;

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
                                     PacketTransformerHandle right) = delete;

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
  struct DecisionNode {
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
    absl::btree_map<int, absl::btree_map<int, PacketTransformerHandle>>
        modify_branch_by_field_match;

    // The "else" branch of this decision node, "keyed" by the value they modify
    // the field to (or not keyed at all for the `default_branch`).
    //
    // INVARIANTS:
    // 1. For every v and b such that (v,b) is in
    //    `default_branch_by_field_modification`, b is not Deny.
    absl::btree_map<int, PacketTransformerHandle>
        default_branch_by_field_modification;
    PacketTransformerHandle default_branch;

    // Protect against regressions in memory layout, as it affects performance.
    static_assert(sizeof(modify_branch_by_field_match) == 24);
    static_assert(sizeof(default_branch_by_field_modification) == 24);

    friend auto operator<=>(const DecisionNode& a,
                            const DecisionNode& b) = default;

    // Hashing, see https://abseil.io/docs/cpp/guides/hash.
    template <typename H>
    friend H AbslHashValue(H h, const DecisionNode& node) {
      return H::combine(std::move(h), node.field, node.default_branch,
                        node.default_branch_by_field_modification,
                        node.modify_branch_by_field_match);
    }
  };

  // Protect against regressions in memory layout, as it affects performance.
  // TODO(dilo): Is this still important with this simpler data structure, or
  // should we remove it until we optimize?
  static_assert(sizeof(DecisionNode) == 64);
  static_assert(alignof(DecisionNode) == 8);

  PacketTransformerHandle NodeToTransformer(DecisionNode&& node);

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

  // Helper functions to deal with DecisionNodes directly.
  // TODO(dilo): Is there a convenient way to either avoid these or avoid making
  // copies of the nodes?
  PacketTransformerHandle Union(DecisionNode left, DecisionNode right);
  PacketTransformerHandle Sequence(DecisionNode left, DecisionNode right);

  // Internal helper function to get a map of possible modification values to
  // branches for a given input value at `node`.
  absl::btree_map<int, PacketTransformerHandle> GetMapAtValue(
      const DecisionNode& node, int value);

  // The decision nodes forming the BDD-style DAG representation of packets.
  // `PacketTransformerHandle::node_index_` indexes into this vector.
  //
  // We use a custom vector class that provides pointer stability, allowing us
  // to create new nodes while traversing the graph. The class also avoids
  // expensive relocations.
  PagedStableVector<DecisionNode, kPageSize> nodes_;

  // A so called "unique table" to ensure each node is only added to `nodes_`
  // once, and thus has a unique `PacketTransformerHandle::node_index`.
  //
  // INVARIANT: `transformer_by_node_[n] = s` iff `nodes_[s.node_index_] == n`.
  absl::flat_hash_map<DecisionNode, PacketTransformerHandle>
      transformer_by_node_;

  // INVARIANT: All `DecisionNode` fields are interned by this manager's
  // PacketFieldManager.
  PacketSetManager packet_set_manager_;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_PACKET_TRANSFORMER_H_
