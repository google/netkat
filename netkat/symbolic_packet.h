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
//
// -----------------------------------------------------------------------------
// File: symbolic_packet.h
// -----------------------------------------------------------------------------
//
// Defines `SymbolicPacket` and its companion class `SymbolicPacketManager`.
// Together, they provide a compact and efficient representation of large packet
// sets, exploiting structural properties that packet sets seen in practice
// typically exhibit.
//
// This is a low level library designed for maximum efficiency, rather than a
// high level library designed for safety and convenience.
//
// The implementation is based on the paper "KATch: A Fast Symbolic Verifier for
// NetKAT" and is closely related to Binary Decision Diagrams (BDDs), see
// https://en.wikipedia.org/wiki/Binary_decision_diagram.
//
// -----------------------------------------------------------------------------
// Why have a manager class?
// -----------------------------------------------------------------------------
//
// The APIs for creating, manipulating, and inspecting `SymbolicPacket`s are all
// defined as methods of the `SymbolicPacketManager` class. But why?
//
// TL;DR, all data associated with `SymbolicPacket`s is stored by the manager
// class; `SymbolicPacket` itself is just a lightweight (32-bit) handle. This
// design pattern is motivated by computational and memory efficiency, and is
// standard for BDD-based libraries.
//
// The manager object acts as an "arena" that owns and manages all memory
// associated with `SymbolicPacket`s, enhancing data locality and sharing. This
// technique is known as interning or hash-consing and is similar to the
// flyweight pattern. It has a long list of benefits, most importantly:
//
// * Canonicity: Can guarantee that semantically identical `SymbolicPacket` are
//   represented by the same handle, making semantic `SymbolicPacket` comparison
//   O(1) (just comparing two integers)!
//
// * Memory efficiency: The graph structures used to encode symbolic packets are
//   maximally shared across all packets, avoiding redundant copies of isomorph
//   subgraphs.
//
// * Cache friendliness: Storing all data in contiguous arrays within the
//   manager improves data locality and thus cache utilization.
//
// * Light representation: Since `SymbolicPacket`s are simply integers in
//   memory, they are cheap to store, copy, compare, and hash.
//
// * Memoization: Thanks to canonicity and lightness of representation,
//   computations on `SymbolicPacket`s can be memoized very efficiently in the
//   manager object. For example, a binary function of type
//
//     SymbolicPacket, SymbolicPacket -> SymbolicPacket
//
//   can be memoized as a lookup table of type (int, int) -> int.
//
// -----------------------------------------------------------------------------
//
// CAUTION: This implementation has NOT yet been optimized for performance.
// See the TODOs in the cc file for low hanging fruit. Beyond known
// inefficiencies, performance can likely be improved significantly further
// through profiling and benchmarking. Also see "Efficient Implementation of a
// BDD Package" for standard techniques to improve performance.

#ifndef GOOGLE_NETKAT_NETKAT_SYMBOLIC_PACKET_H_
#define GOOGLE_NETKAT_NETKAT_SYMBOLIC_PACKET_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/container/fixed_array.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "netkat/evaluator.h"
#include "netkat/interned_field.h"
#include "netkat/netkat.pb.h"
#include "netkat/paged_stable_vector.h"

namespace netkat {

// A "symbolic packet" is a lightweight handle (32 bits)  that represents a set
// of packets. Handles can only be created by a `SymbolicPacketManager` object,
// which owns the graph-based representation of the set. The representation can
// efficiently encode typical large and even infinite sets seen in practice.
//
// The APIs of this object are almost entirely defined as methods of the
// companion class `SymbolicPacketManager`. See the section "Why have a maanger
// class?" at the top of the file to learn why.
//
// CAUTION: Each `SymbolicPacket` is implicitly associated with the manager
// object that created it; using it with a different manager has undefined
// behavior.
//
// This data structure enjoys the following powerful *canonicity property*: two
// symbolic packets represent the same set if and only if they have the same
// memory representation. Since the memory representation is just 32 bits,
// semantic set equality is cheap: O(1)!
//
// Compared to NetKAT predicates, which semantically also represent sets of
// packets, symbolic packets have a few advantages:
// * Cheap to store, copy, hash, and compare: O(1)
// * Cheap to check set equality: O(1)
// * Cheap to check set membership and set containment: O(# packet fields)
class [[nodiscard]] SymbolicPacket {
 public:
  // Default constructor: the empty set of packets.
  SymbolicPacket();

  // Two symbolic packets compare equal iff they represent the same set of
  // concrete packets. Comparison is O(1), thanks to interning/hash-consing.
  friend auto operator<=>(SymbolicPacket a, SymbolicPacket b) = default;

  // Hashing, see https://abseil.io/docs/cpp/guides/hash.
  template <typename H>
  friend H AbslHashValue(H h, SymbolicPacket packet) {
    return H::combine(std::move(h), packet.node_index_);
  }

  // Formatting, see https://abseil.io/docs/cpp/guides/abslstringify.
  template <typename Sink>
  friend void AbslStringify(Sink& sink, SymbolicPacket packet) {
    absl::Format(&sink, "%s", packet.ToString());
  }
  std::string ToString() const;

 private:
  // An index into the `nodes_` vector of the `SymbolicPacketManager` object
  // associated with this `SymbolicPacket`. The semantics of this symbolic
  // packet is entirely determined by the node `nodes_[node_index_]`. The index
  // is otherwise arbitrary and meaningless.
  //
  // We use a 32-bit index as a tradeoff between minimizing memory usage and
  // maximizing the number of `SymbolicPacket`s that can be created, both
  // aspects that impact how well we scale to large NetKAT models. We expect
  // millions, but not billions, of symbolic packets in practice, and 2^32 ~= 4
  // billion.
  uint32_t node_index_;
  explicit SymbolicPacket(uint32_t node_index) : node_index_(node_index) {}
  friend class SymbolicPacketManager;
};

// Protect against regressions in the memory layout, as it affects performance.
static_assert(sizeof(SymbolicPacket) <= 4);

// An "arena" in which `SymbolicPacket`s can be created and manipulated.
//
// This class defines the majority of operations on `SymbolicPacket`s and owns
// all the memory associated with the `SymbolicPacket`s returned by the class's
// methods.
//
// CAUTION: Using a `SymbolicPacket` returned by one `SymbolicPacketManager`
// object with a different manager is undefined behavior.
class SymbolicPacketManager {
 public:
  SymbolicPacketManager() = default;

  // The class is move-only: not copyable, but movable.
  SymbolicPacketManager(const SymbolicPacketManager&) = delete;
  SymbolicPacketManager& operator=(const SymbolicPacketManager&) = delete;
  SymbolicPacketManager(SymbolicPacketManager&&) = default;
  SymbolicPacketManager& operator=(SymbolicPacketManager&&) = default;

  // Returns true iff this symbolic packet represents the empty set of packets.
  bool IsEmptySet(SymbolicPacket packet) const;

  // Returns true iff this symbolic packet represents the set of all packets.
  bool IsFullSet(SymbolicPacket packet) const;

  // Returns true if the set represented by `symbolic_packet` contains the given
  // `concrete_packet`, or false otherwise.
  bool Contains(SymbolicPacket symbolic_packet,
                const Packet& concrete_packet) const;

  // Compiles the given `PredicateProto` into a `SymbolicPacket` that
  // represents the set of packets satisfying the predicate.
  SymbolicPacket Compile(const PredicateProto& pred);

  // The symbolic packet representing the empty set of packets.
  SymbolicPacket EmptySet() const;

  // The symbolic packet representing the set of all packets.
  SymbolicPacket FullSet() const;

  // Returns the set of packets whose `field` is equal to `value`.
  SymbolicPacket Match(absl::string_view field, int value);

  // Returns the set of packets that are in the `left` *AND* in the `right` set.
  // Also known as set intersection.
  SymbolicPacket And(SymbolicPacket left, SymbolicPacket right);

  // Returns the set of packets that are in the `left` *OR* in the `right` set.
  // Also known as set union.
  SymbolicPacket Or(SymbolicPacket left, SymbolicPacket right);

  // Returns the set of packets that are *NOT* in the given set.
  // Also known as set complement.
  SymbolicPacket Not(SymbolicPacket negand);

  // Dynamically checks all class invariants. Exposed for testing only.
  absl::Status CheckInternalInvariants() const;

  // TODO(smolkaj): There are many additional operations supported by this data
  // structure, but not currently implemented. Add them as needed. Examples:
  // * subset - is one set a subset of another?
  // * witness - given a (non-empty) set, return one (or n) elements from the
  //   set.
  // * sample - return a member from the set uniformly at random.

 private:
  // Internally, this class represents symbolic packets (and thus packet sets)
  // as nodes in a directed acyclic graph (DAG). Each node branches based on the
  // value of a single packet field, and each branch points to another
  // symbolic packet, which in turn is either the full/empty set, or represented
  // by another node in the graph.
  //
  // The graph is "ordered", "reduced", and contains no "isomorphic subgraphs":
  //
  // * Ordered: Along each path through the graph, fields increase strictly
  //   monotonically (with respect to `<` defined on `InternedField`s).
  // * Reduced: Intutively, there exist no redundant branches or nodes.
  //   Invariants 1 and 2 on `branch_by_field_value` formalize this intuition.
  // * No isomorphic subgraphs: Nodes are interned by the class, ensuring that
  //   structurally identical nodes are guaranteed to be stored by the class
  //   only once. Together with the other two properties, this implies that each
  //   node stored by the class represents a unique set of packets.
  //
  // This representation is closely related to Binary Decision Diagrams (BDDs),
  // see https://en.wikipedia.org/wiki/Binary_decision_diagram. This variant of
  // BDDs is described in the paper "KATch: A Fast Symbolic Verifier for
  // NetKAT".

  // A decision node in the symbolic packet DAG. The node branches on the value
  // of a single `field`, and (the consequent of) each branch is a
  // `SymbolicPacket` corresponding to either another decision node or the
  // full/empty set. Semantically, represents a cascading conditional of the
  // form:
  //
  //   if      (field == value_1) then branch_1
  //   else if (field == value_2) then branch_2
  //   ...
  //   else default_branch
  struct DecisionNode {
    // The packet field whose value this decision node branches on.
    //
    // INVARIANTS:
    // * Strictly smaller (`<`) than the fields of other decision nodes
    //   reachable from this node.
    // * Interned by `field_manager_`.
    InternedField field;

    // The consequent of the "else" branch of this decision node.
    SymbolicPacket default_branch;

    // The "if" branches of the decision node, "keyed" by the value they branch
    // on. Each element of the array is a (value, branch)-pair encoding
    // "if (field == value) then branch".
    //
    // CHOICE OF DATA STRUCTURE:
    // Logically this is a value -> branch map, but we store it as a fixed-size
    // array to optimize memory layout (contiguous, compact, flat), exploiting
    // the following observations:
    // * Nodes are not mutated after creation, so we can use a fixed-size
    //   container and save some bytes relative to dynamically-sized containers.
    // * None of the set combinator implementations (`And`, `Or`, `Not`) require
    //   fast lookups, so we can avoid the overhead of lookup-optimized data
    //   structures like hash maps.
    //
    // INVARIANTS:
    // 1. Maintained by `NodeToPacket`: `branch_by_field_value` is non-empty.
    //    (If it is empty, the decision node gets replaced by `default_branch`.)
    // 2. Each branch is != `default_branch`.
    //    (If the branch is == `default_branch`, it must be omitted.)
    // 3. The pairs are ordered by strictly increasing value. No two
    //    branches have the same value.
    absl::FixedArray<std::pair<int, SymbolicPacket>,
                     /*use_heap_allocation_above_size=*/0>
        branch_by_field_value;

    // Protect against regressions in memory layout, as it affects performance.
    static_assert(sizeof(branch_by_field_value) == 16);

    friend auto operator<=>(const DecisionNode& a,
                            const DecisionNode& b) = default;

    // Hashing, see https://abseil.io/docs/cpp/guides/hash.
    template <typename H>
    friend H AbslHashValue(H h, const DecisionNode& node) {
      return H::combine(std::move(h), node.field, node.default_branch,
                        node.branch_by_field_value);
    }
  };

  // Protect against regressions in memory layout, as it affects performance.
  static_assert(sizeof(DecisionNode) == 24);
  static_assert(alignof(DecisionNode) == 8);

  SymbolicPacket NodeToPacket(DecisionNode&& node);

  // Returns the `DecisionNode` corresponding to the given `SymbolicPacket`, or
  // crashes if the `packet` is `EmptySet()` or `FullSet()`.
  //
  // Unless there is a bug in the implementation of this class, this function
  // is NOT expected to be called with these special packets that crash.
  const DecisionNode& GetNodeOrDie(SymbolicPacket packet) const;

  // The page size of the `nodes_` vector: 64 MiB or ~ 67 MB.
  // Chosen large enough to reduce the cost of dynamic allocation, and small
  // enough to avoid excessive memory overhead.
  static constexpr size_t kPageSize = (1 << 26) / sizeof(DecisionNode);

  // The decision nodes forming the BDD-style DAG representation of symbolic
  // packets. `SymbolicPacket::node_index_` indexes into this vector.
  //
  // We use a custom vector class that provides pointer stability, allowing us
  // to create new nodes while traversing the graph (e.g. during operations like
  // `And`, `Or`, `Not`). The class also avoids expensive relocations.
  PagedStableVector<DecisionNode, kPageSize> nodes_;

  // A so called "unique table" to ensure each node is only added to `nodes_`
  // once, and thus has a unique `SymbolicPacket::node_index`.
  //
  // INVARIANT: `packet_by_node_[n] = s` iff `nodes_[s.node_index_] == n`.
  absl::flat_hash_map<DecisionNode, SymbolicPacket> packet_by_node_;

  // INVARIANT: All `DecisionNode` fields are interned by this manager.
  InternedFieldManager field_manager_;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_SYMBOLIC_PACKET_H_
