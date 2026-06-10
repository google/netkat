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
// File: packet_set.h
// -----------------------------------------------------------------------------
//
// Defines `PacketSetHandle` and its companion class `PacketSetManager`
// following the manager-handle pattern described in
// `manager_handle_pattern.md`. Together, they provide an often compact and
// efficient representation of large and even infinite packet sets, exploiting
// structural properties that packet sets seen in practice typically exhibit.
//
// Compared to NetKAT predicates, which semantically also represent sets of
// packets, tbis data structure has a few advantages:
// * Cheap to store, copy, hash, and compare: O(1)
// * Cheap to check set equality: O(1)
// * Cheap to check set membership and set containment: O(# packet fields)
//
// This is a low level library designed for maximum efficiency, rather than a
// high level library designed for safety and convenience.
//
// The implementation is based on the paper "KATch: A Fast Symbolic Verifier for
// NetKAT" and is closely related to Binary Decision Diagrams (BDDs), see
// https://en.wikipedia.org/wiki/Binary_decision_diagram.
//
// CAUTION: This implementation has NOT yet been optimized for performance.
// See the TODOs in the cc file for low hanging fruit. Beyond known
// inefficiencies, performance can likely be improved significantly further
// through profiling and benchmarking. Also see "Efficient Implementation of a
// BDD Package" for standard techniques to improve performance.

#ifndef GOOGLE_NETKAT_NETKAT_PACKET_SET_H_
#define GOOGLE_NETKAT_NETKAT_PACKET_SET_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/fixed_array.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/hash/hash.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "netkat/netkat.pb.h"
#include "netkat/packet.h"
#include "netkat/packet_field.h"
#include "netkat/paged_stable_vector.h"

namespace netkat {

// A lightweight handle (32 bits) representing a set of packets. The
// representation can efficiently encode typical large and even infinite sets
// seen in practice.
//
// The APIs of this object are almost entirely defined as methods of the
// companion class `PacketSetManager`, following the manager-handle pattern
// described in `manager_handle_pattern.md`.
//
// CAUTION: Each `PacketSetHandle` is implicitly associated with the manager
// object that created it; using it with a different manager has undefined
// behavior.
//
// This data structure enjoys the following powerful *canonicity property*: two
// handles represent the same set if and only if they have the same memory
// representation. Since the memory representation is just 32 bits, semantic set
// equality is cheap: O(1)!
class [[nodiscard]] PacketSetHandle {
 public:
  // Default constructor: the empty set of packets.
  PacketSetHandle();

  // Two packet set handles compare equal iff they represent the same set of
  // concrete packets. Comparison is O(1), thanks to interning/hash-consing.
  friend auto operator<=>(PacketSetHandle a, PacketSetHandle b) = default;

  // Hashing, see https://abseil.io/docs/cpp/guides/hash.
  template <typename H>
  friend H AbslHashValue(H h, PacketSetHandle packet_set) {
    return H::combine(std::move(h), packet_set.bits_);
  }

  // Formatting, see https://abseil.io/docs/cpp/guides/abslstringify.
  // NOTE: These functions do not produce particularly useful output. Instead,
  // use `PacketSetManager::ToString(packet_set)` whenever possible.
  template <typename Sink>
  friend void AbslStringify(Sink& sink, PacketSetHandle packet_set) {
    absl::Format(&sink, "%s", packet_set.ToString());
  }
  std::string ToString() const;

 private:
  // The location of the decision node defining the semantics of this packet
  // set, packed into 32 bits: the top `kFieldBits` bits hold the index of the
  // packet field the node branches on (`kSentinelFieldIndex` for the sentinel
  // handles representing the empty/full set), and the bottom `kSlotBits` bits
  // hold the node's slot in the `PacketSetManager`'s arena for that field
  // (`nodes_by_field_`). The location is otherwise arbitrary and meaningless.
  //
  // Packing the field into the handle makes the field of a node available
  // without loading the node from memory, which operations like `And` consult
  // on every recursive step (this variant of BDDs orders nodes by field along
  // every path through the node graph).
  //
  // We use 32 bits total as a tradeoff between minimizing memory usage and
  // maximizing the number of `PacketSetHandle`s that can be created, both
  // aspects that impact how well we scale to large NetKAT models. The
  // field/slot split is a further tradeoff between the number of supported
  // fields (2^10 - 1 ~= 1k) and the number of supported decision nodes per
  // field (2^22 ~= 4M); both bounds are enforced at node-creation time.
  static constexpr uint32_t kSlotBits = 22;
  static constexpr uint32_t kFieldBits = 32 - kSlotBits;
  static constexpr uint32_t kMaxSlotsPerField = uint32_t{1} << kSlotBits;
  static constexpr uint32_t kSentinelFieldIndex =
      (uint32_t{1} << kFieldBits) - 1;

  uint32_t bits_;
  explicit PacketSetHandle(uint32_t bits) : bits_(bits) {}
  PacketSetHandle(uint32_t field_index, uint32_t slot)
      : bits_((field_index << kSlotBits) | slot) {}
  uint32_t field_index() const { return bits_ >> kSlotBits; }
  uint32_t slot() const { return bits_ & (kMaxSlotsPerField - 1); }
  friend class PacketSetManager;
};

// Protect against regressions in the memory layout, as it affects performance.
static_assert(sizeof(PacketSetHandle) <= 4);

// An "arena" in which `PacketSetHandle`s can be created and manipulated
// (following the manager-handle pattern, see `manager_handle_pattern.md`).
//
// This class defines the majority of operations on `PacketSetHandle`s and owns
// all the memory associated with the `PacketSetHandle`s returned by the class's
// methods.
//
// CAUTION: Using a `PacketSetHandle` returned by one `PacketSetManager`
// object with a different manager is undefined behavior.
//
// TODO(b/398303840): Persistent use of an `PacketSetManager` object can
// incur unbounded memory growth. Consider adding some garbage collection
// mechanism.
class PacketSetManager {
 public:
  PacketSetManager() = default;

  // The class is move-only: not copyable, but movable.
  // Moves are implemented manually (in the cc file) because the unique tables
  // reference `nodes_` through `nodes_location_`, which must be repointed at
  // the new `nodes_` member on move.
  PacketSetManager(const PacketSetManager&) = delete;
  PacketSetManager& operator=(const PacketSetManager&) = delete;
  PacketSetManager(PacketSetManager&&);
  PacketSetManager& operator=(PacketSetManager&&);

  // Returns true iff this packet set represents the empty set of packets.
  bool IsEmptySet(PacketSetHandle packet_set) const;

  // Returns true iff this packet set represents the set of all packets.
  bool IsFullSet(PacketSetHandle packet_set) const;

  // Returns true if the set represented by `packet_set` contains the given
  // `packet`, or false otherwise.
  bool Contains(PacketSetHandle packet_set, const Packet& packet) const;

  // Returns a dot string representation of the given `packet_set`.
  std::string ToDot(PacketSetHandle packet_set) const;

  // Compiles the given `PredicateProto` into a `PacketSetHandle` that
  // represents the set of packets satisfying the predicate.
  PacketSetHandle Compile(const PredicateProto& pred);

  // The packet set representing the empty set of packets.
  PacketSetHandle EmptySet() const;

  // The packet set representing the set of all packets.
  PacketSetHandle FullSet() const;

  // Returns the set of packets whose `field` is equal to `value`.
  PacketSetHandle Match(absl::string_view field, int value);

  // Returns the set of packets that are in the `left` *AND* in the `right` set.
  // Also known as set intersection.
  PacketSetHandle And(PacketSetHandle left, PacketSetHandle right);

  // Returns the set of packets that are in the `left` *OR* in the `right` set.
  // Also known as set union.
  PacketSetHandle Or(PacketSetHandle left, PacketSetHandle right);

  // Returns the set of packets that are *NOT* in the given set.
  // Also known as set complement.
  PacketSetHandle Not(PacketSetHandle negand);

  // Returns the set of packets that are in either in the `left` or the `right`
  // set, but not in both. Also known as symmetric set difference.
  PacketSetHandle Xor(PacketSetHandle left, PacketSetHandle right);

  // A concrete packet is in `Exists(field, packet_set)` iff setting `field` to
  // any other value will make it a member of the input `set`.
  PacketSetHandle Exists(absl::string_view field, PacketSetHandle packet);

  // Returns a human-readable string representation of the given `packet`,
  // intended for debugging.
  [[nodiscard]] std::string ToString(PacketSetHandle packet_set) const;

  // -- For Testing Only -------------------------------------------------------

  // Dynamically checks all class invariants. Exposed for testing only.
  absl::Status CheckInternalInvariants() const;

  // Returns an arbitrary list of concrete packets that are contained in the
  // given packet_set.
  //
  // This list is not guaranteed to be exhaustive. The only guarantees are:
  // * If the set is non-empty, we return at least one packet.
  // * Every packet we return is contained in the set.
  std::vector<Packet> GetConcretePackets(PacketSetHandle packet_set) const;

  // TODO(smolkaj): There are many additional operations supported by this data
  // structure, but not currently implemented. Add them as needed. Examples:
  // * subset - is one set a subset of another?
  // * witness - given a (non-empty) set, return one (or n) elements from the
  //   set.
  // * sample - return a member from the set uniformly at random.

 private:
  // Internally, this class represents packet sets as nodes in a directed
  // acyclic graph (DAG). Each node branches based on the value of a single
  // packet field, and each branch points to another handle, which in turn
  // represents either another decision node or the full/empty set.
  //
  // The graph is "ordered", "reduced", and contains no "isomorphic subgraphs":
  //
  // * Ordered: Along each path through the graph, fields increase strictly
  //   monotonically (with respect to `<` defined on `PacketFieldHandle`s).
  // * Reduced: Intutively, there exist no redundant branches or nodes.
  //   Invariants 1 and 2 on `branch_by_field_value` formalize this intuition.
  // * No isomorphic subgraphs: Nodes are hash-consed by the class, ensuring
  //   thatstructurally identical nodes are guaranteed to be stored by the class
  //   only once. Together with the other two properties, this implies that each
  //   node stored by the class represents a unique set of packets.
  //
  // This representation is closely related to Binary Decision Diagrams (BDDs),
  // see https://en.wikipedia.org/wiki/Binary_decision_diagram. This variant of
  // BDDs is described in the paper "KATch: A Fast Symbolic Verifier for
  // NetKAT".

  // A decision node in the packet set DAG. The node branches on the value
  // of a single `field`, and (the consequent of) each branch is a
  // `PacketSetHandle` corresponding to either another decision node or the
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
    PacketFieldHandle field;

    // The consequent of the "else" branch of this decision node.
    PacketSetHandle default_branch;

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
    absl::FixedArray<std::pair<int, PacketSetHandle>,
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

  // A key for efficiently hashing a `PredicateProto` to a `PacketSetHandle`.
  // This works as a recursive hash, such that we only internally compile unique
  // messages exactly once.
  struct ProtoHashKey {
    // The `PredicateProto` oneof case.
    int predicate_case;

    // The left child, if `predicate_case` is an operation. In the case
    // `predicate_case` is unary, e.g. Not, this will be the child.
    PacketSetHandle lhs_child;

    // The right child, if `predicate_case` is an operation. In the case
    // `predicate_case` is unary, e.g. Not, this will be defaulted.
    PacketSetHandle rhs_child;

    friend auto operator<=>(const ProtoHashKey& a,
                            const ProtoHashKey& b) = default;

    template <typename H>
    friend H AbslHashValue(H h, const ProtoHashKey& key) {
      return H::combine(std::move(h), key.predicate_case, key.lhs_child,
                        key.rhs_child);
    }
  };

  // Protect against regressions in memory layout, as it affects performance.
  static_assert(sizeof(DecisionNode) == 24);
  static_assert(alignof(DecisionNode) == 8);

  PacketSetHandle NodeToPacket(DecisionNode&& node);

  // Helper function for GetConcretePackets that recursively generates a list of
  // concrete packets that are contained in the given packet set. This
  // function is only used for testing.
  void GetConcretePacketsDfs(PacketSetHandle packet_set, Packet& current_packet,
                             std::vector<Packet>& result) const;

  // Returns the `DecisionNode` corresponding to the given `PacketSetHandle`, or
  // crashes if the `packet` is `EmptySet()` or `FullSet()`.
  //
  // Unless there is a bug in the implementation of this class, this function
  // is NOT expected to be called with these special packets that crash.
  const DecisionNode& GetNodeOrDie(PacketSetHandle packet_set) const;

  [[nodiscard]] std::string ToString(const DecisionNode& node) const;

  // The page size of the per-field node arenas: 16 KiB per page.
  // Chosen large enough to amortize the cost of dynamic allocation over
  // hundreds of nodes, and small enough that (a) models touching many fields
  // don't pay a large per-field memory overhead (each non-empty arena
  // allocates at least one page), and (b) pages stay below the malloc
  // mmap/trim thresholds (typically 128 KiB), so short-lived managers recycle
  // pages through the allocator's freelists instead of syscalls.
  static constexpr size_t kPageSize = (1 << 14) / sizeof(DecisionNode);
  using NodeArena = PagedStableVector<DecisionNode, kPageSize>;

  // The decision nodes forming the BDD-style DAG representation of packet
  // sets, stored by the field they branch on: a node with field index `f` and
  // slot `s` (in the sense of `PacketSetHandle::bits_`) is
  // `nodes_by_field_[f][s]`. Storing nodes by field clusters the nodes of a
  // field together in memory; operations tend to process nodes field by
  // field, so this improves locality.
  //
  // We use a custom vector class for the arenas that provides pointer
  // stability, allowing us to create new nodes while traversing the graph
  // (e.g. during operations like `And`, `Or`, `Not`). The class also avoids
  // expensive relocations.
  //
  // INVARIANT: `nodes_by_field_[f][s].field.index_ == f`.
  std::vector<NodeArena> nodes_by_field_;

  // The location of `nodes_by_field_`, behind a level of indirection that
  // remains stable when the manager object is moved: the unique tables below
  // hash and compare node slots by dereferencing into `nodes_by_field_`, and
  // their hasher/equality functors would otherwise dangle on move. Move
  // operations repoint the location at the new manager's `nodes_by_field_`
  // member.
  std::unique_ptr<const std::vector<NodeArena>*> nodes_location_ =
      std::make_unique<const std::vector<NodeArena>*>(&nodes_by_field_);

  // Hasher and equality for unique table entries, which are slots in the
  // node arena of the table's field. Hashing/comparing the *node* (rather
  // than the slot) is what makes the tables deduplicate by node content.
  // The `DecisionNode` overloads enable heterogeneous lookup, so that a
  // candidate node can be probed before it is added to the arena.
  struct InternedNodeHash {
    using is_transparent = void;
    const std::vector<NodeArena>* const* nodes_by_field;
    uint32_t field_index;
    size_t operator()(uint32_t slot) const {
      return absl::HashOf((**nodes_by_field)[field_index][slot]);
    }
    size_t operator()(const DecisionNode& node) const {
      return absl::HashOf(node);
    }
  };
  struct InternedNodeEq {
    using is_transparent = void;
    const std::vector<NodeArena>* const* nodes_by_field;
    uint32_t field_index;
    bool operator()(uint32_t a, uint32_t b) const {
      const NodeArena& arena = (**nodes_by_field)[field_index];
      return arena[a] == arena[b];
    }
    bool operator()(uint32_t a, const DecisionNode& b) const {
      return (**nodes_by_field)[field_index][a] == b;
    }
    bool operator()(const DecisionNode& a, uint32_t b) const {
      return (**nodes_by_field)[field_index][b] == a;
    }
  };
  using UniqueNodeTable =
      absl::flat_hash_set<uint32_t, InternedNodeHash, InternedNodeEq>;

  // So called "unique tables" to ensure each node is only added to
  // `nodes_by_field_` once, and thus has a unique slot. One table per packet
  // field: a node's entry lives in the table of the field it branches on.
  // Splitting by field keeps the tables, and thus probe sequences, small, and
  // storing slots (instead of node copies) keeps each node stored exactly
  // once, in `nodes_by_field_`.
  //
  // INVARIANT: `unique_table_by_field_.size() == nodes_by_field_.size()`.
  // INVARIANT: `unique_table_by_field_[f]` contains `s` iff
  // `s < nodes_by_field_[f].size()`; no two nodes in an arena are equal.
  std::vector<UniqueNodeTable> unique_table_by_field_;

  // Returns the unique table for nodes branching on `field`, creating it and
  // the field's node arena (as well as those of any smaller fields) if they
  // don't exist yet.
  UniqueNodeTable& GetOrCreateUniqueTable(PacketFieldHandle field);

  // A map of a given `PredicateProto` to a `PacketSetHandle`.
  //
  // This reflects a hash-consing of the proto to the already hash-consed
  // handle. This allows `Compile` to quickly deduce if a policy is new or
  // already exists.
  absl::flat_hash_map<ProtoHashKey, PacketSetHandle> packet_set_by_hash_;

  // INVARIANT: All `DecisionNode` fields are interned by this manager.
  PacketFieldManager field_manager_;

  // Allow `PacketTransformerManager` to access private methods.
  friend class PacketTransformerManager;
  friend class PacketTransformerManagerTestPeer;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_PACKET_SET_H_
