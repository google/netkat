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
// Why have a `SmbolicPacketManager` class?
// -----------------------------------------------------------------------------
//
// The APIs for creating, manipulating, and inspecting `SymbolicPacket`s are all
// defined as methods and static functions of the `SymbolicPacketManager` class.
// But why?
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
// * Canonicity: Can gurantee that semantically identical `SymbolicPacket` are
//   represnted by the same handle, making semantic `SymbolicPacket` comparison
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
//   can be memoized as a loockup table of type (int, int) -> int.
//
// -----------------------------------------------------------------------------
//
// CAUTION: This implementation has NOT yet been optimized for performance.
// Performance can likely be improved significantly, e.g. as follows:
// * Profiling and benchmarking to identify inefficiencies.
// * Using standard techniques described in the literature on BDDs and other
//   decision diagrams, see e.g. "Efficient Implementation of a BDD Package".

#ifndef GOOGLE_NETKAT_NETKAT_SYMBOLIC_PACKET_H_
#define GOOGLE_NETKAT_NETKAT_SYMBOLIC_PACKET_H_

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/fixed_array.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "netkat/evaluator.h"
#include "netkat/netkat.pb.h"

namespace netkat {

// A "symbolic packet" is a lightweight handle (32 bits)  that represents a set
// of packets. Handles can only be created by a `SymbolicPacketManager` object,
// which owns the graph-based representation of the set. The representation can
// efficiently encode typical large and even infinite sets seen in practice.
//
// The APIs of this object are almost entirely defined as methods and static
// members function of the companion class `SymbolicPacketManager`. See the
// section "Why have a `SmbolicPacketManager` class?" at the top of the file to
// learn why.
//
// CAUTION: Each `SymbolicPacket` is implicitly associated with the manager
// object that created it; using it with a different manager has undefined
// behavior.
//
// This data structure enjoys the following powerful *canonicity property*: two
// symbolic packets represent the same set if and only if they have the same
// memory representation. Since the memory representation is just 32 bits, set
// equality is cheap: O(1)!
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

// Protect against regressions in the memory layout, as it effects performance.
static_assert(sizeof(SymbolicPacket) <= 4);

// A lightweight handle (16 bits) that represents a packet field like "dst_ip".
// Handles can only be created by a `SymbolicPacketManager` object, which stores
// the string. Interning/hash-consing fields in this way saves memory and makes
// fields cheap to store, copy, hash, and compare: O(1).
//
// The APIs of this object are almost entirely defined as methods and static
// members function of the companion class `SymbolicPacketManager`. See the
// section "Why have a `SmbolicPacketManager` class?" at the top of the file to
// learn why.
//
// CAUTION: Each `Field` is implicitly associated with the manager object that
// created it; using it with a different manager object has undefined behavior.
class [[nodiscard]] Field {
 public:
  // `Field`s can only be created by `SymbolicPacketManager`.
  Field() = delete;
  friend class SymbolicPacketManager;

  // O(1) comparison, thanks to interning/hash-consing.
  friend auto operator<=>(Field a, Field b) = default;

  // Hashing, see https://abseil.io/docs/cpp/guides/hash.
  template <typename H>
  friend H AbslHashValue(H h, Field field) {
    return H::combine(std::move(h), field.index_);
  }

  // Formatting, see https://abseil.io/docs/cpp/guides/abslstringify.
  template <typename Sink>
  friend void AbslStringify(Sink& sink, Field field) {
    absl::Format(&sink, "Field<%d>", field.index_);
  }

 private:
  // An index into the `fields_` vector of the `SymbolicPacketManager` object
  // associated with this `Field`; `fields_[index_]` is the name of the field.
  // The index is otherwise arbitrary and meaningless.
  //
  // We use a 16-bit index as a tradeoff between minimizing memory usage while
  // supporting sufficiently many fields. We expect 100s, but not more than
  // 2^16 ~= 65k fields.
  uint16_t index_;
  explicit Field(uint16_t index) : index_(index) {}
};

// Protect against regressions in the memory layout, as it effects performance.
static_assert(sizeof(Field) <= 2);

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

  // The symbolic packet representing the empty set of packets.
  static SymbolicPacket EmptySet();

  // The symbolic packet representing the set of all packets.
  static SymbolicPacket FullSet();

  // Returns true iff this symbolic packet represents the empty set of packets.
  [[nodiscard]] bool IsEmptySet(SymbolicPacket packet) const;

  // Returns true iff this symbolic packet represents the set of all packets.
  [[nodiscard]] bool IsFullSet(SymbolicPacket packet) const;

  // Returns true if the set represented by `symbolic_packet` contains the given
  // `concrete_packet`, or false otherwise.
  [[nodiscard]] bool Contains(SymbolicPacket symbolic_packet,
                              netkat::Packet concrete_packet) const;

  // Compiles the given `PredicateProto` into a `SymbolicPacket` that
  // represents the set of packets satisfying the predicate.
  SymbolicPacket Compile(const PredicateProto& pred);

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

  // Returns a human-readable string representation of the given `packet`,
  // intended for debugging.
  [[nodiscard]] std::string PrettyPrint(SymbolicPacket packet) const;

  // Dynamically checks all class invariants. Exposed for testing.
  absl::Status CheckInternalInvariants() const;

  // There are many additional set operations supported by the data structure.
  // We may implement them as needed. For example:
  // * subset - is one set a subset of another?
  // * witness - given a (non-empty) set, return one (or n) elements from the
  //   set.
  // * sample - return a memember from the set uniformly at random.

 private:
  // A decision node in the symbolic packet DAG. The node branches on the value
  // of a single `field`, and (the consequent of) each branch is another
  // `SymbolicPacket`. Semantically, represents a cascading conditional of the
  // form:
  //
  //   if      (field == value_1) then branch_1
  //   else if (field == value_2) then branch_2
  //   ...
  //   else default_branch
  struct DecisionNode {
    // The packet field whose value this decision node branches on.
    //
    // INVARIANT: `field` is strictly smaller than field indices of all
    // sub-nodes.
    Field field;

    // The consequent of the "else" branch of this decision node.
    SymbolicPacket default_branch;

    // The "if" branches of the decision node, "keyed" by the value they branch
    // on. Each element of the array is a (value, branch)-pair encoding
    // "if (field == value) then branch".
    //
    // INVARIANTS:
    // 1. Maintained by `NodeToPacket`: `branch_by_field_value` is non-empty.
    //   (If it is empty, the decision node gets replaced by `default_branch`.)
    // 2. Maintained by `AddCase`: Each branch is != `default_branch`. (If it
    //    is == `default_branch`, it gets omitted.)
    // 3. Maintained by the callers of `AddCase`: The pairs are ordered by
    //    strictly increasing value. No two branches have the same value.
    //
    // Choice of data structure:
    // * Logically this is a map, but we don't require fast look ups and thus
    //   optimize for a compact, contiguous memory layout without indirection.
    // * No need to dynamically resize, hence we can safe some bytes that
    //   dynamic data structures need for bookkeeping.
    absl::FixedArray<std::pair<int, SymbolicPacket>,
                     /*use_heap_allocation_above_size=*/0>
        branch_by_field_value;

    // Protect against regressions in memory layout, as it effects performance.
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

  // Protect against regressions in memory layout, as it effects performance.
  static_assert(sizeof(DecisionNode) == 24);
  static_assert(alignof(DecisionNode) == 8);

  SymbolicPacket NodeToPacket(DecisionNode&& node);

  const DecisionNode& GetNodeOrDie(SymbolicPacket packet) const;

  std::string GetFieldNameOrDie(Field field) const;

  Field GetField(absl::string_view field_name);

  [[nodiscard]] std::string PrettyPrint(const DecisionNode& node) const;

  // The decision nodes forming the BDD-style DAG representation of symbolic
  // packets. `SymbolicPacket::node_index_` indexes into this vector.
  std::vector<DecisionNode> nodes_;

  // A so called "unique table" to ensure each node is only added to `nodes_`
  // once, and thus has a unique `SymbolicPacket::node_index`.
  // INVARIANT: `packet_by_node_[n] = s` iff `nodes_[s.node_index_] == n`.
  absl::flat_hash_map<DecisionNode, SymbolicPacket> packet_by_node_;

  // `Field::index_` indexes into this vector.
  std::vector<std::string> fields_;

  // A so called "unique table" to ensure each field is only added to `fields_`
  // once, and thus has a unique `Field::index_`.
  // INVARIANT: `field_by_name_[n] = field` iff `fields_[field.index_] == n`.
  absl::flat_hash_map<std::string, Field> field_by_name_;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_SYMBOLIC_PACKET_H_
