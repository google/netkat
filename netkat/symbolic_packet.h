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
// symbolic_packet.h
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
// With few exceptions, the APIs for creating, manipulating, and inspecting
// `SymbolicPacket`s are all defined as methods and static functions of the
// `SymbolicPacketManager` class. But why?
//
// TL;DR, all data associated with a `SymbolicPacket` is stored in data vectors
// owned by the manager class. Under the hood, a `SymbolicPacket` is just an
// index into these data vectors. This design pattern is motivated by
// computational and memory efficiency, and is standard for BDD-based libraries.
//
// The manager object acts as an "arena" that owns and manages all memory
// associated with `SymbolicPacket`s, enhancing data locality and sharing. This
// technique is known as hash-consing and is similar to the flyweight pattern
// and string interning. It has a long list of benefits, most importantly:
//
// * Canonicity: Can gurantee that semantically identical `SymbolicPacket` are
//   represnted by the same index into `SymbolicPacketManager`, making semantic
//   `SymbolicPacket` comparison O(1) (just comparing two integers)!
//
// * Memory efficiency: The graph structures used to encode symbolic packets are
//   maximally shared across all packets, avoiding redundant copies.
//
// * Cache friendliness: Storing all data in contiguous arrays within the
//   manager improves data locality and thus cache utilization.
//
// * Light representation: Since `SymbolicPacket`s are simply integres in
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

// CAUTION: This implementation has NOT yet been optimized for performance.
// Performance can likely be improved significantly, e.g. as follows:
// * Profiling and benchmarking to identify inefficiencies.
// * Using standard techniques described in the literature on BDDs and other
//   decision diagrams, see e.g. "Efficient Implementation of a BDD Package".

#ifndef GOOGLE_NETKAT_NETKAT_SYMBOLIC_PACKET_H_
#define GOOGLE_NETKAT_NETKAT_SYMBOLIC_PACKET_H_

#include <cstdint>
#include <limits>
#include <utility>

#include "absl/strings/str_format.h"
#include "netkat/netkat.pb.h"

namespace netkat {

// TODO(smolkaj): Implement this.
class SymbolicPacketManager;

// A "symbolic packet" is a data structure representing a set of packets.
// It is a compressed representation that can efficiently encode typical large
// and even infinite sets seen in practice.
//
// Compared to NetKAT predicates, which semantically also represent sets of
// packets, symbolic packets have a few advantages:
// * Cheap to store, copy, hash, and compare: O(1)
// * Cheap to check set equality: O(1)
// * Cheap to check set membership and set containment: O(# packet fields)
//
// NOTES ON THE API:
// * The majority of operations on `SymbolicPacket`s are defined as methods on
//   the companion class `SymbolicPacketManager`. See the section "Why have a
//   `SmbolicPacketManager` class?" at the top of the file to learn why.
// * Each `SymbolicPacket` is implicitly associated with the manager object that
//   created it; using it with a different manager object has undefined
//   behavior.
// * `EmptySet()` and `FullSet()` are exceptions to the above rule in that they
//   work with any `SymbolicPacketManager` object.
class SymbolicPacket {
 public:
  // Default constructor: the empty set of packets.
  SymbolicPacket() = default;

  // TODO(smolkaj): Move the EmptySet/FullSet APIs to the
  // `SymbolicPacketManager` class for consistency.

  // The symbolic packet representing the empty set of packets.
  static SymbolicPacket EmptySet() { return SymbolicPacket(kEmptySetIndex); }

  // The symbolic packet representing the set of all packets.
  static SymbolicPacket FullSet() { return SymbolicPacket(kFullSetIndex); }

  // Returns true iff this symbolic packet represents the empty set of packets.
  bool IsEmptySet() const { return node_index_ == kEmptySetIndex; }

  // Returns true iff this symbolic packet represents the set of all packets.
  bool IsFullSet() const { return node_index_ == kFullSetIndex; }

  // Two symbolic packets compare equal iff they represent the same set of
  // concrete packets. Comparison is O(1), thanks to a canonical representation.
  friend auto operator<=>(SymbolicPacket a, SymbolicPacket b) = default;

  // Hashing, see https://abseil.io/docs/cpp/guides/hash.
  template <typename H>
  friend H AbslHashValue(H h, SymbolicPacket packet) {
    return H::combine(std::move(h), packet.node_index_);
  }

  // Formatting, see https://abseil.io/docs/cpp/guides/abslstringify.
  template <typename Sink>
  friend void AbslStringify(Sink& sink, SymbolicPacket packet) {
    if (packet.IsEmptySet()) {
      absl::Format(&sink, "SymbolicPacket<false>");
    } else if (packet.IsFullSet()) {
      absl::Format(&sink, "SymbolicPacket<true>");
    } else {
      absl::Format(&sink, "SymbolicPacket<%d>", packet.node_index_);
    }
  }

 private:
  // In memory, a `SymbolicPacket` is just an integer, making it cheap to
  // store, copy, hash, and compare.
  //
  // The `node_index_` is either:
  // * A sentinel value:
  //   * `kEmptySetIndex`, representing the empty set of packets.
  //   * `kFullSetIndex`, representing the full set of packets.
  // * An index into the `nodes_` vector of the `SymbolicPacketManager` object
  //   associated with this `SymbolicPacket`. In this case, the semantics of
  //   this object is given by the node stored at `nodes_[node_index_]` in the
  //   manager object. The index is otherwise arbitrary and meaningless, and
  //   thus, so is this object unless we have access to the associated manager
  //   object.
  //
  // We use a bit width of 32 as a tradeoff between minimizing memory usage
  // (which is critical for scaling to large NetKAT models) and maximizing the
  // number of `SymbolicPacket`s that can be created (which is also critical for
  // scaling to large NetKAT models) -- we expect millions, but probably not
  // billions, of symbolic packets in practice, and 2^32 ~= 4 billion.
  //
  // The sentinel values are chosen maximally to avoid collisions with valid
  // indices, which are assigned dynamically by the manager object starting at
  // 0. For performance reasons, there is no runtime protection against
  // collisions and overflow if we create too many distinct `SymbolicPacket`s.
  //
  // This data structure enjoys the following powerful canonicity property: two
  // symbolic packets represent the same set if and only if they have the same
  // `node_index_`.
  uint32_t node_index_ = SentinelValue::kEmptySetIndex;
  enum SentinelValue : uint32_t {
    kEmptySetIndex = std::numeric_limits<uint32_t>::max(),
    kFullSetIndex = std::numeric_limits<uint32_t>::max() - 1,
  };
  explicit SymbolicPacket(uint32_t node_index) : node_index_(node_index) {}
  friend class SymbolicPacketManager;
};

static_assert(
    sizeof(SymbolicPacket) <= 4,
    "SymbolicPacket should have small memory footprint for performance");

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_SYMBOLIC_PACKET_H_
