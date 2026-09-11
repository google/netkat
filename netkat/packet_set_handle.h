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
// File: packet_set_handle.h
// -----------------------------------------------------------------------------
//
// Defines `PacketSetHandle`, a lightweight handle representing a set of
// packets.
//
// Together with its companion class `PacketSetManager` (defined in
// `packet_set.h`), they provide an often compact and efficient representation
// of large and even infinite packet sets, exploiting structural properties that
// packet sets seen in practice typically exhibit.

#ifndef GOOGLE_NETKAT_NETKAT_PACKET_SET_HANDLE_H_
#define GOOGLE_NETKAT_NETKAT_PACKET_SET_HANDLE_H_

#include <cstdint>
#include <string>
#include <utility>

#include "absl/strings/str_format.h"

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
//
// COMPLEMENTED EDGES:
// A handle is a pair of a "complement bit" and a node index (see `value_`),
// i.e. it is an *edge* pointing at a node, and the edge may be "complemented".
// A complemented edge denotes the complement of the set denoted by the node it
// points at, see
// https://en.wikipedia.org/wiki/Binary_decision_diagram#Complemented_edges.
// This makes set complement an O(1) bit flip and roughly halves the number of
// nodes we need to store, at the cost of a canonicity rule that
// `PacketSetManager` must maintain (see `PacketSetManager::NodeToPacket`).
class [[nodiscard]] PacketSetHandle {
 public:
  // The bit of `value_` encoding whether this is a complemented edge, i.e.
  // whether this handle denotes the complement of the set denoted by the node
  // it points at.
  static constexpr uint32_t kComplementBit = uint32_t{1} << 31;

  // The bits of `value_` encoding the node this handle points at: either an
  // index into the `nodes_` vector of the `PacketSetManager` object associated
  // with this `PacketSetHandle`, or the `kFullSet` sentinel. The index is
  // otherwise arbitrary and meaningless.
  static constexpr uint32_t kNodeIndexMask = ~kComplementBit;

  // The full set of packets is not a decision node, and thus we cannot
  // associate an index into the `nodes_` vector with it. Instead, we represent
  // it using a sentinel value, chosen maximally to avoid collisions with proper
  // indices. The empty set needs no sentinel of its own: it is simply the
  // complement of the full set.
  enum Sentinel : uint32_t {
    // Encodes the full set of packets: the unique terminal node.
    kFullSet = kComplementBit - 1,
    // Encodes the empty set of packets: a complemented edge to the terminal
    // node.
    kEmptySet = kFullSet | kComplementBit,
    // The minimum sentinel node index.
    // Smaller values are reserved for proper indices into the `nodes_` vector.
    kMinSentinel = kFullSet,
  };

  // Default constructor: the empty set of packets.
  PacketSetHandle() : value_(kEmptySet) {}

  // Two packet set handles compare equal iff they represent the same set of
  // concrete packets. Comparison is O(1), thanks to interning/hash-consing.
  friend auto operator<=>(PacketSetHandle a, PacketSetHandle b) = default;

  // Hashing, see https://abseil.io/docs/cpp/guides/hash.
  template <typename H>
  friend H AbslHashValue(H h, PacketSetHandle packet_set) {
    return H::combine(std::move(h), packet_set.value_);
  }

  // Formatting, see https://abseil.io/docs/cpp/guides/abslstringify.
  // NOTE: These functions do not produce particularly useful output. Instead,
  // use `PacketSetManager::ToString(packet_set)` whenever possible.
  template <typename Sink>
  friend void AbslStringify(Sink& sink, PacketSetHandle packet_set) {
    absl::Format(&sink, "%s", packet_set.ToString());
  }
  std::string ToString() const {
    if (value_ == kEmptySet) {
      return "PacketSetHandle<empty>";
    } else if (value_ == kFullSet) {
      return "PacketSetHandle<full>";
    } else if (IsComplemented()) {
      // '!' denotes a complemented edge, i.e. the complement of node `%d`.
      return absl::StrFormat("PacketSetHandle<!%d>", NodeIndex());
    } else {
      return absl::StrFormat("PacketSetHandle<%d>", NodeIndex());
    }
  }

 private:
  // The complement bit (see `kComplementBit`) and the node index (see
  // `kNodeIndexMask`), packed into a single 32-bit word. The semantics of this
  // packet set is entirely determined by the node `nodes_[NodeIndex()]`, and
  // the complement bit: if the bit is set, this handle denotes the complement
  // of the set denoted by that node.
  //
  // We use a 32-bit word as a tradeoff between minimizing memory usage and
  // maximizing the number of `PacketSetHandle`s that can be created, both
  // aspects that impact how well we scale to large NetKAT models. We expect
  // millions, but not billions, of packet sets in practice, and 2^31 ~= 2
  // billion.
  uint32_t value_;

  explicit PacketSetHandle(uint32_t value) : value_(value) {}

  // Returns the index of the node this handle points at, ignoring the
  // complement bit. Note that `x` and `x.Complement()` share the same index.
  uint32_t NodeIndex() const { return value_ & kNodeIndexMask; }

  // Returns whether this is a complemented edge, i.e. whether this handle
  // denotes the complement of the set denoted by the node it points at.
  bool IsComplemented() const { return (value_ & kComplementBit) != 0; }

  // Returns the handle denoting the complement of the set denoted by this
  // handle. O(1)!
  PacketSetHandle Complement() const {
    return PacketSetHandle(value_ ^ kComplementBit);
  }

  // Returns `Complement()` if `complement` is true, and `*this` otherwise.
  PacketSetHandle ComplementIf(bool complement) const {
    return PacketSetHandle(value_ ^ (complement ? kComplementBit : 0));
  }

  friend class PacketSetManager;
};

static_assert(PacketSetHandle::kFullSet == 0x7fff'ffff);
static_assert(PacketSetHandle::kEmptySet == 0xffff'ffff);

// Protect against regressions in the memory layout, as it affects performance.
static_assert(sizeof(PacketSetHandle) <= 4);

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_PACKET_SET_HANDLE_H_
