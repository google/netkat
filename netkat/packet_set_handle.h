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
class [[nodiscard]] PacketSetHandle {
 public:
  // COMPLEMENT EDGES
  // ----------------
  // The most-significant bit of `node_index_` is a "complement" (a.k.a.
  // "negative" or "complemented") edge flag, a standard BDD optimization: when
  // set, the handle denotes the *complement* of the set denoted by the same
  // handle with the flag cleared. This lets a set and its complement share a
  // single decision node, and makes `PacketSetManager::Not` an O(1) bit flip.
  //
  // The remaining 31 bits are the index of the decision node in the manager's
  // `nodes_` vector (or the leaf sentinel below). We expect millions, but not
  // billions, of decision nodes in practice, so 2^31 ~= 2.1 billion is ample.
  static constexpr uint32_t kComplementBit = uint32_t{1} << 31;
  static constexpr uint32_t kIndexMask = kComplementBit - 1;

  // The empty and full sets of packets are not decision nodes. Thanks to
  // complement edges we need only a *single* leaf sentinel: a plain edge to it
  // is the full set, a complement edge to it (`kEmptySet`) is the empty set.
  enum Sentinel : uint32_t {
    // Encodes the full set of packets: a plain edge to the leaf.
    kFullSet = kIndexMask,
    // Encodes the empty set of packets: a complement edge to the leaf.
    kEmptySet = kComplementBit | kIndexMask,
    // Node indices in `[0, kMaxNodeCount)` are proper indices into `nodes_`;
    // they must not collide with the leaf.
    kMaxNodeCount = kIndexMask,
  };

  // Default constructor: the empty set of packets.
  PacketSetHandle() : node_index_(kEmptySet) {}

  // Two packet set handles compare equal iff they represent the same set of
  // concrete packets. Comparison is O(1), thanks to interning/hash-consing and
  // the canonical treatment of complement edges (see `packet_set.h`).
  friend auto operator<=>(PacketSetHandle a, PacketSetHandle b) = default;

  // Hashing, see https://abseil.io/docs/cpp/guides/hash.
  template <typename H>
  friend H AbslHashValue(H h, PacketSetHandle packet_set) {
    return H::combine(std::move(h), packet_set.node_index_);
  }

  // Formatting, see https://abseil.io/docs/cpp/guides/abslstringify.
  // NOTE: These functions do not produce particularly useful output. Instead,
  // use `PacketSetManager::ToString(packet_set)` whenever possible.
  template <typename Sink>
  friend void AbslStringify(Sink& sink, PacketSetHandle packet_set) {
    absl::Format(&sink, "%s", packet_set.ToString());
  }
  std::string ToString() const {
    if (node_index_ == kEmptySet) {
      return "PacketSetHandle<empty>";
    } else if (node_index_ == kFullSet) {
      return "PacketSetHandle<full>";
    } else {
      // A leading "~" marks a complement edge, e.g. "PacketSetHandle<~7>".
      return absl::StrFormat("PacketSetHandle<%s%d>", complemented() ? "~" : "",
                             index());
    }
  }

  // True iff this is a complement edge (see "COMPLEMENT EDGES" above).
  bool complemented() const { return (node_index_ & kComplementBit) != 0; }

 private:
  // The complement bit (see above) packed with the index of the decision node
  // in the `PacketSetManager`'s `nodes_` vector. The semantics of this packet
  // set is entirely determined by `nodes_[index()]` and `complemented()`.
  uint32_t node_index_;

  explicit PacketSetHandle(uint32_t node_index) : node_index_(node_index) {}

  // The decision-node index, with the complement bit masked off.
  uint32_t index() const { return node_index_ & kIndexMask; }

  // This handle with its complement bit toggled: denotes the complement set.
  PacketSetHandle Flip() const {
    return PacketSetHandle(node_index_ ^ kComplementBit);
  }

  friend class PacketSetManager;
};

// Protect against regressions in the memory layout, as it affects performance.
static_assert(sizeof(PacketSetHandle) <= 4);

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_PACKET_SET_HANDLE_H_
