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
#include <limits>
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
  // The empty and full set of packets are not decision nodes, and thus we
  // cannot associate an index into the `nodes_` vector with them. Instead, we
  // represent them using sentinel values, chosen maximally to avoid collisions
  // with proper indices.
  enum Sentinel : uint32_t {
    // Encodes the empty set of packets.
    kEmptySet = std::numeric_limits<uint32_t>::max(),
    // Encodes the full set of packets.
    kFullSet = std::numeric_limits<uint32_t>::max() - 1,
    // The minimum sentinel node index.
    // Smaller values are reserved for proper indices into the `nodes_` vector.
    kMinSentinel = kFullSet,
  };

  // Default constructor: the empty set of packets.
  PacketSetHandle() : node_index_(kEmptySet) {}

  // Two packet set handles compare equal iff they represent the same set of
  // concrete packets. Comparison is O(1), thanks to interning/hash-consing.
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
      return absl::StrFormat("PacketSetHandle<%d>", node_index_);
    }
  }

 private:
  // An index into the `nodes_` vector of the `PacketSetManager` object
  // associated with this `PacketSetHandle`. The semantics of this packet set
  // is entirely determined by the node `nodes_[node_index_]`. The index is
  // otherwise arbitrary and meaningless.
  //
  // We use a 32-bit index as a tradeoff between minimizing memory usage and
  // maximizing the number of `PacketSetHandle`s that can be created, both
  // aspects that impact how well we scale to large NetKAT models. We expect
  // millions, but not billions, of packet sets in practice, and 2^32 ~= 4
  // billion.
  uint32_t node_index_;
  explicit PacketSetHandle(uint32_t node_index) : node_index_(node_index) {}
  friend class PacketSetManager;
};

// Protect against regressions in the memory layout, as it affects performance.
static_assert(sizeof(PacketSetHandle) <= 4);

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_PACKET_SET_HANDLE_H_
