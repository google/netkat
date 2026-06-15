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
// File: packet_transformer_handle.h
// -----------------------------------------------------------------------------
//
// Defines `PacketTransformerHandle`, a lightweight handle representing a
// record-free policy.
//
// Together with its companion class `PacketTransformerManager` (defined in
// `packet_transformer.h`), they provide a compact and efficient representation
// of record-free policies allowing for fast semantic equality checks.

#ifndef GOOGLE_NETKAT_NETKAT_PACKET_TRANSFORMER_HANDLE_H_
#define GOOGLE_NETKAT_NETKAT_PACKET_TRANSFORMER_HANDLE_H_

#include <cstdint>
#include <limits>
#include <string>
#include <utility>

#include "absl/strings/str_format.h"

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
  // The deny and accept policies are not decision nodes, and thus we cannot
  // associate an index into the `nodes_` vector with them. Instead, we
  // represent them using sentinel values, chosen maximally to avoid collisions
  // with proper indices.
  enum Sentinel : uint32_t {
    // Encodes the Deny transformer.
    kDeny = std::numeric_limits<uint32_t>::max(),
    // Encodes the Accept transformer.
    kAccept = std::numeric_limits<uint32_t>::max() - 1,
    // The minimum sentinel node index.
    // Smaller values are reserved for proper indices into the `nodes_` vector.
    kMinSentinel = kAccept,
  };

  // Default constructor: the Deny policy.
  PacketTransformerHandle() : node_index_(kDeny) {}

  // Two packet transformers compare equal iff they represent the same
  // record-free policy (semantically).
  friend auto operator<=>(PacketTransformerHandle a,
                          PacketTransformerHandle b) = default;

  // Hashing, see https://abseil.io/docs/cpp/guides/hash.
  template <typename H>
  friend H AbslHashValue(H h, PacketTransformerHandle transformer) {
    return H::combine(std::move(h), transformer.node_index_);
  }

  // Formatting, see https://abseil.io/docs/cpp/guides/abslstringify.
  template <typename Sink>
  friend void AbslStringify(Sink& sink, PacketTransformerHandle transformer) {
    absl::Format(&sink, "%s", transformer.ToString());
  }
  std::string ToString() const {
    if (node_index_ == kDeny) {
      return "PacketTransformerHandle<deny>";
    } else if (node_index_ == kAccept) {
      return "PacketTransformerHandle<accept>";
    } else {
      return absl::StrFormat("PacketTransformerHandle<%d>", node_index_);
    }
  }

 private:
  // An index into the `nodes_` vector of the `PacketTransformerManager`
  // object associated with this `PacketTransformerHandle`.
  uint32_t node_index_;

  explicit PacketTransformerHandle(uint32_t node_index)
      : node_index_(node_index) {}

  friend class PacketTransformerManager;
  friend class PacketSetManager;
};

// Protect against regressions in the memory layout, as it affects performance.
static_assert(sizeof(PacketTransformerHandle) <= 4);

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_PACKET_TRANSFORMER_HANDLE_H_
