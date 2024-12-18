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
// File: interned_field.h
// -----------------------------------------------------------------------------
//
// A module for "interning" (aka hash-consing) NetKAT packet fields, see
// https://en.wikipedia.org/wiki/String_interning. This makes it cheap to
// compare, hash, copy and store packet fields (small constant time/space).

#ifndef GOOGLE_NETKAT_NETKAT_INTERNED_FIELD_H_
#define GOOGLE_NETKAT_NETKAT_INTERNED_FIELD_H_

#include <compare>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"

namespace netkat {

// An "interned" (aka hash-consed) NetKAT packet field, e.g. "dst_ip".
//
// Technically, a lightweight handle (16 bits) that is very cheap (O(1)) to
// copy, store, hash, and compare. Handles can only be created by an
// `InternedFieldManager` object, which owns the field name (e.g. "dst_ip")
// associated with the handle.
//
// CAUTION: Each `InternedField` is implicitly associated with the manager
// object that created it; using it with a different manager object has
// undefined behavior.
class [[nodiscard]] InternedField {
 public:
  // `InternedField`s can only be created by `InternedFieldManager`.
  InternedField() = delete;
  friend class InternedFieldManager;

  // O(1) comparison, thanks to interning/hash-consing.
  friend auto operator<=>(InternedField a, InternedField b) = default;

  // Hashing, see https://abseil.io/docs/cpp/guides/hash.
  template <typename H>
  friend H AbslHashValue(H h, InternedField field) {
    return H::combine(std::move(h), field.index_);
  }

  // Formatting, see https://abseil.io/docs/cpp/guides/abslstringify.
  template <typename Sink>
  friend void AbslStringify(Sink& sink, InternedField field) {
    absl::Format(&sink, "InternedField<%d>", field.index_);
  }

 private:
  // An index into the `field_names_` vector of the `InternedFieldManager`
  // object associated with this `InternedField`: `field_names_[index_]` is the
  // name of the field. The index is otherwise arbitrary and meaningless.
  //
  // We use a 16-bit index as a tradeoff between minimizing memory usage while
  // supporting sufficiently many fields. We expect 100s, but not more than
  // 2^16 ~= 65k fields.
  uint16_t index_;
  explicit InternedField(uint16_t index) : index_(index) {}
};

// Protect against regressions in the memory layout, as it affects performance.
static_assert(sizeof(InternedField) <= 2);

// An "arena" for interning NetKAT packet fields, owning the memory associated
// with the interned fields.
class InternedFieldManager {
 public:
  InternedFieldManager() = default;

  // Returns an interned representation of field with the given name.
  InternedField GetOrCreateInternedField(absl::string_view field_name);

  // Returns the name of the given interned field, assuming it was created by
  // this manager object. Otherwise, the behavior is undefined.
  std::string GetFieldName(InternedField field) const;

  // Dynamically checks all class invariants. Exposed for testing only.
  absl::Status CheckInternalInvariants() const;

 private:
  // All field names interned by this manager object. The name of an interned
  // field `f` created by this object is `field_names_[f.index_]`.
  std::vector<std::string> field_names_;

  // A so called "unique table" to ensure each field name is added to
  // `field_names_` at most once, and thus is represented by a unique index into
  // that vector.
  //
  // Invariant:
  // `interned_field_by_name_[n] == f` iff `field_names_[f.index_] == n`.
  absl::flat_hash_map<std::string, InternedField> interned_field_by_name_;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_INTERNED_FIELD_H_
