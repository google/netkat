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
// File: interned_vector.h
// -----------------------------------------------------------------------------
//
// Defines `InternedVector`, an append-only vector of pairwise distinct
// ("interned" or "hash-consed") values, supporting efficient lookup of the
// index of a given value.
//
// This is the core data structure underlying the "unique tables" of BDD-style
// managers like `PacketSetManager` and `PacketTransformerManager`. Compared to
// the naive combination of a vector and a hash map from values to indices, it
// stores each value only once (in the vector), and uses compact hash table
// slots consisting of just an index and a cached hash. This roughly halves
// memory usage, avoids copying values into the hash map, and makes rehashing
// cheap (no access to, or rehashing of, the values is required).

#ifndef GOOGLE_NETKAT_NETKAT_INTERNED_VECTOR_H_
#define GOOGLE_NETKAT_NETKAT_INTERNED_VECTOR_H_

#include <cstddef>
#include <cstdint>
#include <utility>

#include "absl/container/flat_hash_set.h"
#include "absl/hash/hash.h"
#include "absl/status/status.h"
#include "gutil/status.h"
#include "netkat/paged_stable_vector.h"

namespace netkat {

// An append-only sequence of pairwise distinct `T`s, stored in a
// `PagedStableVector<T, PageSize>` (and thus with pointer stability).
//
// `T` must be hashable (see https://abseil.io/docs/cpp/guides/hash) and
// equality comparable. Supports up to 2^32 values.
template <class T, size_t PageSize>
class InternedVector {
 public:
  InternedVector() = default;
  InternedVector(InternedVector&&) = default;
  InternedVector& operator=(InternedVector&&) = default;

  // Returns the index of `value` in this vector, appending it first if it is
  // not already present. The second component of the returned pair is true iff
  // `value` was appended.
  std::pair<uint32_t, bool> Intern(T&& value) {
    return Intern(value, [&]() -> T&& { return std::move(value); });
  }

  // Like `Intern(T&&)`, but for the value `make_value()`, which is only called
  // if it is not already present. The value is looked up using `key`, an
  // equivalent representation of the value that may be of a different type
  // `K`, e.g. a representation that is cheaper to construct. Requires that
  // `absl::HashOf(key) == absl::HashOf(make_value())`, and that `v == key` for
  // `T`s `v` iff `v == make_value()`.
  template <class K, class MakeValue>
  std::pair<uint32_t, bool> Intern(const K& key, MakeValue&& make_value) {
    const size_t hash = absl::HashOf(key);
    bool inserted = false;
    auto it = index_by_value_.lazy_emplace(
        LookupKey<K>{.hash = hash, .key = &key, .values = &values_},
        [&](const auto& construct) {
          inserted = true;
          construct(Entry{.hash = hash,
                          .index = static_cast<uint32_t>(values_.size())});
        });
    if (inserted) values_.push_back(make_value());
    return {it->index, inserted};
  }

  // Returns the value at the given `index`. Requires `index < size()`.
  const T& operator[](size_t index) const { return values_[index]; }

  size_t size() const { return values_.size(); }

  // Dynamically checks all class invariants. Exposed for testing only.
  absl::Status CheckInternalInvariants() const {
    RET_CHECK(index_by_value_.size() == values_.size());
    for (size_t i = 0; i < values_.size(); ++i) {
      const T& value = values_[i];
      const size_t hash = absl::HashOf(value);
      auto it = index_by_value_.find(
          LookupKey<T>{.hash = hash, .key = &value, .values = &values_});
      RET_CHECK(it != index_by_value_.end());
      RET_CHECK(it->index == i);
      RET_CHECK(it->hash == hash);
    }
    return absl::OkStatus();
  }

 private:
  using Values = PagedStableVector<T, PageSize>;

  // A key for heterogeneous lookup of a value equivalent to `*key` in
  // `index_by_value_`.
  template <class K>
  struct LookupKey {
    size_t hash;  // `absl::HashOf(*key)`.
    const K* key;
    const Values* values;  // The values that `Entry::index` refers to.
  };

  // A slot in `index_by_value_`, representing the value `values_[index]`.
  struct Entry {
    // Cached `absl::HashOf(values_[index])`, avoiding the need to access the
    // value when rehashing.
    size_t hash;
    uint32_t index;
  };

  struct Hash {
    using is_transparent = void;
    size_t operator()(const Entry& entry) const { return entry.hash; }
    template <class K>
    size_t operator()(const LookupKey<K>& key) const {
      return key.hash;
    }
  };

  struct Eq {
    using is_transparent = void;
    // Entries are distinct iff they refer to distinct (and thus unequal)
    // values.
    bool operator()(const Entry& a, const Entry& b) const {
      return a.index == b.index;
    }
    template <class K>
    bool operator()(const Entry& entry, const LookupKey<K>& key) const {
      return entry.hash == key.hash && (*key.values)[entry.index] == *key.key;
    }
    template <class K>
    bool operator()(const LookupKey<K>& key, const Entry& entry) const {
      return (*this)(entry, key);
    }
  };

  // INVARIANT: The values are pairwise distinct.
  Values values_;

  // INVARIANT: Contains exactly one entry `e` for each value `v` in `values_`,
  // where `e.index` is the index of `v` in `values_` and `e.hash == HashOf(v)`.
  absl::flat_hash_set<Entry, Hash, Eq> index_by_value_;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_INTERNED_VECTOR_H_
