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
// File: sorted_vector_map.h
// -----------------------------------------------------------------------------
//
// Defines `SortedVectorMap`, a map backed by a sorted, contiguous sequence of
// key-value pairs.
//
// Compared to node-based maps like `absl::btree_map` or `std::map`, this
// representation is compact, cache-friendly, cheap to copy/hash/compare, and
// supports O(1) appends of keys larger than all existing keys -- the dominant
// insertion pattern when maps are built by merging sorted inputs. In exchange,
// inserting a key in the middle of the map is O(n). This makes it a good fit
// for small maps and maps that are built in sorted order, as is the case for
// the decision nodes of `PacketTransformerManager`.

#ifndef GOOGLE_NETKAT_NETKAT_SORTED_VECTOR_MAP_H_
#define GOOGLE_NETKAT_NETKAT_SORTED_VECTOR_MAP_H_

#include <algorithm>
#include <cstddef>
#include <initializer_list>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/log/check.h"

namespace netkat {

// A map from `Key` to `Value`, represented as a sequence of key-value pairs
// sorted by strictly increasing key, stored in a `Container` (e.g.
// `std::vector` or `absl::InlinedVector`).
template <class Key, class Value,
          class Container = std::vector<std::pair<Key, Value>>>
class SortedVectorMap {
 public:
  using key_type = Key;
  using mapped_type = Value;
  using value_type = std::pair<Key, Value>;
  using iterator = typename Container::iterator;
  using const_iterator = typename Container::const_iterator;

  SortedVectorMap() = default;
  template <class InputIt>
  SortedVectorMap(InputIt first, InputIt last) : entries_(first, last) {
    DCHECK(absl::c_is_sorted(entries_, KeyLess()));
    DCHECK(absl::c_adjacent_find(entries_, KeyEqual()) == entries_.end())
        << "duplicate keys";
  }
  SortedVectorMap(std::initializer_list<value_type> entries)
      : entries_(entries) {
    absl::c_sort(entries_, KeyLess());
    DCHECK(absl::c_adjacent_find(entries_, KeyEqual()) == entries_.end())
        << "duplicate keys";
  }

  iterator begin() { return entries_.begin(); }
  iterator end() { return entries_.end(); }
  const_iterator begin() const { return entries_.begin(); }
  const_iterator end() const { return entries_.end(); }
  size_t size() const { return entries_.size(); }
  bool empty() const { return entries_.empty(); }
  void clear() { entries_.clear(); }
  void reserve(size_t n) { entries_.reserve(n); }

  // Returns an iterator to the entry with the given `key`, or `end()`.
  iterator find(const Key& key) {
    auto it = LowerBound(key);
    return it != end() && it->first == key ? it : end();
  }
  const_iterator find(const Key& key) const {
    auto it = LowerBound(key);
    return it != end() && it->first == key ? it : end();
  }
  bool contains(const Key& key) const { return find(key) != end(); }

  // Inserts an entry (`key`, Value(args...)) if no entry with the given `key`
  // exists. Returns an iterator to the entry with the given `key`, and whether
  // an insertion took place. O(1) if `key` is larger than all existing keys,
  // O(n) otherwise.
  template <class... Args>
  std::pair<iterator, bool> try_emplace(const Key& key, Args&&... args) {
    if (entries_.empty() || entries_.back().first < key) {
      entries_.emplace_back(std::piecewise_construct,
                            std::forward_as_tuple(key),
                            std::forward_as_tuple(std::forward<Args>(args)...));
      return {entries_.end() - 1, true};
    }
    auto it = LowerBound(key);
    if (it != end() && it->first == key) return {it, false};
    it = entries_.emplace(it, std::piecewise_construct,
                          std::forward_as_tuple(key),
                          std::forward_as_tuple(std::forward<Args>(args)...));
    return {it, true};
  }

  Value& operator[](const Key& key) { return try_emplace(key).first->second; }

  // Inserts the given `entry` if no entry with the same key exists. The
  // `hint` is ignored, and only provided for compatibility with standard maps.
  // O(1) if the key is larger than all existing keys, O(n) otherwise.
  iterator insert(const_iterator /*hint*/, value_type entry) {
    return try_emplace(entry.first, std::move(entry.second)).first;
  }

  // Removes all entries satisfying `predicate`. Returns number removed.
  template <class Predicate>
  friend size_t erase_if(SortedVectorMap& map, Predicate predicate) {
    auto it = std::remove_if(map.entries_.begin(), map.entries_.end(),
                             std::move(predicate));
    size_t num_removed = map.entries_.end() - it;
    map.entries_.erase(it, map.entries_.end());
    return num_removed;
  }

  friend bool operator==(const SortedVectorMap& a, const SortedVectorMap& b) {
    return absl::c_equal(a.entries_, b.entries_);
  }

  // Hashing, see https://abseil.io/docs/cpp/guides/hash.
  template <typename H>
  friend H AbslHashValue(H h, const SortedVectorMap& map) {
    for (const auto& [key, value] : map.entries_) {
      h = H::combine(std::move(h), key, value);
    }
    return H::combine(std::move(h), map.entries_.size());
  }

 private:
  struct KeyLess {
    bool operator()(const value_type& a, const value_type& b) const {
      return a.first < b.first;
    }
  };
  struct KeyEqual {
    bool operator()(const value_type& a, const value_type& b) const {
      return a.first == b.first;
    }
  };

  iterator LowerBound(const Key& key) {
    return std::lower_bound(entries_.begin(), entries_.end(), key,
                            [](const value_type& entry, const Key& key) {
                              return entry.first < key;
                            });
  }
  const_iterator LowerBound(const Key& key) const {
    return std::lower_bound(entries_.begin(), entries_.end(), key,
                            [](const value_type& entry, const Key& key) {
                              return entry.first < key;
                            });
  }

  // INVARIANT: Sorted by strictly increasing key.
  Container entries_;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_SORTED_VECTOR_MAP_H_
