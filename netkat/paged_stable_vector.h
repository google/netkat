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
// File: paged_stable_vector.h
// -----------------------------------------------------------------------------

#ifndef GOOGLE_NETKAT_NETKAT_PAGED_STABLE_VECTOR_H_
#define GOOGLE_NETKAT_NETKAT_PAGED_STABLE_VECTOR_H_

#include <cstddef>
#include <utility>
#include <vector>

namespace netkat {

// A variant of `std::vector` that allocates memory in pages (or "chunks") of
// fixed `PageSize`. This introduces an extra level of indirection and
// introduces some level of discontiguity (depending on `PageSize`), but allows
// the class to guarantee pointer stability: calls to `push_back`/`emplace_back`
// never invalidate pointers/iterators/references to elements previously added
// to the vector.
//
// Allocating memory in pages also avoids the cost of relocation, which may be
// significant for very large vectors in performance-sensitive applications.
//
// The API of this class is kept just large enough to cover our use cases.
template <class T, size_t PageSize>
class PagedStableVector {
 public:
  PagedStableVector() = default;

  size_t size() const {
    return data_.empty() ? 0
                         : (data_.size() - 1) * PageSize + data_.back().size();
  }

  template <class Value>
  void push_back(Value&& value) {
    if (size() % PageSize == 0) data_.emplace_back().reserve(PageSize);
    data_.back().push_back(std::forward<Value>(value));
  }

  template <class... Args>
  void emplace_back(Args&&... value) {
    if (size() % PageSize == 0) data_.emplace_back().reserve(PageSize);
    data_.back().emplace_back(std::forward<Args>(value)...);
  }

  T& operator[](size_t index) {
    return data_[index / PageSize][index % PageSize];
  }
  const T& operator[](size_t index) const {
    return data_[index / PageSize][index % PageSize];
  }

 private:
  std::vector<std::vector<T>> data_;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_PAGED_STABLE_VECTOR_H_
