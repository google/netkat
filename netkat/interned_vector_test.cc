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

#include "netkat/interned_vector.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "fuzztest/fuzztest.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/status_matchers.h"  // IWYU pragma: keep

namespace netkat {
namespace {

using ::testing::Pair;

TEST(InternedVectorTest, DefaultConstructedVectorIsEmpty) {
  InternedVector<std::string, 4> vector;
  EXPECT_EQ(vector.size(), 0);
  EXPECT_OK(vector.CheckInternalInvariants());
}

TEST(InternedVectorTest, InterningNewValuesAppendsThem) {
  InternedVector<std::string, 2> vector;
  EXPECT_THAT(vector.Intern("a"), Pair(0, true));
  EXPECT_THAT(vector.Intern("b"), Pair(1, true));
  EXPECT_THAT(vector.Intern("c"), Pair(2, true));
  ASSERT_EQ(vector.size(), 3);
  EXPECT_EQ(vector[0], "a");
  EXPECT_EQ(vector[1], "b");
  EXPECT_EQ(vector[2], "c");
  EXPECT_OK(vector.CheckInternalInvariants());
}

TEST(InternedVectorTest, InterningExistingValuesReturnsTheirIndex) {
  InternedVector<std::string, 2> vector;
  EXPECT_THAT(vector.Intern("a"), Pair(0, true));
  EXPECT_THAT(vector.Intern("b"), Pair(1, true));
  EXPECT_THAT(vector.Intern("a"), Pair(0, false));
  EXPECT_THAT(vector.Intern("b"), Pair(1, false));
  EXPECT_EQ(vector.size(), 2);
  EXPECT_OK(vector.CheckInternalInvariants());
}

TEST(InternedVectorTest, ReferencesAreStable) {
  InternedVector<int, 2> vector;
  vector.Intern(42);
  const int& first = vector[0];
  for (int i = 0; i < 1000; ++i) vector.Intern(int{i});
  EXPECT_EQ(&first, &vector[0]);
  EXPECT_EQ(first, 42);
}

TEST(InternedVectorTest, MoveConstructionPreservesContents) {
  InternedVector<std::string, 2> vector;
  vector.Intern("a");
  vector.Intern("b");
  InternedVector<std::string, 2> moved = std::move(vector);
  EXPECT_THAT(moved.Intern("b"), Pair(1, false));
  EXPECT_THAT(moved.Intern("c"), Pair(2, true));
  EXPECT_OK(moved.CheckInternalInvariants());
}

// Checks `InternedVector` against a simple reference implementation.
void BehavesLikeVectorPlusHashMap(const std::vector<int>& values) {
  InternedVector<int, 3> vector;
  std::vector<int> reference_values;
  absl::flat_hash_map<int, uint32_t> reference_index_by_value;
  for (int value : values) {
    auto [reference_it, reference_inserted] = reference_index_by_value.insert(
        {value, static_cast<uint32_t>(reference_values.size())});
    if (reference_inserted) reference_values.push_back(value);
    EXPECT_THAT(vector.Intern(int{value}),
                Pair(reference_it->second, reference_inserted));
  }
  ASSERT_EQ(vector.size(), reference_values.size());
  for (size_t i = 0; i < reference_values.size(); ++i) {
    EXPECT_EQ(vector[i], reference_values[i]);
  }
  EXPECT_OK(vector.CheckInternalInvariants());
}
FUZZ_TEST(InternedVectorTest, BehavesLikeVectorPlusHashMap)
    .WithDomains(fuzztest::VectorOf(fuzztest::InRange(-50, 50)));

}  // namespace
}  // namespace netkat
