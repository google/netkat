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

#include "netkat/sorted_vector_map.h"

#include <map>
#include <utility>
#include <vector>

#include "absl/container/inlined_vector.h"
#include "absl/hash/hash_testing.h"
#include "fuzztest/fuzztest.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace netkat {
namespace {

using ::testing::ElementsAre;
using ::testing::IsEmpty;
using ::testing::Pair;

using Map = SortedVectorMap<int, int>;
using InlinedMap =
    SortedVectorMap<int, int, absl::InlinedVector<std::pair<int, int>, 2>>;

TEST(SortedVectorMapTest, DefaultConstructedMapIsEmpty) {
  Map map;
  EXPECT_TRUE(map.empty());
  EXPECT_EQ(map.size(), 0);
  EXPECT_THAT(map, IsEmpty());
}

TEST(SortedVectorMapTest, InitializerListConstructorSortsEntries) {
  Map map = {{3, 30}, {1, 10}, {2, 20}};
  EXPECT_THAT(map, ElementsAre(Pair(1, 10), Pair(2, 20), Pair(3, 30)));
}

TEST(SortedVectorMapTest, FindAndContains) {
  Map map = {{1, 10}, {3, 30}};
  EXPECT_TRUE(map.contains(1));
  EXPECT_FALSE(map.contains(2));
  EXPECT_TRUE(map.contains(3));
  ASSERT_NE(map.find(3), map.end());
  EXPECT_EQ(map.find(3)->second, 30);
  EXPECT_EQ(map.find(0), map.end());
  EXPECT_EQ(map.find(2), map.end());
  EXPECT_EQ(map.find(4), map.end());
}

TEST(SortedVectorMapTest, TryEmplaceDoesNotOverwrite) {
  Map map;
  EXPECT_TRUE(map.try_emplace(2, 20).second);
  EXPECT_TRUE(map.try_emplace(1, 10).second);
  EXPECT_TRUE(map.try_emplace(3, 30).second);
  auto [it, inserted] = map.try_emplace(2, 42);
  EXPECT_FALSE(inserted);
  EXPECT_EQ(it->second, 20);
  EXPECT_THAT(map, ElementsAre(Pair(1, 10), Pair(2, 20), Pair(3, 30)));
}

TEST(SortedVectorMapTest, SubscriptOperatorDefaultConstructs) {
  Map map;
  map[5] += 1;
  map[5] += 1;
  map[3] = 7;
  EXPECT_THAT(map, ElementsAre(Pair(3, 7), Pair(5, 2)));
}

TEST(SortedVectorMapTest, EraseIf) {
  Map map = {{1, 10}, {2, 20}, {3, 30}, {4, 40}};
  EXPECT_EQ(erase_if(map, [](const auto& entry) { return entry.first % 2; }),
            2);
  EXPECT_THAT(map, ElementsAre(Pair(2, 20), Pair(4, 40)));
}

TEST(SortedVectorMapTest, EqualityAndHashing) {
  EXPECT_TRUE(absl::VerifyTypeImplementsAbslHashCorrectly({
      Map(),
      Map{{1, 10}},
      Map{{1, 11}},
      Map{{2, 10}},
      Map{{1, 10}, {2, 20}},
      Map{{1, 20}, {2, 10}},
  }));
}

// Checks that `SortedVectorMap` behaves like `std::map` under a random
// sequence of operations.
template <class M>
void BehavesLikeStdMap(const std::vector<std::pair<int, int>>& operations) {
  M map;
  std::map<int, int> reference;
  for (const auto& [k, value] : operations) {
    const int key = k;
    if (value % 3 == 0) {
      EXPECT_EQ(map.try_emplace(key, value).second,
                reference.try_emplace(key, value).second);
    } else if (value % 3 == 1) {
      map[key] = value;
      reference[key] = value;
    } else {
      erase_if(map, [&](const auto& entry) { return entry.first == key; });
      std::erase_if(reference,
                    [&](const auto& entry) { return entry.first == key; });
    }
    ASSERT_TRUE(std::equal(map.begin(), map.end(), reference.begin(),
                           reference.end(), [](const auto& a, const auto& b) {
                             return a.first == b.first && a.second == b.second;
                           }));
    EXPECT_EQ(map.contains(key), reference.contains(key));
  }
}

void VectorMapBehavesLikeStdMap(
    const std::vector<std::pair<int, int>>& operations) {
  BehavesLikeStdMap<Map>(operations);
}
FUZZ_TEST(SortedVectorMapTest, VectorMapBehavesLikeStdMap)
    .WithDomains(fuzztest::VectorOf(fuzztest::PairOf(
        fuzztest::InRange(0, 20), fuzztest::Arbitrary<int>())));

void InlinedMapBehavesLikeStdMap(
    const std::vector<std::pair<int, int>>& operations) {
  BehavesLikeStdMap<InlinedMap>(operations);
}
FUZZ_TEST(SortedVectorMapTest, InlinedMapBehavesLikeStdMap)
    .WithDomains(fuzztest::VectorOf(fuzztest::PairOf(
        fuzztest::InRange(0, 20), fuzztest::Arbitrary<int>())));

}  // namespace
}  // namespace netkat
