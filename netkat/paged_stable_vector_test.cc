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

#include "netkat/paged_stable_vector.h"

#include <string>
#include <vector>

#include "fuzztest/fuzztest.h"
#include "gtest/gtest.h"

namespace netkat {
namespace {

// A small, but otherwise random page size used throughout the tests.
// Using a small page size is useful for exercising the page replacement logic.
static constexpr int kSmallPageSize = 3;

void PushBackInreasesSize(std::vector<std::string> elements) {
  PagedStableVector<std::string, kSmallPageSize> vector;
  for (const auto& element : elements) {
    vector.push_back(element);
  }
  EXPECT_EQ(vector.size(), elements.size());
}
FUZZ_TEST(PagedStableVectorTest, PushBackInreasesSize);

void EmplaceBackInreasesSize(std::vector<int> elements) {
  PagedStableVector<int, kSmallPageSize> vector;
  for (const auto& element : elements) {
    vector.emplace_back(element);
  }
  EXPECT_EQ(vector.size(), elements.size());
}
FUZZ_TEST(PagedStableVectorTest, EmplaceBackInreasesSize);

void PushBackAddsElementToBack(std::vector<std::string> elements) {
  PagedStableVector<std::string, kSmallPageSize> vector;
  for (int i = 0; i < elements.size(); ++i) {
    vector.push_back(elements[i]);
    for (int j = 0; j < i; ++j) {
      EXPECT_EQ(vector[j], elements[j]);
    }
  }
}
FUZZ_TEST(PagedStableVectorTest, PushBackAddsElementToBack);

void EmplaceBackAddsElementToBack(std::vector<int> elements) {
  PagedStableVector<int, kSmallPageSize> vector;
  for (int i = 0; i < elements.size(); ++i) {
    vector.emplace_back(elements[i]);
    for (int j = 0; j < i; ++j) {
      EXPECT_EQ(vector[j], elements[j]);
    }
  }
}
FUZZ_TEST(PagedStableVectorTest, EmplaceBackAddsElementToBack);

void BracketAssigmentWorks(std::vector<std::string> elements) {
  PagedStableVector<std::string, kSmallPageSize> vector;
  for (int i = 0; i < elements.size(); ++i) {
    vector.push_back("initial value");
  }
  for (int i = 0; i < elements.size(); ++i) {
    vector[i] = elements[i];
  }
  for (int i = 0; i < elements.size(); ++i) {
    EXPECT_EQ(vector[i], elements[i]);
  }
}
FUZZ_TEST(PagedStableVectorTest, BracketAssigmentWorks);

TEST(PagedStableVectorTest, ReferencesDontGetInvalidated) {
  PagedStableVector<std::string, kSmallPageSize> vector;

  // Store a few references.
  vector.push_back("first element");
  std::string* first_element_ptr = &vector[0];
  vector.push_back("second element");
  std::string* second_element_ptr = &vector[1];

  // Push a ton of elements to trigger page allocation.
  // If this were a regular std::vector, the references would be invalidated.
  for (int i = 0; i < 100 * kSmallPageSize; ++i) {
    vector.push_back("dummy");
  }

  // Check that the references are still valid.
  EXPECT_EQ(&vector[0], first_element_ptr);
  EXPECT_EQ(&vector[1], second_element_ptr);
};

}  // namespace
}  // namespace netkat
