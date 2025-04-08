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

#include "netkat/interned_field.h"

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/status_matchers.h"  // IWYU pragma: keep

namespace netkat {

namespace {

using ::testing::StartsWith;

// We use a global manager object across all tests to exercise statefulness.
InternedFieldManager& Manager() {
  static absl::NoDestructor<InternedFieldManager> manager;
  return *manager;
}

// After executing all tests, we check once that no invariants are violated.
class CheckInternedFieldManagerInvariantsOnTearDown
    : public testing::Environment {
 public:
  ~CheckInternedFieldManagerInvariantsOnTearDown() override {}
  void SetUp() override {}
  void TearDown() override { ASSERT_OK(Manager().CheckInternalInvariants()); }
};
testing::Environment* const foo_env = testing::AddGlobalTestEnvironment(
    new CheckInternedFieldManagerInvariantsOnTearDown);

TEST(InternedFieldManagerTest, AbslStringifyWorks) {
  EXPECT_THAT(absl::StrCat(Manager().GetOrCreateInternedField("foo")),
              StartsWith("InternedField"));
}

TEST(InternedFieldManagerTest, AbslHashValueWorks) {
  absl::flat_hash_set<InternedField> set = {
      Manager().GetOrCreateInternedField("foo"),
      Manager().GetOrCreateInternedField("bar"),
  };
  EXPECT_EQ(set.size(), 2);
}

TEST(InternedFieldManagerTest,
     GetOrCreateInternedFieldReturnsSameFieldForSameName) {
  EXPECT_EQ(Manager().GetOrCreateInternedField("foo"),
            Manager().GetOrCreateInternedField("foo"));
}

TEST(InternedFieldManagerTest,
     GetOrCreateInternedFieldReturnsDifferentFieldForDifferentNames) {
  EXPECT_NE(Manager().GetOrCreateInternedField("foo"),
            Manager().GetOrCreateInternedField("bar"));
}

TEST(InternedFieldManagerTest, GetFieldNameReturnsNameOfInternedField) {
  InternedField foo = Manager().GetOrCreateInternedField("foo");
  InternedField bar = Manager().GetOrCreateInternedField("bar");
  EXPECT_EQ(Manager().GetFieldName(foo), "foo");
  EXPECT_EQ(Manager().GetFieldName(bar), "bar");
}
}  // namespace
}  // namespace netkat
