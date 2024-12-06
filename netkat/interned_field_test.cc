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
#include "gutil/status_matchers.h"

namespace netkat {

namespace {

using testing::StartsWith;

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

TEST(InternedFieldManagerTest, AbslStringifyWorkst) {
  EXPECT_THAT(absl::StrCat(Manager().InternField("foo")),
              StartsWith("InternedField"));
}

TEST(InternedFieldManagerTest, AbslHashValueWorks) {
  absl::flat_hash_set<InternedField> set = {
      Manager().InternField("foo"),
      Manager().InternField("bar"),
  };
  EXPECT_EQ(set.size(), 2);
}

TEST(InternedFieldManagerTest, InternFieldReturnsSameFieldForSameName) {
  EXPECT_EQ(Manager().InternField("foo"), Manager().InternField("foo"));
}

TEST(InternedFieldManagerTest,
     InternFieldReturnsDifferentFieldForDifferentNames) {
  EXPECT_NE(Manager().InternField("foo"), Manager().InternField("bar"));
}

TEST(InternedFieldManagerTest, GetFieldNameOrDieReturnsNameOfInternedField) {
  InternedField foo = Manager().InternField("foo");
  InternedField bar = Manager().InternField("bar");
  EXPECT_EQ(Manager().GetFieldNameOrDie(foo), "foo");
  EXPECT_EQ(Manager().GetFieldNameOrDie(bar), "bar");
}
}  // namespace
}  // namespace netkat
