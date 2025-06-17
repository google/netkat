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

#include "netkat/packet_field.h"

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
PacketFieldManager& Manager() {
  static absl::NoDestructor<PacketFieldManager> manager;
  return *manager;
}

// After executing all tests, we check once that no invariants are violated.
class CheckPacketFieldManagerInvariantsOnTearDown
    : public testing::Environment {
 public:
  ~CheckPacketFieldManagerInvariantsOnTearDown() override = default;
  void SetUp() override {}
  void TearDown() override { ASSERT_OK(Manager().CheckInternalInvariants()); }
};
testing::Environment* const foo_env = testing::AddGlobalTestEnvironment(
    new CheckPacketFieldManagerInvariantsOnTearDown);

TEST(PacketFieldManagerTest, AbslStringifyWorks) {
  EXPECT_THAT(absl::StrCat(Manager().GetOrCreatePacketFieldHandle("foo")),
              StartsWith("PacketFieldHandle"));
}

TEST(PacketFieldManagerTest, AbslHashValueWorks) {
  absl::flat_hash_set<PacketFieldHandle> set = {
      Manager().GetOrCreatePacketFieldHandle("foo"),
      Manager().GetOrCreatePacketFieldHandle("bar"),
  };
  EXPECT_EQ(set.size(), 2);
}

TEST(PacketFieldManagerTest,
     GetOrCreatePacketFieldHandleReturnsSameFieldForSameName) {
  EXPECT_EQ(Manager().GetOrCreatePacketFieldHandle("foo"),
            Manager().GetOrCreatePacketFieldHandle("foo"));
}

TEST(PacketFieldManagerTest,
     GetOrCreatePacketFieldHandleReturnsDifferentFieldForDifferentNames) {
  EXPECT_NE(Manager().GetOrCreatePacketFieldHandle("foo"),
            Manager().GetOrCreatePacketFieldHandle("bar"));
}

TEST(PacketFieldManagerTest, GetFieldNameReturnsNameOfPacketFieldHandle) {
  PacketFieldHandle foo = Manager().GetOrCreatePacketFieldHandle("foo");
  PacketFieldHandle bar = Manager().GetOrCreatePacketFieldHandle("bar");
  EXPECT_EQ(Manager().GetFieldName(foo), "foo");
  EXPECT_EQ(Manager().GetFieldName(bar), "bar");
}
}  // namespace
}  // namespace netkat
