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
// -----------------------------------------------------------------------------

#include "netkat/symbolic_packet.h"

#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "gtest/gtest.h"

namespace netkat {
namespace {

TEST(SymbolicPacketTest, DefaultConstructorYieldsEmptySet) {
  EXPECT_TRUE(SymbolicPacket().IsEmptySet());
}

TEST(SymbolicPacketTest, EmptySetIsEmptySet) {
  EXPECT_TRUE(SymbolicPacket::EmptySet().IsEmptySet());
}

TEST(SymbolicPacketTest, FullSetIsFullSet) {
  EXPECT_TRUE(SymbolicPacket::FullSet().IsFullSet());
}

TEST(SymbolicPacketTest, EmptySetDoesNotEqualFullSet) {
  EXPECT_NE(SymbolicPacket::EmptySet(), SymbolicPacket::FullSet());
}

TEST(SymbolicPacketTest, AbslStringifyWorksForEmptySet) {
  EXPECT_EQ(absl::StrCat(SymbolicPacket::EmptySet()), "SymbolicPacket<false>");
}

TEST(SymbolicPacketTest, AbslStringifyWorksForFullSet) {
  EXPECT_EQ(absl::StrCat(SymbolicPacket::FullSet()), "SymbolicPacket<true>");
}

TEST(SymbolicPacketTest, AbslHashValueWorks) {
  absl::flat_hash_set<SymbolicPacket> set = {
      SymbolicPacket::EmptySet(),
      SymbolicPacket::FullSet(),
  };
  EXPECT_EQ(set.size(), 2);
}

}  // namespace
}  // namespace netkat
