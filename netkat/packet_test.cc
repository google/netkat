// Copyright 2026 The NetKAT authors
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

#include "netkat/packet.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace netkat {
namespace {

using ::testing::AllOf;
using ::testing::HasSubstr;

TEST(PacketTest, EmptyPacketToString) {
  Packet packet;
  EXPECT_EQ(PacketToString(packet), "{}");
}

TEST(PacketTest, SingleFieldPacketToString) {
  Packet packet;
  packet["port"] = 80;
  EXPECT_EQ(PacketToString(packet), "{port=80}");
}

TEST(PacketTest, MultiFieldPacketToString) {
  Packet packet;
  packet["port"] = 80;
  packet["ip"] = 123;
  std::string s = PacketToString(packet);
  // Order of elements in flat_hash_map is not guaranteed, so we check for
  // substrings.
  EXPECT_THAT(s, AllOf(HasSubstr("{"), HasSubstr("}"), HasSubstr("port=80"),
                       HasSubstr("ip=123")));
}

}  // namespace
}  // namespace netkat
