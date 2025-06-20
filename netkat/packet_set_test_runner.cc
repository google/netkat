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
// -----------------------------------------------------------------------------

#include <iostream>
#include <ostream>
#include <string>
#include <vector>

#include "netkat/netkat_proto_constructors.h"
#include "netkat/packet_set.h"

namespace netkat {
namespace {

constexpr char kBanner[] =
    "=========================================================================="
    "======\n";
constexpr char kDotRawHeader[] =
    "-- DOT -------------------------------------------------------------------"
    "------\n";
constexpr char kDotUrlHeader[] =
    "-- URL -------------------------------------------------------------------"
    "------\n";
constexpr char kStringHeader[] =
    "-- STRING ----------------------------------------------------------------"
    "------\n";

// A test case for the `ValidateTestRun` function.
struct TestCase {
  // Human-readable description of this test case, for documentation.
  std::string description;
  PredicateProto predicate;
};

std::vector<TestCase> TestCases() {
  std::vector<TestCase> test_cases;

  PredicateProto p =
      OrProto(AndProto(MatchProto("a", 3), MatchProto("b", 4)),
              AndProto(NotProto(MatchProto("b", 5)), MatchProto("c", 5)));
  test_cases.push_back({
      .description =
          "p := (a=3 && b=4) || (b!=5 && c=5). Example from Katch paper Fig 3.",
      .predicate = p,
  });

  PredicateProto q =
      OrProto(AndProto(MatchProto("b", 3), MatchProto("c", 4)),
              AndProto(MatchProto("a", 5), NotProto(MatchProto("c", 5))));
  test_cases.push_back({
      .description =
          "q := (b=3 && c=4) || (a=5 && c!=5). Example from Katch paper Fig 3.",
      .predicate = q,
  });

  test_cases.push_back({
      .description = "p + q. Example from Katch paper Fig 3.",
      .predicate = OrProto(p, q),
  });

  return test_cases;
}

void main() {
  // This test needs a deterministic field interning order, and thus must start
  // from a fresh manager.
  PacketSetManager manager;
  for (const TestCase& test_case : TestCases()) {
    netkat::PacketSetHandle packet_set = manager.Compile(test_case.predicate);
    std::cout << kBanner << "Test case: " << test_case.description << std::endl
              << kBanner;
    std::cout << kStringHeader << manager.ToString(packet_set);
    std::cout << kDotRawHeader << manager.ToDotRaw(packet_set) << std::endl;
    std::cout << kDotUrlHeader << manager.ToDotUrl(packet_set) << std::endl;
  }
}

}  // namespace
}  // namespace netkat

int main() { netkat::main(); }
