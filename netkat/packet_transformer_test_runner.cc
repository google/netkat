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
#include "netkat/packet_transformer.h"

namespace netkat {
namespace {

constexpr char kBanner[] =
    "=========================================================================="
    "======\n";
constexpr char kDotHeader[] =
    "-- DOT -------------------------------------------------------------------"
    "------\n";
constexpr char kStringHeader[] =
    "-- STRING ----------------------------------------------------------------"
    "------\n";

// A test case for the `ValidateTestRun` function.
struct TestCase {
  // Human-readable description of this test case, for documentation.
  std::string description;
  PolicyProto policy;
};

std::vector<TestCase> TestCases() {
  std::vector<TestCase> test_cases;
  test_cases.push_back({
      .description = "p := F. Deny policy.",
      .policy = DenyProto(),
  });
  test_cases.push_back({
      .description = "p := T. Accept policy.",
      .policy = AcceptProto(),
  });
  test_cases.push_back({
      .description = "p := (a!=5). Empty modify branch creates a deny path.",
      .policy = FilterProto(NotProto(MatchProto("a", 5))),
  });

  PolicyProto p = SequenceProto(
      UnionProto(FilterProto(MatchProto("a", 5)),
                 FilterProto(MatchProto("b", 2))),
      UnionProto(ModificationProto("b", 1), FilterProto(MatchProto("c", 5))));

  test_cases.push_back({
      .description =
          "p := (a=5 + b=2);(b:=1 + c=5). Example from Katch paper Fig 5.",
      .policy = p,
  });

  PolicyProto q = UnionProto(
      FilterProto(MatchProto("b", 1)),
      UnionProto(
          ModificationProto("c", 4),
          SequenceProto(ModificationProto("a", 1), ModificationProto("b", 1))));

  test_cases.push_back({
      .description =
          "q := (b=1 + c:=4 + a:=5;b:=1). Example from Katch paper Fig 5.",
      .policy = q,
  });

  test_cases.push_back({
      .description = "p;q. Example from Katch paper Fig 5.",
      .policy = SequenceProto(p, q),
  });

  return test_cases;
}

void main() {
  // This test needs a deterministic field interning order, and thus must start
  // from a fresh manager.
  PacketTransformerManager manager;
  for (const TestCase& test_case : TestCases()) {
    netkat::PacketTransformerHandle packet_transformer =
        manager.Compile(test_case.policy);
    std::cout << kBanner << "Test case: " << test_case.description << std::endl
              << kBanner;
    std::cout << kStringHeader << manager.ToString(packet_transformer);
    std::cout << kDotHeader << manager.ToDot(packet_transformer);
  }
}

}  // namespace
}  // namespace netkat

int main() { netkat::main(); }
