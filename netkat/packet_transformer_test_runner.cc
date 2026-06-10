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
// To generate the `packet_transformer_test.expected` file, run:
//  `bazel run //netkat:packet_transformer_diff_test
//  -- --update`

#include <iostream>
#include <ostream>
#include <string>
#include <vector>

#include "absl/container/btree_set.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "netkat/netkat_proto_constructors.h"
#include "netkat/packet_field.h"
#include "netkat/packet_transformer.h"

namespace netkat {

// Test peer to access `PacketTransformerManager` internals, allowing this
// runner to renumber nodes canonically before printing.
class PacketTransformerManagerTestPeer {
 public:
  // Copies `transformer` into the fresh manager `to`, interning fields and
  // nodes in a deterministic traversal order. This makes the printed handle
  // numbers depend only on the structure of `transformer` — not on the
  // interning order of `from`, which is an implementation detail that changes
  // under refactorings of the manager (e.g. reordering its operations).
  static PacketTransformerHandle CanonicalCopy(
      const PacketTransformerManager& from, PacketTransformerHandle transformer,
      PacketTransformerManager& to) {
    // Intern the fields of all reachable nodes in their original relative
    // order, which the node invariants ("fields increase strictly along each
    // path") depend on, and record the handle translation for `Copy`.
    absl::btree_set<PacketFieldHandle> fields;
    absl::flat_hash_set<PacketTransformerHandle> visited;
    CollectFields(from, transformer, visited, fields);
    absl::flat_hash_map<PacketFieldHandle, PacketFieldHandle> field_translation;
    for (PacketFieldHandle field : fields) {
      field_translation.try_emplace(
          field,
          to.packet_set_manager_.field_manager_.GetOrCreatePacketFieldHandle(
              from.packet_set_manager_.field_manager_.GetFieldName(field)));
    }

    absl::flat_hash_map<PacketTransformerHandle, PacketTransformerHandle>
        copy_by_original;
    return Copy(from, transformer, to, field_translation, copy_by_original);
  }

 private:
  static void CollectFields(
      const PacketTransformerManager& from, PacketTransformerHandle transformer,
      absl::flat_hash_set<PacketTransformerHandle>& visited,
      absl::btree_set<PacketFieldHandle>& fields) {
    if (from.IsDeny(transformer) || from.IsAccept(transformer)) return;
    if (!visited.insert(transformer).second) return;
    const PacketTransformerManager::DecisionNode& node =
        from.GetNodeOrDie(transformer);
    fields.insert(node.field);
    // All match and default modify entries live in the node's flat `modifies`
    // array, so one pass visits every branch.
    for (const auto& [modify_value, branch] : node.modifies) {
      CollectFields(from, branch, visited, fields);
    }
    CollectFields(from, node.default_branch, visited, fields);
  }

  static PacketTransformerHandle Copy(
      const PacketTransformerManager& from, PacketTransformerHandle transformer,
      PacketTransformerManager& to,
      const absl::flat_hash_map<PacketFieldHandle, PacketFieldHandle>&
          field_translation,
      absl::flat_hash_map<PacketTransformerHandle, PacketTransformerHandle>&
          copy_by_original) {
    if (from.IsDeny(transformer)) return to.Deny();
    if (from.IsAccept(transformer)) return to.Accept();
    if (auto it = copy_by_original.find(transformer);
        it != copy_by_original.end()) {
      return it->second;
    }

    const PacketTransformerManager::DecisionNode& node =
        from.GetNodeOrDie(transformer);
    PacketTransformerManager::DecisionNodeBuilder copy{
        .field = field_translation.at(node.field),
    };
    for (const auto& match : node.Matches()) {
      // `operator[]` keeps entries with empty branch maps, which are
      // meaningful: they deny packets matching `match.value`.
      auto& copy_branch_by_modify =
          copy.modify_branch_by_field_match[match.value];
      for (const auto& [modify_value, branch] : match.modifies) {
        copy_branch_by_modify[modify_value] =
            Copy(from, branch, to, field_translation, copy_by_original);
      }
    }
    for (const auto& [modify_value, branch] : node.DefaultModifies()) {
      copy.default_branch_by_field_modification[modify_value] =
          Copy(from, branch, to, field_translation, copy_by_original);
    }
    copy.default_branch = Copy(from, node.default_branch, to, field_translation,
                               copy_by_original);

    PacketTransformerHandle result = to.NodeToTransformer(std::move(copy));
    copy_by_original.emplace(transformer, result);
    return result;
  }
};

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

// A test case for the `PacketTransformerManager::Compile` function.
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
  PacketTransformerManager manager;
  for (const TestCase& test_case : TestCases()) {
    netkat::PacketTransformerHandle packet_transformer =
        manager.Compile(test_case.policy);
    // Renumber nodes and fields canonically, in a fresh manager per test case,
    // so that the printed output depends only on the structure of the compiled
    // transformer and not on the interning order of `manager`.
    PacketTransformerManager canonical_manager;
    netkat::PacketTransformerHandle canonical_transformer =
        PacketTransformerManagerTestPeer::CanonicalCopy(
            manager, packet_transformer, canonical_manager);
    std::cout << kBanner << "Test case: " << test_case.description << std::endl
              << kBanner;
    std::cout << kStringHeader
              << canonical_manager.ToString(canonical_transformer);
    std::cout << kDotHeader << canonical_manager.ToDot(canonical_transformer);
  }
}

}  // namespace
}  // namespace netkat

int main() { netkat::main(); }
