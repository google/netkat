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

#include "netkat/symbolic_packet_transformer.h"

#include <cstdint>
#include <ostream>
#include <utility>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "fuzztest/fuzztest.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/status_matchers.h"  // IWYU pragma: keep
#include "netkat/evaluator.h"
#include "netkat/netkat.pb.h"
#include "netkat/netkat_proto_constructors.h"
#include "netkat/symbolic_packet.h"
#include "re2/re2.h"

namespace netkat {

// We use a global manager object to exercise statefulness more deeply across
// test cases. This also enables better pretty printing for debugging, see
// `PrintTo`.
SymbolicPacketTransformerManager& Manager() {
  static absl::NoDestructor<SymbolicPacketTransformerManager> manager;
  return *manager;
}

// The default `SymbolicPacketTransformer` pretty printer sucks! It does not
// have access to the graph structure representing the packet, since that is
// stored in the manager object. Thus, it returns opaque strings like
// "SymbolicPacketTransformer<123>".
//
// We define this much better override, which GoogleTest gives precedence to.
void PrintTo(const SymbolicPacketTransformer& transformer, std::ostream* os) {
  *os << Manager().ToString(transformer);
}

namespace {

using ::testing::IsEmpty;
using ::testing::Pair;
using ::testing::StartsWith;
using ::testing::UnorderedElementsAre;

// After executing all tests, we check once that no invariants are violated, for
// defense in depth. Checking invariants after each test (e.g. using a fixture)
// would likely not scale and seems overkill.
class CheckSymbolicPacketTransformerManagerInvariantsOnTearDown
    : public testing::Environment {
 public:
  ~CheckSymbolicPacketTransformerManagerInvariantsOnTearDown() override =
      default;
  void SetUp() override {}
  void TearDown() override { ASSERT_OK(Manager().CheckInternalInvariants()); }
};
testing::Environment* const foo_env = testing::AddGlobalTestEnvironment(
    new CheckSymbolicPacketTransformerManagerInvariantsOnTearDown);

/*--- Basic tests ------------------------------------------------------------*/

TEST(SymbolicPacketTransformerManagerTest, DenyIsDeny) {
  EXPECT_TRUE(Manager().IsDeny(Manager().Deny()));
  EXPECT_FALSE(Manager().IsAccept(Manager().Deny()));
}

TEST(SymbolicPacketTransformerManagerTest, AcceptIsAccept) {
  EXPECT_TRUE(Manager().IsAccept(Manager().Accept()));
  EXPECT_FALSE(Manager().IsDeny(Manager().Accept()));
}

TEST(SymbolicPacketTransformerManagerTest, DenyDoesNotEqualAccept) {
  EXPECT_NE(Manager().Deny(), Manager().Accept());
}

TEST(SymbolicPacketTransformerManagerTest, AbslStringifyWorksForDeny) {
  EXPECT_THAT(absl::StrCat(Manager().Deny()),
              StartsWith("SymbolicPacketTransformer"));
}

TEST(SymbolicPacketTransformerManagerTest, AbslStringifyWorksForAccept) {
  EXPECT_THAT(absl::StrCat(Manager().Accept()),
              StartsWith("SymbolicPacketTransformer"));
}

TEST(SymbolicPacketTransformerManagerTest, AbslHashValueWorks) {
  absl::flat_hash_set<SymbolicPacketTransformer> set = {
      Manager().Deny(),
      Manager().Accept(),
  };
  EXPECT_EQ(set.size(), 2);
}

TEST(SymbolicPacketTransformerManagerTest, EmptyPolicyCompilesToDeny) {
  EXPECT_TRUE(Manager().IsDeny(Manager().Compile(PolicyProto())));
}

TEST(SymbolicPacketTransformerManagerTest, RecordPolicyCompilesToAccept) {
  EXPECT_TRUE(Manager().IsAccept(Manager().Compile(RecordProto())));
}

// Symbolic packet transformer compile should give the same result as
// SymbolicPacket -> OfSymbolicPacket, if PolicyProto is only a Filter.
void CompileIsSameAsOfCompiledSymbolicPacket(PredicateProto predicate) {
  SymbolicPacket packet1 =
      Manager().GetSymbolicPacketManager().Compile(predicate);
  EXPECT_EQ(Manager().Compile(FilterProto(predicate)),
            Manager().FromSymbolicPacket(packet1));

  // Using a newly constructed SymbolicPacketManager.
  SymbolicPacketManager packet_manager;
  SymbolicPacket packet2 = packet_manager.Compile(predicate);
  SymbolicPacketTransformerManager manager(std::move(packet_manager));
  EXPECT_EQ(manager.Compile(FilterProto(predicate)),
            manager.FromSymbolicPacket(packet2));
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest,
          CompileIsSameAsOfCompiledSymbolicPacket);

/*--- Basic compilation and method consistency checks ------------------------*/

TEST(SymbolicPacketTransformerManagerTest, AcceptCompilesToAccept) {
  EXPECT_EQ(Manager().Compile(AcceptProto()), Manager().Accept());
}

TEST(SymbolicPacketTransformerManagerTest, DenyCompilesToDeny) {
  EXPECT_EQ(Manager().Compile(DenyProto()), Manager().Deny());
}

void FilterCompilesToFilter(PredicateProto predicate) {
  EXPECT_EQ(Manager().Compile(FilterProto(predicate)),
            Manager().Filter(predicate));
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest, FilterCompilesToFilter);

void ModificationCompilesToModification(std::string field, int value) {
  EXPECT_EQ(Manager().Compile(ModificationProto(field, value)),
            Manager().Modification(field, value));
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest,
          ModificationCompilesToModification);

void UnionCompilesToUnion(PolicyProto left, PolicyProto right) {
  EXPECT_EQ(Manager().Compile(UnionProto(left, right)),
            Manager().Union(Manager().Compile(left), Manager().Compile(right)));
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest, UnionCompilesToUnion);

void SequenceCompilesToSequence(PolicyProto left, PolicyProto right) {
  EXPECT_EQ(
      Manager().Compile(SequenceProto(left, right)),
      Manager().Sequence(Manager().Compile(left), Manager().Compile(right)));
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest, SequenceCompilesToSequence);

void IterateCompilesToIterate(PolicyProto iterable) {
  EXPECT_EQ(Manager().Compile(IterateProto(iterable)),
            Manager().Iterate(Manager().Compile(iterable)));
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest, IterateCompilesToIterate);

/*--- Kleene algebra axioms and equivalences ---------------------------------*/

void UnionIsAssociative(PolicyProto a, PolicyProto b, PolicyProto c) {
  EXPECT_EQ(Manager().Compile(UnionProto(a, UnionProto(b, c))),
            Manager().Compile(UnionProto(UnionProto(a, b), c)));
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest, UnionIsAssociative);

void UnionIsCommutative(PolicyProto a, PolicyProto b) {
  EXPECT_EQ(Manager().Compile(UnionProto(a, b)),
            Manager().Compile(UnionProto(b, a)));
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest, UnionIsCommutative);

void UnionDenyIsIdentity(PolicyProto policy) {
  EXPECT_EQ(Manager().Compile(UnionProto(policy, DenyProto())),
            Manager().Compile(policy));
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest, UnionDenyIsIdentity);

void UnionIsIdempotent(PolicyProto policy) {
  EXPECT_EQ(Manager().Compile(UnionProto(policy, policy)),
            Manager().Compile(policy));
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest, UnionIsIdempotent);

void SequenceIsAssociative(PolicyProto a, PolicyProto b, PolicyProto c) {
  EXPECT_EQ(Manager().Compile(SequenceProto(a, SequenceProto(b, c))),
            Manager().Compile(SequenceProto(SequenceProto(a, b), c)));
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest, SequenceIsAssociative);

void SequenceAcceptIsIdentity(PolicyProto policy) {
  EXPECT_EQ(Manager().Compile(SequenceProto(policy, AcceptProto())),
            Manager().Compile(policy));
  EXPECT_EQ(Manager().Compile(SequenceProto(AcceptProto(), policy)),
            Manager().Compile(policy));
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest, SequenceAcceptIsIdentity);

void SequenceDenyIsAlwaysDeny(PolicyProto policy) {
  EXPECT_TRUE(
      Manager().IsDeny(Manager().Compile(SequenceProto(policy, DenyProto()))));
  EXPECT_TRUE(
      Manager().IsDeny(Manager().Compile(SequenceProto(DenyProto(), policy))));
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest, SequenceDenyIsAlwaysDeny);

void DistributiveLawsHold(PolicyProto a, PolicyProto b, PolicyProto c) {
  // Left distribution.
  EXPECT_EQ(
      Manager().Compile(SequenceProto(a, UnionProto(b, c))),
      Manager().Compile(UnionProto(SequenceProto(a, b), SequenceProto(a, c))));
  // Right distribution.
  EXPECT_EQ(
      Manager().Compile(SequenceProto(UnionProto(a, b), c)),
      Manager().Compile(UnionProto(SequenceProto(a, c), SequenceProto(b, c))));
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest, DistributiveLawsHold);

void IterateUnrollOnce(PolicyProto policy) {
  // Left unroll.
  EXPECT_EQ(Manager().Compile(UnionProto(
                AcceptProto(), SequenceProto(policy, IterateProto(policy)))),
            Manager().Compile(IterateProto(policy)));
  // Right unroll.
  EXPECT_EQ(Manager().Compile(UnionProto(
                AcceptProto(), SequenceProto(IterateProto(policy), policy))),
            Manager().Compile(IterateProto(policy)));
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest, IterateUnrollOnce);

// This test checks that iterate is the least-fixed point on the left and right
// side of a sequence. I.e. that if there is a term x such that x;y (or y;x) is
// smaller than y, then x* is the smallest such term.
void IterateIsLeastFixedPoint(PolicyProto p, PolicyProto q, PolicyProto r) {
  // Left.
  PolicyProto lfp_left_antecedent = UnionProto(q, SequenceProto(p, r));
  if (Manager().Compile(UnionProto(lfp_left_antecedent, r)) ==
      Manager().Compile(r)) {
    PolicyProto left_lfp = SequenceProto(IterateProto(p), q);
    EXPECT_EQ(Manager().Compile(UnionProto(left_lfp, r)), Manager().Compile(r));
  }
  // Right.
  PolicyProto lfp_right_antecedent = UnionProto(p, SequenceProto(q, r));
  if (Manager().Compile(UnionProto(lfp_right_antecedent, q)) ==
      Manager().Compile(q)) {
    PolicyProto right_lfp = SequenceProto(p, IterateProto(r));
    EXPECT_EQ(Manager().Compile(UnionProto(right_lfp, q)),
              Manager().Compile(q));
  }
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest, IterateIsLeastFixedPoint);

/*--- Tests with concrete protos ---------------------------------------------*/

TEST(SymbolicPacketTransformerManagerTest, KatchPaperFig3) {
  // (a=5 + b=2);(b:=1 + c=5)
  PolicyProto p = SequenceProto(
      UnionProto(FilterProto(MatchProto("a", 5)),
                 FilterProto(MatchProto("b", 2))),
      UnionProto(ModificationProto("b", 1), FilterProto(MatchProto("c", 5))));

  // (b=1 + c:=4 + a:=1;b:=1)
  PolicyProto q = UnionProto(
      FilterProto(MatchProto("b", 1)),
      UnionProto(
          ModificationProto("c", 4),
          SequenceProto(ModificationProto("a", 1), ModificationProto("b", 1))));

  SymbolicPacketTransformer p_transformer = Manager().Compile(p);
  SymbolicPacketTransformer q_transformer = Manager().Compile(q);
  SymbolicPacketTransformer sequence_transformer =
      Manager().Compile(SequenceProto(p, q));

  // TODO(b/404543304): Instead of just logging, test these using golden
  // testing.
  LOG(INFO) << "p: \n" << Manager().ToString(p_transformer);
  LOG(INFO) << "p (dotified): \n" << Manager().ToDot(p_transformer);
  LOG(INFO) << "q: \n" << Manager().ToString(q_transformer);
  LOG(INFO) << "q (dotified): \n" << Manager().ToDot(q_transformer);
  LOG(INFO) << "p;q: \n" << Manager().ToString(sequence_transformer);
  LOG(INFO) << "p;q (dotified): \n" << Manager().ToDot(sequence_transformer);

  EXPECT_EQ(Manager().Sequence(p_transformer, q_transformer),
            sequence_transformer);
}

// TODO(b/404543304): Instead of just logging, test these using golden
// testing.
// From Katch paper Fig 3.
TEST(SymbolicPacketTransformerManagerTest,
     SymbolicPacketTransformerToDotStringIsCorrect) {
  // (a=5 + b=2);(b:=1 + c=5)
  PolicyProto p = SequenceProto(
      UnionProto(FilterProto(MatchProto("a", 5)),
                 FilterProto(MatchProto("b", 2))),
      UnionProto(ModificationProto("b", 1), FilterProto(MatchProto("c", 5))));

  SymbolicPacketTransformer p_transformer = Manager().Compile(p);
  std::string dot_string = Manager().ToDot(p_transformer);

  absl::flat_hash_map<uint64_t, std::string> nodes_to_labels;
  absl::flat_hash_set<std::pair<uint64_t, uint64_t>> nodes_to_nodes;
  for (const absl::string_view line : absl::StrSplit(dot_string, '\n')) {
    std::string label;
    uint64_t node;
    if (RE2::PartialMatch(line, R"((\d+) \[label=\"([a-zA-Z]+)\")", &node,
                          &label)) {
      nodes_to_labels.insert({node, label});
    }
    uint64_t from, to;
    if (RE2::PartialMatch(line, R"((\d+) -> (\d+))", &from, &to)) {
      nodes_to_nodes.insert({from, to});
    }
  }
  std::vector<std::pair<std::string, std::string>> labels_to_labels;
  for (const auto& [from, to] : nodes_to_nodes) {
    labels_to_labels.push_back({nodes_to_labels[from], nodes_to_labels[to]});
  }

  EXPECT_THAT(
      labels_to_labels,
      UnorderedElementsAre(Pair("a", "b"), Pair("a", "b"), Pair("b", "T"),
                           Pair("b", "c"), Pair("b", "T"), Pair("b", "c"),
                           Pair("b", "F"), Pair("c", "T"), Pair("c", "F")));
}

TEST(SymbolicPacketTransformerManagerTest,
     SequenceOfNonLoopProducerConvergesToDeny) {
  // a=1 ; b:=1 ; a:=0
  PolicyProto a_to_b = SequenceProto(
      FilterProto(MatchProto("a", 1)),
      SequenceProto(ModificationProto("b", 1), ModificationProto("a", 0)));

  // b=1 ; b:=0 ; a:=1
  PolicyProto b_to_a = SequenceProto(
      FilterProto(MatchProto("b", 1)),
      SequenceProto(ModificationProto("b", 0), ModificationProto("a", 1)));

  // !(once=1) ; a:=1 ; once:=1
  PolicyProto b_to_a_once =
      SequenceProto(FilterProto(NotProto(MatchProto("once", 1))),
                    SequenceProto(b_to_a, ModificationProto("once", 1)));

  SymbolicPacketTransformer a_to_b_and_b_to_a_once_transformer =
      Manager().Compile(UnionProto(a_to_b, b_to_a_once));

  SymbolicPacketTransformer sequenced_transformer2 = Manager().Sequence(
      a_to_b_and_b_to_a_once_transformer, a_to_b_and_b_to_a_once_transformer);

  // Should converge to Deny if sequenced 4 times.
  SymbolicPacketTransformer sequenced_transformer4 =
      Manager().Sequence(sequenced_transformer2, sequenced_transformer2);

  EXPECT_TRUE(Manager().IsDeny(sequenced_transformer4))
      << "a_to_b_and_b_to_a_once_transformer:\n"
      << Manager().ToString(a_to_b_and_b_to_a_once_transformer)
      << "\nsequenced_transformer4:\n"
      << Manager().ToString(sequenced_transformer4);
}

TEST(SymbolicPacketTransformerManagerTest,
     SequenceOfLoopProducerConvergesToNonDeny) {
  // a=1 ; b:=1 ; a:=0
  PolicyProto a_to_b = SequenceProto(
      FilterProto(MatchProto("a", 1)),
      SequenceProto(ModificationProto("b", 1), ModificationProto("a", 0)));

  // b=1 ; b:=0 ; a:=1
  PolicyProto b_to_a = SequenceProto(
      FilterProto(MatchProto("b", 1)),
      SequenceProto(ModificationProto("b", 0), ModificationProto("a", 1)));

  SymbolicPacketTransformer a_to_b_and_b_to_a_transformer =
      Manager().Compile(UnionProto(a_to_b, b_to_a));

  SymbolicPacketTransformer sequenced_transformer2 = Manager().Sequence(
      a_to_b_and_b_to_a_transformer, a_to_b_and_b_to_a_transformer);
  SymbolicPacketTransformer sequenced_transformer4 =
      Manager().Sequence(sequenced_transformer2, sequenced_transformer2);

  EXPECT_FALSE(Manager().IsDeny(sequenced_transformer4));
  EXPECT_EQ(sequenced_transformer2, sequenced_transformer4)
      << "nsequenced_transformer2:\n"
      << Manager().ToString(sequenced_transformer2)
      << "\nsequenced_transformer4:\n"
      << Manager().ToString(sequenced_transformer4);
}

// Tests that a simple sequence of modification then filter same field with
// different value is Deny.
TEST(SymbolicPacketTransformerManagerTest,
     ModifyThenFilterDifferentValueIsDeny) {
  // a:=0 ; a=1
  PolicyProto make_false_then_test =
      SequenceProto(ModificationProto("a", 0), FilterProto(MatchProto("a", 1)));

  EXPECT_TRUE(Manager().IsDeny(Manager().Compile(make_false_then_test)))
      << Manager().ToString(Manager().Compile(make_false_then_test));
}

// Tests that a simple sequence of modification then filter same field with
// same value is Modify.
TEST(SymbolicPacketTransformerManagerTest, ModifyThenFilterSameValueIsModify) {
  // a:=1 ; a=1
  PolicyProto make_true = ModificationProto("a", 1);
  PolicyProto make_true_then_test =
      SequenceProto(make_true, FilterProto(MatchProto("a", 1)));

  EXPECT_EQ(Manager().Compile(make_true_then_test),
            Manager().Compile(make_true));
}

/*--- Tests with packets -----------------------------------------------------*/

TEST(SymbolicPacketTransformerManagerTest, RunDenyAndAccept) {
  Packet packet = {{"field", 1}};
  EXPECT_THAT(Manager().Run(Manager().Deny(), packet), IsEmpty());
  EXPECT_THAT(Manager().Run(Manager().Accept(), packet),
              UnorderedElementsAre(packet));
}

// TODO(dilo): Enable when Run is fully implemented.
// We expect that any concrete packet that is `Run` through a `policy` gives the
// same result as when it is `Evaluate`d on that policy.
// void RunIsSameAsEvaluate(PolicyProto policy,
//                          Packet concrete_packet) {
//   EXPECT_THAT(Manager().Run(Manager().Compile(policy), concrete_packet),
//               ContainerEq(Evaluate(policy, concrete_packet)));
// }
// FUZZ_TEST(SymbolicPacketTransformerManagerTest, RunIsSameAsEvaluate);

}  // namespace
}  // namespace netkat
