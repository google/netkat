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

#include <ostream>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_set.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "fuzztest/fuzztest.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "netkat/evaluator.h"
#include "netkat/netkat.pb.h"
#include "netkat/netkat_proto_constructors.h"
#include "netkat/symbolic_packet.h"

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
  *os << Manager().PrettyPrint(transformer);
}

namespace {

using testing::IsEmpty;
using testing::StartsWith;
using testing::UnorderedElementsAre;

// After executing all tests, we check once that no invariants are violated, for
// defense in depth. Checking invariants after each test (e.g. using a fixture)
// would likely not scale and seems overkill.
class CheckSymbolicPacketTransformerManagerInvariantsOnTearDown
    : public testing::Environment {
 public:
  ~CheckSymbolicPacketTransformerManagerInvariantsOnTearDown() override {}
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
  SymbolicPacketManager packet_manager;
  EXPECT_EQ(Manager().Compile(FilterProto(predicate)),
            Manager().OfSymbolicPacket(packet_manager,
                                       packet_manager.Compile(predicate)));
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

void SequenceDenyIsAnnihilator(PolicyProto policy) {
  EXPECT_EQ(Manager().Compile(SequenceProto(policy, DenyProto())),
            Manager().Compile(DenyProto()));
  EXPECT_EQ(Manager().Compile(SequenceProto(DenyProto(), policy)),
            Manager().Compile(DenyProto()));
}
FUZZ_TEST(SymbolicPacketTransformerManagerTest, SequenceDenyIsAnnihilator);

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
FUZZ_TEST(SymbolicPacketManagerTest, DistributiveLawsHold);

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

// Are the if-statements likely enough to randomly be true that this is a useful
// test?
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

/*--- Tests with more complex protos -----------------------------------------*/

TEST(SymbolicPacketTransformerManagerTest, KatchPaperFig3) {
  // (𝑎=5 + 𝑏=2) · (𝑏:=1 + 𝑐=5)
  PolicyProto p = SequenceProto(
      UnionProto(FilterProto(MatchProto("a", 5)),
                 FilterProto(MatchProto("b", 2))),
      UnionProto(ModificationProto("b", 1), FilterProto(MatchProto("c", 5))));

  // (𝑏=1 + 𝑐:=4 + 𝑎:=1 · 𝑏:=1)
  PolicyProto q = UnionProto(
      FilterProto(MatchProto("b", 1)),
      UnionProto(
          ModificationProto("c", 4),
          SequenceProto(ModificationProto("a", 1), ModificationProto("b", 1))));

  SymbolicPacketTransformer p_transformer = Manager().Compile(p);
  SymbolicPacketTransformer q_transformer = Manager().Compile(q);
  SymbolicPacketTransformer sequence_transformer =
      Manager().Compile(SequenceProto(p, q));

  LOG(INFO) << "p: \n" << Manager().PrettyPrint(p_transformer);
  LOG(INFO) << "q: \n" << Manager().PrettyPrint(q_transformer);
  LOG(INFO) << "p·q: \n" << Manager().PrettyPrint(sequence_transformer);

  EXPECT_EQ(Manager().Sequence(p_transformer, q_transformer),
            sequence_transformer);
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
