#include "netkat/frontend.h"

#include "absl/strings/string_view.h"
#include "fuzztest/fuzztest.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/proto_matchers.h"
#include "netkat/netkat.pb.h"
#include "netkat/netkat_proto_constructors.h"

namespace netkat {
namespace {

using ::fuzztest::Arbitrary;
using ::fuzztest::ContainerOf;
using ::fuzztest::Just;
using ::fuzztest::Map;
using ::fuzztest::OneOf;

void MatchToProtoIsCorrect(absl::string_view field, int value) {
  EXPECT_THAT(Match(field, value).ToProto(),
              EqualsProto(MatchProto(field, value)));
}
FUZZ_TEST(FrontEndTest, MatchToProtoIsCorrect);

TEST(FrontEndTest, TrueToProtoIsCorrect) {
  EXPECT_THAT(Predicate::True().ToProto(), EqualsProto(TrueProto()));
}

TEST(FrontEndTest, FalseToProtoIsCorrect) {
  EXPECT_THAT(Predicate::False().ToProto(), EqualsProto(FalseProto()));
}

// Returns a FUZZ_TEST domain that returns an arbitrary Match, True or False
// predicate. This allows us to provide fuzz tests with arbitrary Predicates to
// test on.
fuzztest::Domain<Predicate> SingleLevelPredicateDomain() {
  return OneOf(Just(Predicate::True()), Just(Predicate::False()),
               Map(Match, Arbitrary<absl::string_view>(), Arbitrary<int>()));
}

void NegateToProtoIsCorrect(Predicate predicate) {
  Predicate negand = !predicate;
  EXPECT_THAT(negand.ToProto(), EqualsProto(NotProto(predicate.ToProto())));
}
FUZZ_TEST(FrontEndTest, NegateToProtoIsCorrect)
    .WithDomains(SingleLevelPredicateDomain());

void AndToProtoIsCorrect(Predicate lhs, Predicate rhs) {
  Predicate and_pred = lhs && rhs;
  EXPECT_THAT(and_pred.ToProto(),
              EqualsProto(AndProto(lhs.ToProto(), rhs.ToProto())));
}
FUZZ_TEST(FrontEndTest, AndToProtoIsCorrect)
    .WithDomains(/*lhs=*/SingleLevelPredicateDomain(),
                 /*rhs=*/SingleLevelPredicateDomain());

void OrToProtoIsCorrect(Predicate lhs, Predicate rhs) {
  Predicate or_pred = lhs || rhs;
  EXPECT_THAT(or_pred.ToProto(),
              EqualsProto(OrProto(lhs.ToProto(), rhs.ToProto())));
}
FUZZ_TEST(FrontEndTest, OrToProtoIsCorrect)
    .WithDomains(/*lhs=*/SingleLevelPredicateDomain(),
                 /*rhs=*/SingleLevelPredicateDomain());

void OperationOrderIsPreserved(Predicate a, Predicate b, Predicate c) {
  Predicate abc = !(a || b) && c || a;
  EXPECT_THAT(
      abc.ToProto(),
      EqualsProto(OrProto(
          AndProto(NotProto(OrProto(a.ToProto(), b.ToProto())), c.ToProto()),
          a.ToProto())));
}
FUZZ_TEST(FrontEndTest, OperationOrderIsPreserved)
    .WithDomains(/*a=*/SingleLevelPredicateDomain(),
                 /*b=*/SingleLevelPredicateDomain(),
                 /*c=*/SingleLevelPredicateDomain());

// Returns a FUZZ_TEST domain that returns an arbitrary Policy. This policy may
// contain an arbitrary predicate or modification. This allows us to provide
// fuzz tests with arbitrary concrete policies.
fuzztest::Domain<Policy> FilterOrModifyPolicyDomain() {
  return OneOf(Map(Filter, SingleLevelPredicateDomain()),
               Map(Modify, Arbitrary<absl::string_view>(), Arbitrary<int>()));
}

TEST(FrontEndTest, AcceptToProtoIsCorrect) {
  EXPECT_THAT(Policy::Accept().ToProto(), EqualsProto(AcceptProto()));
}

TEST(FrontEndTest, DenyToProtoIsCorrect) {
  EXPECT_THAT(Policy::Deny().ToProto(), EqualsProto(DenyProto()));
}

TEST(FrontEndTest, RecordToProtoIsCorrect) {
  EXPECT_THAT(Record().ToProto(), EqualsProto(RecordProto()));
}

void FilteredPredicateToProtoIsCorrect(Predicate predicate) {
  EXPECT_THAT(Filter(predicate).ToProto(),
              EqualsProto(FilterProto(predicate.ToProto())));
}
FUZZ_TEST(FrontEndTest, FilteredPredicateToProtoIsCorrect)
    .WithDomains(/*predicate=*/SingleLevelPredicateDomain());

void ModifyToProtoIsCorrect(absl::string_view field, int value) {
  EXPECT_THAT(Modify(field, value).ToProto(),
              EqualsProto(ModificationProto(field, value)));
}
FUZZ_TEST(FrontEndTest, ModifyToProtoIsCorrect);

void IterateToProtoIsCorrect(Policy policy) {
  EXPECT_THAT(Iterate(policy).ToProto(),
              EqualsProto(IterateProto(policy.ToProto())));
}
FUZZ_TEST(FrontEndTest, IterateToProtoIsCorrect)
    .WithDomains(/*policy=*/FilterOrModifyPolicyDomain());

TEST(FrontEndTest, SequenceWithNoElementsIsAccept) {
  EXPECT_THAT(Sequence().ToProto(), EqualsProto(AcceptProto()));
}

void SequenceWithOneElementIsSelf(Policy policy) {
  EXPECT_THAT(Sequence(policy).ToProto(), EqualsProto(policy.ToProto()));
}
FUZZ_TEST(FrontEndTest, SequenceWithOneElementIsSelf)
    .WithDomains(/*policy=*/FilterOrModifyPolicyDomain());

void SequencePreservesOrder(std::vector<Policy> policies) {
  if (policies.size() < 2) GTEST_SKIP();

  Policy policy = Sequence(policies[0], policies[1]);
  PolicyProto expected_proto =
      SequenceProto(policies[0].ToProto(), policies[1].ToProto());
  for (int i = 2; i < policies.size(); ++i) {
    policy = Sequence(policy, policies[i]);
    expected_proto = SequenceProto(expected_proto, policies[i].ToProto());
  }

  EXPECT_THAT(Sequence(policies).ToProto(), EqualsProto(policy.ToProto()));
  EXPECT_THAT(policy.ToProto(), EqualsProto(expected_proto));
}
FUZZ_TEST(FrontEndTest, SequencePreservesOrder)
    .WithDomains(
        /*policies=*/ContainerOf<std::vector<Policy>>(
            FilterOrModifyPolicyDomain())
            .WithMinSize(2));

void SequenceNArgsIsSameAsList(Policy a, Policy b, Policy c) {
  EXPECT_THAT(Sequence(a, b, c).ToProto(),
              EqualsProto(Sequence({a, b, c}).ToProto()));
}
FUZZ_TEST(FrontEndTest, SequenceNArgsIsSameAsList)
    .WithDomains(
        /*a=*/FilterOrModifyPolicyDomain(),
        /*b=*/FilterOrModifyPolicyDomain(),
        /*c=*/FilterOrModifyPolicyDomain());

TEST(FrontEndTest, UnionWithNoElementsIsDeny) {
  EXPECT_THAT(Union().ToProto(), EqualsProto(DenyProto()));
}

void UnionWithOneElementIsSelf(Policy policy) {
  EXPECT_THAT(Union(policy).ToProto(), EqualsProto(policy.ToProto()));
}
FUZZ_TEST(FrontEndTest, UnionWithOneElementIsSelf)
    .WithDomains(/*policy=*/FilterOrModifyPolicyDomain());

void UnionPreservesOrder(std::vector<Policy> policies) {
  if (policies.size() < 2) GTEST_SKIP();

  Policy policy = Union(policies[0], policies[1]);
  PolicyProto expected_proto =
      UnionProto(policies[0].ToProto(), policies[1].ToProto());
  for (int i = 2; i < policies.size(); ++i) {
    policy = Union(policy, policies[i]);
    expected_proto = UnionProto(expected_proto, policies[i].ToProto());
  }

  EXPECT_THAT(Union(policies).ToProto(), EqualsProto(policy.ToProto()));
  EXPECT_THAT(policy.ToProto(), EqualsProto(expected_proto));
}
FUZZ_TEST(FrontEndTest, UnionPreservesOrder)
    .WithDomains(
        /*policies=*/ContainerOf<std::vector<Policy>>(
            FilterOrModifyPolicyDomain())
            .WithMinSize(2));

void UnionNArgsIsSameAsList(Policy a, Policy b, Policy c) {
  EXPECT_THAT(Union(a, b, c).ToProto(),
              EqualsProto(Union({a, b, c}).ToProto()));
}
FUZZ_TEST(FrontEndTest, UnionNArgsIsSameAsList)
    .WithDomains(
        /*a=*/FilterOrModifyPolicyDomain(),
        /*b=*/FilterOrModifyPolicyDomain(),
        /*c=*/FilterOrModifyPolicyDomain());

void MixedPolicyOperationsHasCorrectOrder(Policy a, Policy b, Policy c) {
  // Create an arbitrary policy,
  //   p = ((a + b + c); c; record) + a; b; record
  Policy mixed_policy =
      Union(Sequence(Union(a, b, c), c, Record()), Sequence(a, b, Record()));

  // Should be equivalent to: ((((a+b) + c); c); record) + ((a;b); record)
  EXPECT_THAT(
      mixed_policy.ToProto(),
      EqualsProto(UnionProto(
          SequenceProto(
              SequenceProto(
                  UnionProto(UnionProto(a.ToProto(), b.ToProto()), c.ToProto()),
                  c.ToProto()),
              RecordProto()),
          SequenceProto(SequenceProto(a.ToProto(), b.ToProto()),
                        RecordProto()))));
}
FUZZ_TEST(FrontEndTest, MixedPolicyOperationsHasCorrectOrder)
    .WithDomains(
        /*a=*/FilterOrModifyPolicyDomain(),
        /*b=*/FilterOrModifyPolicyDomain(),
        /*c=*/FilterOrModifyPolicyDomain());

}  // namespace
}  // namespace netkat
