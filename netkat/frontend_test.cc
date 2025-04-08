#include "netkat/frontend.h"

#include "absl/strings/string_view.h"
#include "fuzztest/fuzztest.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/proto_matchers.h"
#include "netkat/gtest_utils.h"
#include "netkat/netkat.pb.h"
#include "netkat/netkat_proto_constructors.h"

namespace netkat {
namespace {

using ::fuzztest::ContainerOf;
using ::gutil::EqualsProto;
using ::netkat::netkat_test::AtomicDupFreePolicyDomain;
using ::netkat::netkat_test::AtomicPredicateDomain;

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

void NegateToProtoIsCorrect(Predicate predicate) {
  Predicate negand = !predicate;
  EXPECT_THAT(negand.ToProto(), EqualsProto(NotProto(predicate.ToProto())));
}
FUZZ_TEST(FrontEndTest, NegateToProtoIsCorrect)
    .WithDomains(AtomicPredicateDomain());

void AndToProtoIsCorrect(Predicate lhs, Predicate rhs) {
  Predicate and_pred = lhs && rhs;
  EXPECT_THAT(and_pred.ToProto(),
              EqualsProto(AndProto(lhs.ToProto(), rhs.ToProto())));
}
FUZZ_TEST(FrontEndTest, AndToProtoIsCorrect)
    .WithDomains(/*lhs=*/AtomicPredicateDomain(),
                 /*rhs=*/AtomicPredicateDomain());

void OrToProtoIsCorrect(Predicate lhs, Predicate rhs) {
  Predicate or_pred = lhs || rhs;
  EXPECT_THAT(or_pred.ToProto(),
              EqualsProto(OrProto(lhs.ToProto(), rhs.ToProto())));
}
FUZZ_TEST(FrontEndTest, OrToProtoIsCorrect)
    .WithDomains(/*lhs=*/AtomicPredicateDomain(),
                 /*rhs=*/AtomicPredicateDomain());

void XorToProtoIsCorrect(Predicate lhs, Predicate rhs) {
  Predicate xor_pred = Xor(lhs, rhs);
  EXPECT_THAT(xor_pred.ToProto(),
              EqualsProto(XorProto(lhs.ToProto(), rhs.ToProto())));
}
FUZZ_TEST(FrontEndTest, XorToProtoIsCorrect)
    .WithDomains(/*lhs=*/AtomicPredicateDomain(),
                 /*rhs=*/AtomicPredicateDomain());

void OperationOrderIsPreserved(Predicate a, Predicate b, Predicate c) {
  Predicate abc = !(a || b) && c || a;
  EXPECT_THAT(
      abc.ToProto(),
      EqualsProto(OrProto(
          AndProto(NotProto(OrProto(a.ToProto(), b.ToProto())), c.ToProto()),
          a.ToProto())));
}
FUZZ_TEST(FrontEndTest, OperationOrderIsPreserved)
    .WithDomains(/*a=*/AtomicPredicateDomain(),
                 /*b=*/AtomicPredicateDomain(),
                 /*c=*/AtomicPredicateDomain());

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
    .WithDomains(/*predicate=*/AtomicPredicateDomain());

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
    .WithDomains(/*policy=*/AtomicDupFreePolicyDomain());

TEST(FrontEndTest, SequenceWithNoElementsIsAccept) {
  EXPECT_THAT(Sequence().ToProto(), EqualsProto(AcceptProto()));
}

void SequenceWithOneElementIsSelf(Policy policy) {
  EXPECT_THAT(Sequence(policy).ToProto(), EqualsProto(policy.ToProto()));
}
FUZZ_TEST(FrontEndTest, SequenceWithOneElementIsSelf)
    .WithDomains(/*policy=*/AtomicDupFreePolicyDomain());

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
            AtomicDupFreePolicyDomain())
            .WithMinSize(2)
            .WithMaxSize(64));  // Limit the max size to avoid stack crash.

void SequenceNArgsIsSameAsList(Policy a, Policy b, Policy c) {
  EXPECT_THAT(Sequence(a, b, c).ToProto(),
              EqualsProto(Sequence({a, b, c}).ToProto()));
}
FUZZ_TEST(FrontEndTest, SequenceNArgsIsSameAsList)
    .WithDomains(
        /*a=*/AtomicDupFreePolicyDomain(),
        /*b=*/AtomicDupFreePolicyDomain(),
        /*c=*/AtomicDupFreePolicyDomain());

TEST(FrontEndTest, UnionWithNoElementsIsDeny) {
  EXPECT_THAT(Union().ToProto(), EqualsProto(DenyProto()));
}

void UnionWithOneElementIsSelf(Policy policy) {
  EXPECT_THAT(Union(policy).ToProto(), EqualsProto(policy.ToProto()));
}
FUZZ_TEST(FrontEndTest, UnionWithOneElementIsSelf)
    .WithDomains(/*policy=*/AtomicDupFreePolicyDomain());

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
            AtomicDupFreePolicyDomain())
            .WithMinSize(2)
            .WithMaxSize(64));  // Limit the max size to avoid stack crash.

void UnionNArgsIsSameAsList(Policy a, Policy b, Policy c) {
  EXPECT_THAT(Union(a, b, c).ToProto(),
              EqualsProto(Union({a, b, c}).ToProto()));
}
FUZZ_TEST(FrontEndTest, UnionNArgsIsSameAsList)
    .WithDomains(
        /*a=*/AtomicDupFreePolicyDomain(),
        /*b=*/AtomicDupFreePolicyDomain(),
        /*c=*/AtomicDupFreePolicyDomain());

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
        /*a=*/AtomicDupFreePolicyDomain(),
        /*b=*/AtomicDupFreePolicyDomain(),
        /*c=*/AtomicDupFreePolicyDomain());

}  // namespace
}  // namespace netkat
