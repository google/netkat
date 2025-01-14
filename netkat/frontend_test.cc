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

}  // namespace
}  // namespace netkat
