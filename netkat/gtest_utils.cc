#include "netkat/gtest_utils.h"

#include "fuzztest/fuzztest.h"
#include "google/protobuf/descriptor.h"
#include "netkat/frontend.h"
#include "netkat/netkat.pb.h"

namespace netkat::netkat_test {

using ::fuzztest::Arbitrary;
using ::fuzztest::Just;
using ::fuzztest::Map;
using ::fuzztest::OneOf;

namespace {

template <typename T>
bool FieldTypeIs(const google::protobuf::FieldDescriptor* field) {
  return field->message_type() == T::descriptor();
};

}  // namespace

fuzztest::Domain<PredicateProto> ArbitraryValidPredicateProto() {
  return fuzztest::Arbitrary<PredicateProto>()
      // The domain will recursively set all fields. This ensures
      // PredicateProto will have its members PredicateProto set.
      .WithFieldsAlwaysSet()
      // The domain will ensure all PredicateProto::Match::field will be
      // non-empty.
      .WithProtobufFields(
          FieldTypeIs<PredicateProto::Match>,
          fuzztest::Arbitrary<PredicateProto::Match>().WithStringFieldAlwaysSet(
              "field", fuzztest::String().WithMinSize(1)));
}

fuzztest::Domain<PolicyProto> ArbitraryValidPolicyProto() {
  return fuzztest::Arbitrary<PolicyProto>()
      // The domain will recursively set all fields. This ensures
      // PolicyProto will have its members PolicyProto set.
      .WithFieldsAlwaysSet()
      // The domain will ensure all PolicyProto::Modification::field will be
      // non-empty.
      .WithProtobufFields(FieldTypeIs<PolicyProto::Modification>,
                          fuzztest::Arbitrary<PolicyProto::Modification>()
                              .WithStringFieldAlwaysSet(
                                  "field", fuzztest::String().WithMinSize(1)))
      .WithProtobufFields(FieldTypeIs<PredicateProto>,
                          ArbitraryValidPredicateProto());
}

fuzztest::Domain<Predicate> AtomicPredicateDomain() {
  return OneOf(Just(Predicate::True()), Just(Predicate::False()),
               Map(Match, Arbitrary<absl::string_view>(), Arbitrary<int>()));
}

fuzztest::Domain<Policy> AtomicDupFreePolicyDomain() {
  return OneOf(Map(Filter, AtomicPredicateDomain()),
               Map(Modify, Arbitrary<absl::string_view>(), Arbitrary<int>()));
}

}  // namespace netkat::netkat_test
