#include "netkat/gtest_utils.h"

#include "fuzztest/fuzztest.h"
#include "netkat/frontend.h"

namespace netkat::netkat_test {

using ::fuzztest::Arbitrary;
using ::fuzztest::Just;
using ::fuzztest::Map;
using ::fuzztest::OneOf;

fuzztest::Domain<Predicate> AtomicPredicateDomain() {
  return OneOf(Just(Predicate::True()), Just(Predicate::False()),
               Map(Match, Arbitrary<absl::string_view>(), Arbitrary<int>()));
}

fuzztest::Domain<Policy> AtomicDupFreePolicyDomain() {
  return OneOf(Map(Filter, AtomicPredicateDomain()),
               Map(Modify, Arbitrary<absl::string_view>(), Arbitrary<int>()));
}

}  // namespace netkat::netkat_test
