#include "netkat/gmock_utils.h"

#include "fuzztest/fuzztest.h"
#include "netkat/frontend.h"

namespace netkat_test {

using ::fuzztest::Arbitrary;
using ::fuzztest::Just;
using ::fuzztest::Map;
using ::fuzztest::OneOf;
using ::netkat::Filter;
using ::netkat::Match;
using ::netkat::Modify;
using ::netkat::Policy;
using ::netkat::Predicate;

fuzztest::Domain<Predicate> SingleLevelPredicateDomain() {
  return OneOf(Just(Predicate::True()), Just(Predicate::False()),
               Map(Match, Arbitrary<absl::string_view>(), Arbitrary<int>()));
}

fuzztest::Domain<Policy> FilterOrModifyPolicyDomain() {
  return OneOf(Map(Filter, SingleLevelPredicateDomain()),
               Map(Modify, Arbitrary<absl::string_view>(), Arbitrary<int>()));
}

}  // namespace netkat_test
