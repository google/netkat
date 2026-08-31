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
//
// -----------------------------------------------------------------------------
// File: gtest_utils.h
// -----------------------------------------------------------------------------
//
// This file contains useful functions/matchers to be used for NetKAT testing.
// As such all definitions in this file are expected to be used exclusively in
// tests.
#ifndef GOOGLE_NETKAT_NETKAT_GTEST_UTILS_H_
#define GOOGLE_NETKAT_NETKAT_GTEST_UTILS_H_

#include <string>

#include "fuzztest/fuzztest.h"
#include "gmock/gmock.h"
#include "google/protobuf/descriptor.h"
#include "netkat/counter_example.h"
#include "netkat/frontend.h"

namespace netkat::netkat_test {

template <typename T>
bool FieldTypeIs(const google::protobuf::FieldDescriptor* field) {
  return field->message_type() == T::descriptor();
}

// Returns a FUZZ_TEST domain for an arbitrary valid PredicateProto.
// See netkat::Predicate::FromProto for the definition of a valid
// PredicateProto.
// Nonetheless, invalid protos are accepted in the backend where empty is
// defined to mean false.
fuzztest::Domain<PredicateProto> ArbitraryValidPredicateProto();

// Same as ArbitraryValidPredicateProto but without Pull.
fuzztest::Domain<PredicateProto> ArbitraryValidPredicateProtoWithoutPull();

// Returns a FUZZ_TEST domain for an arbitrary valid PolicyProto.
// See netkat::Policy::FromProto for the definition of a valid PolicyProto.
// Nonetheless, invalid protos are accepted in the backend where empty is
// defined to mean DENY policy.
fuzztest::Domain<PolicyProto> ArbitraryValidPolicyProto();

// Same as ArbitraryValidPolicyProto but without Pull.
fuzztest::Domain<PolicyProto> ArbitraryValidPolicyProtoWithoutPull();

// Returns a FUZZ_TEST domain for an arbitrary, atomic Predicate. I.e., the
// predicate may be any of: an arbitrary Match, or the True/False predicates.
fuzztest::Domain<Predicate> AtomicPredicateDomain();

// Returns a FUZZ_TEST domain for an arbitrary, dup-free, atomic Policy. I.e.,
// the policy may be any of an arbitrary Modify or filtered, atomic predicate.
fuzztest::Domain<Policy> AtomicDupFreePolicyDomain();

// Matches a netkat::SuccessOrCounterExample that represents success (no
// CounterExample).
// On failure, explains the mismatch with the CounterExample's Explain() output.
MATCHER(IsSuccess, negation ? "has CounterExample" : "is success") {
  if (arg.IsSuccess()) {
    return true;
  }
  *result_listener << "\nCounterExample:\n" << arg.Explain();
  return false;
}

// Matches a netkat::SuccessOrCounterExample that contains a CounterExample.
MATCHER(HasCounterExample, negation ? "is success" : "has CounterExample") {
  if (!arg.IsSuccess()) {
    return true;
  }
  *result_listener << "No CounterExample generated, statement was success.";
  return false;
}

}  // namespace netkat::netkat_test

#endif  // GOOGLE_NETKAT_NETKAT_GTEST_UTILS_H_
