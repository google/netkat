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

#include "fuzztest/fuzztest.h"
#include "netkat/frontend.h"

namespace netkat::netkat_test {

// Returns a FUZZ_TEST domain for an arbitrary, atomic Predicate. I.e., the
// predicate may be any of: an arbitrary Match, or the True/False predicates.
fuzztest::Domain<Predicate> AtomicPredicateDomain();

// Returns a FUZZ_TEST domain for an arbitrary, dup-free, atomic Policy. I.e.,
// the policy may be any of an arbitrary Modify or filtered, atomic predicate.
fuzztest::Domain<Policy> AtomicDupFreePolicyDomain();

}  // namespace netkat::netkat_test

#endif  // GOOGLE_NETKAT_NETKAT_GTEST_UTILS_H_
