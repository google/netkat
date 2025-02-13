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
// File: gmock_utils.h
// -----------------------------------------------------------------------------
//
// This file contains useful gMock matchers, to be used for NetKAT testing. As
// such all definitions in this file are expected to be used exclusively in
// tests.
#ifndef GOOGLE_NETKAT_NETKAT_GMOCK_UTILS_H_
#define GOOGLE_NETKAT_NETKAT_GMOCK_UTILS_H_

#include "fuzztest/fuzztest.h"
#include "netkat/frontend.h"

namespace netkat_test {

// Returns a FUZZ_TEST domain that returns an arbitrary Match, True or False
// predicate. This allows us to provide fuzz tests with arbitrary Predicates to
// test on.
fuzztest::Domain<netkat::Predicate> SingleLevelPredicateDomain();

// Returns a FUZZ_TEST domain that returns an arbitrary Policy. This policy may
// contain an arbitrary predicate or modification. This allows us to provide
// fuzz tests with arbitrary concrete policies.
fuzztest::Domain<netkat::Policy> FilterOrModifyPolicyDomain();

}  // namespace netkat_test

#endif  // GOOGLE_NETKAT_NETKAT_GMOCK_UTILS_H_
