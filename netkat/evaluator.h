// Copyright 2024 The NetKAT authors
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
// File: evaluator.h
// -----------------------------------------------------------------------------
//
// Defines a library of functions for evaluating NetKAT predicates and policies
// on concrete packets.

#ifndef GOOGLE_NETKAT_NETKAT_EVALUATOR_H_
#define GOOGLE_NETKAT_NETKAT_EVALUATOR_H_

#include <string>

#include "absl/container/flat_hash_map.h"
#include "netkat/netkat.pb.h"

namespace netkat {

// A NetKAT packet is a map from field names to their values.
//
// NOTE: This is a simplistic, initial definition of `Packet` that we expect to
// replace in the future. In particular, the value type will change to support
// things like 128-bit IPv6 addresses.
//
// Fields that are not present in the map are assumed to carry an implicit "not
// present" value that is distinct from all explicitly-assignable values.
using Packet = absl::flat_hash_map<std::string, int>;

// Returns true if the given `packet` satisfies the given `predicate`, false
// otherwise.
//
// Note: Empty predicates are considered unsatisfiable.
bool Evaluate(const PredicateProto& predicate, const Packet& packet);

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_EVALUATOR_H_
