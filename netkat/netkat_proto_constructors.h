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
// File: netkat_proto_helpers.h
// -----------------------------------------------------------------------------
//
// Helper functions to make constructing netkat.proto messages more readable,
// specifically in unit test where readability is key.

#ifndef GOOGLE_NETKAT_NETKAT_NETKAT_PROTO_CONSTRUCTORS_H_
#define GOOGLE_NETKAT_NETKAT_NETKAT_PROTO_CONSTRUCTORS_H_

#include <string>

#include "absl/strings/string_view.h"
#include "netkat/netkat.pb.h"

namespace netkat {

// -- Predicate constructors ---------------------------------------------------

PredicateProto TrueProto();
PredicateProto FalseProto();
PredicateProto MatchProto(absl::string_view field, int value);
PredicateProto AndProto(PredicateProto left, PredicateProto right);
PredicateProto OrProto(PredicateProto left, PredicateProto right);
PredicateProto NotProto(PredicateProto negand);
PredicateProto XorProto(PredicateProto left, PredicateProto right);

// -- Basic Policy constructors ------------------------------------------------

PolicyProto FilterProto(PredicateProto filter);
PolicyProto ModificationProto(absl::string_view field, int value);
PolicyProto RecordProto();
PolicyProto SequenceProto(PolicyProto left, PolicyProto right);
PolicyProto UnionProto(PolicyProto left, PolicyProto right);
PolicyProto IterateProto(PolicyProto iterable);

// -- Derived Policy constructors ----------------------------------------------

PolicyProto DenyProto();
PolicyProto AcceptProto();

// Returns a shorthand string from a given NetKAT policy/predicate. This follows
// roughly the shorthand typically used in literature. Specifically:
//
//   Predicate And -> '&&'
//   Predicate Or -> '||'
//   Predicate Not -> '!'
//   Predicate Xor -> '(+)'
//   Policy Sequence -> ';'
//   Policy Or -> '+'
//   Iterate -> '*'
//   Record -> 'record'
//   Match -> '@field==value'
//   Modify -> '@field:=value'
//   True -> 'true'
//   False -> 'false'
//
// Note that parenthesis elimination is not performed.
//
// TODO(anthonyroy): Refactor this out to a different helper filer and/or widen
// the scope of this one.
std::string AsShorthandString(PolicyProto policy);
std::string AsShorthandString(PredicateProto predicate);

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_NETKAT_PROTO_CONSTRUCTORS_H_
