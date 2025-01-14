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
// File: frontend.h
// -----------------------------------------------------------------------------
//
// This file contains the definitions for the frontend facing NetKAT API.
// This API is how a majority of users are expected to build and manipulate
// NetKAT related policy.
//
// Under the hood, very minimal logic is performed at this stage. This API acts
// as a set of convenient helpers to generate a valid intermediate proto
// representation (IR). See `netkat.proto`.
#ifndef GOOGLE_NETKAT_NETKAT_FRONTEND_H_
#define GOOGLE_NETKAT_NETKAT_FRONTEND_H_

#include <utility>

#include "absl/strings/string_view.h"
#include "netkat/netkat.pb.h"

namespace netkat {

// Represents a NetKAT predicate.
//
// In general terms, a NetKAT predicate is some Boolean combination of matches
// on packets. Practically speaking, it is useful to think of predicates as a
// "filter" on the sets of packets at some given point in a NetKAT program.
//
// TODO: b/377697348 - create and point to resources/tutorials for NetKAT.
//
// This class provides overloads, and therefore support, for the given boolean
// operations: `&&`, `||` and `!`. These overloads follow conventional operation
// precedence order and, as per the literature, logically behave as expected.
// These overloads allow for convenient building of Predicates, for example:
//
//   Predicate allowed_packets =
//       Match("port", 1) && Match("vlan", 10) || Match("dst_mac", X);
//
// NOTE: SHORT CIRCUITING DOES NOT OCCUR! The following equivalent statements
// will generate differing protos:
//
//   Predicate p1 = Predicate::True() || Predicate::False();
//   Predicate p2 = Predicate::True();
//   assert(!MessageDifferencer::Equivalent(p1.ToProto(), p2.ToProto());
//
// Internally this class simply builds a `PredicateProto` and does not
// *currently* perform any specific optimizations of the proto as it is built.
class Predicate {
 public:
  // We currently only allow predicate construction through helpers, e.g.
  // `Match`, `True`, `False`.
  Predicate() = delete;

  // Returns the underlying IR proto.
  //
  // Users should generally not handle this proto directly, unless done with
  // policy building.
  PredicateProto ToProto() const& { return predicate_; }
  PredicateProto ToProto() && { return std::move(predicate_); }

  // TODO(anthonyroy): Add a FromProto.

  // Logical operators. These perform exactly as expected, with the
  // exception of short circuiting.
  //
  // These objects by themselves are not intrinsically truthy, so a lack of
  // short circuiting will not generate semantically different sequences.
  friend Predicate operator&&(Predicate lhs, Predicate rhs);
  friend Predicate operator||(Predicate lhs, Predicate rhs);
  friend Predicate operator!(Predicate predicate);

  // Match operation for a Predicate. See below for the full definition. We
  // utilize friend association to ensure program construction is well-formed.
  friend Predicate Match(absl::string_view, int);

  // Predicates that conceptually represent a packet being universally accepted
  // or denied/droped.
  //
  // Concretely this is simply a constant `Predicate(true/false)`.
  static Predicate True();
  static Predicate False();

 private:
  // Hide default proto construction to hinder building of ill-formed programs.
  explicit Predicate(PredicateProto pred) : predicate_(std::move(pred)) {}

  PredicateProto predicate_;
};

// Represents a match on some field in the NetKAT packet. This is typically
// referred to as a "test" in the literature.
//
// Matches may be on any concrete packet field, switch local meta-fields, NetKAT
// specific fields (e.g. location), or even arbitrary labels introduced only for
// the specific programs.
//
//   netkat::Match("ethertype", 0x0800) // L2 Header field.
//   netkat::Match("dst_ip", X)         // L3 Header field.
//   netkat::Match("pkt_mark", Y)       // OVS metadata field.
//   netkat::Match("switch", Z)         // Location for the NetKAT Automata.
//   netkat::Match("has_foo", 0)        // Custom program label.
//
// TODO: b/377704955 - Add type safety.
//
// Field verification is currently limited when using raw strings, both in type
// safety and naming. Prefer to use either enum<>string mappings OR constants
// rather than re-typing strings for field names.
Predicate Match(absl::string_view field, int value);

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_FRONTEND_H_
