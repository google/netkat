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
#include <vector>

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

// Represents a NetKAT policy.
//
// A NetKAT policy, sometimes referred to as a NetKAT program, is the
// over-arching type used to define network behavior. More formally, a NetKAT
// policy is a logical combination of `Predicate`s, `Modify`s, `Record`s, etc.
//
// A `Predicate` on its own is sufficient to be a policy, see `Filter`, but
// we combine these with actions, such as `Modify`, to fully realize a
// network automata.
//
//   Predicate at_src_link = Match("switch", 0) && Match("port", 0);
//   Policy go_to_dst = Sequence(Modify("switch", 1), Modify("port", 1));
//   Policy link_action = Sequence(Filter(at_src_link), go_to_dst);
//
// In the above example we define some source link and an action, or policy,
// that would send a packet to a given destination switch. The composition of
// those two then builds an automata that is roughly "If the packet is at
// switch0:port0, it is sent to switch1:port1." Though take note that we've only
// built a unidirectional link policy here.
class Policy {
 public:
  PolicyProto ToProto() const& { return policy_; }
  PolicyProto ToProto() && { return std::move(policy_); }

  // TODO: anthonyroy - Create a FromProto.

  // The set of operations that define a NetKAT policy. See below for each
  // operation's definition. We utilize friend association to ensure program
  // construction is well-formed.
  friend Policy Filter(Predicate);
  friend Policy Modify(absl::string_view, int);
  friend Policy Sequence(std::vector<Policy>);
  friend Policy Union(std::vector<Policy>);
  friend Policy Iterate(Policy);
  friend Policy Record();

  // Policies that conceptually represent a program that should accept or
  // deny/drop all packets.
  static Policy Accept();
  static Policy Deny();

 private:
  // Hide default proto construction to hinder building of ill-formed programs.
  explicit Policy(PolicyProto policy) : policy_(std::move(policy)) {}

  // The underlying IR that has been built thus far.
  PolicyProto policy_;
};

// Returns a policy that filters packets by `predicate`.
Policy Filter(Predicate predicate);

// Performs a modification on some `field` in the NetKAT packet. This is not
// required to be a label that yet exists and may even be an arbitrary label.
//
// Similar to `Match` except this sets `field` to `new_value` while match
// instead filters on the value.
Policy Modify(absl::string_view field, int new_value);

// Performs a left-to-right sequential composition of each policy in `policies`.
//
// For example,
//
//   Sequence({p0, p1, p2, p3})
//
// Is equivalent to
//
//   Sequence({Sequence({Sequence({p0, p1}), p2}), p3})
//
// Semantically this behaves like a function composition in which, for some
// list p0...pn, we feed the preceeding program inputs into p0 and forward each
// of p0's outputs into p1, we then forward each of p1's outputs into p2, etc.
//
// Note that this means Sequence(p0, p1) and Sequence(p1, p0) may be
// semantically different as sequential composition is non-commutative. It is
// however associative so Sequence(p0, Sequence(p1, p2)) is the same as
// Sequence(Sequence(p0, p1), p2).
//
// Also note, an empty list will return the Accept policy, while a singular
// entry will simply be the policy itself.
Policy Sequence(std::vector<Policy> policies);

// Allows callers to Sequence policies without wrapping them in a list. Prefer
// this overload when reasonble. For example, instead of
//
//   Sequence({p0, p1, p2, p3})
//
// Prefer
//
//   Sequence(p0, p1, p2, p3)
template <typename... T>
Policy Sequence(T&&... policies) {
  return Sequence({std::forward<T>(policies)...});
}

// Performs a left-to-right set union of each policy in `policies`. For example,
//
//   Union({p0, p1, p2, p3});
//
// Is equivalent to
//
//   Union({Union({Union({p0, p1}), p2}), p3})
//
// Union is both associative and commutative.
//
// Note that an empty list will return the Deny policy, while a singular
// entry will simply be the policy itself.
Policy Union(std::vector<Policy> policies);

// Allows callers to Union policies without wrapping them in a list. Prefer
// this overload when reasonble. For example, instead of
//
//   Union({p0, p1, p2, p3})
//
// Prefer
//
//   Union(p0, p1, p2, p3)
template <typename... T>
Policy Union(T&&... policies) {
  return Union({std::forward<T>(policies)...});
}

// Iterates over the given policy 0 to many times. Also known as the Kleene
// Star operation. Iterate may be otherwise defined as,
//
//   Iterate(p) == Union(Policy::Accept(), p, Sequence(p,p), ...);
//
// For a practical example, we may assume some topology built of link actions.
// E.g.
//
//   Predicate at_src_link = Match("switch", 0) && Match("port", 0);
//   Policy go_to_dst = Sequence(Modify("switch", 1), Modify("port", 1));
//   Policy link_action0 = Sequence(Filter(at_src_link), go_to_dst);
//   ...
//   Policy topology = Union(link_action0, link_action1, ...);
//
// We may then use `Iterate` to build a policy that "walks" all paths in the
// network, reachable by some arbitrary switch.
//
//   Policy set_any_port = Union(Modify("port", 0), Modify("port", 1), ...);
//   Policy walk_topology =
//        Sequence(Filter(Match("switch", X)), set_any_port, Iterate(topology));
Policy Iterate(Policy policy);

// Records the packet into the packet history. Referred to as 'dup' in the
// literature.
//
// It is necessary to emplace Record statements in a program wherever decisions
// wish to be disambiguated/verified.
//
// TODO: b/377697348 - Enhance this comment with a simple example.
Policy Record();

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_FRONTEND_H_
