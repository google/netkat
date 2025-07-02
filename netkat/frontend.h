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

#include <bitset>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
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
  // `Match`, `True`, `False` or `Predicate::FromProto(...)`.
  Predicate() = delete;

  // Creates a Predicate from `predicate_proto`.
  // If `predicate_proto` is ill-formed, returns InvalidArgument error.
  // A `predicate_proto` is considered valid if:
  //    - For scalar OneOf fields
  //      - `bool_constant` is valid
  //      - `match` is valid if `match::field` is not empty.
  //    - For Recursive OneOf fields made up of PredicateProto, it is valid if
  //      the member fields are present and valid. For example, `and_op` is
  //      valid if `and_op::left` and `and_op::right` are valid.
  static absl::StatusOr<Predicate> FromProto(PredicateProto predicate_proto);

  // Returns the underlying IR proto.
  //
  // Users should generally not handle this proto directly.
  PredicateProto ToProto() const& { return predicate_; }
  PredicateProto ToProto() && { return std::move(predicate_); }

  // Returns a reference to the underlying IR proto.
  //
  // This reference will only be valid for either the lifetime of this class OR
  // until the object is moved.
  const PredicateProto& GetProto() const& { return predicate_; }

  // Logical operators. These perform exactly as expected, with the
  // exception of short circuiting.
  //
  // These objects by themselves are not intrinsically truthy, so a lack of
  // short circuiting will not generate semantically different programs.
  friend Predicate operator&&(Predicate lhs, Predicate rhs);
  friend Predicate operator||(Predicate lhs, Predicate rhs);
  friend Predicate operator!(Predicate predicate);
  friend Predicate Xor(Predicate lhs, Predicate rhs);

  // Predicates that conceptually represent a packet being universally accepted
  // or denied/droped.
  //
  // Concretely this is simply a constant `Predicate(true/false)`.
  static Predicate True();
  static Predicate False();

  // Match operation for a Predicate. See below for the full definition. We
  // utilize friend association to ensure program construction is well-formed.
  friend Predicate Match(absl::string_view, int);

 private:
  // Hide default proto construction to hinder building of ill-formed programs.
  explicit Predicate(PredicateProto pred) : predicate_(std::move(pred)) {}

  // Calling GetProto on an R-value predicate is at best inefficient and, more
  // likely, a bug. Use ToProto instead.
  const PredicateProto& GetProto() && = delete;

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
  // Returns the underlying IR proto.
  //
  // Users should generally not handle this proto directly.
  PolicyProto ToProto() const& { return policy_; }
  PolicyProto ToProto() && { return std::move(policy_); }

  // Creates a Policy from `policy_proto`.
  // If `policy_proto` is ill-formed, returns InvalidArgument error.
  // A `policy_proto` is considered valid if:
  //   - An empty PolicyProto is invalid.
  //   - For scalar `policy` OneOf field:
  //     - `record` is valid.
  //     - `modification` is valid if `Modification::field` is not empty.
  //     - `filter` is valid if `filter` is a valid PredicateProto (see
  //     definition above).
  //   - For recursive OneOf fields made up of PolicyProto(s), it is valid if
  //     the member fields are present and valid. For example, `sequence_op` is
  //     valid if `sequence_op::left` and `sequence_op::right` are valid.
  static absl::StatusOr<Policy> FromProto(PolicyProto policy_proto);

  // Returns a reference to the underlying IR proto.
  //
  // This reference will only be valid for either the lifetime of this class OR
  // until `ToProto()&&` is called (moving the underlying reference), whichever
  // is sooner.
  const PolicyProto& GetProto() const& { return policy_; }

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

  // Calling GetProto on an R-value policy is at best inefficient and, more
  // likely, a bug. Use ToProto instead.
  const PolicyProto& GetProto() && = delete;

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
//   Predicate at_src0_link0 = Match("switch", 0) && Match("port", 0);
//   Policy go_to_dst1 = Sequence(Modify("switch", 1), Modify("port", 1));
//   Policy link_action0 = Sequence(Filter(at_src0_link0), go_to_dst1);
//   ...
//   Policy topology = Union(link_action0, link_action1, ...);
//
// We may then use `Iterate` to build a policy that "walks" all paths in the
// network, reachable by some arbitrary switch.
//
//   Policy set_any_port = Union(Modify("port", 0), Modify("port", 1), ...);
//   Policy walk_topology_from_x =
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

////////////////////////////////////////////////////////////////////////////////
// The following are a set of temporary helpers to utilize ternaries in NetKAT
// programs.
//
// TODO: b/420948630 - Replace this with an efficient representation.
//
// Supporting ternaries this way is very inefficient, in both representation and
// computation, but exists to allow further prototyping. The final API will be
// more robust and efficient, involving a more catered representation in the IR
// and backend.
//
// Note that it is the user's responsibility to ensure that each field has the
// correct bit-width. If two programs assume differing bit-widths of the same
// field, comparisons are likely to be wrong.
////////////////////////////////////////////////////////////////////////////////

// A representation of a ternary. A ternary is typically represented as some
// N-bit value/mask structure. That is, for some N-bit width ternary the mask
// represents what bits we need to care about in the value portion. E.g.
//
//   TernaryField<2>{.value = {0b11}, mask = {0b10}} means match 0b1*, ie only
//   the left-most bit must be set to 1.
//
// Note that sometimes the above may be written as the shorthand 0x3/0x2.
template <uint8_t BitWidth>
struct TernaryField {
  std::bitset<BitWidth> value;
  std::bitset<BitWidth> mask;
};

// Matches a presumed ternary `field`. Only indices with `new_value.mask` set
// to 1 will be matched. E.g. b0011/b0001 will only result in a `Predicate` that
// matches the LSB.
//
// An empty mask will result in Predicate::True.
template <uint8_t N>
inline Predicate Match(absl::string_view field, TernaryField<N> value) {
  Predicate predicate = Predicate::True();
  for (int i = 0; i < N; ++i) {
    if (!value.mask[i]) continue;
    const int bit_val = value.value[i] ? 1 : 0;
    predicate =
        std::move(predicate) && Match(absl::StrCat(field, "_b", i), bit_val);
  }
  return predicate;
}

// Modifies a presumed ternary `field`. Only indices with `new_value.mask`set
// to 1 will be modified. E.g. b0011/b0001 will only result in the LSB being
// set, so a ternary like b1100 will only be set to b1101.
//
// An empty mask will result in Policy::Accept.
template <uint8_t N>
inline Policy Modify(absl::string_view field, TernaryField<N> new_value) {
  Policy policy = Policy::Accept();
  for (int i = 0; i < N; ++i) {
    if (!new_value.mask[i]) continue;
    const int value = new_value.value[i] ? 1 : 0;
    policy = Sequence(
        {std::move(policy), Modify(absl::StrCat(field, "_b", i), value)});
  }
  return policy;
}

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_FRONTEND_H_
