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

#include "netkat/netkat_proto_constructors.h"

#include <string>
#include <utility>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "netkat/netkat.pb.h"

namespace netkat {

PredicateProto TrueProto() {
  PredicateProto proto;
  proto.mutable_bool_constant()->set_value(true);
  return proto;
}

PredicateProto FalseProto() {
  PredicateProto proto;
  proto.mutable_bool_constant()->set_value(false);
  return proto;
}

PredicateProto MatchProto(absl::string_view field, int value) {
  PredicateProto proto;
  PredicateProto::Match& match = *proto.mutable_match();
  match.set_field(std::string(field));
  match.set_value(value);
  return proto;
}
PredicateProto AndProto(PredicateProto left, PredicateProto right) {
  PredicateProto proto;
  PredicateProto::And& and_op = *proto.mutable_and_op();
  *and_op.mutable_left() = std::move(left);
  *and_op.mutable_right() = std::move(right);
  return proto;
}

PredicateProto OrProto(PredicateProto left, PredicateProto right) {
  PredicateProto proto;
  PredicateProto::Or& or_op = *proto.mutable_or_op();
  *or_op.mutable_left() = std::move(left);
  *or_op.mutable_right() = std::move(right);
  return proto;
}
PredicateProto NotProto(PredicateProto negand) {
  PredicateProto proto;
  PredicateProto::Not& not_op = *proto.mutable_not_op();
  *not_op.mutable_negand() = std::move(negand);
  return proto;
}
PredicateProto XorProto(PredicateProto left, PredicateProto right) {
  PredicateProto proto;
  PredicateProto::Xor& xor_op = *proto.mutable_xor_op();
  *xor_op.mutable_left() = std::move(left);
  *xor_op.mutable_right() = std::move(right);
  return proto;
}

// -- Basic Policy constructors ------------------------------------------------

PolicyProto FilterProto(PredicateProto filter) {
  PolicyProto policy;
  *policy.mutable_filter() = std::move(filter);
  return policy;
}

PolicyProto ModificationProto(absl::string_view field, int value) {
  PolicyProto policy;
  policy.mutable_modification()->set_field(field);
  policy.mutable_modification()->set_value(value);
  return policy;
}

PolicyProto RecordProto() {
  PolicyProto policy;
  policy.mutable_record();
  return policy;
}

PolicyProto SequenceProto(PolicyProto left, PolicyProto right) {
  PolicyProto policy;
  *policy.mutable_sequence_op()->mutable_left() = std::move(left);
  *policy.mutable_sequence_op()->mutable_right() = std::move(right);
  return policy;
}

PolicyProto UnionProto(PolicyProto left, PolicyProto right) {
  PolicyProto policy;
  *policy.mutable_union_op()->mutable_left() = std::move(left);
  *policy.mutable_union_op()->mutable_right() = std::move(right);
  return policy;
}

PolicyProto IterateProto(PolicyProto iterable) {
  PolicyProto policy;
  *policy.mutable_iterate_op()->mutable_iterable() = std::move(iterable);
  return policy;
}

PolicyProto DifferenceProto(PolicyProto left, PolicyProto right) {
  PolicyProto policy;
  *policy.mutable_difference_op()->mutable_left() = std::move(left);
  *policy.mutable_difference_op()->mutable_right() = std::move(right);
  return policy;
}

// -- Derived Policy constructors ----------------------------------------------

PolicyProto DenyProto() { return FilterProto(FalseProto()); }

PolicyProto AcceptProto() { return FilterProto(TrueProto()); }

std::string AsShorthandString(PredicateProto predicate) {
  switch (predicate.predicate_case()) {
    case PredicateProto::kBoolConstant:
      return predicate.bool_constant().value() ? "true" : "false";
    case PredicateProto::kMatch:
      return absl::StrFormat("@%s==%d", predicate.match().field(),
                             predicate.match().value());
    case PredicateProto::kAndOp:
      return absl::StrFormat("(%s && %s)",
                             AsShorthandString(predicate.and_op().left()),
                             AsShorthandString(predicate.and_op().right()));
    case PredicateProto::kOrOp:
      return absl::StrFormat("(%s || %s)",
                             AsShorthandString(predicate.or_op().left()),
                             AsShorthandString(predicate.or_op().right()));
    case PredicateProto::kNotOp:
      return absl::StrCat("!", AsShorthandString(predicate.not_op().negand()));
    case PredicateProto::kXorOp:
      return absl::StrFormat("(%s (+) %s)",
                             AsShorthandString(predicate.xor_op().left()),
                             AsShorthandString(predicate.xor_op().right()));
    case PredicateProto::PREDICATE_NOT_SET:
      return "false";
  }
}

std::string AsShorthandString(PolicyProto policy) {
  switch (policy.policy_case()) {
    case PolicyProto::kFilter:
      return AsShorthandString(policy.filter());
    case PolicyProto::kModification:
      return absl::StrFormat("@%s:=%d", policy.modification().field(),
                             policy.modification().value());
    case PolicyProto::kRecord:
      return "record";
    case PolicyProto::kSequenceOp:
      return absl::StrFormat("(%s; %s)",
                             AsShorthandString(policy.sequence_op().left()),
                             AsShorthandString(policy.sequence_op().right()));
    case PolicyProto::kUnionOp:
      return absl::StrFormat("(%s + %s)",
                             AsShorthandString(policy.union_op().left()),
                             AsShorthandString(policy.union_op().right()));
    case PolicyProto::kIterateOp:
      return absl::StrFormat("(%s)*",
                             AsShorthandString(policy.iterate_op().iterable()));
    case PolicyProto::kDifferenceOp:
      return absl::StrFormat("(%s - %s)",
                             AsShorthandString(policy.difference_op().left()),
                             AsShorthandString(policy.difference_op().right()));
    case PolicyProto::POLICY_NOT_SET:
      return "deny";
  }
}

}  // namespace netkat
