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

}  // namespace netkat
