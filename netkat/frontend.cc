#include "netkat/frontend.h"

#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/strings/string_view.h"
#include "netkat/netkat.pb.h"

namespace netkat {

Predicate operator!(Predicate predicate) {
  PredicateProto proto;
  *proto.mutable_not_op()->mutable_negand() = std::move(predicate).ToProto();
  return Predicate(std::move(proto));
}

Predicate operator&&(Predicate lhs, Predicate rhs) {
  PredicateProto proto;
  *proto.mutable_and_op()->mutable_left() = std::move(lhs).ToProto();
  *proto.mutable_and_op()->mutable_right() = std::move(rhs).ToProto();
  return Predicate(std::move(proto));
}

Predicate operator||(Predicate lhs, Predicate rhs) {
  PredicateProto proto;
  *proto.mutable_or_op()->mutable_left() = std::move(lhs).ToProto();
  *proto.mutable_or_op()->mutable_right() = std::move(rhs).ToProto();
  return Predicate(std::move(proto));
}

Predicate Predicate::True() {
  PredicateProto proto;
  proto.mutable_bool_constant()->set_value(true);
  return Predicate(std::move(proto));
}

Predicate Predicate::False() {
  PredicateProto proto;
  proto.mutable_bool_constant()->set_value(false);
  return Predicate(std::move(proto));
}

Predicate Match(absl::string_view field, int value) {
  PredicateProto proto;
  PredicateProto::Match& match = *proto.mutable_match();
  match.set_field(field);
  match.set_value(value);
  return Predicate(std::move(proto));
}
}  // namespace netkat
