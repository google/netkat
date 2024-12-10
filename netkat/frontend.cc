#include "netkat/frontend.h"

#include <utility>
#include <vector>

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

Policy Modify(absl::string_view field, int new_value) {
  PolicyProto proto;
  PolicyProto::Modification& mod = *proto.mutable_modification();
  mod.set_field(field);
  mod.set_value(new_value);
  return Policy(std::move(proto));
}

Policy Sequence(std::vector<Policy> policies) {
  if (policies.empty()) return Policy::Accept();
  if (policies.size() == 1) return std::move(policies[0]);

  PolicyProto proto;
  PolicyProto::Sequence* root = proto.mutable_sequence_op();
  for (int i = policies.size() - 1; i > 1; --i) {
    *root->mutable_right() = std::move(policies[i]).ToProto();
    root = root->mutable_left()->mutable_sequence_op();
  }
  *root->mutable_left() = std::move(policies[0]).ToProto();
  *root->mutable_right() = std::move(policies[1]).ToProto();
  return Policy(std::move(proto));
}

Policy Union(std::vector<Policy> policies) {
  if (policies.empty()) return Policy::Deny();
  if (policies.size() == 1) return std::move(policies[0]);

  PolicyProto proto;
  PolicyProto::Union* root = proto.mutable_union_op();
  for (int i = policies.size() - 1; i > 1; --i) {
    *root->mutable_right() = std::move(policies[i]).ToProto();
    root = root->mutable_left()->mutable_union_op();
  }
  *root->mutable_left() = std::move(policies[0]).ToProto();
  *root->mutable_right() = std::move(policies[1]).ToProto();
  return Policy(std::move(proto));
}

Policy Iterate(Policy policy) {
  PolicyProto proto;
  *proto.mutable_iterate_op()->mutable_iterable() = std::move(policy).ToProto();
  return Policy(std::move(proto));
}

Policy Record() {
  PolicyProto proto;
  proto.mutable_record();
  return Policy(std::move(proto));
}

Policy Filter(Predicate predicate) {
  PolicyProto proto;
  *proto.mutable_filter() = std::move(predicate).ToProto();
  return Policy(std::move(proto));
}

Policy Policy::Accept() { return Filter(Predicate::True()); }

Policy Policy::Deny() { return Filter(Predicate::False()); }

}  // namespace netkat
