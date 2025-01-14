#include "netkat/frontend.h"

#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "netkat/netkat.pb.h"
#include "netkat/netkat_proto_constructors.h"

namespace netkat {

Predicate operator!(Predicate predicate) {
  return Predicate(NotProto(std::move(predicate).ToProto()));
}

Predicate operator&&(Predicate lhs, Predicate rhs) {
  return Predicate(
      AndProto(std::move(lhs).ToProto(), std::move(rhs).ToProto()));
}

Predicate operator||(Predicate lhs, Predicate rhs) {
  return Predicate(OrProto(std::move(lhs).ToProto(), std::move(rhs).ToProto()));
}

Predicate Predicate::True() { return Predicate(TrueProto()); }

Predicate Predicate::False() { return Predicate(FalseProto()); }

Predicate Match(absl::string_view field, int value) {
  return Predicate(MatchProto(field, value));
}

Policy Modify(absl::string_view field, int new_value) {
  return Policy(ModificationProto(field, new_value));
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
  return Policy(IterateProto(std::move(policy).ToProto()));
}

Policy Record() { return Policy(RecordProto()); }

Policy Filter(Predicate predicate) {
  return Policy(FilterProto(std::move(predicate).ToProto()));
}

Policy Policy::Accept() { return Filter(Predicate::True()); }

Policy Policy::Deny() { return Filter(Predicate::False()); }

}  // namespace netkat
