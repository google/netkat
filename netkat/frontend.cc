#include "netkat/frontend.h"

#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "gutil/status.h"
#include "netkat/netkat.pb.h"
#include "netkat/netkat_proto_constructors.h"
namespace netkat {

// Recursively checks whether `predicate_proto` is valid.
absl::Status RecursivelyCheckIsValid(const PredicateProto& predicate_proto) {
  switch (predicate_proto.predicate_case()) {
    case PredicateProto::PREDICATE_NOT_SET:
      return absl::InvalidArgumentError("Unset Predicate case is invalid");
    case PredicateProto::kMatch:
      if (predicate_proto.match().field().empty()) {
        return absl::InvalidArgumentError(
            "PredicateProto::Match::field is invalid because it is empty.");
      }
      return absl::OkStatus();
    case PredicateProto::kBoolConstant:
      return absl::OkStatus();
    case PredicateProto::kAndOp: {
      RETURN_IF_ERROR(RecursivelyCheckIsValid(predicate_proto.and_op().left()))
              .SetPrepend()
          << "PredicateProto::And's lhs is invalid: ";
      RETURN_IF_ERROR(RecursivelyCheckIsValid(predicate_proto.and_op().right()))
              .SetPrepend()
          << "PredicateProto::And's rhs is invalid: ";
      return absl::OkStatus();
    }
    case PredicateProto::kOrOp: {
      RETURN_IF_ERROR(RecursivelyCheckIsValid(predicate_proto.or_op().left()))
              .SetPrepend()
          << "PredicateProto::Or's lhs is invalid: ";
      RETURN_IF_ERROR(RecursivelyCheckIsValid(predicate_proto.or_op().right()))
              .SetPrepend()
          << "PredicateProto::Or's rhs is invalid: ";
      return absl::OkStatus();
    }
    case PredicateProto::kXorOp: {
      RETURN_IF_ERROR(RecursivelyCheckIsValid(predicate_proto.xor_op().left()))
              .SetPrepend()
          << "PredicateProto::Xor's lhs is invalid: ";
      RETURN_IF_ERROR(RecursivelyCheckIsValid(predicate_proto.xor_op().right()))
              .SetPrepend()
          << "PredicateProto::Xor's rhs is invalid: ";
      return absl::OkStatus();
    }
    case PredicateProto::kNotOp:
      RETURN_IF_ERROR(
          RecursivelyCheckIsValid(predicate_proto.not_op().negand()))
              .SetPrepend()
          << "PredicateProto::Not's negand is invalid: ";
      return absl::OkStatus();
  }
}

absl::StatusOr<Predicate> Predicate::FromProto(PredicateProto predicate_proto) {
  RETURN_IF_ERROR(RecursivelyCheckIsValid(predicate_proto));
  return Predicate(std::move(predicate_proto));
}

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

Predicate Xor(Predicate lhs, Predicate rhs) {
  return Predicate(
      XorProto(std::move(lhs).ToProto(), std::move(rhs).ToProto()));
}

Predicate Predicate::True() { return Predicate(TrueProto()); }

Predicate Predicate::False() { return Predicate(FalseProto()); }

Predicate Match(absl::string_view field, int value) {
  return Predicate(MatchProto(field, value));
}

absl::Status RecursivelyCheckIsValid(const PolicyProto& policy_proto) {
  switch (policy_proto.policy_case()) {
    case PolicyProto::kFilter:
      return RecursivelyCheckIsValid(policy_proto.filter());
    case PolicyProto::kModification:
      if (policy_proto.modification().field().empty()) {
        return absl::InvalidArgumentError(
            "PolicyProto::Modification::field is invalid because it is empty.");
      }
      return absl::OkStatus();
    case PolicyProto::kRecord:
      return absl::OkStatus();
    case PolicyProto::kSequenceOp:
      RETURN_IF_ERROR(
          RecursivelyCheckIsValid(policy_proto.sequence_op().left()))
              .SetPrepend()
          << "PolicyProto::SequenceOp::left is invalid: ";
      RETURN_IF_ERROR(
          RecursivelyCheckIsValid(policy_proto.sequence_op().right()))
              .SetPrepend()
          << "PolicyProto::SequenceOp::right is invalid: ";
      return absl::OkStatus();
    case PolicyProto::kUnionOp:
      RETURN_IF_ERROR(RecursivelyCheckIsValid(policy_proto.union_op().left()))
              .SetPrepend()
          << "PolicyProto::UnionOp::left is invalid: ";
      RETURN_IF_ERROR(RecursivelyCheckIsValid(policy_proto.union_op().right()))
              .SetPrepend()
          << "PolicyProto::UnionOp::right is invalid: ";
      return absl::OkStatus();
    case PolicyProto::kIterateOp:
      RETURN_IF_ERROR(
          RecursivelyCheckIsValid(policy_proto.iterate_op().iterable()))
          << "PolicyProto::Iterate::policy is invalid: ";
      return absl::OkStatus();
    case PolicyProto::POLICY_NOT_SET:
      return absl::InvalidArgumentError("Unset Policy case is invalid");
  }
}
absl::StatusOr<Policy> Policy::FromProto(PolicyProto policy_proto) {
  RETURN_IF_ERROR(RecursivelyCheckIsValid(policy_proto));
  return Policy(std::move(policy_proto));
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
