#include "netkat/interned_policy.h"

#include <utility>
#include <variant>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "netkat/netkat.pb.h"

namespace netkat {

InternedPolicyRepresentation InternedPolicyManager::Sequence(
    InternedPolicyRepresentation&& left, InternedPolicyRepresentation&& right) {
  InternedSequence result;
  if (auto* left_sequence = std::get_if<InternedSequence>(&left)) {
    result = std::move(*left_sequence);
  } else {
    result.policies.push_back(RepresentationToPolicy(std::move(left)));
  }
  if (auto* right_sequence = std::get_if<InternedSequence>(&right)) {
    for (InternedPolicy policy : right_sequence->policies) {
      result.policies.push_back(policy);
    }
  } else {
    result.policies.push_back(RepresentationToPolicy(std::move(right)));
  }
  return result;
}

InternedPolicyRepresentation InternedPolicyManager::Union(
    InternedPolicyRepresentation&& left, InternedPolicyRepresentation&& right) {
  InternedUnion result;
  if (auto* left_union = std::get_if<InternedUnion>(&left)) {
    result = std::move(*left_union);
  } else {
    result.policies.insert(RepresentationToPolicy(std::move(left)));
  }
  if (auto* right_union = std::get_if<InternedUnion>(&right)) {
    result.policies.insert(right_union->policies.begin(),
                           right_union->policies.end());
  } else {
    result.policies.insert(RepresentationToPolicy(std::move(right)));
  }
  return result;
}

InternedPolicyRepresentation InternedPolicyManager::Iterate(
    InternedPolicyRepresentation&& policy) {
  if (std::holds_alternative<InternedIteration>(policy)) return policy;
  return InternedIteration{
      .policy = RepresentationToPolicy(std::move(policy)),
  };
}

InternedPolicyRepresentation InternedPolicyManager::ToInternedRepresentation(
    const PredicateProto& predicate, bool negate) {
  switch (predicate.predicate_case()) {
    case PredicateProto::kBoolConstant: {
      bool constant = predicate.bool_constant().value();
      if (negate) constant = !constant;
      return constant ? Accept() : Deny();
    }

    case PredicateProto::PREDICATE_NOT_SET: {
      return negate ? Accept() : Deny();
    }

    case PredicateProto::kMatch: {
      return InternedMatch{
          .negated = negate,
          .field = field_manager_.GetOrCreateInternedField(
              predicate.match().field()),
          .value = predicate.match().value(),
      };
    }

    case PredicateProto::kAndOp: {
      const PredicateProto& left = predicate.and_op().left();
      const PredicateProto& right = predicate.and_op().right();
      if (negate) {
        return Union(ToInternedRepresentation(left, negate),
                     ToInternedRepresentation(right, negate));
      } else {
        return Sequence(ToInternedRepresentation(left, negate),
                        ToInternedRepresentation(right, negate));
      }
    }

    case PredicateProto::kOrOp: {
      const PredicateProto& left = predicate.or_op().left();
      const PredicateProto& right = predicate.or_op().right();
      if (negate) {
        return Sequence(ToInternedRepresentation(left, negate),
                        ToInternedRepresentation(right, negate));
      } else {
        return Union(ToInternedRepresentation(left, negate),
                     ToInternedRepresentation(right, negate));
      }
    }

    case PredicateProto::kNotOp: {
      return ToInternedRepresentation(predicate.not_op().negand(), !negate);
    }

    case PredicateProto::kXorOp: {
      LOG(FATAL) << "TODO(smolkaj): Implement.";
    }
  }
  LOG(DFATAL) << "Unhandled predicate kind: " << predicate.predicate_case();
  return Deny();
}

InternedPolicyRepresentation InternedPolicyManager::ToInternedRepresentation(
    const PolicyProto& policy) {
  switch (policy.policy_case()) {
    case PolicyProto::kFilter: {
      return ToInternedRepresentation(policy.filter(), /*negate=*/false);
    }
    case PolicyProto::kModification: {
      return InternedModification{
          .field = field_manager_.GetOrCreateInternedField(
              policy.modification().field()),
          .value = policy.modification().value(),
      };
    }
    case PolicyProto::kRecord: {
      return InternedRecord{};
    }
    case PolicyProto::kSequenceOp: {
      return Sequence(ToInternedRepresentation(policy.sequence_op().left()),
                      ToInternedRepresentation(policy.sequence_op().right()));
    }
    case PolicyProto::kUnionOp: {
      return Union(ToInternedRepresentation(policy.union_op().left()),
                   ToInternedRepresentation(policy.union_op().right()));
    }
    case PolicyProto::kIterateOp: {
      return Iterate(ToInternedRepresentation(policy.iterate_op().iterable()));
    }
    case PolicyProto::POLICY_NOT_SET: {
      return Deny();
    }
  }
}

InternedPolicy InternedPolicyManager::GetOrCreateInternedPolicy(
    const PolicyProto& policy) {
  return RepresentationToPolicy(ToInternedRepresentation(policy));
}

InternedPolicy InternedPolicyManager::RepresentationToPolicy(
    InternedPolicyRepresentation&& representation) {
  auto [it, inserted] = interned_policy_by_representation_.try_emplace(
      representation, InternedPolicy(representations_.size()));
  if (inserted) representations_.push_back(std::move(representation));
  return it->second;
}

const InternedPolicyRepresentation& InternedPolicyManager::GetRepresentation(
    InternedPolicy policy) const {
  CHECK_LT(policy.index_, representations_.size());
  return representations_[policy.index_];
}

}  // namespace netkat
