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
// -----------------------------------------------------------------------------

#include "netkat/evaluator.h"

#include "absl/container/flat_hash_set.h"
#include "absl/log/log.h"
#include "netkat/netkat.pb.h"

namespace netkat {

bool Evaluate(const PredicateProto& predicate, const Packet& packet) {
  switch (predicate.predicate_case()) {
    case PredicateProto::kBoolConstant:
      return predicate.bool_constant().value();
    case PredicateProto::kNotOp:
      return !Evaluate(predicate.not_op().negand(), packet);
    case PredicateProto::kAndOp:
      return Evaluate(predicate.and_op().left(), packet) &&
             Evaluate(predicate.and_op().right(), packet);
    case PredicateProto::kOrOp:
      return Evaluate(predicate.or_op().left(), packet) ||
             Evaluate(predicate.or_op().right(), packet);
    case PredicateProto::kXorOp:
      return (!Evaluate(predicate.xor_op().left(), packet) &&
              Evaluate(predicate.xor_op().right(), packet)) ||
             (Evaluate(predicate.xor_op().left(), packet) &&
              !Evaluate(predicate.xor_op().right(), packet));
    case PredicateProto::kMatch:
      if (auto iter = packet.find(predicate.match().field());
          iter != packet.end()) {
        return iter->second == predicate.match().value();
      } else {
        return false;
      }
    case PredicateProto::PREDICATE_NOT_SET:
      return false;
  }
  LOG(FATAL) << "Unexpected value for PredicateProto predicate_case: "
             << static_cast<int>(predicate.predicate_case());
}

absl::flat_hash_set<Packet> Evaluate(
    const PolicyProto& policy, const absl::flat_hash_set<Packet>& packets) {
  absl::flat_hash_set<Packet> result;
  for (const Packet& packet : packets) {
    result.merge(Evaluate(policy, packet));
  }
  return result;
}

absl::flat_hash_set<Packet> Evaluate(const PolicyProto& policy,
                                     const Packet& packet) {
  switch (policy.policy_case()) {
    case PolicyProto::kFilter:
      return Evaluate(policy.filter(), packet)
                 ? absl::flat_hash_set<Packet>({packet})
                 : absl::flat_hash_set<Packet>();
    case PolicyProto::kModification: {
      Packet modified_packet = packet;
      // Adds field if it doesn't exist, and modifies it otherwise.
      modified_packet[policy.modification().field()] =
          policy.modification().value();
      return {modified_packet};
    }
    case PolicyProto::kRecord:
      // Record is treated as a no-op.
      return {packet};
    case PolicyProto::kSequenceOp:
      return Evaluate(policy.sequence_op().right(),
                      Evaluate(policy.sequence_op().left(), packet));
    case PolicyProto::kUnionOp: {
      absl::flat_hash_set<Packet> result =
          Evaluate(policy.union_op().left(), packet);
      result.merge(Evaluate(policy.union_op().right(), packet));
      return result;
    }
    case PolicyProto::kIterateOp: {
      // p* = 1 + p + p;p + p;p;p + ...
      absl::flat_hash_set<Packet> result = {packet};  // 1
      // Evaluate p on result until fixed point, marked by no change in size.
      int last_size;
      do {
        last_size = result.size();
        result.merge(Evaluate(policy.iterate_op().iterable(), result));  // p^n
      } while (last_size != result.size());
      return result;
    }
    case PolicyProto::kDifferenceOp: {
      absl::flat_hash_set<Packet> result =
          Evaluate(policy.difference_op().left(), packet);
      const absl::flat_hash_set<Packet> subtrahend =
          Evaluate(policy.difference_op().right(), packet);
      absl::erase_if(result,
                     [&](const Packet& p) { return subtrahend.contains(p); });
      return result;
    }
    case PolicyProto::POLICY_NOT_SET:
      // Unset policy is treated as Deny.
      return {};
  }
}

}  // namespace netkat
