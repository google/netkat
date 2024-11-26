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

}  // namespace netkat
