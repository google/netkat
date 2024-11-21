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

#include "absl/log/log.h"
#include "gtest/gtest.h"
#include "netkat/netkat.pb.h"
#include "fuzztest/fuzztest.h"

namespace netkat {
namespace {

// Sanity fuzz test to show that the FuzzTest library works.
void DummmyFuzzTest(PredicateProto pred, PolicyProto pol) {
  LOG_EVERY_N_SEC(INFO, 1) << "pred = " << pred;
  LOG_EVERY_N_SEC(INFO, 1) << "pol = " << pol;
}
FUZZ_TEST(NetkatProtoTest, DummmyFuzzTest);

// Ensures that the protobuf C++ compiler does not add underscores to the
// generated code for sub messages and oneof fields of `PredicateProto`.
//
// This test is needed because we uses key words such as "and", "or", "not",
// "bool", which are all reserved protobuf/C++ keywords.
TEST(NetkatProtoTest, PredicateOneOfFieldNamesDontRequireUnderscores) {
  PredicateProto predicate;
  switch (predicate.predicate_case()) {
    case PredicateProto::kAndOp: {
      const PredicateProto::And& and_op = predicate.and_op();
      LOG(INFO) << "and_op: " << and_op;
      break;
    }
    case PredicateProto::kOrOp: {
      const PredicateProto::Or& or_op = predicate.or_op();
      LOG(INFO) << "or_op: " << or_op;
      break;
    }
    case PredicateProto::kNotOp: {
      const PredicateProto::Not& not_op = predicate.not_op();
      LOG(INFO) << "not_op: " << not_op;
      break;
    }
    case PredicateProto::kMatch: {
      const PredicateProto::Match& match = predicate.match();
      LOG(INFO) << "match: " << match;
      break;
    }
    case PredicateProto::kBoolConstant: {
      const PredicateProto::Bool& bool_constant = predicate.bool_constant();
      LOG(INFO) << "bool_constant: " << bool_constant;
      break;
    }
    case PredicateProto::PREDICATE_NOT_SET:
      break;
  }
}

TEST(NetkatProtoTest, PolicyOneOfFieldNamesDontRequireUnderscores) {
  PolicyProto policy;
  switch (policy.policy_case()) {
    case PolicyProto::kFilter: {
      const PredicateProto& filter = policy.filter();
      LOG(INFO) << "filter: " << filter;
      break;
    }
    case PolicyProto::kModification: {
      const PolicyProto::Modification& modification = policy.modification();
      LOG(INFO) << "modification: " << modification;
      break;
    }
    case PolicyProto::kRecord: {
      const PolicyProto::Record& record = policy.record();
      LOG(INFO) << "record: " << record;
      break;
    }
    case PolicyProto::kSequenceOp: {
      const PolicyProto::Sequence& sequence_op = policy.sequence_op();
      LOG(INFO) << "sequence: " << sequence_op;
      break;
    }
    case PolicyProto::kUnionOp: {
      const PolicyProto::Union& union_op = policy.union_op();
      LOG(INFO) << "union: " << union_op;
      break;
    }
    case PolicyProto::kIterateOp: {
      const PolicyProto::Iterate& iter = policy.iterate_op();
      LOG(INFO) << "iterate: " << iter;
      break;
    }
    case PolicyProto::POLICY_NOT_SET:
      break;
  }
}

}  // namespace
}  // namespace netkat
