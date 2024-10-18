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

namespace netkat {
namespace {

// Ensures that the protobuf C++ compiler does not add underscores to the
// generated code for sub messages and oneof fields of `PredicateProto`.
//
// This test is needed because we uses key words such as "and", "or", "not",
// "bool", which are all reserved protobuf/C++ keywords.
TEST(NetkatProtoTest, PredicateOneOfFieldNamesDontRequireUnderscores) {
  PredicateProto predicate;
  switch (predicate.predicate_case()) {
    case PredicateProto::kAndOperation: {
      const PredicateProto::And& and_operation = predicate.and_operation();
      LOG(INFO) << "and_operation: " << and_operation;
      break;
    }
    case PredicateProto::kOrOperation: {
      const PredicateProto::Or& or_operation = predicate.or_operation();
      LOG(INFO) << "or_operation: " << or_operation;
      break;
    }
    case PredicateProto::kNotOperation: {
      const PredicateProto::Not& not_operation = predicate.not_operation();
      LOG(INFO) << "not_operation: " << not_operation;
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

}  // namespace
}  // namespace netkat
