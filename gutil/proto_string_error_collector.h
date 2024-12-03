/* Copyright 2018 The TensorFlow Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
==============================================================================*/

#ifndef GOOGLE_NETKAT_GUTIL_PROTO_STRING_ERROR_COLLECTOR_H_
#define GOOGLE_NETKAT_GUTIL_PROTO_STRING_ERROR_COLLECTOR_H_

#include <string>

#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "google/protobuf/io/tokenizer.h"

namespace netkat {

// Collects errors by appending them to a given string.
class StringErrorCollector : public google::protobuf::io::ErrorCollector {
 public:
  // String error_text is unowned and must remain valid during the use of
  // StringErrorCollector.
  explicit StringErrorCollector(std::string* error_text)
      : error_text_{error_text} {};
  StringErrorCollector(const StringErrorCollector&) = delete;
  StringErrorCollector& operator=(const StringErrorCollector&) = delete;

  // Implementation of protobuf::io::ErrorCollector::AddError.
  void RecordError(int line, int column, absl::string_view message) override {
    if (error_text_ != nullptr) {
      absl::SubstituteAndAppend(error_text_, "$0($1): $2\n", line, column,
                                message);
    }
  }

  // Implementation of protobuf::io::ErrorCollector::RecordWarning.
  void RecordWarning(int line, int column, absl::string_view message) override {
    RecordError(line, column, message);
  }

 private:
  std::string* const error_text_;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_GUTIL_PROTO_STRING_ERROR_COLLECTOR_H_
