// Copyright 2026 The NetKAT authors
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

#include "netkat/table_builder.h"

#include <source_location>  // NOLINT - absl::SourceLocation not available yet.
#include <string>
#include <utility>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "gutil/proto.h"
#include "netkat/table.h"

namespace netkat {

NetkatTableBuilder::NetkatTableBuilder(NetkatTable& table) : table_(table) {}

NetkatTableBuilder& NetkatTableBuilder::LogRules() {
  LOG(INFO) << "Rules in the table builder: \n"
            << absl::StrJoin(
                   located_rules_, "\n",
                   [](std::string* out, const LocatedRule& located_rule) {
                     const NetkatTable::Rule& rule = located_rule.rule;
                     absl::StrAppend(
                         out, "priority: ", rule.priority, "\nmatch: ",
                         gutil::PrintTextProto(rule.match.GetProto()),
                         "action: ",
                         gutil::PrintTextProto(rule.action.GetProto()));
                   });
  return *this;
}

NetkatTableBuilder& NetkatTableBuilder::AddRule(NetkatTable::Rule rule,
                                                std::source_location loc) {
  located_rules_.push_back({std::move(rule), loc});
  return *this;
}

absl::Status NetkatTableBuilder::InstallRules() {
  NetkatTable temp_table(table_);
  for (LocatedRule& located_rule : located_rules_) {
    std::source_location location = located_rule.location;
    absl::Status status = temp_table.AddRule(std::move(located_rule.rule));
    if (!status.ok()) {
      // Clear all the located rules in the table builder to avoid installing an
      // invalid table entry accidentally in a later call to `InstallRules`.
      located_rules_.clear();
      return absl::Status(
          status.code(),
          absl::StrCat(location.file_name(), ":", location.line(),
                       ": Failed to install table rule: ", status.message()));
    }
  }
  table_ = std::move(temp_table);
  return absl::OkStatus();
}

}  // namespace netkat
