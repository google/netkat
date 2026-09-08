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

#ifndef GOOGLE_NETKAT_NETKAT_TABLE_BUILDER_H_
#define GOOGLE_NETKAT_NETKAT_TABLE_BUILDER_H_

#include <source_location>  // NOLINT - absl::SourceLocation not available yet.
#include <vector>

#include "absl/status/status.h"
#include "netkat/table.h"

namespace netkat {

// A builder class for modifying an existing NetkatTable using a fluent
// interface. Modifications are applied atomically: if any rule fails to be
// installed (e.g., due to a constraint violation), the underlying table remains
// completely unmodified.
class NetkatTableBuilder {
 public:
  // Creates a NetkatTableBuilder that modifies the given `table`. Note that
  // NetkatTable must outlive the NetkatTableBuilder.
  explicit NetkatTableBuilder(NetkatTable& table);

  // Logs the current rules in the NetkatTableBuilder to LOG(INFO).
  NetkatTableBuilder& LogRules();

  // Adds a rule to be inserted into the table at the given priority.
  NetkatTableBuilder& AddRule(
      NetkatTable::Rule rule,
      std::source_location loc = std::source_location::current());

  // Moves all buffered rules into the table atomically. Returns an error
  // with the source location of the caller if any rule cannot be successfully
  // added. If any rule fails to be installed (e.g., due to a constraint
  // violation), the underlying table remains completely unmodified,
  // NetkatTableBuilder dumps all the rules that were added to it, and an error
  // is returned.
  absl::Status InstallRules();

 private:
  friend class NetkatTable;

  // A rule with its source location, for error reporting.
  struct LocatedRule {
    // A rule to be installed in the table.
    NetkatTable::Rule rule;
    // The source location of the rule, for error reporting.
    std::source_location location;
  };

  std::vector<LocatedRule> located_rules_;
  NetkatTable& table_;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_TABLE_BUILDER_H_
