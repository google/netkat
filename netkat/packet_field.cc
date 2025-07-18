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

#include "netkat/packet_field.h"

#include <string>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "gutil/status.h"

namespace netkat {

PacketFieldHandle PacketFieldManager::GetOrCreatePacketFieldHandle(
    absl::string_view field_name) {
  auto [it, inserted] = packet_field_by_name_.try_emplace(
      field_name, PacketFieldHandle(field_names_.size()));
  if (inserted) field_names_.push_back(std::string(field_name));
  return it->second;
}

std::string PacketFieldManager::GetFieldName(PacketFieldHandle field) const {
  if (field.index_ >= field_names_.size()) {
    LOG(DFATAL) << "PacketFieldManager::GetFieldName: field index "
                << field.index_
                << " out of bounds. Returning arbitrary string.";
    return "INTERNAL ERROR: PacketFieldManager::GetFieldName out of bounds";
  }
  return field_names_[field.index_];
}

absl::Status PacketFieldManager::CheckInternalInvariants() const {
  for (int i = 0; i < field_names_.size(); ++i) {
    auto it = packet_field_by_name_.find(field_names_[i]);
    RET_CHECK(it != packet_field_by_name_.end());
    RET_CHECK(it->second.index_ == i);
  }

  for (const auto& [name, field] : packet_field_by_name_) {
    RET_CHECK(field.index_ < field_names_.size());
    RET_CHECK(field_names_[field.index_] == name);
  }

  return absl::OkStatus();
}

}  // namespace netkat
