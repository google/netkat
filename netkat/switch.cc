// Copyright 2025 The NetKAT authors
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
#include "netkat/switch.h"

#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "netkat/frontend.h"

namespace netkat {

absl::Status NetkatSwitch::AddStage(
    std::unique_ptr<NetkatSwitchPipelineStage> stage) {
  if (stage == nullptr) return absl::InvalidArgumentError("Stage is null");
  stages_.push_back(std::move(stage));
  return absl::OkStatus();
}

NetkatSwitchPipelineStage* NetkatSwitch::GetStage(int index) const {
  if (index < 0 || index >= stages_.size()) return nullptr;
  return stages_[index].get();
}

netkat::Policy NetkatSwitch::GetPolicy() const {
  if (stages_.empty()) return netkat::Policy::Deny();

  netkat::Policy policy = netkat::Policy::Accept();
  netkat::Policy clean_up = netkat::Policy::Accept();
  for (const std::unique_ptr<NetkatSwitchPipelineStage>& stage : stages_) {
    policy = netkat::Sequence(std::move(policy), stage->GetPolicy());
    clean_up = netkat::Sequence(std::move(clean_up), stage->CleanUp());
  }
  return netkat::Sequence(std::move(policy), std::move(clean_up));
}

}  // namespace netkat
