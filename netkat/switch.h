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
//
// -----------------------------------------------------------------------------
// File: switch.h
// -----------------------------------------------------------------------------
//
// This file contains an API and definition of a networking switch represented
// in NetKAT. This may be used to easily build a switch from multiple stages,
// where each stage is responsible for defining a portion of the overall switch
// configuration. The resulting policy will then be NetKAT, in which formal
// verification may then be performed.
#ifndef GOOGLE_NETKAT_NETKAT_SWITCH_H_
#define GOOGLE_NETKAT_NETKAT_SWITCH_H_

#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "netkat/frontend.h"

namespace netkat {

// Defines an interface that represents a logical pipeline stage of a networking
// switch, represented in NetKAT. The pipeline stage consists of two primary
// functions:
//
//   * GetPolicy; which returns the policy that should be applied at the stage.
//
//   * CleanUp; which returns a policy that should be applied to remove any
//   metadata fields.
//
// Alone, and when joined together, the pipeline stage policy should eventually
// reflect a packet's traversal of pre-designed / installed rules through a
// switch. See `NetkatSwitch`.
class NetkatSwitchPipelineStage {
 public:
  virtual ~NetkatSwitchPipelineStage() = default;

  // Returns the complete policy of this pipeline stage.
  virtual netkat::Policy GetPolicy() const = 0;

  // Returns a pipeline stage that is the merge of `this` and `other`, appending
  // their rules. Returns an error if the merge is not possible or violates any
  // internal constraints, e.g. rule determinism.
  virtual absl::StatusOr<std::unique_ptr<NetkatSwitchPipelineStage>> MergeStage(
      const NetkatSwitchPipelineStage& other) const = 0;

  // Defines policy that cleans up any metadata that should not be retained
  // across a switch, e.g. unsetting a VRF id before moving to the next switch.
  //
  // The policy defined here will be appended to the end of the final policy of
  // the switch.
  virtual netkat::Policy CleanUp() const = 0;
};

// Defines a switch that is composed of multiple pipeline stages. The generated
// policy is then the ordered-sequence of all the rules in all the underlying
// stages.
//
// If the switch has no stages then a packet will simply drop.
//
// TODO(anthonyroy): Showcase an example of how to use this class.
class NetkatSwitch {
 public:
  // Returns a NetkatSwitch that is configured with the provided stages.
  //
  // Each stage is required to be of type
  // `std::unique_ptr<NetkatSwitchPipelineStage>` and will be added in the order
  // they are passed in. Stages must be non-null. For example:
  //
  //   ASSIGN_OR_RETURN(NetkatSwitch netkat_switch, NetkatSwitch::Create(
  //       std::make_unique<VlanStage>(),
  //       std::make_unique<VrfStage>(),
  //       std::make_unique<NexthopStage>());
  template <typename... Stages>
  static absl::StatusOr<NetkatSwitch> Create(Stages&&... stages);

  // Appends a non-null stage to the end of the switch.
  //
  // This is useful in cases where switch stage construction is conditional.
  absl::Status AddStage(std::unique_ptr<NetkatSwitchPipelineStage> stage);

  // Returns the complete policy of this switch.
  //
  // Concretely, this will return the ordered sequence of all the rules in all
  // the underlying stages, followed by the sequence of all stage's CleanUp
  // policies.
  netkat::Policy GetPolicy() const;

  // Returns a mutable pointer to the underlying stage at the given `index`.
  // Returns nullptr if no such `index` exists.
  NetkatSwitchPipelineStage* GetStage(int index) const;

  // Returns a mutable pointer to the underlying stage at the given `index`.
  // Returns nullptr if no such `index` exists.
  //
  // This is a convenience function that uses static_cast to downcast the stage
  // to the provided type.
  template <typename T>
  T* GetStage(int index) const {
    if (auto* stage = GetStage(index); stage != nullptr) {
      return static_cast<T*>(stage);
    }
    return nullptr;
  }

 private:
  std::vector<std::unique_ptr<NetkatSwitchPipelineStage>> stages_;
};

// We define NetkatSwitch::Create here to enhance the readability of the
// NetkatSwitch API. I.e. Users need not look below!
template <typename... Stages>
absl::StatusOr<NetkatSwitch> NetkatSwitch::Create(Stages&&... stages) {
  static_assert(
      std::conjunction_v<std::is_convertible<
          std::decay_t<Stages>, std::unique_ptr<NetkatSwitchPipelineStage>>...>,
      "All arguments must be convertible to "
      "std::unique_ptr<NetkatSwitchPipelineStage>");
  NetkatSwitch nk_switch;
  // Fold expression, equivalent to repeated AddStage calls. E.g.
  //   if (!nk_switch.AddStage(<first_argument>) ||
  //       !nk_switch.AddStage(<second_argument> || ...) {
  //     return absl::InternalError("Failed to add stage");
  // }
  // TODO: b/443300735 - Propagate the status failure of AddStage.
  if ((... || [&]() -> bool {
        return !nk_switch.AddStage(std::forward<Stages>(stages)).ok();
      }())) {
    return absl::InvalidArgumentError("Failed to add stage");
  }
  return nk_switch;
}

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_SWITCH_H_
