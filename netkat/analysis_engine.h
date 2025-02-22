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
// File: analysis_engine.h
// -----------------------------------------------------------------------------
//
// The user-facing API for reasoning about NetKAT policies and predicates.

#ifndef GOOGLE_NETKAT_NETKAT_ANALYSIS_ENGINE_H_
#define GOOGLE_NETKAT_NETKAT_ANALYSIS_ENGINE_H_

#include "netkat/frontend.h"
#include "netkat/symbolic_packet.h"

namespace netkat {

// Class for reasoning about NetKAT policies and predicates.
//
// This is a class rather than a namespace of free functions as the class
// maintains state to optimize the speed of repeated calls. The state is not
// intended to have any effect on functional behavior.
//
// TODO(b/398303840): Persistent use of an `AnalysisEngine` object can incur
// unbounded memory growth. Consider adding some garbage collection mechanism.
class AnalysisEngine {
 public:
  // Checks whether two predicates are "equivalent", meaning they match the same
  // set of packets, meaning `Evaluate(left, packet) == Evaluate(right, packet)`
  // for all packets.
  bool CheckEquivalent(const Predicate& left, const Predicate& right);

 private:
  SymbolicPacketManager packet_manager_;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_ANALYSIS_ENGINE_H_
