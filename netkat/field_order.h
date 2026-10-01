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
// File: field_order.h
// -----------------------------------------------------------------------------
//
// Heuristics for ordering the packet fields of NetKAT policies, which can
// affect the size of their decision diagrams, and thus the performance of the
// backend, dramatically.

#ifndef GOOGLE_NETKAT_NETKAT_FIELD_ORDER_H_
#define GOOGLE_NETKAT_NETKAT_FIELD_ORDER_H_

#include <string>
#include <vector>

#include "absl/types/span.h"
#include "netkat/netkat.pb.h"

namespace netkat {

// Returns the fields of the given policies and predicates, in order of first
// appearance (in a left-to-right, pre-order traversal).
std::vector<std::string> FieldsInOrderOfAppearance(
    absl::Span<const PolicyProto> policies,
    absl::Span<const PredicateProto> predicates = {});

// Returns an order of the fields of the given policies and predicates that is
// likely to result in small decision diagrams, first field first, for use with
// `PacketSetManager::DeclareFields`. Roughly, orders fields by data flow (the
// stage of a pipeline `p1; p2; ...` that first uses them), and then by how
// much of the policy they select between (as in `sw=1; t1 + sw=2; t2`). See
// the implementation for details. Runs in linear time.
//
// For best results, pass a single policy capturing the whole workload, e.g.
// `ingress; network; egress` for a reachability query.
std::vector<std::string> HeuristicFieldOrder(
    absl::Span<const PolicyProto> policies,
    absl::Span<const PredicateProto> predicates = {});

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_FIELD_ORDER_H_
