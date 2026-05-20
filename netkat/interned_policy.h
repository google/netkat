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
// File: interned_policy.h
// -----------------------------------------------------------------------------
//
// A module for interning (aka hash-consing) NetKAT policies in a normal form
// that discards some syntactic structure while preserving the semantics.
//
// E.g., `(a;b); c` and `a; (b; c)` have the same representation, which is okay
// because they are semantially equivalent.
//
// This policy representation is suitable when we don't care about the exact
// syntactic structure of the policy, but only about its semantics.
//
// TODO(smolkaj): List the structure that is discarded.

#ifndef GOOGLE_NETKAT_NETKAT_INTERNED_POLICY_H_
#define GOOGLE_NETKAT_NETKAT_INTERNED_POLICY_H_

#include <cstddef>
#include <cstdint>
#include <variant>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "netkat/interned_field.h"
#include "netkat/netkat.pb.h"
#include "netkat/paged_stable_vector.h"

namespace netkat {

// -- Interned policy handle ---------------------------------------------------

// An interned (aka hash-consed) NetKAT policy.
//
// Technically, a lightweight handle (64 bits) that is very cheap (O(1)) to
// copy, store, hash, and compare. Handles can only be created by an
// `InternedPolicyManager` object, which owns the policy representation
// associated with the handle.
//
// CAUTION: Each `InternedPolicy` is implicitly associated with the manager
// object that created it; using it with a different manager object has
// undefined behavior.
class [[nodiscard]] InternedPolicy {
 public:
  // `InternedPolicy`s can only be created by `InternedPolicyManager`.
  InternedPolicy() = delete;
  friend class InternedPolicyManager;

  // O(1) comparison, thanks to interning/hash-consing.
  // Two interned policies compare equal iff they have the same normal form,
  // which discards the following syntactic structure:
  // * Associativity: The associtivity of policies in a sequence or union.
  // * Commutativity: The order of policies in a union.
  // * The placement of negations (negation normal form).
  // * Idempotence of unions and iterates.
  // * Equivalence of And/Or and Sequence/Union on predicates.
  friend auto operator<=>(InternedPolicy a, InternedPolicy b) = default;

  // Hashing, see https://abseil.io/docs/cpp/guides/hash.
  template <typename H>
  friend H AbslHashValue(H h, InternedPolicy policy) {
    return H::combine(std::move(h), policy.index_);
  }

  // Formatting, see https://abseil.io/docs/cpp/guides/abslstringify.
  template <typename Sink>
  friend void AbslStringify(Sink& sink, InternedPolicy policy) {
    absl::Format(&sink, "InternedPolicy<%d>", policy.index_);
  }

 private:
  // An index into the `representations_` vector of the
  // `InternedPolicyManager` object associated with this `InternedPolicy`:
  // `representations_[index_]` is the representation of the policy. The
  // index is otherwise arbitrary and meaningless.
  //
  // We use a 64-bit index as a tradeoff between minimizing memory usage while
  // supporting sufficiently many policies.
  uint64_t index_;
  explicit InternedPolicy(uint64_t index) : index_(index) {}
};

// -- Interned policy representation -------------------------------------------

// Same as `Match` in `PredicateProto`, but with interned fields and allowing
// for negation.
struct InternedMatch {
  // Whether the match is negated, i.e. `field != value`.
  bool negated;
  // The field to match.
  InternedField field;
  // The value to match against.
  int32_t value;

  friend auto operator<=>(InternedMatch a, InternedMatch b) = default;
  template <typename H>
  friend H AbslHashValue(H h, InternedMatch match) {
    return H::combine(std::move(h), match.field, match.value, match.negated);
  }
};

// Protect against regressions in memory layout, as it affects performance.
static_assert(sizeof(InternedMatch) == 8);

// Same as `Modification` in `PolicyProto`, but with interned fields.
struct InternedModification {
  // The field to modify.
  InternedField field;
  // The value to set the field to.
  int32_t value;

  friend auto operator<=>(InternedModification a,
                          InternedModification b) = default;
  template <typename H>
  friend H AbslHashValue(H h, InternedModification modification) {
    return H::combine(std::move(h), modification.field, modification.value);
  }
};

// Same as `Sequence` in `PolicyProto`, but n-ary instead of binary and with
// interned policies.
struct InternedSequence {
  // The sequence of policies to apply sequentially. The empty sequence
  // represents the true filter (i.e. Accept).
  std::vector<InternedPolicy> policies;

  friend auto operator<=>(const InternedSequence& a,
                          const InternedSequence& b) = default;
  template <typename H>
  friend H AbslHashValue(H h, const InternedSequence& sequence) {
    return H::combine(std::move(h), sequence.policies);
  }
};

// Same as `Union` in `PolicyProto`, but n-ary instead of binary and with
// interned policies.
struct InternedUnion {
  // The union of policies. The empty set represents the false filter (i.e.
  // Deny).
  absl::flat_hash_set<InternedPolicy> policies;

  friend auto operator<=>(const InternedUnion& a,
                          const InternedUnion& b) = default;
  template <typename H>
  friend H AbslHashValue(H h, const InternedUnion& union_) {
    return H::combine(std::move(h), union_.policies);
  }
};

// Same as `Iterate` in `PolicyProto`, but with an interned policy.
struct InternedIteration {
  // The policy to iterate.
  InternedPolicy policy;

  friend auto operator<=>(InternedIteration, InternedIteration) = default;
  template <typename H>
  friend H AbslHashValue(H h, InternedIteration iteration) {
    return H::combine(std::move(h), iteration.policy);
  }
};

// Same as `Record` in `PolicyProto`, but as a struct instead of a proto.
struct InternedRecord {
  friend auto operator<=>(InternedRecord, InternedRecord) = default;
  template <typename H>
  friend H AbslHashValue(H h, InternedRecord) {
    return h;
  }
};

using InternedPolicyRepresentation =
    // We put `InternedUnion` first so this variant default-constructs to the
    // false filter (i.e. Deny).
    std::variant<InternedUnion, InternedSequence, InternedIteration,
                 InternedRecord, InternedMatch, InternedModification>;

// Protect against regressions in memory layout, as it affects performance.
static_assert(sizeof(InternedPolicyRepresentation) == 40);

// -- Interned policy manager --------------------------------------------------

// An "arena" for interning NetKAT policies, owning the memory associated
// with the interned policies.
class InternedPolicyManager {
 public:
  InternedPolicyManager() = default;

  // Returns an interned and normalized representation of the given policy.
  InternedPolicy GetOrCreateInternedPolicy(const PolicyProto& policy);

  // Returns the name of the given interned policy, assuming it was interned by
  // this manager object. Otherwise, the behavior is undefined.
  const InternedPolicyRepresentation& GetRepresentation(
      InternedPolicy policy) const;

  // Dynamically checks all class invariants. Exposed for testing only.
  // absl::Status CheckInternalInvariants() const;

 private:
  // We allocate 10k policies at a time as a tradeoff between minimizing memory
  // overhead and minimizing the cost of dynamic allocation.
  static constexpr size_t kPageSize = 10'000;

  // All policies interned by this manager object. The representation of an
  // interned policy `p` created by this object is
  // `representations_[p.index_]`.
  PagedStableVector<InternedPolicyRepresentation, kPageSize> representations_;

  // A so called "unique table" to ensure each policy is added to
  // `representations_` at most once, and thus is represented by a unique
  // index into that vector.
  //
  // Invariant:
  // `interned_policy_by_representation_[r] == p` iff
  // `representations_[p.index_] == r`.
  absl::flat_hash_map<InternedPolicyRepresentation, InternedPolicy>
      interned_policy_by_representation_;

  InternedFieldManager field_manager_;

  InternedPolicy RepresentationToPolicy(
      InternedPolicyRepresentation&& representation);

  InternedPolicyRepresentation ToInternedRepresentation(
      const PolicyProto& policy);
  InternedPolicyRepresentation ToInternedRepresentation(
      const PredicateProto& predicate, bool negate);

  // -- Smart constructors -----------------------------------------------------
  InternedPolicyRepresentation Deny() { return InternedUnion{}; }
  InternedPolicyRepresentation Accept() {
    return InternedSequence {}
  }
  InternedPolicyRepresentation Sequence(InternedPolicyRepresentation&& left,
                                        InternedPolicyRepresentation&& right);
  InternedPolicyRepresentation Union(InternedPolicyRepresentation&& left,
                                     InternedPolicyRepresentation&& right);
  InternedPolicyRepresentation Iterate(InternedPolicyRepresentation&& policy);
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_INTERNED_POLICY_H_
