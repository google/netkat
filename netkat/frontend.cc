#include "netkat/frontend.h"

#include <utility>

#include "absl/strings/string_view.h"
#include "netkat/netkat.pb.h"
#include "netkat/netkat_proto_constructors.h"

namespace netkat {

Predicate operator!(Predicate predicate) {
  return Predicate(NotProto(std::move(predicate).ToProto()));
}

Predicate operator&&(Predicate lhs, Predicate rhs) {
  return Predicate(
      AndProto(std::move(lhs).ToProto(), std::move(rhs).ToProto()));
}

Predicate operator||(Predicate lhs, Predicate rhs) {
  return Predicate(OrProto(std::move(lhs).ToProto(), std::move(rhs).ToProto()));
}

Predicate Predicate::True() { return Predicate(TrueProto()); }

Predicate Predicate::False() { return Predicate(FalseProto()); }

Predicate Match(absl::string_view field, int value) {
  return Predicate(MatchProto(field, value));
}
}  // namespace netkat
