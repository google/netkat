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
// File: field_order_study.cc
// -----------------------------------------------------------------------------
//
// Measures how sensitive the NetKAT backend is to the order of packet fields,
// on the workloads of `network_benchmark.cc`. For each workload, runs it under
// many field orders (all orders, or random ones) and reports the best, median,
// and worst running time, relative to the default order.
//
// Each run happens in a forked child process with a timeout and a memory
// limit, since bad orders can blow up.

#include <poll.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>  // NOLINT: For timing.
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <random>
#include <regex>  // NOLINT: Only used to parse debug strings.
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "absl/types/span.h"
#include "netkat/benchmark_networks.h"
#include "netkat/field_order.h"
#include "netkat/netkat.pb.h"
#include "netkat/netkat_proto_constructors.h"
#include "netkat/packet_set.h"
#include "netkat/packet_set_handle.h"
#include "netkat/packet_transformer.h"
#include "netkat/packet_transformer_handle.h"

ABSL_FLAG(std::vector<std::string>, workloads, {},
          "Workloads to study (default: all).");
ABSL_FLAG(std::string, size, "small", "Instance size: small or large.");
ABSL_FLAG(std::optional<int>, size_override, std::nullopt,
          "Overrides the instance size of all workloads.");
ABSL_FLAG(int, max_exhaustive_fields, 6,
          "Studies all orders of workloads with at most this many fields, and "
          "random orders otherwise.");
ABSL_FLAG(int, samples, 24, "Number of random orders.");
ABSL_FLAG(uint64_t, seed, 1, "Seed for random orders.");
ABSL_FLAG(int, reps, 3, "Repetitions per order; reports the minimum.");
ABSL_FLAG(double, timeout_s, 20, "Timeout per order, in seconds.");
ABSL_FLAG(int, memory_limit_gb, 12, "Memory limit per order, in GiB.");
ABSL_FLAG(bool, print_orders, true,
          "Prints the result of each order, not just the summary.");
ABSL_FLAG(int, perturbations, 0,
          "If positive, instead measures the default and heuristic orders on "
          "this many random perturbations of each workload (see `Perturb`).");
ABSL_FLAG(std::vector<std::string>, orders, {},
          "Additional orders to measure, with fields separated by '/'.");
ABSL_FLAG(bool, only_heuristics, false,
          "Only measures the default and heuristic orders.");

namespace netkat {
namespace {

struct Instance {
  // The policies and predicates of the workload.
  std::vector<PolicyProto> policies;
  std::vector<PredicateProto> predicates;
  // Runs the workload on the above policies and predicates. Returns false if a
  // sanity check fails.
  std::function<bool(PacketTransformerManager&, const Instance&)> run;
  // Returns a single policy representing the whole workload, from which we
  // compute the heuristic field order: e.g. `ingress; policy; egress` for a
  // reachability query. By default, the union of the policies.
  std::function<PolicyProto(const Instance&)> query;
};

PolicyProto Query(const Instance& instance) {
  if (instance.query) return instance.query(instance);
  return BalancedUnionProto(instance.policies);
}

// Returns `from; policy; to`.
PolicyProto Between(const PredicateProto& from, const PolicyProto& policy,
                    const PredicateProto& to) {
  return SequenceProto(FilterProto(from),
                       SequenceProto(policy, FilterProto(to)));
}

struct Workload {
  std::string name;
  int small_size;
  int large_size;
  std::function<Instance(int)> make;
};

// Returns an instance that compiles the given policy.
Instance CompileInstance(PolicyProto policy) {
  return {.policies = {std::move(policy)},
          .run = [](PacketTransformerManager& m, const Instance& i) {
            (void)m.Compile(i.policies[0]);
            return true;
          }};
}

// Returns an instance that computes the packets that can be delivered from
// the `network`'s ingress to its egress, forward and backward.
Instance ReachabilityInstance(const NetworkModel& network) {
  return {.policies = {EndToEndPolicy(network)},
          .predicates = {network.ingress, network.egress},
          .run =
              [](PacketTransformerManager& m, const Instance& i) {
                PacketSetManager& packet_sets = m.GetPacketSetManager();
                PacketTransformerHandle end_to_end = m.Compile(i.policies[0]);
                PacketSetHandle ingress = packet_sets.Compile(i.predicates[0]);
                PacketSetHandle egress = packet_sets.Compile(i.predicates[1]);
                PacketSetHandle forward =
                    packet_sets.And(m.Push(ingress, end_to_end), egress);
                PacketSetHandle backward =
                    packet_sets.And(m.Pull(end_to_end, egress), ingress);
                return packet_sets.IsEmptySet(forward) ==
                       packet_sets.IsEmptySet(backward);
              },
          .query =
              [](const Instance& i) {
                return Between(i.predicates[0], i.policies[0], i.predicates[1]);
              }};
}

std::vector<Workload> AllWorkloads() {
  std::vector<Workload> workloads;
  workloads.push_back({"FatTreeCompile", 12, 32, [](int k) {
                         return CompileInstance(
                             EndToEndPolicy(FatTree({.k = k})));
                       }});
  workloads.push_back({"FatTreeMultipathCompile", 12, 32, [](int k) {
                         return CompileInstance(EndToEndPolicy(
                             FatTree({.k = k, .multipath = true})));
                       }});
  workloads.push_back({"FatTreeReachability", 12, 32, [](int k) {
                         return ReachabilityInstance(FatTree({.k = k}));
                       }});
  workloads.push_back(
      {"FatTreeTenantIsolation", 8, 20, [](int k) {
         FatTreeOptions options = {.k = k, .num_tenants = 4};
         std::vector<PredicateProto> tenant0, others;
         for (const FatTreeHost& host : FatTreeHosts(k)) {
           (FatTreeTenant(options, host) == 0 ? tenant0 : others)
               .push_back(FatTreeHostLocation(k, host));
         }
         return Instance{
             .policies = {EndToEndPolicy(FatTree(options))},
             .predicates = {BalancedOrProto(std::move(tenant0)),
                            BalancedOrProto(std::move(others))},
             .run =
                 [](PacketTransformerManager& m, const Instance& i) {
                   PacketSetManager& packet_sets = m.GetPacketSetManager();
                   PacketSetHandle leaked = packet_sets.And(
                       m.Push(packet_sets.Compile(i.predicates[0]),
                              m.Compile(i.policies[0])),
                       packet_sets.Compile(i.predicates[1]));
                   return packet_sets.IsEmptySet(leaked);
                 },
             .query =
                 [](const Instance& i) {
                   return Between(i.predicates[0], i.policies[0],
                                  i.predicates[1]);
                 }};
       }});
  workloads.push_back(
      {"FatTreeSliceEquivalence", 8, 20, [](int k) {
         EquivalenceQuery query =
             FatTreeSliceEquivalence({.k = k, .num_tenants = 4}, /*tenant=*/0);
         return Instance{
             .policies = {query.left, query.right},
             .run = [](PacketTransformerManager& m, const Instance& i) {
               return m.Compile(i.policies[0]) == m.Compile(i.policies[1]);
             }};
       }});
  workloads.push_back({"WanCompile", 128, 512, [](int n) {
                         return CompileInstance(
                             EndToEndPolicy(ShortestPathWan(n).network));
                       }});
  workloads.push_back(
      {"WanReachability", 128, 512,
       [](int n) { return ReachabilityInstance(ShortestPathWan(n).network); }});
  workloads.push_back(
      {"WanWaypointBypass", 128, 512, [](int n) {
         Wan wan = ShortestPathWan(n);
         int waypoint = 0;
         for (int s = 0; s < wan.adjacency.size(); ++s) {
           if (wan.adjacency[s].size() > wan.adjacency[waypoint].size()) {
             waypoint = s;
           }
         }
         return Instance{
             .policies = {EndToEndPolicyAvoiding(wan.network, waypoint)},
             .predicates = {wan.network.ingress, wan.network.egress},
             .run =
                 [](PacketTransformerManager& m, const Instance& i) {
                   PacketSetManager& packet_sets = m.GetPacketSetManager();
                   (void)packet_sets.And(
                       m.Push(packet_sets.Compile(i.predicates[0]),
                              m.Compile(i.policies[0])),
                       packet_sets.Compile(i.predicates[1]));
                   return true;
                 },
             .query =
                 [](const Instance& i) {
                   return Between(i.predicates[0], i.policies[0],
                                  i.predicates[1]);
                 }};
       }});
  workloads.push_back({"AclCompile", 1024, 16384, [](int n) {
                         return CompileInstance(
                             AclPolicy(ClassBenchStyleAclRules(n)));
                       }});
  workloads.push_back(
      {"AclChangeImpact", 1024, 16384, [](int n) {
         std::vector<AclRule> rules = ClassBenchStyleAclRules(n);
         PolicyProto before = AclPolicy(rules);
         rules.erase(rules.begin() + rules.size() / 2);
         return Instance{
             .policies = {before, AclPolicy(rules)},
             .run = [](PacketTransformerManager& m, const Instance& i) {
               PacketTransformerHandle old_acl = m.Compile(i.policies[0]);
               PacketTransformerHandle new_acl = m.Compile(i.policies[1]);
               (void)m.GetAllInputPacketsThatProduceAnyOutput(
                   m.Union(m.Difference(old_acl, new_acl),
                           m.Difference(new_acl, old_acl)));
               return true;
             }};
       }});
  workloads.push_back({"SwitchPipelineCompile", 2048, 16384, [](int n) {
                         return CompileInstance(
                             SaiStyleSwitchPipeline(n).Policy());
                       }});
  workloads.push_back(
      {"SwitchPipelineAnalysis", 2048, 16384, [](int n) {
         return Instance{
             .policies = {SaiStyleSwitchPipeline(n).Policy()},
             .predicates = {MatchProto("port", 0)},
             .run =
                 [](PacketTransformerManager& m, const Instance& i) {
                   PacketTransformerHandle pipeline = m.Compile(i.policies[0]);
                   (void)m.Pull(pipeline, m.GetPacketSetManager().Compile(
                                              i.predicates[0]));
                   (void)m.GetAllInputPacketsThatProduceAnyOutput(pipeline);
                   return true;
                 },
             .query =
                 [](const Instance& i) {
                   return SequenceProto(i.policies[0],
                                        FilterProto(i.predicates[0]));
                 }};
       }});
  workloads.push_back(
      {"NatGatewayCompile", 16384, 262144,
       [](int n) { return CompileInstance(NatGatewayWithFlows(n).Policy()); }});
  workloads.push_back(
      {"NatRoundTrip", 2048, 16384, [](int n) {
         NatGateway nat = NatGatewayWithFlows(n);
         return Instance{
             .policies = {FilterProto(nat.internal_flows), nat.source_nat,
                          nat.inverse_source_nat},
             .run =
                 [](PacketTransformerManager& m, const Instance& i) {
                   PacketTransformerHandle domain = m.Compile(i.policies[0]);
                   return m.Sequence(
                              m.Sequence(domain, m.Compile(i.policies[1])),
                              m.Compile(i.policies[2])) == domain;
                 },
             .query =
                 [](const Instance& i) {
                   return SequenceProto(
                       i.policies[0],
                       SequenceProto(i.policies[1], i.policies[2]));
                 }};
       }});
  // Validation workloads, not used to design the heuristic.
  workloads.push_back({"BackboneCompile", 32, 128, [](int n) {
                         return CompileInstance(EndToEndPolicy(Backbone(n)));
                       }});
  workloads.push_back({"BackboneReachability", 32, 128, [](int n) {
                         return ReachabilityInstance(Backbone(n));
                       }});
  return workloads;
}

// Randomly swaps the operands of commutative operators (`+`, `&&`, `||`) in
// the given policy or predicate, which changes the order in which fields are
// first used, but not the semantics.
void Perturb(PredicateProto& predicate, std::mt19937_64& random);
void Perturb(PolicyProto& policy, std::mt19937_64& random) {
  switch (policy.policy_case()) {
    case PolicyProto::kFilter:
      Perturb(*policy.mutable_filter(), random);
      break;
    case PolicyProto::kSequenceOp:
      Perturb(*policy.mutable_sequence_op()->mutable_left(), random);
      Perturb(*policy.mutable_sequence_op()->mutable_right(), random);
      break;
    case PolicyProto::kUnionOp: {
      PolicyProto::Union& op = *policy.mutable_union_op();
      if (random() % 2) op.mutable_left()->Swap(op.mutable_right());
      Perturb(*op.mutable_left(), random);
      Perturb(*op.mutable_right(), random);
      break;
    }
    case PolicyProto::kIterateOp:
      Perturb(*policy.mutable_iterate_op()->mutable_iterable(), random);
      break;
    case PolicyProto::kDifferenceOp:
      Perturb(*policy.mutable_difference_op()->mutable_left(), random);
      Perturb(*policy.mutable_difference_op()->mutable_right(), random);
      break;
    default:
      break;
  }
}
void Perturb(PredicateProto& predicate, std::mt19937_64& random) {
  switch (predicate.predicate_case()) {
    case PredicateProto::kAndOp: {
      PredicateProto::And& op = *predicate.mutable_and_op();
      if (random() % 2) op.mutable_left()->Swap(op.mutable_right());
      Perturb(*op.mutable_left(), random);
      Perturb(*op.mutable_right(), random);
      break;
    }
    case PredicateProto::kOrOp: {
      PredicateProto::Or& op = *predicate.mutable_or_op();
      if (random() % 2) op.mutable_left()->Swap(op.mutable_right());
      Perturb(*op.mutable_left(), random);
      Perturb(*op.mutable_right(), random);
      break;
    }
    case PredicateProto::kNotOp:
      Perturb(*predicate.mutable_not_op()->mutable_negand(), random);
      break;
    case PredicateProto::kXorOp:
      Perturb(*predicate.mutable_xor_op()->mutable_left(), random);
      Perturb(*predicate.mutable_xor_op()->mutable_right(), random);
      break;
    case PredicateProto::kPullOp:
      Perturb(*predicate.mutable_pull_op()->mutable_policy(), random);
      Perturb(*predicate.mutable_pull_op()->mutable_pred(), random);
      break;
    default:
      break;
  }
}

// The result of running a workload under some field order.
struct Result {
  enum class Status { kOk, kTimeout, kCrash, kWrong } status;
  double ms = std::numeric_limits<double>::infinity();
  // The order of the fields used by the run, comma separated.
  std::string actual_order;
};

// Returns the order of the given `fields` in the `manager`, by reading it off
// the decision diagram of a conjunction of matches on all fields.
std::string FieldOrderOf(PacketTransformerManager& manager,
                         const std::vector<std::string>& fields) {
  PacketSetManager& packet_sets = manager.GetPacketSetManager();
  PacketSetHandle conjunction = packet_sets.FullSet();
  for (const std::string& field : fields) {
    conjunction = packet_sets.And(conjunction, packet_sets.Match(field, 0));
  }
  std::string dump = packet_sets.ToString(conjunction);
  std::map<int, std::string> field_by_index;
  static const std::regex* kFieldRegex =
      new std::regex("PacketFieldHandle<([0-9]+)>:'([^']*)'");
  for (auto it = std::sregex_iterator(dump.begin(), dump.end(), *kFieldRegex);
       it != std::sregex_iterator(); ++it) {
    field_by_index[std::stoi((*it)[1])] = (*it)[2];
  }
  std::vector<std::string> order;
  order.reserve(field_by_index.size());
  for (const auto& [index, field] : field_by_index) order.push_back(field);
  return absl::StrJoin(order, ",");
}

// Runs `instance` under the given field order (or the default order, if
// `order` is null) in a child process.
Result RunInChild(const Instance& instance,
                  const std::vector<std::string>& fields,
                  const std::vector<std::string>* order) {
  int fds[2];
  if (pipe(fds) != 0) return {Result::Status::kCrash};
  pid_t pid = fork();
  if (pid == 0) {
    close(fds[0]);
    rlimit limit;
    limit.rlim_cur = limit.rlim_max =
        static_cast<rlim_t>(absl::GetFlag(FLAGS_memory_limit_gb)) << 30;
    setrlimit(RLIMIT_AS, &limit);
    double best = std::numeric_limits<double>::infinity();
    bool ok = true;
    std::string actual_order;
    for (int rep = 0; rep < absl::GetFlag(FLAGS_reps); ++rep) {
      auto start = std::chrono::steady_clock::now();
      PacketTransformerManager manager;
      if (order != nullptr) manager.GetPacketSetManager().DeclareFields(*order);
      ok &= instance.run(manager, instance);
      auto end = std::chrono::steady_clock::now();
      best = std::min(
          best, std::chrono::duration<double>(end - start).count() * 1000.0);
      if (rep == 0) actual_order = FieldOrderOf(manager, fields);
    }
    if (!ok) best = -1;
    (void)!write(fds[1], &best, sizeof(best));
    uint32_t length = actual_order.size();
    (void)!write(fds[1], &length, sizeof(length));
    (void)!write(fds[1], actual_order.data(), length);
    _exit(0);
  }
  close(fds[1]);
  pollfd poll_fd = {.fd = fds[0], .events = POLLIN};
  int timeout_ms = absl::GetFlag(FLAGS_timeout_s) * 1000;
  Result result = {Result::Status::kCrash};
  int ready = poll(&poll_fd, 1, timeout_ms);
  double ms;
  if (ready == 0) {
    kill(pid, SIGKILL);
    result = {Result::Status::kTimeout};
  } else if (read(fds[0], &ms, sizeof(ms)) == sizeof(ms)) {
    result = ms < 0 ? Result{Result::Status::kWrong}
                    : Result{Result::Status::kOk, ms};
    uint32_t length = 0;
    if (read(fds[0], &length, sizeof(length)) == sizeof(length)) {
      result.actual_order.resize(length);
      size_t done = 0;
      while (done < length) {
        ssize_t n =
            read(fds[0], result.actual_order.data() + done, length - done);
        if (n <= 0) break;
        done += n;
      }
    }
  }
  close(fds[0]);
  waitpid(pid, nullptr, 0);
  return result;
}

std::string ToString(const Result& result) {
  switch (result.status) {
    case Result::Status::kOk:
      return absl::StrFormat("%.1f", result.ms);
    case Result::Status::kTimeout:
      return "timeout";
    case Result::Status::kCrash:
      return "crash";
    case Result::Status::kWrong:
      return "WRONG";
  }
}

// Measures the default and heuristic orders on `n` random perturbations of
// `instance`.
void StudyPerturbations(const std::string& name, int size,
                        const Instance& instance, int n) {
  std::vector<double> ratios;
  double worst_default = 0, worst_heuristic = 0;
  for (int seed = 0; seed <= n; ++seed) {
    Instance perturbed = instance;
    // Seed 0 is the unperturbed instance.
    if (seed > 0) {
      std::mt19937_64 random(seed);
      for (PolicyProto& policy : perturbed.policies) Perturb(policy, random);
      for (PredicateProto& predicate : perturbed.predicates) {
        Perturb(predicate, random);
      }
    }
    std::vector<std::string> fields =
        FieldsInOrderOfAppearance(perturbed.policies, perturbed.predicates);
    const PolicyProto query = Query(perturbed);
    std::vector<std::string> heuristic =
        HeuristicFieldOrder(absl::MakeConstSpan(&query, 1));
    Result default_result = RunInChild(perturbed, fields, nullptr);
    Result heuristic_result = RunInChild(perturbed, fields, &heuristic);
    std::printf("PERTURB %s/%d seed=%d default %s [%s] heuristic %s [%s]\n",
                name.c_str(), size, seed, ToString(default_result).c_str(),
                default_result.actual_order.c_str(),
                ToString(heuristic_result).c_str(),
                absl::StrJoin(heuristic, ",").c_str());
    std::fflush(stdout);
    worst_default = std::max(worst_default, default_result.ms);
    worst_heuristic = std::max(worst_heuristic, heuristic_result.ms);
    ratios.push_back(default_result.ms / heuristic_result.ms);
  }
  double log_sum = 0;
  for (double ratio : ratios) log_sum += std::log(ratio);
  std::sort(ratios.begin(), ratios.end());
  std::printf(
      "PSUMMARY %s/%d n=%zu default/heuristic: geomean=%.2f min=%.2f "
      "max=%.2f worst_default=%.1f worst_heuristic=%.1f\n",
      name.c_str(), size, ratios.size(), std::exp(log_sum / ratios.size()),
      ratios.front(), ratios.back(), worst_default, worst_heuristic);
  std::fflush(stdout);
}

void Study(const Workload& workload) {
  const int size =
      absl::GetFlag(FLAGS_size_override)
          .value_or(absl::GetFlag(FLAGS_size) == "large" ? workload.large_size
                                                         : workload.small_size);
  Instance instance = workload.make(size);
  if (int n = absl::GetFlag(FLAGS_perturbations); n > 0) {
    StudyPerturbations(workload.name, size, instance, n);
    return;
  }
  std::vector<std::string> fields =
      FieldsInOrderOfAppearance(instance.policies, instance.predicates);

  // The orders to study, and their labels.
  std::vector<std::pair<std::string, std::vector<std::string>>> orders;
  orders.push_back({"appearance", fields});
  {
    const PolicyProto query = Query(instance);
    auto start = std::chrono::steady_clock::now();
    std::vector<std::string> heuristic =
        HeuristicFieldOrder(absl::MakeConstSpan(&query, 1));
    auto end = std::chrono::steady_clock::now();
    std::printf("%s/%d heuristic_cost_ms %.1f\n", workload.name.c_str(), size,
                std::chrono::duration<double>(end - start).count() * 1000.0);
    orders.push_back({"heuristic", std::move(heuristic)});
  }
  for (const std::string& order : absl::GetFlag(FLAGS_orders)) {
    orders.push_back({"custom", absl::StrSplit(order, '/')});
  }
  if (!absl::GetFlag(FLAGS_only_heuristics)) {
    std::vector<std::string> sorted = fields;
    std::sort(sorted.begin(), sorted.end());
    if (fields.size() <= absl::GetFlag(FLAGS_max_exhaustive_fields)) {
      do {
        orders.push_back({"all", sorted});
      } while (std::next_permutation(sorted.begin(), sorted.end()));
    } else {
      std::mt19937_64 random(absl::GetFlag(FLAGS_seed));
      for (int i = 0; i < absl::GetFlag(FLAGS_samples); ++i) {
        std::shuffle(sorted.begin(), sorted.end(), random);
        orders.push_back({"random", sorted});
      }
    }
  }

  Result default_result = RunInChild(instance, fields, nullptr);
  std::printf("%s/%d default %s [%s]\n", workload.name.c_str(), size,
              ToString(default_result).c_str(),
              default_result.actual_order.c_str());
  std::fflush(stdout);
  std::vector<double> sampled;
  int num_timeouts = 0;
  for (const auto& [label, order] : orders) {
    Result result = RunInChild(instance, fields, &order);
    if (result.status == Result::Status::kOk &&
        result.actual_order != absl::StrJoin(order, ",")) {
      std::printf("ORDER MISMATCH: %s\n", result.actual_order.c_str());
    }
    if (absl::GetFlag(FLAGS_print_orders) || label == "heuristic")
      std::printf("%s/%d %s %s [%s]\n", workload.name.c_str(), size,
                  label.c_str(), ToString(result).c_str(),
                  absl::StrJoin(order, ",").c_str());
    std::fflush(stdout);
    if (label == "all" || label == "random") {
      sampled.push_back(result.ms);
      if (result.status == Result::Status::kTimeout) ++num_timeouts;
    }
  }
  if (sampled.empty()) return;
  std::sort(sampled.begin(), sampled.end());
  std::printf(
      "SUMMARY %s/%d fields=%zu orders=%zu default=%.1f best=%.1f "
      "median=%.1f p90=%.1f worst=%.1f timeouts=%d\n",
      workload.name.c_str(), size, fields.size(), sampled.size(),
      default_result.ms, sampled.front(), sampled[sampled.size() / 2],
      sampled[sampled.size() * 9 / 10], sampled.back(), num_timeouts);
  std::fflush(stdout);
}

}  // namespace
}  // namespace netkat

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  std::vector<std::string> selected = absl::GetFlag(FLAGS_workloads);
  for (const netkat::Workload& workload : netkat::AllWorkloads()) {
    if (!selected.empty() &&
        absl::c_find(selected, workload.name) == selected.end()) {
      continue;
    }
    netkat::Study(workload);
  }
  return 0;
}
