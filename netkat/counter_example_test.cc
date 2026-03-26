#include "netkat/counter_example.h"

#include <utility>

#include "absl/status/status.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/status_matchers.h"
#include "netkat/evaluator.h"
#include "netkat/frontend.h"
#include "netkat/packet_transformer.h"

namespace netkat {
namespace {

using ::gutil::IsOkAndHolds;
using ::gutil::StatusIs;
using ::testing::HasSubstr;
using ::testing::StrEq;

TEST(CounterExampleTest,
     CreateEquivalenceCounterExampleReturnsErrorIfPoliciesAreTheSame) {
  PacketTransformerManager manager;
  PacketTransformerHandle policy = manager.Compile(Policy::Deny().ToProto());
  EXPECT_THAT(
      CounterExample::CreateEquivalenceCounterExample(policy, policy, manager),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CounterExampleTest, CreateEquivalenceCounterExampleReturnsCounterExample) {
  PacketTransformerManager manager;
  PacketTransformerHandle policy1 = manager.Compile(Policy::Accept().ToProto());
  PacketTransformerHandle policy2 = manager.Compile(Policy::Deny().ToProto());
  ASSERT_OK_AND_ASSIGN(CounterExample counter_example,
                       CounterExample::CreateEquivalenceCounterExample(
                           policy1, policy2, manager));
  EXPECT_THAT(counter_example.GetInputPacketInLeftButNotRight(),
              IsOkAndHolds(Packet{}));
  EXPECT_THAT(counter_example.GetInputPacketInRightButNotLeft(),
              StatusIs(absl::StatusCode::kNotFound));

  // The explanation should include the input packet and output packet, which in
  // this case are the same.
  EXPECT_THAT(counter_example.Explain(), HasSubstr("{}"));

  // The explanation should indicate that the output packet produced is from the
  // left policy, but not the right policy.
  EXPECT_THAT(counter_example.Explain(),
              HasSubstr("left policy, but not on right policy"));
}

TEST(SuccessOrCounterExampleTest, DefaultConstructorIsSuccess) {
  SuccessOrCounterExample success_or_counter_example;
  EXPECT_TRUE(success_or_counter_example.IsSuccess());
  EXPECT_THAT(success_or_counter_example.Explain(), StrEq("Success"));
}

TEST(SuccessOrCounterExampleTest, ConstructorWithCounterExampleIsNotSuccess) {
  PacketTransformerManager manager;
  ASSERT_OK_AND_ASSIGN(
      CounterExample counter_example,
      CounterExample::CreateEquivalenceCounterExample(
          manager.Compile(Policy::Deny().ToProto()),
          manager.Compile(Policy::Accept().ToProto()), manager));
  SuccessOrCounterExample success_or_counter_example(
      std::move(counter_example));
  EXPECT_FALSE(success_or_counter_example.IsSuccess());
  EXPECT_THAT(success_or_counter_example.Explain(), Not(StrEq("Success")));

  // The explanation should include the input packet and output packet, which in
  // this case are the same.
  EXPECT_THAT(success_or_counter_example.Explain(), HasSubstr("{}"));

  // The explanation should indicate that the output packet produced is from the
  // right policy, but not the left policy.
  EXPECT_THAT(success_or_counter_example.Explain(),
              HasSubstr("right policy, but not on left policy"));
}

TEST(SuccessOrCounterExampleTest,
     DifferentModifiesReturnsCounterExampleOfAllPackets) {
  PacketTransformerManager manager;
  PacketTransformerHandle policy1 = manager.Compile(
      Sequence(Modify("switch", 1), Modify("port", 1)).ToProto());
  PacketTransformerHandle policy2 = manager.Compile(
      Sequence(Modify("switch", 1), Modify("port", 2)).ToProto());
  ASSERT_OK_AND_ASSIGN(CounterExample counter_example,
                       CounterExample::CreateEquivalenceCounterExample(
                           policy1, policy2, manager));
  SuccessOrCounterExample success_or_counter_example(
      std::move(counter_example));
  EXPECT_FALSE(success_or_counter_example.IsSuccess());
  EXPECT_THAT(success_or_counter_example.GetCounterExampleOrDie()
                  .GetInputPacketInLeftButNotRight(),
              IsOkAndHolds(Packet{}));

  // The explanation should include the input packet and output packet. Since
  // the order of fields in the packet map is unspecified, we check for the
  // presence of the fields in the explanation rather than the full packet.
  EXPECT_THAT(success_or_counter_example.Explain(),
              testing::AllOf(HasSubstr("{}"), HasSubstr("switch=1"),
                             HasSubstr("port=1")));
}

}  // namespace
}  // namespace netkat
