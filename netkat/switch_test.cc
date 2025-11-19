#include "netkat/switch.h"

#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gutil/status_matchers.h"  // IWYU pragma: keep
#include "netkat/analysis_engine.h"
#include "netkat/frontend.h"

namespace netkat {
namespace {

using ::absl_testing::StatusIs;
using ::testing::Return;

class MockPipelineStage : public NetkatSwitchPipelineStage {
 public:
  MOCK_METHOD(Policy, GetPolicy, (), (const, override));
  MOCK_METHOD((absl::StatusOr<std::unique_ptr<NetkatSwitchPipelineStage>>),
              MergeStage, (const NetkatSwitchPipelineStage&),
              (const, override));
  MOCK_METHOD(Policy, CleanUp, (), (const, override));
};

TEST(NetkatSwitchTest, CreateFailsWithNullStage) {
  EXPECT_THAT(NetkatSwitch::Create(nullptr),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(NetkatSwitchTest, CreateFailsWithMixedNullAndNonNullStage) {
  auto mock_stage = std::make_unique<MockPipelineStage>();
  EXPECT_THAT(NetkatSwitch::Create(std::move(mock_stage), nullptr),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(NetkatSwitchTest, AddStageIgnoredForNullStage) {
  NetkatSwitch nk_switch;
  EXPECT_THAT(nk_switch.AddStage(nullptr),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_EQ(nk_switch.GetStage(0), nullptr);
}

TEST(NetkatSwitchTest, AddStageWithCreateIsOk) {
  ASSERT_OK_AND_ASSIGN(
      NetkatSwitch nk_switch,
      NetkatSwitch::Create(std::make_unique<MockPipelineStage>()));
  EXPECT_OK(nk_switch.AddStage(std::make_unique<MockPipelineStage>()));
  auto* mock_stage = nk_switch.GetStage<MockPipelineStage>(0);
  auto* mock_stage_2 = nk_switch.GetStage<MockPipelineStage>(1);
  EXPECT_NE(mock_stage, nullptr);
  EXPECT_NE(mock_stage_2, nullptr);
  EXPECT_NE(mock_stage, mock_stage_2);
}

TEST(NetkatSwitchTest, GetStageOnEmptySwitchIsNull) {
  NetkatSwitch nk_switch;
  EXPECT_EQ(nk_switch.GetStage(0), nullptr);
}

TEST(NetkatSwitchTest, GetStageWithInvalidIndexIsNull) {
  NetkatSwitch nk_switch;
  EXPECT_OK(nk_switch.AddStage(std::make_unique<MockPipelineStage>()));
  EXPECT_EQ(nk_switch.GetStage(1), nullptr);
}

TEST(NetkatSwitchTest, SingleStageSwitchReturnsCorrectPolicy) {
  ASSERT_OK_AND_ASSIGN(
      NetkatSwitch nk_switch,
      NetkatSwitch::Create(std::make_unique<MockPipelineStage>()));

  auto* mock_stage = nk_switch.GetStage<MockPipelineStage>(0);
  ASSERT_NE(mock_stage, nullptr);
  EXPECT_CALL(*mock_stage, GetPolicy())
      .WillOnce(
          Return(Sequence(Filter(Match("vlan_id", 1)), Modify("vrf", 1))));
  EXPECT_CALL(*mock_stage, CleanUp()).WillOnce(Return(Modify("vrf", -1)));

  netkat::AnalysisEngine engine;
  EXPECT_TRUE(engine
                  .CheckEquivalent(
                      nk_switch.GetPolicy(),
                      Sequence(Filter(Match("vlan_id", 1)), Modify("vrf", -1)))
                  .IsSuccess());
}

TEST(NetkatSwitchTest, MultiStageSwitchReturnsCorrectPolicy) {
  ASSERT_OK_AND_ASSIGN(
      NetkatSwitch nk_switch,
      NetkatSwitch::Create(std::make_unique<MockPipelineStage>(),
                           std::make_unique<MockPipelineStage>()));

  auto* mock_stage = nk_switch.GetStage<MockPipelineStage>(0);
  ASSERT_NE(mock_stage, nullptr);
  EXPECT_CALL(*mock_stage, GetPolicy())
      .WillOnce(
          Return(Sequence(Filter(Match("vlan_id", 1)), Modify("vrf", 1))));
  EXPECT_CALL(*mock_stage, CleanUp()).WillOnce(Return(Modify("vrf", -1)));

  auto* mock_stage_2 = nk_switch.GetStage<MockPipelineStage>(1);
  ASSERT_NE(mock_stage_2, nullptr);
  EXPECT_CALL(*mock_stage_2, GetPolicy())
      .WillOnce(Return(Sequence(Filter(Match("vrf", 1)), Modify("vlan_id", 2),
                                Modify("rnd_tag", 1))));
  EXPECT_CALL(*mock_stage_2, CleanUp()).WillOnce(Return(Modify("rnd_tag", -1)));

  // The VLAN sets a VRF, the VRF remaps the VLAN. The resulting policy should
  // be as-if the VLAN is simply remapped... plus the metadata cleanup.
  netkat::AnalysisEngine engine;
  EXPECT_TRUE(
      engine
          .CheckEquivalent(
              nk_switch.GetPolicy(),
              Sequence(Filter(Match("vlan_id", 1)), Modify("vlan_id", 2),
                       Modify("vrf", -1), Modify("rnd_tag", -1)))
          .IsSuccess());
}

}  // namespace
}  // namespace netkat
