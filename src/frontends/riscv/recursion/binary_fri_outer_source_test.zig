//! Focused custody tests for binary FRI rows 18--34.
const shard_0 = @import("binary_fri_outer_source_test_capture_fixture.zig");
const shard_1 = @import("binary_fri_outer_source_test_fixture.zig");
const shard_2 = @import("binary_fri_outer_source_test_expect_arithmetic_plan_parity.zig");
const shard_3 = @import("binary_fri_outer_source_test_validate_composition_input_base_rows.zig");
const shard_4 = @import("binary_fri_outer_source_test_suite_5.zig");

pub const Fixture = shard_1.Fixture;
pub const FullComposition = shard_0.FullComposition;
pub const buildFullComposition = shard_0.buildFullComposition;
pub const CaptureFixture = shard_0.CaptureFixture;
