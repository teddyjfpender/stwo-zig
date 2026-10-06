const std = @import("std");
const direct = @import("recursion/air/segment_leaf_wrapper_roster_direct_v4.zig");
const v2 = @import("recursion/air/segment_outer_adapter_manifest_v2.zig");
const catalog = @import("recursion/air/segment_outer_typed_catalog_v2.zig");
const program_mod = @import("recursion/ethereum_leaf_link_program_v3.zig");
const fixture = @import("wrapper_roster_v3_test_root.zig");

test "direct 47-row wrapper roster excludes post-challenge provider input" {
    const allocator = std.testing.allocator;
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    const base = try v2.assemble(&source_catalog, fixture.authorityIds());
    var program = try program_mod.ProgramV3.init(allocator);
    defer program.deinit();
    const shape = direct.Shape{ .program_words = 100, .base_poseidon_calls = 1193 };
    const plan = try direct.Plan.build(allocator, &base, &program, shape);
    try plan.validateAgainst(allocator, &base, &program, shape);
    try std.testing.expectEqual(@as(usize, 47), direct.COMPONENT_COUNT);
    try std.testing.expectEqual(@as(usize, 1193 + 77 + 7 + 13), plan.poseidon_calls.total);
    try std.testing.expectEqual(@as(u32, 11), plan.placements[34].?.geometry.log_size);
    try std.testing.expectEqual(@as(u8, 44), plan.placements[44].?.claimed_sum_index);
    try std.testing.expectEqual(@as(u8, 46), plan.placements[46].?.claimed_sum_index);
    try std.testing.expectEqualDeep(program_mod.SCHEDULE_ID, plan.program_schedule_id);
    try std.testing.expect(!direct.COMPLETE_WRAPPER_PROOF_AVAILABLE);
    try std.testing.expectError(error.V3WrapperProofUnavailable, plan.requireCompleteWrapperProof());

    var mutated = plan;
    mutated.program_schedule_id[0] ^= 1;
    try std.testing.expectError(error.InvalidV3WrapperRoster, mutated.validate());
    mutated = plan;
    mutated.placements[34].?.geometry.log_size += 1;
    try std.testing.expectError(error.InvalidV3WrapperRoster, mutated.validate());
    mutated = plan;
    mutated.poseidon_calls.program += 1;
    try std.testing.expectError(error.InvalidV3WrapperRoster, mutated.validate());
    try std.testing.expectError(
        error.InvalidV3WrapperRoster,
        plan.validateAgainst(allocator, &base, &program, .{ .program_words = 101, .base_poseidon_calls = 1193 }),
    );
}
