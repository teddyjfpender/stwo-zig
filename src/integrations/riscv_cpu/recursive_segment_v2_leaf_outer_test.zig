const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const subject = @import("recursive_segment_v2_leaf_outer.zig");
const recursive_fri_outer = @import("recursive_fri_outer.zig");

const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;

test "V2 leaf outer shared row34 ranges are exact and fail closed" {
    var calls = [_]poseidon2_air.Call{
        call(11),
        call(29),
        call(47),
    };
    const layout = try subject.SharedPoseidonCallLayoutV2.initBoundaryPrefix(
        2,
        1,
        &calls,
    );
    try layout.validate(&calls);
    try std.testing.expectEqual(@as(usize, 2), try layout.transcript.count());
    try std.testing.expectEqual(
        @as(usize, 1),
        try layout.statement_authority.count(),
    );
    try std.testing.expectEqual(@as(usize, 0), try layout.verifier_core.count());
    try std.testing.expect(!layout.verifier_core_range_populated);
    try std.testing.expect(!layout.call_set_complete);

    calls[1].input[7] +%= 1;
    try std.testing.expectError(error.CallLayoutMismatch, layout.validate(&calls));
    calls[1].input[7] -%= 1;

    var overlap = layout;
    overlap.statement_authority.start -= 1;
    try std.testing.expectError(error.CallLayoutMismatch, overlap.validate(&calls));

    var second_provider = layout;
    second_provider.total_call_count -= 1;
    try std.testing.expectError(
        error.CallLayoutMismatch,
        second_provider.validate(&calls),
    );

    const core_calls = [_]poseidon2_air.Call{ call(71), call(89) };
    var complete = try subject.OwnedCompletePoseidonScheduleV2.init(
        std.testing.allocator,
        &layout,
        &calls,
        &core_calls,
    );
    defer complete.deinit();
    try complete.validateAgainst(&layout, &calls);
    try std.testing.expect(complete.layout.verifier_core_range_populated);
    try std.testing.expect(complete.layout.call_set_complete);
    try std.testing.expectEqual(
        core_calls.len,
        try complete.layout.verifier_core.count(),
    );
    try std.testing.expectEqual(calls.len + core_calls.len, complete.calls.len);

    complete.calls[0].input[0] +%= 1;
    try std.testing.expectError(
        error.CallLayoutMismatch,
        complete.validateAgainst(&layout, &calls),
    );
    complete.calls[0].input[0] -%= 1;
    try complete.validateAgainst(&layout, &calls);

    complete.calls[complete.calls.len - 1].input[3] +%= 1;
    try std.testing.expectError(
        error.CallLayoutMismatch,
        complete.validateAgainst(&layout, &calls),
    );
}

test "V2 leaf outer capability stays fail closed before the outer STARK" {
    try std.testing.expect(subject.CAPTURE_CUSTODY_REQUIRED);
    try std.testing.expect(subject.TRANSCRIPT_PROGRAM_V2_EXACT);
    try std.testing.expectEqual(@as(usize, 1), subject.SHARED_ROW34_PROVIDER_COUNT);
    try std.testing.expect(subject.ROW34_BOUNDARY_PREFIX_AVAILABLE);
    try std.testing.expect(subject.ROW34_COMPLETE_LAYOUT_SUPPORTED);
    try std.testing.expect(!subject.ROW34_VERIFIER_CORE_RANGE_POPULATED);
    try std.testing.expect(!subject.ROW34_CALL_SET_COMPLETE);
    try std.testing.expect(!subject.ROWS_0_9_PUBLISHABLE);
    try std.testing.expect(!subject.EXACT_47_DOMAIN_CLOSURE_AVAILABLE);
    try std.testing.expect(!subject.OUTER_STARK_VERIFIED);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
}

test "V2 leaf target names two boundary sources outside the universal roster" {
    try std.testing.expectEqual(
        @as(u8, 36),
        recursive_fri_outer.V2_UNIVERSAL_ROSTER_COMPONENT_COUNT,
    );
    try std.testing.expectEqual(
        @as(u8, 2),
        recursive_fri_outer.V2_AUTHORITY_SOURCE_COMPONENT_COUNT,
    );
    try std.testing.expectEqual(
        @as(u8, 38),
        recursive_fri_outer.V2_TARGET_COMPONENT_COUNT,
    );
}

fn call(seed: u32) poseidon2_air.Call {
    var input: [poseidon2_air.WIDTH]u32 = undefined;
    for (&input, 0..) |*word, index| word.* = seed + @as(u32, @intCast(index));
    return .{
        .input = input,
        .wide = false,
        .io = true,
        .narrow_output = null,
    };
}
