//! Hold guest execution fixed; compare fewer native STARKs before recursion.
//! This is segmentation, not a joint PCS across independently sized AIRs.
const std = @import("std");
const jobs = @import("block_v6_native_batch_scaling_test.zig");

test "block-v6 tiling same execution canonical q70 pow26" {
    try run(.csp_q70_pow26);
}

test "block-v6 tiling same execution diagnostic q8" {
    try run(.diagnostic_q8_pow0);
}

fn run(selected: @import("../../recursion/blake3_execution_parent_protocol.zig").Profile) !void {
    const base = if (std.posix.getenv("STWO_NATIVE_TILE_STEPS")) |raw| try std.fmt.parseInt(u32, raw, 10) else 64;
    if (base < 2 or base > 65536 or base % 2 != 0) return error.InvalidNativeTileSteps;
    const one = [_]u32{13 * base};
    const three = [_]u32{ 4 * base, 4 * base, 5 * base };
    const nine = [_]u32{ base, 2 * base, base, 2 * base, base, 2 * base, base, 2 * base, base };
    var expected: ?[32]u8 = null;
    for ([_][]const u32{ &one, &three, &nine }) |sizes| {
        const digest = try jobs.runJob(selected, base, sizes, true);
        if (expected) |previous| try std.testing.expectEqualDeep(previous, digest);
        expected = digest;
    }
    std.debug.print("BLOCK_V6_TILE_EQUIVALENCE profile={s} cycles={d} partitions=1,3,9 endpoints_match=true globals_open=true\n", .{ @tagName(selected), 13 * base });
}
