const std = @import("std");
const Fixture = @import("../prover/block_v7_execution_caller_test_v1.zig");
const Metadata = @import("block_v7_mixed_metadata_v1.zig");
const Cold = @import("block_v7_mixed_fixed_v1.zig");
const Producer = @import("block_v7_bounded_complete_cpu_producer_v1.zig");
const Key = @import("blake3_parent_fixed_key_v1.zig");
const Consumer = struct {
    pub const Result = void;
    pub fn consume(f: Fixture.Fixture) !void {
        const a = f.allocator;
        const metadata = try Metadata.Owned.init(a, f.trusted, f.input);
        defer metadata.deinit();
        const input = metadata.input();
        const one_log = blk: {
            var one = try Cold.Owned.deriveWindow(a, input, 0, 1, 64, 2, .{});
            defer one.deinit();
            break :blk @max(@as(u32, 18), std.mem.max(u32, &try Key.rowLogs(one.fixed)));
        };
        const opts = Producer.Options{ .profile = .diagnostic_q8_pow0, .max_originals = 64, .direct = .{ .max_row_log = one_log } };
        try std.testing.expectError(error.MixedDirectResourceLimit, Cold.Owned.deriveWindow(a, input, 0, 3, 64, 2, .{ .max_row_log = one_log }));
        var selected = try Producer.selectWindow(a, input, 0, 3, opts);
        defer selected.cold.deinit();
        try std.testing.expectEqual(@as(usize, 1), selected.count);
        try std.testing.expectEqual(@as(usize, 1), selected.resource_retries);
        var too_small = opts;
        too_small.direct.max_row_log = one_log - 1;
        try std.testing.expectError(error.OriginalVerifierExceedsWindowBudget, Producer.selectWindow(a, input, 0, 1, too_small));
        var altered = input;
        altered.epoch.digest[0] ^= 1;
        try std.testing.expectError(error.UntrustedV7Epoch, Producer.selectWindow(a, altered, 0, 2, opts));
        std.debug.print("V7_COLD_WINDOW_RETRY initial_children=3 one_log={d} selected=1 retries=1 live_witness_prepared=false malformed_epoch_preserved=true\n", .{one_log});
    }
};
test "v7 bounded cold window retries original row cap without masking admission errors" {
    try Fixture.runFixture(false, true, Consumer);
}
