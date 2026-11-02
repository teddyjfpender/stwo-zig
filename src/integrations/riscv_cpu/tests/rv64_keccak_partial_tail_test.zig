const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const K = rv.crypto.keccak;
const L = K.layout;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const a = std.testing.allocator;
test "Keccak domain-only schedule suppresses only incomplete output phase across every admissible log" {
    var changed: usize = 0;
    for (5..27) |value| {
        const log: u32 = @intCast(value);
        const n = @as(usize, 1) << @intCast(log);
        const complete_rows = n / L.ROWS_PER_PAIR * L.ROWS_PER_PAIR;
        for ([_]usize{ 0, complete_rows - L.ROWS_PER_PAIR, complete_rows }) |start| {
            for (0..L.ROWS_PER_PAIR) |phase| {
                const logical = start + phase;
                if (logical >= n) break;
                const row = try K.trace.fixedAt(log, logical);
                const complete = logical < complete_rows;
                for (0..L.ROWS_PER_PAIR) |c| try std.testing.expectEqual(@as(u32, @intFromBool(c == phase and (phase != 26 or complete))), row[c].v);
                try std.testing.expectEqual(@as(u32, @intFromBool(logical == 0)), row[L.FIRST].v);
                try std.testing.expectEqual(@as(u32, @intCast(logical / L.ROWS_PER_PAIR)), row[L.SLOT_INDEX].v);
                try std.testing.expectEqual(@as(u32, @intFromBool(complete)), row[L.COMPLETE_SLOT].v);
                if (!complete and phase == 26) {
                    changed += 1;
                    try std.testing.expect(log == 14 or log == 15);
                }
            }
        }
        const first_partial = try K.trace.fixedAt(log, complete_rows);
        try std.testing.expect(first_partial[0].isOne());
    }
    try std.testing.expectEqual(@as(usize, 2), changed);
}
test "Keccak padded log14 and log15 reproduce old native wrap failure and corrected residuals" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x4b544149, 37 });
    const ch = K.equations.Challenges.draw(&channel);
    const scratch = try a.create(K.component.Scratch);
    defer a.destroy(scratch);
    const residuals = try a.alloc(Q, L.CONSTRAINTS);
    defer a.free(residuals);
    for ([_]u32{ 14, 15 }) |log| {
        const n = @as(usize, 1) << @intCast(log);
        const logical = n / L.ROWS_PER_PAIR * L.ROWS_PER_PAIR + 26;
        const row = try K.trace.fixedAt(log, logical);
        for (&scratch.fixed, row) |*v, b| v.* = Q.fromBase(b);
        @memset(&scratch.main, Q.zero());
        for (&scratch.shifted) |*state| @memset(state, Q.zero());
        @memset(&scratch.previous_header, Q.zero());
        @memset(&scratch.interaction, Q.zero());
        // One nonzero input bit at active row0. All other referenced rows are
        // inactive padding (or dummy input B at row1 for the odd C1 call).
        if ((logical + 1) % n == 0) scratch.shifted[2][0] = Q.one();
        if ((logical + 2) % n == 0) scratch.shifted[3][0] = Q.one();
        var sink = rv.evaluation.Sink{ .values = residuals };
        K.equations.emit(scratch.row(), &scratch.interaction, Q.zero(), Q.zero(), ch, .{ .calls = 1, .first_id = 1 }, &sink);
        for (residuals) |v| try std.testing.expect(v.isZero());
        scratch.fixed[26] = Q.one(); // exact pre-fix schedule, no equation edit
        sink.count = 0;
        K.equations.emit(scratch.row(), &scratch.interaction, Q.zero(), Q.zero(), ch, .{ .calls = 1, .first_id = 1 }, &sink);
        try std.testing.expect(residuals[L.HEADER + 1].eql(rv.evaluation.q(if (log == 14) 8 else 1).neg()));
        const columns = try K.trace.fixedColumnsForLog(a, log);
        defer a.free(columns);
        for (0..n) |i| {
            const expected = try K.trace.fixedAt(log, i);
            const physical = rv.witness.physical(i, log);
            for (expected, 0..) |v, c| try std.testing.expect(v.eql(columns[c * n + physical]));
        }
    }
}
