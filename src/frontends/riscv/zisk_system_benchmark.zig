const std = @import("std");
const core = @import("stwo_core");
const authority = @import("air/guest_precompile/keccakf_authority.zig");
const witness = @import("air/guest_precompile/keccakf_witness.zig");
const counts = @import("air/guest_precompile/keccakf_multiplicities.zig");
export fn system_trace(input: *const authority.State, out: *authority.PermutationTrace) void {
    out.* = authority.buildTrace(input.*);
}
export fn system_batch(op: u32, rounds: u32) u64 {
    var input: authority.State = undefined;
    for (&input, 0..) |*v, i| v.* = i;
    var sum: u64 = 0;
    var counters = counts.Counters.init(std.heap.page_allocator) catch unreachable;
    defer counters.deinit();
    for (0..rounds) |r| {
        input[0] = r;
        if (op == 0) {
            var s = input;
            authority.permute(&s);
            for (s) |v| sum +%= v;
        } else if (op == 1) {
            const trace = authority.buildTrace(input);
            std.mem.doNotOptimizeAway(&trace);
            for (trace) |row| for (row) |v| {
                sum +%= v;
            };
        } else {
            const slot = witness.buildSlot(input, input) catch unreachable;
            std.mem.doNotOptimizeAway(&slot);
            if (op == 3) {
                counters.slots = 0;
                counters.recordSlot(&slot) catch unreachable;
            }
            for (slot.rows) |row| {
                for (row.state) |v| sum +%= v;
                for (row.parity) |v| sum +%= v;
            }
        }
    }
    if (op == 3) {
        for (counters.chi) |v| sum +%= v.toU32();
        for (counters.xor5) |v| sum +%= v.toU32();
    }
    return sum;
}
test "system benchmark Keccak trace and witness semantic gates" {
    _ = @import("air/guest_precompile/tests/keccakf_witness_test.zig");
    var random = std.Random.DefaultPrng.init(198);
    for (0..128) |_| {
        var state: authority.State = undefined;
        for (&state) |*v| v.* = random.random().int(u64);
        const trace = authority.buildTrace(state);
        var reference = std.crypto.core.keccak.KeccakF(1600){ .st = state };
        reference.permute();
        try std.testing.expectEqualSlices(u64, &reference.st, &trace[24]);
        try authority.validateTrace(state, &trace);
    }
}
test "system frame fast paths retain encoded digest bytes" {
    const framing = core.channel.blake3.framing;
    const digest = [_]u8{0x89} ** 32;
    const words = [_]u32{ 0, 1, 0xffffffff, 0x01020304 };
    const felts = [_]core.fields.qm31.QM31{core.fields.qm31.QM31.fromU32Unchecked(1, 2, 3, 4)};
    const leaf = [_]core.fields.m31.M31{ core.fields.m31.M31.one(), core.fields.m31.M31.zero() };
    const frames = [_]framing.Frame{ .{ .init = {} }, .{ .words = .{ .state = digest, .values = &words } }, .{ .felts = .{ .state = digest, .values = &felts } }, .{ .integer = .{ .state = digest, .value = 0xfedcba9876543210 } }, .{ .root = .{ .state = digest, .value = digest } }, .{ .draw = .{ .state = digest, .index = 0xffffffffffffffff } }, .{ .pow = .{ .state = digest, .bits = 26, .nonce = 123 } }, .{ .leaf = &leaf }, .{ .node = .{ .left = digest, .right = digest } } };
    for (frames) |frame| {
        const bytes = try frame.encode(std.testing.allocator);
        defer std.testing.allocator.free(bytes);
        var expected: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(bytes, &expected, .{});
        try std.testing.expectEqualSlices(u8, &expected, &frame.hash());
    }
    const encoded = try frames[1].encode(std.testing.allocator);
    defer std.testing.allocator.free(encoded);
    const at = framing.PROTOCOL_ID.len + 1 + 32;
    try std.testing.expectEqual(@as(u64, 4), std.mem.readInt(u64, encoded[at..][0..8], .little));
    for (words, 0..) |word, i| try std.testing.expectEqual(word, std.mem.readInt(u32, encoded[at + 8 + i * 4 ..][0..4], .little));
}
test {
    _ = @import("air/guest_precompile/tests/keccakf_multiplicities_test.zig");
}

export fn system_slot_case(a: *const authority.State, b: *const authority.State, rows: [*]u8, histogram: [*]u32) void {
    const slot = witness.buildSlot(a.*, b.*) catch unreachable;
    var counters = counts.Counters.init(std.heap.page_allocator) catch unreachable;
    defer counters.deinit();
    counters.recordSlot(&slot) catch unreachable;
    counters.validateTotals() catch unreachable;
    var at: usize = 0;
    for (slot.rows) |row| {
        rows[at] = row.in_use_a;
        rows[at + 1] = row.in_use_b;
        at += 2;
        @memcpy(rows[at..][0..row.state.len], &row.state);
        at += row.state.len;
        @memcpy(rows[at..][0..row.parity.len], &row.parity);
        at += row.parity.len;
    }
    for (counters.chi, 0..) |v, i| histogram[i] = v.toU32();
    for (counters.xor5, 0..) |v, i| histogram[counters.chi.len + i] = v.toU32();
}
