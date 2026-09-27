//! Pure equation/source-boundary fixtures. These construct no admitted child,
//! capture, receipt, PCS proof, guest execution or successful root verifier.
const std = @import("std");
const G = @import("../recursion/air/block_v5_wide_native_public_graph_v1.zig");
const Wide = @import("../recursion/air/block_v5_recursive_u64_span_v1.zig");
const Public = @import("../recursion/block_v5_wide_native_public_values_v1.zig");
const Span = @import("../recursion/block_v5_pc_clock_span_v1.zig");
fn parts(first: u64, clock: u32) !G.Parts {
    if (clock == 0) return error.InvalidTestClock;
    const steps = clock - 1;
    const last = try std.math.add(u64, first, steps);
    var result = G.Parts{ .original_digest = @splat(0x35), .expected_digest = @splat(0x35), .first = Wide.encode(first), .last = Wide.encode(last), .clock = undefined, .steps = undefined, .add_carries = try Public.addCarries(first, steps), .increment_carries = try Wide.carries(steps) };
    std.mem.writeInt(u32, &result.clock, clock, .little);
    std.mem.writeInt(u32, &result.steps, steps, .little);
    return result;
}
fn sources() [G.INPUT_COUNT]G.Source {
    var result: [G.INPUT_COUNT]G.Source = undefined;
    for (&result, 0..) |*source, index| source.* = .{ .cell = @intCast(index / 4), .part = @intCast(index % 4) };
    return result;
}
fn boundaryFixture(a: std.mem.Allocator) !void {
    for ([_]struct { first: u64, clock: u32 }{ .{ .first = (1 << 30) - 1, .clock = 3 }, .{ .first = (1 << 32) - 1, .clock = 3 }, .{ .first = (1 << 63) - 1, .clock = 3 }, .{ .first = std.math.maxInt(u64) - 1, .clock = 2 }, .{ .first = std.math.maxInt(u64), .clock = 1 }, .{ .first = 0x0102030405060708, .clock = 0xffffffff } }) |case| {
        var graph = try G.record(a, try parts(case.first, case.clock), sources());
        defer graph.deinit();
        try std.testing.expectEqual(@as(u32, G.INPUT_COUNT), graph.circuit.input_count);
        try std.testing.expect(!G.Prepared.complete_source_authority);
    }
}
test "wide original bridge: full-u64 count equations cross legacy cutoff u32 u63 and final-u64 boundary" {
    try boundaryFixture(std.testing.allocator);
}
test "wide original bridge: public carry graph construction exhaustively rolls back OOM" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, boundaryFixture, .{});
}
fn rejects(candidate: G.Parts) !void {
    const result = G.record(std.testing.allocator, candidate, sources());
    if (result) |value| {
        var owned = value;
        owned.deinit();
        return error.TestUnexpectedSuccess;
    } else |failure| try std.testing.expectEqual(error.UnsatisfiedCircuit, failure);
}
test "wide original bridge: digest high-clock steps count carry and overflow mutations reject" {
    const original = try parts((1 << 32) - 1, 3);
    var changed = original;
    changed.expected_digest[31] ^= 1;
    try rejects(changed);
    changed = original;
    changed.first[7] ^= 1;
    try rejects(changed);
    changed = original;
    changed.last[7] ^= 1;
    try rejects(changed);
    changed = original;
    changed.clock[0] ^= 1;
    try rejects(changed);
    changed = original;
    changed.steps[0] ^= 1;
    try rejects(changed);
    changed = original;
    changed.add_carries[0] ^= 1;
    try rejects(changed);
    changed = original;
    changed.add_carries[1] = 2;
    try rejects(changed);
    changed = original;
    changed.increment_carries[0] = 2;
    try rejects(changed);
    changed = try parts(std.math.maxInt(u64), 1);
    changed.steps[0] = 1;
    changed.clock[0] = 2;
    changed.last = Wide.encode(0);
    changed.add_carries = @splat(1);
    try rejects(changed);
    try std.testing.expectError(error.Overflow, Public.addCarries(std.math.maxInt(u64), 1));
}
test "wide original bridge: legacy six-word grammar stays rejected while original span admits full-u64" {
    const native = Span.Span{ .job_id = @splat(1), .source_image_digest = @splat(2), .sealed_digest = @splat(3), .job_segment_count = 1, .first_index = 0, .segment_count = 1, .first_cycle = 1 << 32, .last_cycle = (1 << 32) + 1, .initial_pc = 0x1000, .final_pc = 0x1004 };
    try native.validate();
    try std.testing.expectError(error.V5PcClockFoldRangeExceeded, @import("../recursion/block_v5_open_parent_public_bus_v1.zig").validateSpanBound(native));
    const digest = try native.identity();
    var changed = native;
    changed.last_cycle += 1;
    try std.testing.expect(!std.meta.eql(digest, try changed.identity()));
}

// Plain equation-test byte view; never used as original policy, Admission,
// Fresh, successful receiver or capture. Coordinates are fixture layout only.
const ByteView = struct {
    words: [30]u32,
    pub fn validate(_: *const ByteView) !void {}
    pub fn originalDigest(_: *const ByteView) !Public.Coordinate {
        return .{ .first_cell = 0, .word_count = 8 };
    }
    pub fn expectedDigest(_: *const ByteView) !Public.Coordinate {
        return .{ .first_cell = 8, .word_count = 8 };
    }
    pub fn firstCycle(_: *const ByteView) !Public.Coordinate {
        return .{ .first_cell = 16, .word_count = 2 };
    }
    pub fn lastCycle(_: *const ByteView) !Public.Coordinate {
        return .{ .first_cell = 18, .word_count = 2 };
    }
    pub fn clock(_: *const ByteView) !Public.Coordinate {
        return .{ .first_cell = 20, .word_count = 1 };
    }
    pub fn auxFirst(_: *const ByteView) !u32 {
        return 21;
    }
    pub fn cell(self: *const ByteView, coordinate: u32) ![4]@import("stwo_core").fields.m31.M31 {
        if (coordinate >= self.words.len) return error.InvalidTestCoordinate;
        var out: [4]@import("stwo_core").fields.m31.M31 = undefined;
        for (&out, 0..) |*byte, part| byte.* = @import("stwo_core").fields.m31.M31.fromCanonical((self.words[coordinate] >> @as(u5, @intCast(8 * part))) & 255);
        return out;
    }
};
test "wide original bridge: independent graph reconstruction rejects equal-byte source substitution" {
    const p = try parts((1 << 32) - 1, 3);
    var view = ByteView{ .words = undefined };
    for (0..8) |index| {
        view.words[index] = std.mem.readInt(u32, p.original_digest[4 * index ..][0..4], .little);
        view.words[8 + index] = std.mem.readInt(u32, p.expected_digest[4 * index ..][0..4], .little);
    }
    for (0..2) |index| {
        view.words[16 + index] = std.mem.readInt(u32, p.first[4 * index ..][0..4], .little);
        view.words[18 + index] = std.mem.readInt(u32, p.last[4 * index ..][0..4], .little);
    }
    view.words[20] = std.mem.readInt(u32, &p.clock, .little);
    view.words[21] = std.mem.readInt(u32, &p.steps, .little);
    for (0..4) |index| {
        view.words[22 + index] = p.add_carries[index];
        view.words[26 + index] = p.increment_carries[index];
    }
    var graph = try G.prepare(std.testing.allocator, &view);
    defer graph.deinit();
    try graph.validate(&view);
    graph.sources[0].cell = 1;
    try std.testing.expectError(error.UntrustedWideNativeGraphInput, graph.validate(&view));
}
