//! A private digest passes between two hash graphs inside one actual STARK.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const F = @import("blake3_fixture_roster.zig").Fixture(true);
const hash = @import("blake3_hash_witness.zig");
const private = @import("blake3_private_hash_witness.zig");
const graph = @import("blake3_hash_plan.zig");
const bridge = @import("blake3_input_bridge.zig");
const M31 = f.M31;
const Message = "a private intermediate digest must be constrained by its producer";
const FIRST = 401;
const SECOND = 402;
const Combined = struct {
    g: []f.g.Row,
    xor: []f.xor.Row,
    boundary: []f.boundary.Row,
    input: []bridge.Row,
    fn logs(self: Combined) [4]u32 {
        return .{ log(self.g.len), log(self.xor.len), log(self.boundary.len), log(self.input.len) };
    }
    fn log(len: usize) u32 {
        return @max(1, std.math.log2_int_ceil(usize, len));
    }
};
test "BLAKE3 private hash chain proves without exposing its intermediate digest" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var intermediate: [32]u8 = undefined;
    var final: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(Message, &intermediate, .{});
    std.crypto.hash.Blake3.hash(&intermediate, &final, .{});
    const caller = try callerForLength(a, Message.len);
    const first = try hash.prepare(a, FIRST, Message, intermediate);
    const second = try private.prepare(a, SECOND, caller, &intermediate, final);
    const live = try combine(a, first.rows, second.rows);
    const logs = live.logs();
    const rows = .{
        try f.padded(f.g, a, live.g, logs[0]),
        try f.padded(f.xor, a, live.xor, logs[1]),
        try f.padded(f.boundary, a, live.boundary, logs[2]),
        try f.padded(bridge, a, live.input, logs[3]),
    };
    // The verifier receives original message and final digest only. The first
    // digest placeholder is removed with its eight public boundary rows.
    const trusted_pp = try preprocessing(a, Message, final);
    var false_final = final;
    false_final[17] ^= 0x80;
    const false_pp = try preprocessing(a, Message, false_final);
    try @import("blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted_pp, false_pp);
}
fn callerForLength(a: std.mem.Allocator, len: usize) !private.Caller {
    var plan = try graph.build(a, len);
    defer plan.deinit();
    for (plan.output, 0..) |wire, i| if (wire != plan.output[0] + i) return error.NoncontiguousBlake3Root;
    return .{ .circuit = FIRST, .first_wire = plan.output[0] };
}
fn preprocessing(a: std.mem.Allocator, message: []const u8, final: [32]u8) ![]f.Column {
    const first = try hash.trustedRows(a, FIRST, message, @splat(0));
    const caller = try callerForLength(a, message.len);
    const second = try private.trustedRows(a, SECOND, caller, 32, final);
    const fixed = try combine(a, first, second);
    const logs = fixed.logs();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ fixed.g, fixed.xor, fixed.boundary, fixed.input }, 0..) |Air, data, i| try f.project(Air, a, data, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
// Arena-owned fixture arrays. The first graph's final output consumers are
// replaced by the second graph's bridge, preserving exact wire multiplicities.
fn combine(a: std.mem.Allocator, first: hash.Rows, second: private.Rows) !Combined {
    return .{
        .g = try concat(f.g.Row, a, first.g_rows, second.hash_rows.g_rows),
        .xor = try concat(f.xor.Row, a, first.xor_rows, second.hash_rows.xor_rows),
        .boundary = try concat(f.boundary.Row, a, first.boundary_rows[0 .. first.boundary_rows.len - 8], second.hash_rows.boundary_rows),
        .input = second.bridge_rows,
    };
}
fn concat(comptime T: type, a: std.mem.Allocator, left: []const T, right: []const T) ![]T {
    const result = try a.alloc(T, left.len + right.len);
    @memcpy(result[0..left.len], left);
    @memcpy(result[left.len..], right);
    return result;
}
