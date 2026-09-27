//! Public state/index -> constrained hash -> exact native scalar challenges.
//! Transcript state transitions and ordered rejection retries are separate gates.
const std = @import("std");
const core = @import("stwo_core");
const f = @import("blake3_proof_fixture.zig");
const block = @import("blake3_challenge_block.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{block});
const hash = @import("blake3_hash_witness.zig");
const graph = @import("blake3_hash_plan.zig");
const M31 = f.M31;
const HASH = 601;
const CHALLENGE = 602;
const Combined = struct {
    g: []f.g.Row,
    xor: []f.xor.Row,
    boundary: []f.boundary.Row,
    challenge: []block.Row,
    fn logs(self: Combined) [4]u32 {
        return .{ log(self.g.len), log(self.xor.len), log(self.boundary.len), log(self.challenge.len) };
    }
    fn log(len: usize) u32 {
        return @max(1, std.math.log2_int_ceil(usize, len));
    }
};
test "BLAKE3 native draw produces constrained scalar challenges in a complete CPU proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var channel = core.channel.blake3.Channel{};
    channel.mixU64(198);
    channel.n_draws = 3;
    const frame = core.channel.blake3.Frame{ .draw = .{ .state = channel.digestBytes(), .index = channel.n_draws } };
    const bytes = try frame.encode(a);
    const expected = try channel.drawSecureFelts(a, 2);
    // This fixture is an accepted first attempt. Boundary vectors separately
    // exercise the two rare rejected u32s in every position of the block.
    try std.testing.expectEqual(@as(u64, 4), channel.n_draws);
    const values: [8]M31 = expected[0].toM31Array() ++ expected[1].toM31Array();
    const schedule = try scheduleFor(a, bytes.len);
    const digest = frame.hash();
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    const live = try combine(a, (try hash.prepare(a, HASH, bytes, digest)).rows, try block.logicalRow(schedule, words), values);
    const logs = live.logs();
    const rows = .{
        try f.padded(f.g, a, live.g, logs[0]),
        try f.padded(f.xor, a, live.xor, logs[1]),
        try f.padded(f.boundary, a, live.boundary, logs[2]),
        try f.padded(block, a, live.challenge, logs[3]),
    };
    const trusted_pp = try preprocessing(a, bytes, values);
    var false_values = values;
    false_values[6] = false_values[6].add(M31.one());
    const false_pp = try preprocessing(a, bytes, false_values);
    try @import("blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted_pp, false_pp);
}
fn scheduleFor(a: std.mem.Allocator, len: usize) !block.Schedule {
    var plan = try graph.build(a, len);
    defer plan.deinit();
    for (plan.output, 0..) |wire, i| if (wire != plan.output[0] + i) return error.NoncontiguousBlake3Root;
    return .{ .source_circuit = HASH, .source_first = plan.output[0], .destination_circuit = CHALLENGE, .destination_first = 0, .uses = @splat(1), .status_wire = 8, .status_uses = 1 };
}
fn preprocessing(a: std.mem.Allocator, bytes: []const u8, values: [8]M31) ![]f.Column {
    const fixed = try combine(a, try hash.trustedRows(a, HASH, bytes, @splat(0)), try block.fixedRow(try scheduleFor(a, bytes.len)), values);
    const logs = fixed.logs();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ fixed.g, fixed.xor, fixed.boundary, fixed.challenge }, 0..) |Air, data, i| try f.project(Air, a, data, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
fn combine(a: std.mem.Allocator, source: hash.Rows, challenge: block.Row, values: [8]M31) !Combined {
    // Replace eight public digest consumers with the challenge component, then
    // bind its eight scalar outputs and accepted status to the statement.
    const retained = source.boundary_rows.len - 8;
    const boundaries = try a.alloc(f.boundary.Row, retained + 9);
    @memcpy(boundaries[0..retained], source.boundary_rows[0..retained]);
    for (values, 0..) |value, i| boundaries[retained + i] = try f.boundary.logicalCoordinates(CHALLENGE, @intCast(i), M31.one().neg(), .{ value, M31.zero(), M31.zero(), M31.zero() });
    boundaries[retained + 8] = try f.boundary.logicalCoordinates(CHALLENGE, 8, M31.one().neg(), .{ M31.one(), M31.zero(), M31.zero(), M31.zero() });
    const challenges = try a.alloc(block.Row, 1);
    challenges[0] = challenge;
    return .{ .g = source.g_rows, .xor = source.xor_rows, .boundary = boundaries, .challenge = challenges };
}
