//! Exact contiguous rejection-sampling prefix for a public state/start statement.
//! Transcript transitions must authenticate that statement in production.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const hash = @import("blake3_hash_witness.zig");
const graph = @import("blake3_hash_plan.zig");
pub const g = @import("blake3_g_call.zig");
pub const xor = @import("blake3_xor_call.zig");
pub const boundary = @import("blake3_boundary.zig");
pub const challenge = @import("blake3_challenge_block.zig");
pub const Consumption = enum {
    one,
    two,
    pub fn words(self: Consumption) usize {
        return if (self == .one) 4 else 8;
    }
};
pub const Statement = struct {
    namespace: u32,
    state: [32]u8,
    start: u64,
    attempts: u32,
    values: [8]M31,
    consumption: Consumption = .two,
};
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    g_rows: []g.Row,
    xor_rows: []xor.Row,
    boundary_rows: []boundary.Row,
    challenge_rows: []challenge.Row,
    next_draw: u64,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn logs(self: *const Prepared) [4]u32 {
        return .{ log(self.g_rows.len), log(self.xor_rows.len), log(self.boundary_rows.len), log(self.challenge_rows.len) };
    }
    fn log(n: usize) u32 {
        return if (n <= 1) 1 else std.math.log2_int_ceil(usize, n);
    }
};
pub fn prepare(a: std.mem.Allocator, s: Statement) !Prepared {
    return build(a, s, true);
}
pub fn trusted(a: std.mem.Allocator, s: Statement) !Prepared {
    return build(a, s, false);
}
fn build(backing: std.mem.Allocator, s: Statement, live: bool) !Prepared {
    if (s.attempts == 0) return error.InvalidBlake3Draw;
    const next = std.math.add(u64, s.start, s.attempts) catch return error.InvalidBlake3Draw;
    const last_namespace = @as(u64, s.namespace) + 2 * @as(u64, s.attempts) - 1;
    if (last_namespace >= core.fields.m31.Modulus) return error.InvalidBlake3Draw;
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var gs: std.ArrayList(g.Row) = .empty;
    var xs: std.ArrayList(xor.Row) = .empty;
    var bs: std.ArrayList(boundary.Row) = .empty;
    var cs: std.ArrayList(challenge.Row) = .empty;
    for (0..s.attempts) |attempt| {
        const circuit = s.namespace + 2 * @as(u32, @intCast(attempt));
        const last = attempt + 1 == s.attempts;
        const frame = core.channel.blake3.Frame{ .draw = .{ .state = s.state, .index = s.start + attempt } };
        const bytes = try frame.encode(a);
        defer a.free(bytes);
        var plan = try graph.build(a, bytes.len);
        defer plan.deinit();
        for (plan.output, 0..) |wire, i| if (wire != plan.output[0] + i) return error.InvalidBlake3Draw;
        var uses: [8]u32 = @splat(0);
        if (last) @memset(uses[0..s.consumption.words()], 1);
        const schedule = challenge.Schedule{ .source_circuit = circuit, .source_first = plan.output[0], .destination_circuit = circuit + 1, .destination_first = 0, .uses = uses, .status_wire = 8, .status_uses = 1 };
        var source: hash.Rows = undefined;
        var row = try challenge.fixedRow(schedule);
        if (live) {
            const prepared = try hash.prepare(a, circuit, bytes, @splat(0));
            source = prepared.rows;
            var words: [8]u32 = undefined;
            for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, prepared.digest[4 * i ..][0..4], .little);
            row = try challenge.logicalRow(schedule, words);
        } else source = try hash.trustedRows(a, circuit, bytes, @splat(0));
        defer source.deinit();
        try gs.appendSlice(a, source.g_rows);
        try xs.appendSlice(a, source.xor_rows);
        try bs.appendSlice(a, source.boundary_rows[0 .. source.boundary_rows.len - 8]);
        try cs.append(a, row);
        var status = try boundary.logicalCoordinates(circuit + 1, 8, M31.one().neg(), scalar(if (last) M31.one() else M31.zero()));
        if (live) status[0] = row[70];
        try bs.append(a, status);
        if (last) for (s.values[0..s.consumption.words()], 0..) |value, i| {
            var output = try boundary.logicalCoordinates(circuit + 1, @intCast(i), M31.one().neg(), scalar(value));
            if (live) output[0] = row[i * 8 + 7];
            try bs.append(a, output);
        };
    }
    // Finalize every allocation before copying the arena's ownership state.
    const g_rows = try gs.toOwnedSlice(a);
    const xor_rows = try xs.toOwnedSlice(a);
    const boundary_rows = try bs.toOwnedSlice(a);
    const challenge_rows = try cs.toOwnedSlice(a);
    return .{ .arena = arena, .g_rows = g_rows, .xor_rows = xor_rows, .boundary_rows = boundary_rows, .challenge_rows = challenge_rows, .next_draw = next };
}
fn scalar(value: M31) [4]M31 {
    return .{ value, M31.zero(), M31.zero(), M31.zero() };
}
