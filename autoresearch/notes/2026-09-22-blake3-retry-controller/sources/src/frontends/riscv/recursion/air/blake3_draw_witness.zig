//! Exact contiguous rejection-sampling prefix with public or authenticated state.
//! Transcript transitions must authenticate that statement in production.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const hash = @import("blake3_hash_witness.zig");
const frame_hash = @import("blake3_frame_witness.zig");
pub const route = frame_hash.route;
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
    /// Caller must consume each accepted scalar output exactly once.
    export_outputs: bool = false,
    state_source: ?@import("blake3_frame_route.zig").Caller = null,
};
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    g_rows: []g.Row,
    xor_rows: []xor.Row,
    boundary_rows: []boundary.Row,
    challenge_rows: []challenge.Row,
    next_draw: u64,
    output_source: @import("blake3_frame_route.zig").Caller,
    route_rows: []route.Row,
    state_uses: [8]u32,
    attempt_sources: []const @import("blake3_frame_route.zig").Caller,
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
    return build(a, s, true, false);
}
pub fn trusted(a: std.mem.Allocator, s: Statement) !Prepared {
    return build(a, s, false, false);
}
/// Export raw candidate blocks and acceptance bits; caller must enforce retries.
/// next_draw is the end of the physical batch, not the selected native counter.
pub fn prepareAttempts(a: std.mem.Allocator, s: Statement) !Prepared {
    return build(a, s, true, true);
}
pub fn trustedAttempts(a: std.mem.Allocator, s: Statement) !Prepared {
    return build(a, s, false, true);
}
fn build(backing: std.mem.Allocator, s: Statement, live: bool, raw_attempts: bool) !Prepared {
    if (s.attempts == 0) return error.InvalidBlake3Draw;
    const next = std.math.add(u64, s.start, s.attempts) catch return error.InvalidBlake3Draw;
    const last_namespace = @as(u64, s.namespace) + 2 * @as(u64, s.attempts) - 1;
    if (last_namespace >= core.fields.m31.Modulus) return error.InvalidBlake3Draw;
    if (s.state_source) |caller| {
        if (caller.circuit >= s.namespace and caller.circuit <= last_namespace) return error.InvalidBlake3Draw;
    }
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    const attempt_sources = try a.alloc(@import("blake3_frame_route.zig").Caller, if (raw_attempts) s.attempts else 0);
    var gs: std.ArrayList(g.Row) = .empty;
    var xs: std.ArrayList(xor.Row) = .empty;
    var bs: std.ArrayList(boundary.Row) = .empty;
    var cs: std.ArrayList(challenge.Row) = .empty;
    var rs: std.ArrayList(route.Row) = .empty;
    var state_uses: [8]u32 = @splat(0);
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
        if (raw_attempts) attempt_sources[attempt] = .{ .circuit = circuit + 1, .first_wire = 0 };
        if (last or raw_attempts) @memset(uses[0..s.consumption.words()], 1);
        const schedule = challenge.Schedule{ .source_circuit = circuit, .source_first = plan.output[0], .destination_circuit = circuit + 1, .destination_first = 0, .uses = uses, .status_wire = 8, .status_uses = 1 };
        var private: ?frame_hash.Prepared = null;
        defer if (private) |*value| value.deinit();
        var public: ?hash.Rows = null;
        defer if (public) |*value| value.deinit();
        var source: @FieldType(frame_hash.Prepared, "rows") = undefined;
        var digest: ?[32]u8 = null;
        if (s.state_source) |caller| {
            const bindings = [_]frame_hash.Binding{.{ .role = .state, .caller = caller }};
            private = if (live) try frame_hash.prepare(a, circuit, frame, &bindings, @splat(0)) else try frame_hash.trusted(a, circuit, frame, &bindings, @splat(0));
            source = private.?.rows;
            digest = private.?.digest;
            try rs.appendSlice(a, private.?.route_rows);
            for (&state_uses, private.?.source_uses[0]) |*total, count| {
                total.* = std.math.add(u32, total.*, count) catch return error.InvalidBlake3Draw;
                if (total.* >= core.fields.m31.Modulus) return error.InvalidBlake3Draw;
            }
        } else {
            if (live) {
                const prepared = try hash.prepare(a, circuit, bytes, @splat(0));
                public = prepared.rows;
                digest = prepared.digest;
            } else public = try hash.trustedRows(a, circuit, bytes, @splat(0));
            source = .{ .g_rows = public.?.g_rows, .xor_rows = public.?.xor_rows, .boundary_rows = public.?.boundary_rows };
        }
        var row = try challenge.fixedRow(schedule);
        if (digest) |value| {
            var words: [8]u32 = undefined;
            for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, value[4 * i ..][0..4], .little);
            row = try challenge.logicalRow(schedule, words);
        }
        try gs.appendSlice(a, source.g_rows);
        try xs.appendSlice(a, source.xor_rows);
        try bs.appendSlice(a, source.boundary_rows[0 .. source.boundary_rows.len - 8]);
        try cs.append(a, row);
        if (!raw_attempts) {
            var status = try boundary.logicalCoordinates(circuit + 1, 8, M31.one().neg(), scalar(if (last) M31.one() else M31.zero()));
            if (live) status[0] = row[70];
            try bs.append(a, status);
        }
        if (!raw_attempts and last and !s.export_outputs) for (s.values[0..s.consumption.words()], 0..) |value, i| {
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
    const route_rows = try rs.toOwnedSlice(a);
    return .{ .attempt_sources = attempt_sources, .output_source = .{ .circuit = @intCast(last_namespace), .first_wire = 0 }, .route_rows = route_rows, .state_uses = state_uses, .arena = arena, .g_rows = g_rows, .xor_rows = xor_rows, .boundary_rows = boundary_rows, .challenge_rows = challenge_rows, .next_draw = next };
}
fn scalar(value: M31) [4]M31 {
    return .{ value, M31.zero(), M31.zero(), M31.zero() };
}
