//! Committed SHA-256 truth columns and private Wire35 interaction publication.
//! Inputs are untrusted advice; their truth is the AIR plus Wire35 closure.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../evaluation.zig");
const R = @import("../../memory/closed_ram/mod.zig");
const L = @import("layout.zig");
const N = @import("native.zig");
const Eq = @import("equations.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;

pub fn fixed(a: std.mem.Allocator, log: u32) ![]M {
    try L.validateGeometry(0, 1, log);
    const n = @as(usize, 1) << @intCast(log);
    const out = try a.alloc(M, L.FIXED * n);
    for (0..n) |row| {
        const p = R.trace.physical(row, log);
        out[L.ROW * n + p] = M.fromCanonical(@intCast(row));
        out[L.FIRST * n + p] = M.fromCanonical(@intFromBool(row == 0));
        out[L.LAST * n + p] = M.fromCanonical(@intFromBool(row == n - 1));
    }
    return out;
}

/// Scalar mask view over one native row, for interaction generation and tests.
pub const RowView = struct {
    fixed_values: [L.FIXED]Q,
    main_values: *const N.Row,
    previous_active: Q = Q.zero(),
    inter: [L.INTERACTION]Q = @splat(Q.zero()),
    previous_inter: [L.INTERACTION]Q = @splat(Q.zero()),
    pub fn fixed(self: *const RowView, c: usize) Q {
        return self.fixed_values[c];
    }
    pub fn main(self: *const RowView, c: usize) Q {
        return Q.fromBase(M.fromCanonical(self.main_values[c]));
    }
    pub fn previousActive(self: *const RowView) Q {
        return self.previous_active;
    }
    pub fn interaction(self: *const RowView, c: usize) Q {
        return self.inter[c];
    }
    pub fn previousInteraction(self: *const RowView, c: usize) Q {
        return self.previous_inter[c];
    }
};

pub const Source = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    first_id: u32,
    /// Copied narrow advice: survives MAIN release for interaction work.
    inputs: []N.Input,
    fixed: []M,
    owns_fixed: bool = true,
    main: []M,
    owns_main: bool = true,
    main_allocator: ?std.mem.Allocator = null,
    interaction: []M = &.{},

    pub fn init(a: std.mem.Allocator, inputs: []const N.Input, first_id: u32, log: u32) !Source {
        try L.validateGeometry(inputs.len, first_id, log);
        const n = @as(usize, 1) << @intCast(log);
        const copy = try a.dupe(N.Input, inputs);
        errdefer a.free(copy);
        const f = try fixed(a, log);
        errdefer a.free(f);
        const main = try a.alloc(M, L.MAIN * n);
        errdefer a.free(main);
        var row: N.Row = undefined;
        var padding: N.Row = undefined;
        _ = N.fill(&padding, N.PADDING);
        for (0..n) |r| {
            const p = R.trace.physical(r, log);
            const values = if (r < inputs.len) blk: {
                _ = N.fill(&row, inputs[r]);
                row[L.ACTIVE] = 1;
                break :blk &row;
            } else &padding;
            for (values, 0..) |v, c| main[c * n + p] = M.fromCanonical(v);
        }
        return .{ .allocator = a, .log_size = log, .first_id = first_id, .inputs = copy, .fixed = f, .main = main };
    }
    pub fn size(self: *const Source) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn releaseMain(self: *Source) !void {
        if (self.owns_main) (self.main_allocator orelse self.allocator).free(self.main);
        self.main = &.{};
        self.owns_main = false;
    }
    pub fn deinit(self: *Source) void {
        self.releaseMain() catch {};
        const a = self.allocator;
        if (self.owns_fixed) a.free(self.fixed);
        a.free(self.inputs);
        a.free(self.interaction);
        self.* = undefined;
    }
    pub fn validateMetadata(self: *const Source) !void {
        try L.validateGeometry(self.inputs.len, self.first_id, self.log_size);
        if (self.fixed.len != L.FIXED * self.size()) return error.InvalidSha256Metadata;
    }
    /// Publishes the two cumulative Wire35 columns from copied advice alone.
    pub fn generateInteraction(self: *Source, wire: Eq.Wire) !Q {
        if (self.interaction.len != 0) return error.InvalidSha256Phase;
        try self.validateMetadata();
        const n = self.size();
        const out = try self.allocator.alloc(M, L.INTERACTION * n);
        errdefer self.allocator.free(out);
        var total = Q.zero();
        for (0..n) |r| {
            const p = R.trace.physical(r, self.log_size);
            // Inactive rows carry zero weight on every Wire35 event.
            var fractions = [2]Q{ Q.zero(), Q.zero() };
            if (r < self.inputs.len) {
                const input = self.inputs[r];
                const output = N.compress(input.state, &input.block);
                var d: [4]Q = undefined;
                for (&d, 0..) |*x, id| x.* = wire.denominator(&externalTuple(self.first_id + @as(u32, @intCast(r)), @intCast(id), N.wireBytes(input, output, @intCast(id))));
                fractions[0] = (try d[0].inv()).add(try d[1].inv()).neg();
                fractions[1] = (try d[3].inv()).sub(try d[2].inv());
            }
            total = total.add(fractions[0]);
            R.trace.store(out, n, p, 0, total);
            total = total.add(fractions[1]);
            R.trace.store(out, n, p, 4, total);
        }
        // C[r] = S_r - claim: the last cumulative entry is zero and the claim
        // enters once at FIRST, exactly as the transition constraint states.
        R.trace.center(out, n, 0, total);
        R.trace.center(out, n, 4, total);
        self.interaction = out;
        return total;
    }
};

pub fn externalTuple(id: u32, wire: u32, bytes: [32]u8) [L.WIRE_ARITY]Q {
    var t: [L.WIRE_ARITY]Q = undefined;
    t[0] = Q.fromBase(M.fromCanonical(L.PROGRAM_KIND));
    t[1] = Q.fromBase(M.fromCanonical(id));
    t[2] = Q.fromBase(M.fromCanonical(wire));
    for (t[3..], bytes) |*v, b| v.* = Q.fromBase(M.fromCanonical(b));
    return t;
}
