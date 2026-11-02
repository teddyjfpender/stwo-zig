//! Committed arith256_mod truth columns and private interaction publication.
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
        out[L.BYTE * n + p] = M.fromCanonical(@intCast(row & 0xff));
    }
    return out;
}

/// Scalar mask view over one native row, for interaction checks and tests.
pub const RowView = struct {
    fixed_values: [L.FIXED]Q,
    main_values: *const N.Row,
    previous_active: Q = Q.zero(),
    inter: []const Q = &.{},
    previous_inter: []const Q = &.{},
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

/// Native row `r` of a trace over `inputs`: active rows, then zero padding.
/// MULT is the BYTE multiplicity of value r on rows 0..255 (else zero).
pub fn nativeRow(row: *N.Row, inputs: []const N.Input, counts: *const [256]u64, r: usize) void {
    if (r < inputs.len) {
        _ = N.fill(row, inputs[r]);
    } else @memset(row, 0);
    row[L.MULT] = if (r < 256) @intCast(counts[r]) else 0;
}
/// BYTE multiplicities of the whole trace (padding rows query 0 and 128).
pub fn byteCounts(inputs: []const N.Input, n: usize) ![256]u64 {
    var counts: [256]u64 = @splat(0);
    var row: N.Row = undefined;
    for (inputs) |input| {
        _ = N.fill(&row, input);
        for (0..L.BYTE_QUERIES) |i| {
            const q = L.query(i);
            counts[row[q.column] + q.addend] += 1;
        }
    }
    const padding = n - inputs.len;
    counts[0] += @as(u64, padding) * (L.Q_LIMBS + L.LIMBS + 2 * L.CARRIES);
    counts[128] += @as(u64, padding) * L.CARRIES;
    var mass: u64 = 0;
    for (counts) |c| mass += c;
    if (mass != @as(u64, L.BYTE_QUERIES) * n or mass >= core.fields.m31.Modulus) return error.Arith256LookupMassExceeded;
    return counts;
}

pub const Source = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    first_id: u32,
    /// Copied narrow advice: survives MAIN release for interaction work.
    inputs: []N.Input,
    counts: [256]u64,
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
        const counts = try byteCounts(inputs, n);
        const f = try fixed(a, log);
        errdefer a.free(f);
        const main = try a.alloc(M, L.MAIN * n);
        errdefer a.free(main);
        var row: N.Row = undefined;
        for (0..n) |r| {
            const p = R.trace.physical(r, log);
            nativeRow(&row, inputs, &counts, r);
            for (row, 0..) |v, c| main[c * n + p] = M.fromCanonical(v);
        }
        return .{ .allocator = a, .log_size = log, .first_id = first_id, .inputs = copy, .counts = counts, .fixed = f, .main = main };
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
        if (self.fixed.len != L.FIXED * self.size()) return error.InvalidArith256Metadata;
    }
    /// Publishes both cumulative chains from copied advice alone and returns
    /// the Wire35 claim (the BYTE chain closes to zero).
    pub fn generateInteraction(self: *Source, ch: Eq.Challenges) !Q {
        if (self.interaction.len != 0) return error.InvalidArith256Phase;
        try self.validateMetadata();
        const n = self.size();
        const out = try self.allocator.alloc(M, L.INTERACTION * n);
        errdefer self.allocator.free(out);
        var table: [256]Q = undefined;
        for (&table, 0..) |*t, v| t.* = try ch.bytes.sub(Q.fromBase(M.fromCanonical(@intCast(v)))).inv();
        var bytes_total = Q.zero();
        var wire_total = Q.zero();
        var row: N.Row = undefined;
        for (0..n) |r| {
            const p = R.trace.physical(r, self.log_size);
            nativeRow(&row, self.inputs, &self.counts, r);
            for (0..L.BYTE_BATCHES) |b| {
                for (0..2) |i| {
                    const index = 2 * b + i;
                    if (index < L.BYTE_QUERIES) {
                        const q = L.query(index);
                        bytes_total = bytes_total.add(table[row[q.column] + q.addend]);
                    } else if (index == L.BYTE_QUERIES) {
                        bytes_total = bytes_total.sub(table[r & 0xff].mul(Q.fromBase(M.fromCanonical(row[L.MULT]))));
                    }
                }
                R.trace.store(out, n, p, 4 * b, bytes_total);
            }
            if (r < self.inputs.len) {
                const input = self.inputs[r];
                const result = N.reference(input.a, input.b, input.c, input.m);
                for (0..L.WIRE_FRACTIONS) |w| {
                    const id: u32 = @intCast(w);
                    const inv = try ch.wire.denominator(&externalTuple(self.first_id + @as(u32, @intCast(r)), id, N.wireBytes(input, result, id))).inv();
                    wire_total = if (id == L.OUTPUT_WIRE) wire_total.add(inv) else wire_total.sub(inv);
                    if (w % 2 == 1) R.trace.store(out, n, p, L.WIRE_FIRST + 4 * (w / 2), wire_total);
                }
            } else for (0..L.WIRE_BATCHES) |w| R.trace.store(out, n, p, L.WIRE_FIRST + 4 * w, wire_total);
        }
        if (!bytes_total.isZero()) return error.InvalidArith256ByteCounts;
        // C[r] = S_r - claim: the last cumulative entry is zero and the claim
        // enters once at FIRST, exactly as the transition constraint states.
        for (0..L.WIRE_BATCHES) |w| R.trace.center(out, n, L.WIRE_FIRST + 4 * w, wire_total);
        self.interaction = out;
        return wire_total;
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
