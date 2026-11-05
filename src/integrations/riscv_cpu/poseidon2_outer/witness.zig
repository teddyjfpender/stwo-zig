//! Five-roster MAIN/LogUp witness; all topology and fanouts come from Authority.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Circuit = @import("stwo_circuit_frontend");
const A = @import("authority.zig");
const Context = @import("context.zig").Context;
const L = @import("layout.zig");
const Row = @import("row.zig");
const Old = @import("stwo_circuit_cpu_integration").om31.witness;
const C = Circuit.witness.components;
const M = A.M;
const O = A.O;
const Q = A.Q;
pub const Elements = Old.Elements;
pub const Claims = [5]O;
const LogUp = Engine.air.logup_columns.ForField(O);
fn assignment(ctx: *const Context, key: *const A.Authority, id: u32) !Q {
    if (id < key.original_vars) return ctx.base.get(.{ .idx = id });
    if (id >= key.usage.len) return error.InvalidPoseidonAssignmentAddress;
    return if (id < key.original_vars + key.rows[1] - key.raw[1]) Q.fromU32Unchecked(2, 0, 0, 0) else Q.zero();
}
pub fn main(a: std.mem.Allocator, ctx: *const Context, key: *const A.Authority) !A.Columns {
    if (ctx.base.trace_only or !ctx.finalized or ctx.poisoned or ctx.base.circuit.n_vars != key.original_vars) return error.InvalidPoseidonAssignment;
    var out = try A.Columns.init(a, .main, key.logs);
    errdefer out.deinit();
    for (0..key.rows[0]) |r| {
        const value = try assignment(ctx, key, key.fixed.values[0].values[r].v);
        for (value.toM31Array(), 0..) |v, j| out.put(A.MAIN_START[0] + j, r, v);
    }
    for (0..key.rows[1]) |r| {
        inline for (0..3) |i| {
            const value = try assignment(ctx, key, key.fixed.values[6 + i].values[r].v);
            for (value.toM31Array(), 0..) |v, j| out.put(A.MAIN_START[1] + 4 * i + j, r, v);
        }
    }
    for (0..key.rows[2]) |r| {
        const value = (try assignment(ctx, key, key.fixed.values[10].values[r].v)).toM31Array();
        for (value[1..]) |v| if (!v.isZero()) return error.PoseidonInputNotM31;
        var row: [4]M = undefined;
        C.m31_to_u32.row(value[0], &row);
        for (row, 0..) |v, j| out.put(A.MAIN_START[2] + j, r, v);
        for ([_]u32{ row[1].v, row[2].v, 32767 - row[2].v }) |v| {
            if (v >= 65536) return error.PoseidonRangeOutsideTable;
            const old = out.values[A.MAIN_START[4]].values[v].v;
            if (old + 1 >= Core.fields.m31.Modulus) return error.PoseidonCharacteristicBound;
            out.put(A.MAIN_START[4], v, M.fromCanonical(old + 1));
        }
    }
    for (0..key.rows[3]) |r| {
        var input: [24]M = @splat(M.zero());
        if (r < key.raw[3]) for (&input, 0..) |*v, j| {
            const value = (try assignment(ctx, key, key.fixed.values[13 + L.INPUT_ID + j].values[r].v)).toM31Array();
            for (value[1..]) |coordinate| if (!coordinate.isZero()) return error.PoseidonInputNotM31;
            v.* = value[0];
        };
        const row = try Row.fill(input);
        if (r < key.raw[3]) for (0..24) |j| {
            const value = try assignment(ctx, key, key.fixed.values[13 + L.OUTPUT_ID + j].values[r].v);
            if (!value.eql(Q.fromBase(row[L.OUTPUT + j]))) return error.InvalidPoseidonPermutationAssignment;
        };
        for (row, 0..) |v, j| out.put(A.MAIN_START[3] + j, r, v);
    }
    return out;
}
fn read(comptime n: usize, columns: []const A.Col, begin: usize, r: usize) [n]M {
    var out: [n]M = undefined;
    for (&out, columns[begin..][0..n]) |*v, column| v.* = column.values[r];
    return out;
}
pub const Raw = struct {
    key: *const A.Authority,
    main: []const A.Col,
    pub fn fill(self: *const Raw, kind: usize, r: usize, storage: *[48]C.Lookup) ![]const C.Lookup {
        const k = self.key;
        switch (kind) {
            0 => {
                storage[0..2].* = C.eq.lookups(&read(4, self.main, A.MAIN_START[0], r), .{ .in0 = k.fixed.values[0].values[r], .in1 = k.fixed.values[1].values[r] });
                return storage[0..2];
            },
            1 => {
                storage[0..3].* = C.qm31_ops.lookups(&read(12, self.main, A.MAIN_START[1], r), .{ .in0 = k.fixed.values[6].values[r], .in1 = k.fixed.values[7].values[r], .out = k.fixed.values[8].values[r], .mults = k.fixed.values[9].values[r] });
                return storage[0..3];
            },
            2 => {
                storage[0..5].* = C.m31_to_u32.lookups(&read(4, self.main, A.MAIN_START[2], r), .{ .input = k.fixed.values[10].values[r], .output = k.fixed.values[11].values[r], .mults = k.fixed.values[12].values[r] });
                return storage[0..5];
            },
            3 => {
                const ports = Row.portsFor(M, &read(L.MAIN_COLUMNS, self.main, A.MAIN_START[3], r), &read(L.FIXED_COLUMNS, k.fixed.values, A.FIXED_START[3], r));
                for (ports, storage) |port, *out| out.* = .{ .numerator = port.numerator, .tuple = port.tuple, .len = 6 };
                return storage;
            },
            4 => {
                storage[0] = .{ .numerator = self.main[A.MAIN_START[4]].values[r].neg(), .tuple = .{ M.fromCanonical(Circuit.common.component_list.RANGE_CHECK_16_RELATION_ID), k.fixed.values[86].values[r], M.zero(), M.zero(), M.zero(), M.zero() }, .len = 2 };
                return storage[0..1];
            },
            else => return error.InvalidPoseidonComponent,
        }
    }
};
pub const Interaction = struct {
    allocator: std.mem.Allocator,
    columns: []A.Col,
    claims: Claims,
    pub fn deinit(self: *Interaction) void {
        Circuit.witness.trace.freeColumns(self.allocator, self.columns);
        self.* = undefined;
    }
};
const Fractions = struct {
    raw: *const Raw,
    kind: usize,
    elements: *const Elements,
    fn fill(self: @This(), r: usize, out: []LogUp.Fraction) !void {
        var storage: [48]C.Lookup = undefined;
        try Old.pairFractions(self.elements, try self.raw.fill(self.kind, r, &storage), out);
    }
};
pub fn closure(outputs: []const Q, claims: Claims, elements: *const Elements) !O {
    var sum = O.zero();
    for (claims) |claim| sum = sum.add(claim);
    for (outputs, 0..) |value, i| sum = sum.add(try Old.outputTerm(elements, 3 + i, value));
    return sum.add(try Old.outputTerm(elements, 2, Circuit.witness.trace.U_VALUE));
}
pub fn interaction(a: std.mem.Allocator, key: *const A.Authority, main_columns: []const A.Col, outputs: []const Q, elements: *const Elements) !Interaction {
    if (outputs.len != key.n_outputs) return error.InvalidPoseidonOutputCount;
    const raw = Raw{ .key = key, .main = main_columns };
    var blocks: [5]?LogUp.Output = @splat(null);
    defer for (blocks) |maybe| if (maybe) |block| Circuit.witness.trace.freeColumns(a, block.columns);
    var claims: Claims = undefined;
    for (0..5) |kind| {
        const block = try LogUp.build(a, key.logs[kind], L.FACTS[kind].classic_interaction / 8, Fractions{ .raw = &raw, .kind = kind, .elements = elements }, Fractions.fill);
        blocks[kind] = block;
        claims[kind] = block.claimed_sum;
    }
    if (!(try closure(outputs, claims, elements)).isZero()) return error.PoseidonGlobalLookupSum;
    const columns = try a.alloc(A.Col, A.INTER_COUNT);
    var at: usize = 0;
    for (&blocks) |*maybe| {
        const block = maybe.*.?;
        @memcpy(columns[at..][0..block.columns.len], block.columns);
        at += block.columns.len;
        a.free(block.columns);
        maybe.* = null;
    }
    return .{ .allocator = a, .columns = columns, .claims = claims };
}
