//! R7 owned MAIN and seven shared-Var interaction blocks. First five rows use
//! unchanged arithmetic/P2 authorities; no legacy finalized flag is forged.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Circuit = @import("stwo_circuit_frontend");
const A = @import("../authority.zig");
const Context = @import("../context.zig").Context;
const L = @import("../layout.zig");
const Row = @import("../row.zig");
const D = @import("row.zig");
const MulRow = @import("../native_omul/row.zig");
const K = @import("outer_authority.zig");
const Old = @import("stwo_circuit_cpu_integration").om31.witness;
const C = Circuit.witness.components;
const Lookup = C.Lookup;
const Base = @import("../witness.zig");
const M = A.M;
const O = A.O;
const Q = A.Q;
const LogUp = Engine.air.logup_columns.ForField(O);
pub const Elements = Base.Elements;
pub const Claims = [7]O;
fn assignment(ctx: *const Context, key: *const A.Authority, id: u32) !Q {
    if (id < key.original_vars) return ctx.base.get(.{ .idx = id });
    if (id >= key.usage.len) return error.InvalidPoseidonAssignmentAddress;
    return if (id < key.original_vars + key.rows[1] - key.raw[1]) Q.fromU32Unchecked(2, 0, 0, 0) else Q.zero();
}
pub fn main(a: std.mem.Allocator, ctx: *const Context, key: *const K.Key) !A.Columns {
    const source = &key.core.base;
    if (ctx.base.trace_only or !ctx.native_dot_finalized or ctx.finalized or ctx.poisoned or ctx.base.circuit.n_vars != source.original_vars) return error.InvalidPoseidonAssignment;
    var out = try K.columns(a, 1, source.logs, key.core.mul_log, key.dot_log);
    errdefer out.deinit();
    for (0..source.rows[0]) |r| {
        const value = try assignment(ctx, source, source.fixed.values[0].values[r].v);
        for (value.toM31Array(), 0..) |v, j| out.put(A.MAIN_START[0] + j, r, v);
    }
    for (0..source.rows[1]) |r| {
        inline for (0..3) |i| {
            const value = try assignment(ctx, source, source.fixed.values[6 + i].values[r].v);
            for (value.toM31Array(), 0..) |v, j| out.put(A.MAIN_START[1] + 4 * i + j, r, v);
        }
    }
    for (0..source.rows[2]) |r| {
        const value = (try assignment(ctx, source, source.fixed.values[10].values[r].v)).toM31Array();
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
    for (0..source.rows[3]) |r| {
        var input: [24]M = @splat(M.zero());
        if (r < source.raw[3]) for (&input, 0..) |*v, j| {
            const value = (try assignment(ctx, source, source.fixed.values[13 + L.INPUT_ID + j].values[r].v)).toM31Array();
            for (value[1..]) |coordinate| if (!coordinate.isZero()) return error.PoseidonInputNotM31;
            v.* = value[0];
        };
        const row = try Row.fill(input);
        if (r < source.raw[3]) for (0..24) |j| {
            const value = try assignment(ctx, source, source.fixed.values[13 + L.OUTPUT_ID + j].values[r].v);
            if (!value.eql(Q.fromBase(row[L.OUTPUT + j]))) return error.InvalidPoseidonPermutationAssignment;
        };
        for (row, 0..) |v, j| out.put(A.MAIN_START[3] + j, r, v);
    }
    for (ctx.native_mul_calls.items, 0..) |gate, r| {
        const ids = [6]u32{ gate.inputs[0], gate.inputs[1], gate.inputs[2], gate.inputs[3], gate.outputs[0], gate.outputs[1] };
        for (ids, 0..) |id, i| for (ctx.base.get(.{ .idx = id }).toM31Array(), 0..) |value, j| out.put(K.MUL_MAIN_START + 4 * i + j, r, value);
    }
    var prior = O.zero();
    for (0..key.dot_raw) |logical| {
        const r = K.physical(logical, key.dot_log);
        var fixed: [D.FIXED]M = undefined;
        for (&fixed, source.fixed.values[K.FIXED_START..][0..D.FIXED]) |*v, col| v.* = col.values[r];
        const scalar = ctx.base.get(.{ .idx = fixed[2].v }).toM31Array();
        for (scalar[1..]) |v| if (!v.isZero()) return error.NativeDotScalarNotBase;
        const weight = O{ .c0 = ctx.base.get(.{ .idx = fixed[0].v }), .c1 = ctx.base.get(.{ .idx = fixed[1].v }) };
        const row = D.fill(weight, scalar[0], prior, !fixed[D.FIRST].isZero());
        const result = O.fromM31Array(row[D.ACC..][0..8].*);
        if (!fixed[D.LAST].isZero()) for (0..2) |i| {
            const value = ctx.base.get(.{ .idx = fixed[D.OUTPUT_IDS + i].v });
            if (!value.eql(if (i == 0) result.c0 else result.c1)) return error.NativeDotOutputMismatch;
        };
        for (row, 0..) |v, col| out.put(K.MAIN_START + col, r, v);
        prior = result;
    }
    return out;
}
const Fractions = struct {
    raw: *const Base.Raw,
    key: *const K.Key,
    kind: usize,
    elements: *const Elements,
    fn fill(self: @This(), r: usize, out: []LogUp.Fraction) !void {
        var storage: [48]Lookup = undefined;
        if (self.kind < 5) return Old.pairFractions(self.elements, try self.raw.fill(self.kind, r, &storage), out);
        if (self.kind == 6) {
            var main_values: [D.MAIN]M = undefined;
            var fixed: [D.FIXED]M = undefined;
            for (&main_values, self.raw.main[K.MAIN_START..][0..D.MAIN]) |*value, column| value.* = column.values[r];
            for (&fixed, self.key.core.base.fixed.values[K.FIXED_START..][0..D.FIXED]) |*value, column| value.* = column.values[r];
            for (D.portsFor(M, &main_values, &fixed), storage[0..6]) |port, *lookup| lookup.* = .{ .numerator = port.numerator, .tuple = port.tuple, .len = 6 };
            return Old.pairFractions(self.elements, storage[0..6], out);
        }
        var main_values: [MulRow.MAIN]M = undefined;
        var fixed: [MulRow.FIXED]M = undefined;
        for (&main_values, self.raw.main[K.MUL_MAIN_START..][0..MulRow.MAIN]) |*value, column| value.* = column.values[r];
        for (&fixed, self.key.core.base.fixed.values[K.MUL_FIXED_START..][0..MulRow.FIXED]) |*value, column| value.* = column.values[r];
        for (MulRow.portsFor(M, &main_values, &fixed), storage[0..6]) |port, *lookup| lookup.* = .{ .numerator = port.numerator, .tuple = port.tuple, .len = 6 };
        return Old.pairFractions(self.elements, storage[0..6], out);
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
pub fn closure(outputs: []const Q, claims: Claims, elements: *const Elements) !O {
    var sum = O.zero();
    for (claims) |claim| sum = sum.add(claim);
    for (outputs, 0..) |value, i| sum = sum.add(try Old.outputTerm(elements, 3 + i, value));
    return sum.add(try Old.outputTerm(elements, 2, Circuit.witness.trace.U_VALUE));
}
pub fn interaction(a: std.mem.Allocator, key: *const K.Key, main_columns: []const A.Col, outputs: []const Q, elements: *const Elements) !Interaction {
    if (outputs.len != key.core.base.n_outputs) return error.InvalidPoseidonOutputCount;
    const raw = Base.Raw{ .key = &key.core.base, .main = main_columns };
    var blocks: [7]?LogUp.Output = @splat(null);
    defer for (blocks) |block| if (block) |value| Circuit.witness.trace.freeColumns(a, value.columns);
    var claims: Claims = undefined;
    for (0..7) |kind| {
        const width: usize = if (kind < 5) L.FACTS[kind].classic_interaction / 8 else if (kind == 5) MulRow.INTER / 8 else D.INTER / 8;
        const block = try LogUp.build(a, if (kind < 5) key.core.base.logs[kind] else if (kind == 5) key.core.mul_log else key.dot_log, width, Fractions{ .raw = &raw, .key = key, .kind = kind, .elements = elements }, Fractions.fill);
        blocks[kind] = block;
        claims[kind] = block.claimed_sum;
    }
    if (!(try closure(outputs, claims, elements)).isZero()) return error.PoseidonGlobalLookupSum;
    const columns = try a.alloc(A.Col, K.INTER_COUNT);
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
