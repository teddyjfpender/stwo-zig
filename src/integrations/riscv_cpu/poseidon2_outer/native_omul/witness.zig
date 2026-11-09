//! R6 six-component witness; original five row generators remain authorities.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Circuit = @import("stwo_circuit_frontend");
const A = @import("../authority.zig");
const L = @import("../layout.zig");
const Context = @import("../context.zig").Context;
const Base = @import("../witness.zig");
const Old = @import("stwo_circuit_cpu_integration").om31.witness;
const K = @import("authority.zig");
const Row = @import("row.zig");
const M = A.M;
const O = A.O;
const Q = A.Q;
const Lookup = Circuit.witness.components.Lookup;
const LogUp = Engine.air.logup_columns.ForField(O);
pub const Elements = Base.Elements;
pub const Claims = [6]O;
pub fn main(a: std.mem.Allocator, ctx: *const Context, key: *const K.Key) !A.Columns {
    var core = try Base.main(a, ctx, &key.base);
    defer core.deinit();
    const values = try a.alloc(A.Col, K.MAIN_COUNT);
    var made: usize = 0;
    errdefer {
        for (values[0..made]) |column| a.free(column.values);
        a.free(values);
    }
    @memcpy(values[0..A.MAIN_COUNT], core.values);
    made = A.MAIN_COUNT;
    a.free(core.values);
    core.values = &.{};
    for (values[A.MAIN_COUNT..]) |*column| {
        const v = try a.alloc(M, key.mul_rows);
        @memset(v, M.zero());
        column.* = .{ .log_size = key.mul_log, .values = v };
        made += 1;
    }
    for (ctx.native_mul_calls.items, 0..) |gate, r| {
        const ids = [6]u32{ gate.inputs[0], gate.inputs[1], gate.inputs[2], gate.inputs[3], gate.outputs[0], gate.outputs[1] };
        for (ids, 0..) |id, i| {
            for (ctx.base.get(.{ .idx = id }).toM31Array(), 0..) |value, j| @constCast(values[K.MAIN_START + 4 * i + j].values)[r] = value;
        }
    }
    return .{ .allocator = a, .values = values };
}
const Fractions = struct {
    raw: *const Base.Raw,
    key: *const K.Key,
    kind: usize,
    elements: *const Elements,
    fn fill(self: @This(), r: usize, out: []LogUp.Fraction) !void {
        var storage: [48]Lookup = undefined;
        if (self.kind < 5) return Old.pairFractions(self.elements, try self.raw.fill(self.kind, r, &storage), out);
        var main_values: [Row.MAIN]M = undefined;
        var fixed: [Row.FIXED]M = undefined;
        for (&main_values, self.raw.main[K.MAIN_START..][0..Row.MAIN]) |*value, column| value.* = column.values[r];
        for (&fixed, self.key.base.fixed.values[K.FIXED_START..][0..Row.FIXED]) |*value, column| value.* = column.values[r];
        for (Row.portsFor(M, &main_values, &fixed), storage[0..6]) |port, *lookup| lookup.* = .{ .numerator = port.numerator, .tuple = port.tuple, .len = 6 };
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
    if (outputs.len != key.base.n_outputs) return error.InvalidPoseidonOutputCount;
    const raw = Base.Raw{ .key = &key.base, .main = main_columns };
    var blocks: [6]?LogUp.Output = @splat(null);
    defer for (blocks) |block| if (block) |value| Circuit.witness.trace.freeColumns(a, value.columns);
    var claims: Claims = undefined;
    for (0..6) |kind| {
        const width = if (kind < 5) L.FACTS[kind].classic_interaction / 8 else Row.INTER / 8;
        const block = try LogUp.build(a, if (kind < 5) key.base.logs[kind] else key.mul_log, width, Fractions{ .raw = &raw, .key = key, .kind = kind, .elements = elements }, Fractions.fill);
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
