//! Dedicated degree-three width24 Poseidon2 row. Every physical row is a
//! valid permutation, including disabled padding; FIXED alone disables ports.
const std = @import("std");
const Core = @import("stwo_core");
const P = Core.crypto.poseidon2_m31_w24;
const L = @import("layout.zig");
const M = Core.fields.m31.M31;
const Q = Core.fields.qm31.QM31;
const O = Core.fields.om31.OM31;
pub fn lift(comptime F: type, value: M) F {
    return if (F == M) value else F.fromBase(value);
}
fn Ops(comptime F: type) type {
    return struct {
        pub fn constant(_: @This(), value: u32) error{}!F {
            return lift(F, M.fromCanonical(value));
        }
        pub fn add(_: @This(), a: F, b: F) error{}!F {
            return a.add(b);
        }
        pub fn sub(_: @This(), a: F, b: F) error{}!F {
            return a.sub(b);
        }
        pub fn mul(_: @This(), a: F, b: F) error{}!F {
            return a.mul(b);
        }
    };
}
/// Same pinned linear layers and round constants as native. Only the S-box
/// materialization is replaced: x2 and x5, with x5-x*x2*x2 degree three.
fn walk(comptime F: type, state: *[24]F, boxes: anytype) !void {
    const ops = Ops(F){};
    try P.externalFor(F, ops, state);
    for (P.parameters.EXTERNAL_INITIAL) |round| {
        for (state, round) |*value, constant| value.* = boxes.sbox(try ops.add(value.*, try ops.constant(constant)));
        try P.externalFor(F, ops, state);
    }
    for (P.parameters.INTERNAL) |constant| {
        state[0] = boxes.sbox(try ops.add(state[0], try ops.constant(constant)));
        try P.internalFor(F, ops, state);
    }
    for (P.parameters.EXTERNAL_FINAL) |round| {
        for (state, round) |*value, constant| value.* = boxes.sbox(try ops.add(value.*, try ops.constant(constant)));
        try P.externalFor(F, ops, state);
    }
}
const Fill = struct {
    row: *L.Row,
    cursor: usize = L.TEMPORARY,
    pub fn sbox(self: *@This(), x: M) M {
        const square = x.mul(x);
        const fifth = x.mul(square.mul(square));
        self.row[self.cursor] = square;
        self.row[self.cursor + 1] = fifth;
        self.cursor += 2;
        return fifth;
    }
};
pub fn fill(input: [24]M) !L.Row {
    var row: L.Row = undefined;
    row[L.INPUT..][0..24].* = input;
    var state = input;
    var boxes = Fill{ .row = &row };
    try walk(M, &state, &boxes);
    std.debug.assert(boxes.cursor == L.OUTPUT);
    row[L.OUTPUT..][0..24].* = state;
    return row;
}
pub fn paddingRow() L.Row {
    return fill(@splat(M.zero())) catch unreachable;
}
fn Evaluate(comptime F: type) type {
    return struct {
        row: *const [L.MAIN_COLUMNS]F,
        roots: *[L.CONSTRAINTS]F,
        cursor: usize = L.TEMPORARY,
        next: usize = 0,
        pub fn sbox(self: *@This(), x: F) F {
            const square = self.row[self.cursor];
            const fifth = self.row[self.cursor + 1];
            self.roots[self.next] = square.sub(x.mul(x));
            self.roots[self.next + 1] = fifth.sub(x.mul(square.mul(square)));
            self.cursor += 2;
            self.next += 2;
            return fifth;
        }
    };
}
pub fn evaluateFor(comptime F: type, row: *const [L.MAIN_COLUMNS]F) ![L.CONSTRAINTS]F {
    var roots: [L.CONSTRAINTS]F = undefined;
    var state = row[L.INPUT..][0..24].*;
    var boxes = Evaluate(F){ .row = row, .roots = &roots };
    try walk(F, &state, &boxes);
    std.debug.assert(boxes.cursor == L.OUTPUT and boxes.next == 2 * L.SBOXES);
    for (state, row[L.OUTPUT..][0..24], 0..) |value, output, i| roots[boxes.next + i] = value.sub(output);
    return roots;
}
pub const GATE_RELATION_ID = @import("stwo_circuit_frontend").common.component_list.GATE_RELATION_ID;
pub fn PortFor(comptime F: type) type {
    return struct { numerator: F, tuple: [6]F };
}
/// FIXED is receiver/source-owned. Variable IDs and fanout are not MAIN
/// columns. Four-coordinate tuples force every admitted port into base M31.
pub fn portsFor(comptime F: type, row: *const [L.MAIN_COLUMNS]F, fixed: *const [L.FIXED_COLUMNS]F) [L.PORTS]PortFor(F) {
    var out: [L.PORTS]PortFor(F) = undefined;
    const zero = lift(F, M.zero());
    const tag = lift(F, M.fromCanonical(GATE_RELATION_ID));
    for (0..24) |i| {
        out[i] = .{ .numerator = fixed[L.ENABLED], .tuple = .{ tag, fixed[L.INPUT_ID + i], row[L.INPUT + i], zero, zero, zero } };
        out[24 + i] = .{ .numerator = zero.sub(fixed[L.OUTPUT_USES + i]), .tuple = .{ tag, fixed[L.OUTPUT_ID + i], row[L.OUTPUT + i], zero, zero, zero } };
    }
    return out;
}
pub fn sourceIdentity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/rv64/poseidon2-outer/w24/degree3-x2-x5/ports/v1\x00");
    hash.update(&P.parameterIdentity());
    hash.update(@embedFile("layout.zig"));
    hash.update(@embedFile("row.zig"));
    return hash.finalResult();
}
fn allZero(comptime F: type, values: []const F) bool {
    for (values) |v| if (!v.isZero()) return false;
    return true;
}
test "dedicated Poseidon row matches pinned native and rejects input x2 x5 and output mutants even with disabled ports" {
    for (0..4) |case| {
        var input: [24]M = undefined;
        for (&input, 0..) |*value, i| value.* = M.fromCanonical(@intCast(if (case == 0) 0 else if (case == 1) i else if (case == 2) 2147483646 else i * 137 + 41));
        const row = try fill(input);
        var expected = input;
        P.permute(&expected);
        try std.testing.expectEqualSlices(M, &expected, row[L.OUTPUT..][0..24]);
        try std.testing.expect(allZero(M, &try evaluateFor(M, &row)));
        for ([_]usize{ L.INPUT + 7, L.TEMPORARY + 11, L.TEMPORARY + 12, L.OUTPUT + 17 }) |index| {
            var bad = row;
            bad[index] = bad[index].add(M.one());
            try std.testing.expect(!allZero(M, &try evaluateFor(M, &bad)));
            const ports = portsFor(M, &bad, &L.paddingFixed());
            for (ports) |port| try std.testing.expect(port.numerator.isZero());
        }
    }
    const pad = paddingRow();
    try std.testing.expect(allZero(M, &try evaluateFor(M, &pad)));
}
test "dedicated Poseidon AIR native OM31 equals circuit lane and rejects each temporary family" {
    const Lane = @import("../rv64_recursion/om31_circuit_lane.zig");
    const a = std.testing.allocator;
    const row = try fill(@splat(M.fromCanonical(17)));
    for ([_]usize{ L.MAIN_COLUMNS, L.TEMPORARY, L.TEMPORARY + 1, L.OUTPUT + 3 }) |bad_index| {
        var native: [L.MAIN_COLUMNS]O = undefined;
        for (&native, row, 0..) |*value, m, i| value.* = O.fromBase(if (i == bad_index) m.add(M.one()) else m);
        const expected = try evaluateFor(O, &native);
        var ctx = try Lane.Context.init(a, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        Lane.begin(&ctx);
        var open = true;
        defer if (open) Lane.finish() catch {};
        var wires: [L.MAIN_COLUMNS]Lane.Lane = undefined;
        for (&wires, native) |*wire, value| wire.* = try Lane.Lane.guess(&ctx, value);
        const roots = try evaluateFor(Lane.Lane, &wires);
        for (roots, expected) |root, value| {
            try std.testing.expect(root.value().eql(value));
            try ctx.eq(root.c0.v, ctx.zero());
            try ctx.eq(root.c1.v, ctx.zero());
        }
        open = false;
        try Lane.finish();
        try ctx.finalize(false);
        try std.testing.expectEqual(bad_index == L.MAIN_COLUMNS, try ctx.isCircuitValid());
    }
}
