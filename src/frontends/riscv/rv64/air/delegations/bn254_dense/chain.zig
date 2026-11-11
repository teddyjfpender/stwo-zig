//! Closed square(A)->temporary; multiply(temporary,B)->public output program.
//! The immutable ROM owns every ID and fanout. Arithmetic rows acquire input
//! byte authority only from this local SSA relation, never public equality.
//! This module is a source/witness foundation, not production admission.
const std = @import("std");
const core = @import("stwo_core");
const S = @import("spec.zig");
const R = @import("row.zig");
const A = @import("air.zig");
const E = @import("../../evaluation.zig");
pub const Q = core.fields.om31.OM31;
pub const M = core.fields.m31.M31;
pub const Wire = @import("../curves/equations.zig").WireFor(Q);
pub const KIND: u32 = 0x44535341;
pub const INITIAL_MAIN = 33;
pub const INITIAL_FIXED = 34; // active, immutable value ID, 32 pinned public bytes
pub const INITIAL_LOG = 5;
pub const SQUARE_LOG = 8;
pub const MULTIPLY_LOG = 9;
pub const TABLE_LOG = 8;
pub const Role = enum { initial, square, multiply };
pub const INITIAL_VALUES = 24;
pub const MAX_ID = 35;
pub const SSA_POSITIVE_MASS = 432;
pub const SSA_NEGATIVE_MASS = 432;
pub fn sourceDigest() [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(@embedFile("chain.zig"), &digest, .{});
    return digest;
}
pub fn lanes(role: Role) usize {
    return switch (role) {
        .initial => 1,
        .square => 16,
        .multiply => 32,
    };
}
pub fn rowLog(role: Role) u32 {
    return switch (role) {
        .initial => INITIAL_LOG,
        .square => SQUARE_LOG,
        .multiply => MULTIPLY_LOG,
    };
}
pub fn terms(role: Role) usize {
    return switch (role) {
        .initial => 1,
        .square => 13,
        .multiply => 24,
    };
}
/// No IDs, weights, operation choices or table selectors are witness columns.
pub const Edge = struct { id: u32, weight: i32, input: ?usize };
pub fn edge(role: Role, coordinate: usize, lane: usize) ?Edge {
    std.debug.assert(coordinate < if (role == .initial) @as(usize, 32) else 12);
    if (lane >= terms(role)) return null;
    return switch (role) {
        .initial => if (coordinate < 24) .{ .id = @intCast(coordinate), .weight = 12, .input = null } else null,
        .square => if (lane < 12) .{ .id = @intCast(lane), .weight = -1, .input = lane } else .{ .id = @intCast(24 + coordinate), .weight = 12, .input = null },
        .multiply => .{ .id = @intCast(if (lane < 12) 24 + lane else lane), .weight = -1, .input = lane },
    };
}
fn k(comptime F: type, x: u32) F {
    return E.qFor(F, x);
}
/// Full typed 35-coordinate tuple (family, call ID, SSA value ID, 32 bytes).
/// The common request ID is pinned to one in this closed two-operation class.
pub fn denominator(comptime F: type, value_id: F, bytes: [32]F, wire: Wire) E.SecureFor(F) {
    var tuple: [35]F = undefined;
    tuple[0] = k(F, KIND);
    tuple[1] = F.one();
    tuple[2] = value_id;
    @memcpy(tuple[3..], &bytes);
    return E.denominatorFor(F, wire.offset, &wire.coefficients, &tuple, true);
}
/// Committed row expression for all local SSA terminals, including the initial
/// producer. Immutable IDs are FIXED/ROM expressions; source masks include them.
pub fn fraction(comptime role: Role, comptime F: type, v: anytype, wire: Wire, lane: usize) struct { F, E.SecureFor(F) } {
    if (lane >= terms(role)) return .{ F.zero(), E.SecureFor(F).one() };
    var bytes: [32]F = undefined;
    var id: F = undefined;
    var weight: F = undefined;
    if (role == .initial) {
        id = v.fixed(1);
        weight = v.main(0).mul(k(F, 12));
        for (&bytes, 0..) |*b, i| b.* = v.main(1 + i);
    } else {
        const kind: S.Kind = if (role == .square) .square else .multiply;
        const L = R.Layout(kind);
        if (lane < S.inputs(kind)) {
            id = k(F, @intCast(if (role == .square) lane else if (lane < 12) 24 + lane else lane));
            weight = v.main(0).neg();
            for (&bytes, 0..) |*b, i| b.* = v.main(L.INPUT + 32 * lane + i);
        } else {
            id = F.zero();
            inline for (0..12) |i| id = id.add(v.fixed(i).mul(k(F, 24 + i)));
            weight = v.main(0).mul(k(F, 12));
            for (&bytes, 0..) |*b, i| b.* = v.main(L.OUTPUT + i);
        }
    }
    return .{ weight, denominator(F, id, bytes, wire) };
}
/// The only public input equalities live here, outside arithmetic rows.
pub fn emitInitial(comptime F: type, v: anytype, sink: *E.SinkFor(F)) void {
    sink.emit(v.main(0).sub(v.fixed(0)));
    for (0..32) |byte| sink.emit(v.main(1 + byte).sub(v.fixed(2 + byte)));
}
pub const Witness = struct {
    initial: [32][INITIAL_MAIN]u32,
    square: [12]R.Layout(.square).Row,
    multiply: [12]R.Layout(.multiply).Row,
    table: [256]u32,
    public: [24]u256,
    output: [12]u256,
    pub fn init(a: [12]u256, b: [12]u256) Witness {
        var self: Witness = undefined;
        @memcpy(self.public[0..12], &a);
        @memcpy(self.public[12..], &b);
        self.initial = @splat(@splat(0));
        for (self.public, 0..) |value, i| {
            self.initial[i][0] = 1;
            for (0..32) |byte| self.initial[i][1 + byte] = S.B.limbOf(value, byte);
        }
        var mul_input: [24]u256 = undefined;
        inline for (0..12) |coordinate| {
            self.square[coordinate] = R.Layout(.square).fill(coordinate, &a);
            mul_input[coordinate] = R.Layout(.square).output(coordinate, &a);
        }
        @memcpy(mul_input[12..], &b);
        inline for (0..12) |coordinate| {
            self.multiply[coordinate] = R.Layout(.multiply).fill(coordinate, &mul_input);
            self.output[coordinate] = R.Layout(.multiply).output(coordinate, &mul_input);
        }
        self.recount();
        return self;
    }
    pub const View = struct {
        w: *const Witness,
        role: Role,
        row: usize,
        pub fn main(v: *const @This(), c: usize) Q {
            if (v.row >= (if (v.role == .initial) @as(usize, 32) else 12)) return Q.zero();
            const x = switch (v.role) {
                .initial => v.w.initial[v.row][c],
                .square => v.w.square[v.row][c],
                .multiply => v.w.multiply[v.row][c],
            };
            return Q.fromBase(M.fromCanonical(x));
        }
        pub fn fixed(v: *const @This(), c: usize) Q {
            const x: u32 = if (v.role == .initial) (if (c == 0) @intFromBool(v.row < 24) else if (c == 1) @intCast(v.row) else if (v.row < 24) S.B.limbOf(v.w.public[v.row], c - 2) else 0) else if (c < 12) @intFromBool(c == v.row % 12) else if (c == A.FIX_ACTIVE) @intFromBool(v.row < 12) else @intCast(v.row % 256);
            return Q.fromBase(M.fromCanonical(x));
        }
        pub fn selector(v: *const @This(), c: usize) Q {
            return Q.fromBase(M.fromCanonical(@intFromBool(v.row == c)));
        }
    };
    pub fn view(self: *const Witness, role: Role, row_index: usize) View {
        return .{ .w = self, .role = role, .row = row_index };
    }
    pub fn recount(self: *Witness) void {
        self.table = @splat(0);
        inline for (.{ Role.square, Role.multiply }) |role| for (0..12) |r| {
            const kind: S.Kind = if (role == .square) .square else .multiply;
            const v = self.view(role, r);
            for (0..R.Layout(kind).BYTE_QUERIES) |i| {
                const x = A.query(kind, Q, &v, i).toM31Array();
                std.debug.assert(x[0].v < 256);
                for (x[1..]) |top| std.debug.assert(top.v == 0);
                self.table[x[0].v] += 1;
            }
        };
    }
    pub fn ssaSum(self: *const Witness, wire: Wire) !Q {
        var sum = Q.zero();
        inline for (.{ Role.initial, Role.square, Role.multiply }) |role| {
            for (0..if (role == .initial) @as(usize, 32) else 12) |r| {
                const v = self.view(role, r);
                for (0..lanes(role)) |lane| {
                    const f = fraction(role, Q, &v, wire, lane);
                    sum = sum.add(f[0].mul(try f[1].inv()));
                }
            }
        }
        return sum;
    }
    pub fn byteSum(self: *const Witness, beta: Q) !Q {
        var sum = Q.zero();
        inline for (.{ Role.square, Role.multiply }) |role| for (0..12) |r| {
            const kind: S.Kind = if (role == .square) .square else .multiply;
            const v = self.view(role, r);
            for (0..R.Layout(kind).BYTE_QUERIES) |i| sum = sum.add(try beta.sub(A.query(kind, Q, &v, i)).inv());
        };
        for (self.table, 0..) |count, value| sum = sum.sub(Q.fromBase(M.fromCanonical(count)).mul(try beta.sub(Q.fromBase(M.fromCanonical(@intCast(value)))).inv()));
        return sum;
    }
};
