//! Conditional z-specific physical fixture authority. Source programs/constants
//! are immutable; production must bind variable z to the real Miller writer.
const std = @import("std");
const core = @import("stwo_core");
const S = @import("spec.zig");
const P = @import("physical_spec.zig");
const PW = @import("physical_witness.zig");
const W = @import("witness.zig");
const DA = @import("../bn254_dense/air.zig");
const H = @import("../bn254_hint/source.zig");
const E = @import("../../evaluation.zig");
pub const Q = core.fields.om31.OM31;
pub const M = core.fields.m31.M31;
pub const Wire = @import("../curves/equations.zig").WireFor(Q);
pub const Role = enum { frontier, square, multiply, hint, table };
pub const KIND: u32 = 0x52534445;
pub const FANOUT = blk: {
    @setEvalBranchQuota(100_000);
    break :blk S.fanout(&W.ROM);
};
pub fn kind(comptime role: Role) P.Kind {
    return if (role == .square) .square else .multiply;
}
pub fn logSize(role: Role) u32 {
    return switch (role) {
        .square => 10,
        .multiply => 9,
        .hint => 5,
        .frontier => 6,
        .table => 8,
    };
}
pub fn mainWidth(comptime role: Role) usize {
    return switch (role) {
        .square, .multiply => PW.Layout(kind(role)).MAIN,
        .hint => H.MAIN,
        .frontier => 33,
        .table => 1,
    };
}
pub fn readIdStart(comptime role: Role) usize {
    return P.rows(kind(role)) + 2;
}
pub fn writerIdColumn(comptime role: Role) usize {
    return readIdStart(role) + P.inputs(kind(role));
}
pub fn writerWeightColumn(comptime role: Role) usize {
    return writerIdColumn(role) + 1;
}
pub fn goalColumn() usize {
    return writerWeightColumn(.multiply) + 1;
}
pub fn goalByteColumn() usize {
    return goalColumn() + 1;
}
pub fn fixedWidth(comptime role: Role) usize {
    return switch (role) {
        .square => writerWeightColumn(role) + 1,
        .multiply => goalByteColumn() + 1,
        .hint => H.FIXED,
        .frontier => 35,
        .table => 1,
    };
}
fn k(comptime F: type, n: u32) F {
    return E.qFor(F, n);
}
fn readMask(comptime role: Role, comptime F: type, v: anytype, lane: usize) F {
    if (role == .multiply or lane < 4) return v.main(0);
    var mask = F.zero();
    inline for (0..12) |i| mask = mask.add(v.fixed(i));
    return mask;
}
pub fn byteFraction(comptime role: Role, comptime F: type, v: anytype, beta: Q, lane: usize) struct { F, E.SecureFor(F) } {
    if (role == .table) {
        if (lane != 0) return .{ F.zero(), E.SecureFor(F).one() };
        return .{ v.main(0).neg(), E.splatFor(F, beta).sub(E.liftFor(F, v.fixed(0))) };
    }
    if (role == .hint) {
        if (lane >= H.BYTE_QUERIES) return .{ F.zero(), E.SecureFor(F).one() };
        return .{ v.fixed(H.ACTIVE), E.splatFor(F, beta).sub(E.liftFor(F, H.byteQuery(F, v, lane))) };
    }
    if (role == .frontier) return .{ F.zero(), E.SecureFor(F).one() };
    if (lane >= PW.Layout(kind(role)).BYTE_QUERIES) return .{ F.zero(), E.SecureFor(F).one() };
    return .{ v.main(0), E.splatFor(F, beta).sub(E.liftFor(F, DA.queryFor(P, kind(role), F, v, lane))) };
}
pub fn ssaFraction(comptime role: Role, comptime F: type, v: anytype, wire: Wire, lane: usize) struct { F, E.SecureFor(F) } {
    var tuple: [35]F = undefined;
    tuple[0] = k(F, KIND);
    tuple[1] = F.one();
    var weight = F.zero();
    if (role == .hint) {
        if (lane != 0) return .{ F.zero(), E.SecureFor(F).one() };
        tuple = H.ssaTuple(F, v, k(F, KIND), F.one());
        weight = H.ssaWeight(F, v);
    } else if (role == .frontier) {
        if (lane != 0) return .{ F.zero(), E.SecureFor(F).one() };
        tuple[2] = v.fixed(1);
        weight = v.main(0).mul(v.fixed(2));
        for (tuple[3..], 0..) |*b, i| b.* = v.main(1 + i);
    } else if (role == .square or role == .multiply) {
        const inputs = P.inputs(kind(role));
        const L = PW.Layout(kind(role));
        if (lane > inputs) return .{ F.zero(), E.SecureFor(F).one() };
        if (lane < inputs) {
            tuple[2] = v.fixed(readIdStart(role) + lane);
            weight = v.main(0).mul(readMask(role, F, v, lane)).neg();
            for (tuple[3..], 0..) |*b, i| b.* = v.main(L.INPUT + 32 * lane + i);
        } else {
            tuple[2] = v.fixed(writerIdColumn(role));
            weight = v.main(0).mul(v.fixed(writerWeightColumn(role)));
            for (tuple[3..], 0..) |*b, i| b.* = v.main(L.OUTPUT + i);
        }
    } else return .{ F.zero(), E.SecureFor(F).one() };
    return .{ weight, E.denominatorFor(F, wire.offset, &wire.coefficients, &tuple, true) };
}
pub fn constraints(comptime role: Role) usize {
    return switch (role) {
        .frontier => 33,
        .table => 0,
        .hint => H.CONSTRAINTS,
        .square => DA.constraintsFor(P, .square) + 1 + 32 * 12,
        .multiply => DA.constraintsFor(P, .multiply) + 1 + 32,
    };
}
pub fn emit(comptime role: Role, comptime F: type, v: anytype, sink: *E.SinkFor(F)) void {
    if (role == .frontier) {
        sink.emit(v.main(0).sub(v.fixed(0)));
        for (0..32) |i| sink.emit(v.main(1 + i).sub(v.fixed(3 + i)));
    }
    if (role == .hint) H.emitCanonical(F, v, sink);
    if (role == .square or role == .multiply) {
        const L = PW.Layout(kind(role));
        DA.emitInheritedFor(P, kind(role), F, v, sink);
        sink.emit(v.main(L.MULT));
        if (role == .square) {
            for (0..12) |slot| {
                const unused = v.main(0).sub(readMask(role, F, v, slot));
                for (0..32) |b| sink.emit(unused.mul(v.main(L.INPUT + 32 * slot + b)));
            }
        } else {
            for (0..32) |b| sink.emit(v.fixed(goalColumn()).mul(v.main(L.OUTPUT + b).sub(if (b == 0) v.fixed(goalByteColumn()) else F.zero())));
        }
    }
}
pub const Model = struct {
    physical: *const PW.Physical,
    public: [S.INITIAL]u256,
    table: [256]u32,
    pub fn init(physical: *const PW.Physical, expected_z: *const [12]u256) !Model {
        var out = Model{ .physical = physical, .public = undefined, .table = @splat(0) };
        for (expected_z) |value| if (value >= S.B.BN254_P) return error.NonCanonicalExpectedResidueZ;
        @memcpy(out.public[0..12], expected_z);
        @memcpy(out.public[12..], &S.Frobenius.POOL);
        out.recount();
        return out;
    }
    pub const View = struct {
        model: *const Model,
        role: Role,
        row: usize,
        pub fn main(v: *const @This(), column: usize) Q {
            const n: u32 = switch (v.role) {
                .table => v.model.table[v.row],
                .frontier => if (v.row < S.INITIAL) (if (column == 0) 1 else S.B.limbOf(v.model.public[v.row], column - 1)) else 0,
                .hint => if (v.row < S.PRIVATE_HINTS) v.model.physical.logical.hints[v.row][column] else 0,
                .square => v.model.physical.main(.square, v.row, column),
                .multiply => v.model.physical.main(.multiply, v.row, column),
            };
            return Q.fromBase(M.fromCanonical(n));
        }
        pub fn fixed(v: *const @This(), column: usize) Q {
            const n: u32 = switch (v.role) {
                .table => @intCast(v.row),
                .frontier => if (v.row < S.INITIAL) (if (column == 0) 1 else if (column == 1) @intCast(v.row) else if (column == 2) FANOUT[v.row] else S.B.limbOf(v.model.public[v.row], column - 3)) else 0,
                .hint => if (v.row < S.PRIVATE_HINTS) (if (column == H.ACTIVE) 1 else if (column == H.WRITER_ID) @intCast(S.INITIAL + v.row) else FANOUT[S.INITIAL + v.row]) else 0,
                .square => arithmeticFixed(.square, v.row, column),
                .multiply => arithmeticFixed(.multiply, v.row, column),
            };
            return Q.fromBase(M.fromCanonical(n));
        }
    };
    fn arithmeticFixed(comptime role: Role, row: usize, column: usize) u32 {
        const operation = comptime kind(role);
        const count = if (role == .square) PW.SQUARE_ROWS else PW.MULTIPLY_ROWS;
        if (column == P.rows(operation) + 1) return @intCast(row % 256);
        if (row >= count) return 0;
        const node = PW.Physical.nodeAt(operation, row);
        if (column < P.rows(operation)) return @intFromBool(column == node.opcode);
        if (column == P.rows(operation)) return 1;
        if (column < writerIdColumn(role)) {
            const slot = column - readIdStart(role);
            return if (node.input[slot] == S.UNUSED) 0 else node.input[slot];
        }
        if (column == writerIdColumn(role)) return node.writer;
        if (column == writerWeightColumn(role)) return FANOUT[node.writer];
        return if (column == goalColumn()) @intFromBool(node.pin_one) else @intFromBool(node.pin_one and node.opcode == 0);
    }
    pub fn view(self: *const Model, role: Role, row: usize) View {
        return .{ .model = self, .role = role, .row = row };
    }
    pub fn recount(self: *Model) void {
        self.table = @splat(0);
        inline for (.{ Role.square, Role.multiply, Role.hint }) |role| {
            const count = if (role == .square) PW.SQUARE_ROWS else if (role == .multiply) PW.MULTIPLY_ROWS else S.PRIVATE_HINTS;
            const queries = if (role == .hint) H.BYTE_QUERIES else PW.Layout(kind(role)).BYTE_QUERIES;
            for (0..count) |row| {
                const v = self.view(role, row);
                for (0..queries) |i| {
                    const q = if (role == .hint) H.byteQuery(Q, &v, i) else DA.queryFor(P, kind(role), Q, &v, i);
                    const x = q.toM31Array();
                    std.debug.assert(x[0].v < 256);
                    for (x[1..]) |high| std.debug.assert(high.v == 0);
                    self.table[x[0].v] += 1;
                }
            }
        }
    }
};
