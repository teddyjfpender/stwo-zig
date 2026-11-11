//! Source-owned initial/export frontier and exact local SSA expression authority.
//! Only the frontier pins public bytes. Arithmetic consumes initial/canonical
//! writer bytes through the full typed local relation. Not production admission.
const std = @import("std");
const core = @import("stwo_core");
const S = @import("spec.zig");
const W = @import("witness.zig");
const DenseAir = @import("../bn254_dense/air.zig");
const E = @import("../../evaluation.zig");
pub const Q = core.fields.om31.OM31;
pub const M = core.fields.m31.M31;
pub const Wire = @import("../curves/equations.zig").WireFor(Q);
pub const KIND: u32 = 0x47325353;
pub const Role = enum { frontier, arithmetic, table };
pub const FRONTIER_MAIN = 33;
pub const FRONTIER_FIXED = 35; // active, SSA ID, signed source weight, public bytes32
pub const ARITH_LOG = 8;
pub const FRONTIER_LOG = 5;
pub const TABLE_LOG = 8;
pub fn rowLog(role: Role) u32 {
    return if (role == .frontier) FRONTIER_LOG else 8;
}
pub fn fixedWidth(comptime kind: S.Kind, role: Role) usize {
    return switch (role) {
        .frontier => FRONTIER_FIXED,
        .arithmetic => S.rows(kind) + 2,
        .table => 1,
    };
}
pub fn mainWidth(comptime kind: S.Kind, role: Role) usize {
    return switch (role) {
        .frontier => FRONTIER_MAIN,
        .arithmetic => W.Layout(kind).MAIN,
        .table => 1,
    };
}
fn k(comptime F: type, x: u32) F {
    return E.qFor(F, x);
}
fn literal(comptime F: type, x: i32) F {
    const value = k(F, @intCast(@abs(x)));
    return if (x < 0) value.neg() else value;
}
pub fn scalarTuple(comptime F: type, id: F, bytes: [32]F, wire: Wire) E.SecureFor(F) {
    var tuple: [35]F = undefined;
    tuple[0] = k(F, KIND);
    tuple[1] = F.one();
    tuple[2] = id;
    @memcpy(tuple[3..], &bytes);
    return E.denominatorFor(F, wire.offset, &wire.coefficients, &tuple, true);
}
pub fn ssaFraction(comptime kind: S.Kind, comptime role: Role, comptime F: type, v: anytype, wire: Wire, lane: usize) struct { F, E.SecureFor(F) } {
    var bytes: [32]F = undefined;
    var id = F.zero();
    var weight = F.zero();
    if (role == .frontier) {
        if (lane != 0) return .{ F.zero(), E.SecureFor(F).one() };
        id = v.fixed(1);
        weight = v.main(0).mul(v.fixed(2));
        for (&bytes, 0..) |*x, i| x.* = v.main(1 + i);
    } else if (role == .arithmetic) {
        const L = W.Layout(kind);
        const p = comptime S.program(kind);
        const fanout = comptime S.fanout(kind);
        if (lane > S.inputs(kind)) return .{ F.zero(), E.SecureFor(F).one() };
        if (lane < S.inputs(kind)) {
            inline for (0..comptime S.rows(kind)) |step| {
                const input_ids = comptime S.operandIds(kind, step);
                if (input_ids[lane] != S.UNUSED) {
                    id = id.add(v.fixed(step).mul(k(F, input_ids[lane])));
                    weight = weight.sub(v.fixed(step));
                }
            }
            for (&bytes, 0..) |*x, i| x.* = v.main(L.INPUT + 32 * lane + i);
        } else {
            inline for (0..comptime S.rows(kind)) |step| {
                const writer = p.operations[step].writer;
                id = id.add(v.fixed(step).mul(k(F, writer)));
                weight = weight.add(v.fixed(step).mul(k(F, fanout[writer])));
            }
            for (&bytes, 0..) |*x, i| x.* = v.main(L.OUTPUT + i);
        }
        weight = weight.mul(v.main(0));
    } else return .{ F.zero(), E.SecureFor(F).one() };
    return .{ weight, scalarTuple(F, id, bytes, wire) };
}
pub fn byteFraction(comptime kind: S.Kind, comptime role: Role, comptime F: type, v: anytype, beta: Q, lane: usize) struct { F, E.SecureFor(F) } {
    if (role == .table) {
        if (lane != 0) return .{ F.zero(), E.SecureFor(F).one() };
        return .{ v.main(0).neg(), E.splatFor(F, beta).sub(E.liftFor(F, v.fixed(0))) };
    }
    if (role != .arithmetic or lane >= W.Layout(kind).BYTE_QUERIES) return .{ F.zero(), E.SecureFor(F).one() };
    return .{ v.main(0), E.splatFor(F, beta).sub(E.liftFor(F, DenseAir.queryFor(S, kind, F, v, lane))) };
}
pub fn constraints(comptime kind: S.Kind, comptime role: Role) usize {
    return switch (role) {
        .frontier => 33,
        .table => 0,
        .arithmetic => DenseAir.constraintsFor(S, kind) + 1 + 32 * S.inputs(kind),
    };
}
pub fn emit(comptime kind: S.Kind, comptime role: Role, comptime F: type, v: anytype, sink: *E.SinkFor(F)) void {
    if (role == .frontier) {
        sink.emit(v.main(0).sub(v.fixed(0)));
        for (0..32) |i| sink.emit(v.main(1 + i).sub(v.fixed(3 + i)));
    }
    if (role == .arithmetic) {
        const L = W.Layout(kind);
        DenseAir.emitInheritedFor(S, kind, F, v, sink);
        sink.emit(v.main(L.MULT));
        for (0..S.inputs(kind)) |slot| {
            var unused = F.zero();
            inline for (0..comptime S.rows(kind)) |step| {
                const ids = comptime S.operandIds(kind, step);
                if (ids[slot] == S.UNUSED) unused = unused.add(v.fixed(step));
            }
            for (0..32) |byte| sink.emit(unused.mul(v.main(L.INPUT + 32 * slot + byte)));
        }
    }
}
pub fn Model(comptime kind: S.Kind) type {
    return struct {
        actual: W.Witness(kind),
        /// Independently expected initial+export bytes, never taken from actual
        /// intermediate advice. Tests construct these from pinned oracle vectors.
        public: [S.initialCount(kind) + 12]u256,
        table: [256]u32,
        pub fn init(actual: W.Witness(kind), expected_initial: *const [S.initialCount(kind)]u256, expected_point: S.Point, expected_line: [3]S.FQ2) !@This() {
            var self: @This() = .{ .actual = actual, .public = undefined, .table = @splat(0) };
            for (expected_initial) |value| if (value >= S.B.BN254_P) return error.NonCanonicalExpectedG2Input;
            if (kind == .doubling and (expected_initial[6] != (S.B.BN254_P + 1) / 2 or expected_initial[7] != S.TWIST_B[0] or expected_initial[8] != S.TWIST_B[1])) return error.WrongG2SourceConstant;
            for (expected_point) |pair| for (pair) |value| {
                if (value >= S.B.BN254_P) return error.NonCanonicalExpectedG2Output;
            };
            for (expected_line) |pair| for (pair) |value| {
                if (value >= S.B.BN254_P) return error.NonCanonicalExpectedG2Output;
            };
            @memcpy(self.public[0..S.initialCount(kind)], expected_initial);
            for (expected_point, 0..) |p, i| for (p, 0..) |value, j| {
                self.public[S.initialCount(kind) + 2 * i + j] = value;
            };
            const inverse_three: u256 = (2 * S.B.BN254_P + 1) / 3;
            const program = comptime S.program(kind);
            for (expected_line, 0..) |p, i| for (p, 0..) |value, j| {
                const coefficient = program.line_scale[i];
                self.public[S.initialCount(kind) + 6 + 2 * i + j] = if (coefficient == -1 and value != 0) S.B.BN254_P - value else if (coefficient == 3) @intCast(@as(S.B.Big, value) * inverse_three % S.B.BN254_P) else value;
            };
            self.recount();
            return self;
        }
        pub const View = struct {
            model: *const Model(kind),
            role: Role,
            row: usize,
            pub fn main(v: *const @This(), c: usize) Q {
                var value: u32 = 0;
                switch (v.role) {
                    .table => value = v.model.table[v.row],
                    .frontier => {
                        if (v.row < v.model.public.len) value = if (c == 0) 1 else S.B.limbOf(v.model.public[v.row], c - 1);
                    },
                    .arithmetic => {
                        if (v.row < S.rows(kind)) value = v.model.actual.arithmetic[v.row][c];
                    },
                }
                return Q.fromBase(M.fromCanonical(value));
            }
            pub fn fixed(v: *const @This(), c: usize) Q {
                var value: i32 = 0;
                switch (v.role) {
                    .table => value = @intCast(v.row),
                    .arithmetic => value = if (c < S.rows(kind)) @intFromBool(c == v.row % S.rows(kind)) else if (c == S.rows(kind)) @intFromBool(v.row < S.rows(kind)) else @intCast(v.row),
                    .frontier => if (v.row < v.model.public.len) {
                        const p = comptime S.program(kind);
                        const fanout = comptime S.fanout(kind);
                        if (c == 0) value = 1 else if (c == 1) value = if (v.row < S.initialCount(kind)) @intCast(v.row) else if (v.row < S.initialCount(kind) + 6) p.point[v.row - S.initialCount(kind)] else p.line[v.row - S.initialCount(kind) - 6] else if (c == 2) value = if (v.row < S.initialCount(kind)) @intCast(fanout[v.row]) else -1 else value = S.B.limbOf(v.model.public[v.row], c - 3);
                    },
                }
                return literal(Q, value);
            }
        };
        pub fn view(self: *const @This(), role: Role, row: usize) View {
            return .{ .model = self, .role = role, .row = row };
        }
        pub fn recount(self: *@This()) void {
            self.table = @splat(0);
            for (0..S.rows(kind)) |r| {
                const v = self.view(.arithmetic, r);
                for (0..W.Layout(kind).BYTE_QUERIES) |i| {
                    const x = DenseAir.queryFor(S, kind, Q, &v, i).toM31Array();
                    std.debug.assert(x[0].v < 256);
                    for (x[1..]) |top| std.debug.assert(top.v == 0);
                    self.table[x[0].v] += 1;
                }
            }
        }
    };
}
