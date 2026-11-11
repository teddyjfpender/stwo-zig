//! Complete conditional subgroup four-role source. The public input Q is toy
//! independently expected FIXED data, not a reusable production key/VM binding.
const std = @import("std");
const core = @import("stwo_core");
const S = @import("spec.zig");
const W = @import("witness.zig");
const Hint = @import("../../bn254_hint/source.zig");
const HW = @import("../../bn254_hint/witness.zig");
const DA = @import("../../bn254_dense/air.zig");
const E = @import("../../../evaluation.zig");
pub const Q = core.fields.om31.OM31;
pub const M = core.fields.m31.M31;
pub const Wire = @import("../../curves/equations.zig").WireFor(Q);
pub const Role = enum { frontier, arithmetic, hints, table };
pub const KIND = S.SSA_NAMESPACE;
pub const ARITH_ROWS = W.ROM.count - W.ROM.hints;
pub const HINT_ROWS = W.ROM.hints;
pub const FRONTIER_ROWS = S.INITIAL + W.ROM.assertion_count;
pub const FANOUT = blk: {
    @setEvalBranchQuota(100_000);
    break :blk S.fanout(&W.ROM);
};
pub const ARITH_INDICES = indices(false);
pub const HINT_INDICES = indices(true);
fn indices(comptime hints: bool) [if (hints) HINT_ROWS else ARITH_ROWS]usize {
    @setEvalBranchQuota(100_000);
    var result: [if (hints) HINT_ROWS else ARITH_ROWS]usize = undefined;
    var at: usize = 0;
    for (W.ROM.nodes[0..W.ROM.count], 0..) |node, i| if ((node.op == .hint_norm_inverse) == hints) {
        result[at] = i;
        at += 1;
    };
    std.debug.assert(at == result.len);
    return result;
}
pub fn logSize(role: Role) u32 {
    return switch (role) {
        .arithmetic => 12,
        .hints, .frontier => 9,
        .table => 8,
    };
}
pub fn mainWidth(comptime role: Role) usize {
    return switch (role) {
        .arithmetic => W.Layout.MAIN,
        .hints => Hint.MAIN,
        .frontier => 33,
        .table => 1,
    };
}
pub fn readIdStart() usize {
    return S.OPCODES + 2;
}
pub fn writerIdColumn() usize {
    return readIdStart() + 7;
}
pub fn writerWeightColumn() usize {
    return writerIdColumn() + 1;
}
pub fn fixedWidth(comptime role: Role) usize {
    return switch (role) {
        .arithmetic => writerWeightColumn() + 1,
        .hints => Hint.FIXED,
        .frontier => 35,
        .table => 1,
    };
}
fn k(comptime F: type, x: u32) F {
    return E.qFor(F, x);
}
fn mask(comptime F: type, v: anytype, lane: usize) F {
    var result = F.zero();
    inline for (0..S.OPCODES) |opcode| if (lane < S.arity(@enumFromInt(opcode))) {
        result = result.add(v.fixed(opcode));
    };
    return result;
}
pub fn ssaFraction(comptime role: Role, comptime F: type, v: anytype, wire: Wire, lane: usize) struct { F, E.SecureFor(F) } {
    var tuple: [35]F = undefined;
    var weight = F.zero();
    if (role == .hints) {
        if (lane != 0) return .{ F.zero(), E.SecureFor(F).one() };
        tuple = Hint.ssaTuple(F, v, k(F, KIND), F.one());
        weight = Hint.ssaWeight(F, v);
    } else if (role == .frontier) {
        if (lane != 0) return .{ F.zero(), E.SecureFor(F).one() };
        tuple[0] = k(F, KIND);
        tuple[1] = F.one();
        tuple[2] = v.fixed(1);
        for (0..32) |i| tuple[3 + i] = v.main(1 + i);
        weight = v.main(0).mul(v.fixed(2));
    } else if (role == .arithmetic) {
        if (lane > 7) return .{ F.zero(), E.SecureFor(F).one() };
        tuple[0] = k(F, KIND);
        tuple[1] = F.one();
        if (lane < 7) {
            tuple[2] = v.fixed(readIdStart() + lane);
            weight = v.main(0).mul(mask(F, v, lane)).neg();
            for (0..32) |i| tuple[3 + i] = v.main(W.Layout.INPUT + 32 * lane + i);
        } else {
            tuple[2] = v.fixed(writerIdColumn());
            weight = v.main(0).mul(v.fixed(writerWeightColumn()));
            for (0..32) |i| tuple[3 + i] = v.main(W.Layout.OUTPUT + i);
        }
    } else return .{ F.zero(), E.SecureFor(F).one() };
    return .{ weight, E.denominatorFor(F, wire.offset, &wire.coefficients, &tuple, true) };
}
pub fn byteFraction(comptime role: Role, comptime F: type, v: anytype, beta: Q, lane: usize) struct { F, E.SecureFor(F) } {
    if (role == .table) {
        if (lane != 0) return .{ F.zero(), E.SecureFor(F).one() };
        return .{ v.main(0).neg(), E.splatFor(F, beta).sub(E.liftFor(F, v.fixed(0))) };
    }
    if (role == .arithmetic) {
        if (lane >= W.Layout.BYTE_QUERIES) return .{ F.zero(), E.SecureFor(F).one() };
        return .{ v.main(0), E.splatFor(F, beta).sub(E.liftFor(F, DA.queryFor(S, .quadratic, F, v, lane))) };
    }
    if (role == .hints) {
        if (lane >= Hint.BYTE_QUERIES) return .{ F.zero(), E.SecureFor(F).one() };
        return .{ v.fixed(Hint.ACTIVE), E.splatFor(F, beta).sub(E.liftFor(F, Hint.byteQuery(F, v, lane))) };
    }
    return .{ F.zero(), E.SecureFor(F).one() };
}
pub fn constraints(comptime role: Role) usize {
    return switch (role) {
        .frontier => 33,
        .arithmetic => DA.constraintsFor(S, .quadratic) + 1 + 32 * 7,
        .hints => Hint.CONSTRAINTS,
        .table => 0,
    };
}
pub fn emit(comptime role: Role, comptime F: type, v: anytype, sink: *E.SinkFor(F)) void {
    if (role == .frontier) {
        sink.emit(v.main(0).sub(v.fixed(0)));
        for (0..32) |i| sink.emit(v.main(1 + i).sub(v.fixed(3 + i)));
    }
    if (role == .hints) Hint.emitCanonical(F, v, sink);
    if (role == .arithmetic) {
        DA.emitInheritedFor(S, .quadratic, F, v, sink);
        sink.emit(v.main(W.Layout.MULT));
        for (0..7) |slot| {
            const unused = v.main(0).sub(mask(F, v, slot));
            for (0..32) |i| sink.emit(unused.mul(v.main(W.Layout.INPUT + 32 * slot + i)));
        }
    }
}
pub const Model = struct {
    actual: *const W.Witness,
    public: [FRONTIER_ROWS]u256,
    hints: [HINT_ROWS]Hint.Row,
    table: [256]u32,
    pub fn init(actual: *const W.Witness, expected_q: [2][2]u256) !Model {
        const initial = try S.initialValues(expected_q);
        var self = Model{ .actual = actual, .public = @splat(0), .hints = undefined, .table = @splat(0) };
        @memcpy(self.public[0..S.INITIAL], &initial);
        for (HINT_INDICES, &self.hints) |index, *row| row.* = try HW.fill(actual.values[W.ROM.nodes[index].writer]);
        self.recount();
        return self;
    }
    pub const View = struct {
        model: *const Model,
        role: Role,
        row: usize,
        pub fn main(v: *const @This(), c: usize) Q {
            var x: u32 = 0;
            switch (v.role) {
                .table => x = v.model.table[v.row],
                .frontier => if (v.row < FRONTIER_ROWS) {
                    x = if (c == 0) 1 else S.B.limbOf(v.model.public[v.row], c - 1);
                },
                .hints => if (v.row < HINT_ROWS) {
                    x = v.model.hints[v.row][c];
                },
                .arithmetic => if (v.row < ARITH_ROWS) {
                    x = v.model.actual.rows[ARITH_INDICES[v.row] * W.Layout.MAIN + c];
                },
            }
            return Q.fromBase(M.fromCanonical(x));
        }
        pub fn fixed(v: *const @This(), c: usize) Q {
            var x: i32 = 0;
            switch (v.role) {
                .table => x = @intCast(v.row),
                .frontier => if (v.row < FRONTIER_ROWS) {
                    const initial = v.row < S.INITIAL;
                    const id: usize = if (initial) v.row else W.ROM.assertions[v.row - S.INITIAL];
                    x = if (c == 0) 1 else if (c == 1) @intCast(id) else if (c == 2) (if (initial) @intCast(FANOUT[id]) else -1) else S.B.limbOf(v.model.public[v.row], c - 3);
                },
                .hints => if (v.row < HINT_ROWS) {
                    const node = W.ROM.nodes[HINT_INDICES[v.row]];
                    x = if (c == Hint.ACTIVE) 1 else if (c == Hint.WRITER_ID) node.writer else @intCast(FANOUT[node.writer]);
                },
                .arithmetic => {
                    if (c == S.OPCODES + 1) x = @intCast(v.row % 256) else if (v.row < ARITH_ROWS) {
                        const node = W.ROM.nodes[ARITH_INDICES[v.row]];
                        if (c < S.OPCODES) x = @intFromBool(c == @intFromEnum(node.op)) else if (c == S.OPCODES) x = 1 else if (c < writerIdColumn()) {
                            const id = node.input[c - readIdStart()];
                            x = if (id == S.NONE) 0 else id;
                        } else x = if (c == writerIdColumn()) node.writer else @intCast(FANOUT[node.writer]);
                    }
                },
            }
            const magnitude = Q.fromBase(M.fromCanonical(@intCast(@abs(x))));
            return if (x < 0) magnitude.neg() else magnitude;
        }
    };
    pub fn view(self: *const Model, role: Role, row: usize) View {
        return .{ .model = self, .role = role, .row = row };
    }
    pub fn recount(self: *Model) void {
        self.table = @splat(0);
        inline for (.{ Role.arithmetic, Role.hints }) |role| {
            const count = if (role == .arithmetic) ARITH_ROWS else HINT_ROWS;
            const n = if (role == .arithmetic) W.Layout.BYTE_QUERIES else Hint.BYTE_QUERIES;
            for (0..count) |row| {
                const v = self.view(role, row);
                for (0..n) |query| {
                    const q = if (role == .arithmetic) DA.queryFor(S, .quadratic, Q, &v, query) else Hint.byteQuery(Q, &v, query);
                    const words = q.toM31Array();
                    std.debug.assert(words[0].v < 256);
                    for (words[1..]) |word| std.debug.assert(word.v == 0);
                    self.table[words[0].v] += 1;
                }
            }
        }
    }
};
