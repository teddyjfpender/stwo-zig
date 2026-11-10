//! Conditional complete preparation frontier and local source expressions.
//! Q-specific public bytes are toy fixture authority, not production VK/setup.
const std = @import("std");
const core = @import("stwo_core");
const S = @import("spec.zig");
const W = @import("witness.zig");
const DA = @import("../../bn254_dense/air.zig");
const E = @import("../../../evaluation.zig");
pub const Q = core.fields.om31.OM31;
pub const M = core.fields.m31.M31;
pub const Wire = @import("../../curves/equations.zig").WireFor(Q);
pub const Role = enum { frontier, doubling, addition, table };
pub const KIND: u32 = 0x47325052;
pub const FRONTIER_MAIN = 33;
pub const FRONTIER_FIXED = 35;
pub const FANOUT = blk: {
    @setEvalBranchQuota(100_000);
    break :blk S.fanout(&W.ROM);
};
pub fn kind(comptime role: Role) S.Kind {
    return if (role == .doubling) .doubling else .addition;
}
pub fn logSize(role: Role) u32 {
    return switch (role) {
        .doubling => 11,
        .addition => 9,
        .frontier => 10,
        .table => 8,
    };
}
pub fn mainWidth(comptime role: Role) usize {
    return switch (role) {
        .doubling, .addition => W.Layout(kind(role)).MAIN,
        .frontier => 33,
        .table => 1,
    };
}
pub fn readIdStart(comptime role: Role) usize {
    return S.rows(kind(role)) + 2;
}
pub fn writerIdColumn(comptime role: Role) usize {
    return readIdStart(role) + S.inputs(kind(role));
}
pub fn writerWeightColumn(comptime role: Role) usize {
    return writerIdColumn(role) + 1;
}
pub fn fixedWidth(comptime role: Role) usize {
    return switch (role) {
        .doubling, .addition => writerWeightColumn(role) + 1,
        .frontier => 35,
        .table => 1,
    };
}
fn k(comptime F: type, value: u32) F {
    return E.qFor(F, value);
}
fn validSlot(comptime operation: S.Kind, comptime opcode: usize, slot: usize) bool {
    if (operation == .doubling and opcode < S.PREFIX) return slot < if (opcode < 2) @as(usize, 1) else 4;
    const local = comptime S.Base.operandIds(operation, if (operation == .doubling) opcode - S.PREFIX else opcode);
    return local[slot] != S.Base.UNUSED;
}
fn readMask(comptime role: Role, comptime F: type, v: anytype, slot: usize) F {
    var mask = F.zero();
    inline for (0..comptime S.rows(kind(role))) |opcode| if (validSlot(kind(role), opcode, slot)) {
        mask = mask.add(v.fixed(opcode));
    };
    return mask;
}
pub fn ssaFraction(comptime role: Role, comptime F: type, v: anytype, wire: Wire, lane: usize) struct { F, E.SecureFor(F) } {
    var id = F.zero();
    var weight = F.zero();
    var bytes: [32]F = undefined;
    if (role == .frontier) {
        if (lane != 0) return .{ F.zero(), E.SecureFor(F).one() };
        id = v.fixed(1);
        weight = v.main(0).mul(v.fixed(2));
        for (&bytes, 0..) |*b, i| b.* = v.main(1 + i);
    } else if (role == .doubling or role == .addition) {
        const L = W.Layout(kind(role));
        const inputs = S.inputs(kind(role));
        if (lane > inputs) return .{ F.zero(), E.SecureFor(F).one() };
        if (lane < inputs) {
            id = v.fixed(readIdStart(role) + lane);
            weight = v.main(0).mul(readMask(role, F, v, lane)).neg();
            for (&bytes, 0..) |*b, i| b.* = v.main(L.INPUT + 32 * lane + i);
        } else {
            id = v.fixed(writerIdColumn(role));
            weight = v.main(0).mul(v.fixed(writerWeightColumn(role)));
            for (&bytes, 0..) |*b, i| b.* = v.main(L.OUTPUT + i);
        }
    } else return .{ F.zero(), E.SecureFor(F).one() };
    var tuple: [35]F = undefined;
    tuple[0] = k(F, KIND);
    tuple[1] = F.one();
    tuple[2] = id;
    @memcpy(tuple[3..], &bytes);
    return .{ weight, E.denominatorFor(F, wire.offset, &wire.coefficients, &tuple, true) };
}
pub fn byteFraction(comptime role: Role, comptime F: type, v: anytype, beta: Q, lane: usize) struct { F, E.SecureFor(F) } {
    if (role == .table) {
        if (lane != 0) return .{ F.zero(), E.SecureFor(F).one() };
        return .{ v.main(0).neg(), E.splatFor(F, beta).sub(E.liftFor(F, v.fixed(0))) };
    }
    if (role != .doubling and role != .addition) return .{ F.zero(), E.SecureFor(F).one() };
    if (lane >= W.Layout(kind(role)).BYTE_QUERIES) return .{ F.zero(), E.SecureFor(F).one() };
    return .{ v.main(0), E.splatFor(F, beta).sub(E.liftFor(F, DA.queryFor(S, kind(role), F, v, lane))) };
}
pub fn constraints(comptime role: Role) usize {
    return switch (role) {
        .frontier => 33,
        .table => 0,
        .doubling, .addition => DA.constraintsFor(S, kind(role)) + 1 + 32 * S.inputs(kind(role)),
    };
}
pub fn emit(comptime role: Role, comptime F: type, v: anytype, sink: *E.SinkFor(F)) void {
    if (role == .frontier) {
        sink.emit(v.main(0).sub(v.fixed(0)));
        for (0..32) |i| sink.emit(v.main(1 + i).sub(v.fixed(3 + i)));
    }
    if (role == .doubling or role == .addition) {
        const L = W.Layout(kind(role));
        DA.emitInheritedFor(S, kind(role), F, v, sink);
        sink.emit(v.main(L.MULT));
        for (0..S.inputs(kind(role))) |slot| {
            const unused = v.main(0).sub(readMask(role, F, v, slot));
            for (0..32) |b| sink.emit(unused.mul(v.main(L.INPUT + 32 * slot + b)));
        }
    }
}
pub const Model = struct {
    actual: *const W.Witness,
    public: [S.FRONTIER_ROWS]u256,
    table: [256]u32,
    pub fn init(actual: *const W.Witness, expected_initial: *const [S.INITIAL]u256, expected_exports: *const [S.EXPORTS]u256) !Model {
        const q: [2]S.FQ2 = .{ expected_initial[0..2].*, expected_initial[2..4].* };
        const canonical = try S.initialValues(q);
        if (!std.mem.eql(u256, &canonical, expected_initial)) return error.WrongPreparationSourceLiteral;
        for (expected_exports) |value| if (value >= S.B.BN254_P) return error.NonCanonicalPreparationExport;
        var self = Model{ .actual = actual, .public = undefined, .table = @splat(0) };
        @memcpy(self.public[0..S.INITIAL], expected_initial);
        @memcpy(self.public[S.INITIAL..], expected_exports);
        self.recount();
        return self;
    }
    pub const View = struct {
        model: *const Model,
        role: Role,
        row: usize,
        pub fn main(v: *const @This(), c: usize) Q {
            var value: u32 = 0;
            switch (v.role) {
                .frontier => if (v.row < S.FRONTIER_ROWS) {
                    value = if (c == 0) 1 else S.B.limbOf(v.model.public[v.row], c - 1);
                },
                .table => value = v.model.table[v.row],
                .doubling => if (v.row < S.DOUBLE_ROWS) {
                    value = v.model.actual.double_main[v.row * W.Layout(.doubling).MAIN + c];
                },
                .addition => if (v.row < S.ADD_ROWS) {
                    value = v.model.actual.add_main[v.row * W.Layout(.addition).MAIN + c];
                },
            }
            return Q.fromBase(M.fromCanonical(value));
        }
        pub fn fixed(v: *const @This(), c: usize) Q {
            var value: i32 = 0;
            switch (v.role) {
                .table => value = @intCast(v.row),
                .frontier => if (v.row < S.FRONTIER_ROWS) {
                    const initial = v.row < S.INITIAL;
                    const export_index = if (initial) 0 else v.row - S.INITIAL;
                    const id = if (initial) @as(S.ID, @intCast(v.row)) else if (export_index < 87 * 6) W.ROM.transitions[export_index / 6].line[export_index % 6] else W.ROM.final_point[export_index - 87 * 6];
                    value = if (c == 0) 1 else if (c == 1) id else if (c == 2) (if (initial) @intCast(FANOUT[id]) else -1) else S.B.limbOf(v.model.public[v.row], c - 3);
                },
                .doubling => value = arithmeticFixed(.doubling, v.row, c),
                .addition => value = arithmeticFixed(.addition, v.row, c),
            }
            const absolute = Q.fromBase(M.fromCanonical(@intCast(@abs(value))));
            return if (value < 0) absolute.neg() else absolute;
        }
    };
    fn arithmeticFixed(comptime role: Role, row: usize, c: usize) i32 {
        const nodes = if (role == .doubling) W.ROM.doubles[0..] else W.ROM.adds[0..];
        if (c == S.rows(kind(role)) + 1) return @intCast(row % 256);
        if (row >= nodes.len) return 0;
        const node = nodes[row];
        if (c < S.rows(kind(role))) return @intFromBool(c == node.opcode);
        if (c == S.rows(kind(role))) return 1;
        if (c < writerIdColumn(role)) {
            const id = node.input[c - readIdStart(role)];
            return if (id == S.UNUSED) 0 else id;
        }
        return if (c == writerIdColumn(role)) node.writer else @intCast(FANOUT[node.writer]);
    }
    pub fn view(self: *const Model, role: Role, row: usize) View {
        return .{ .model = self, .role = role, .row = row };
    }
    pub fn recount(self: *Model) void {
        self.table = @splat(0);
        inline for (.{ Role.doubling, Role.addition }) |role| {
            const rows_ = if (role == .doubling) S.DOUBLE_ROWS else S.ADD_ROWS;
            for (0..rows_) |r| {
                const v = self.view(role, r);
                for (0..W.Layout(kind(role)).BYTE_QUERIES) |i| {
                    const x = DA.queryFor(S, kind(role), Q, &v, i).toM31Array();
                    std.debug.assert(x[0].v < 256);
                    for (x[1..]) |top| std.debug.assert(top.v == 0);
                    self.table[x[0].v] += 1;
                }
            }
        }
    }
};
