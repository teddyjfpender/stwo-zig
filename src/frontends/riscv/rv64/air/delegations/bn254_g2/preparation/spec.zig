//! Complete immutable 87-line preparation schedule. Q-independent IDs and ROM.
//! Ten canonical prefix equations derive signed/Frobenius inputs inside the
//! argument. Curve/subgroup/infinity and external VM bindings remain separate.
const std = @import("std");
pub const Base = @import("../spec.zig");
pub const B = Base.B;
pub const Kind = Base.Kind;
pub const FQ2 = Base.FQ2;
pub const INITIAL = 13;
pub const PREFIX = 10;
pub const DOUBLES = 64;
pub const ADDS = 23;
pub const TRANSITIONS = 87;
pub const DOUBLE_ROWS = PREFIX + DOUBLES * 24;
pub const ADD_ROWS = ADDS * 22;
pub const VALUES = INITIAL + DOUBLE_ROWS + ADD_ROWS;
pub const EXPORTS = TRANSITIONS * 6 + 6;
pub const FRONTIER_ROWS = INITIAL + EXPORTS;
pub const ID = u16;
pub const UNUSED = std.math.maxInt(ID);
pub const ATE = [_]i8{ 0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, 1, 1 };
pub const PSI_X: FQ2 = .{ 21575463638280843010398324269430826099269044274347216827212613867836435027261, 10307601595873709700152284273816112264069230130616436755625194854815875713954 };
pub const PSI_Y: FQ2 = .{ 2821565182194536844548159561693502659359617185244120367078079554186484126554, 3505843767911556378687030309984248845540243509899259641013678093033130930403 };
pub fn inputs(kind: Kind) usize {
    return Base.inputs(kind);
}
/// The double component shares one envelope with its ten prefix equations.
pub fn rows(kind: Kind) usize {
    return if (kind == .doubling) PREFIX + 24 else 22;
}
pub fn terms(comptime kind: Kind, comptime opcode: usize) []const B.Term {
    if (kind == .addition) return Base.terms(.addition, opcode);
    if (opcode >= PREFIX) return Base.terms(.doubling, opcode - PREFIX);
    const result = comptime blk: {
        var list: [3]B.Term = undefined;
        if (opcode < 2) {
            list[0] = .{ .a = .{ .in = 0 }, .coef = -1 };
            list[1] = .{ .a = .{ .out = 0 }, .coef = -1 };
            break :blk list[0..2].*;
        }
        const imaginary = opcode % 2 == 1;
        const negative = opcode >= 8;
        list[0] = .{ .a = .{ .in = 0 }, .b = .{ .in = if (imaginary) 3 else 2 }, .coef = if (negative) -1 else 1 };
        list[1] = .{ .a = .{ .in = 1 }, .b = .{ .in = if (imaginary) 2 else 3 }, .coef = if (imaginary != negative) -1 else 1 };
        list[2] = .{ .a = .{ .out = 0 }, .coef = -1 };
        break :blk list;
    };
    return &result;
}
pub fn envelope(comptime kind: Kind) B.Def {
    const mass = comptime blk: {
        var maximum: [4]i32 = @splat(0);
        for (0..rows(kind)) |opcode| {
            var current: [4]i32 = @splat(0);
            for (terms(kind, opcode)) |t| current[(if (t.b != null) @as(usize, 0) else 2) + @as(usize, @intFromBool(t.coef < 0))] += @intCast(@abs(t.coef));
            for (&maximum, current) |*m, c| m.* = @max(m.*, c);
        }
        break :blk maximum;
    };
    const relation = &[_]B.Term{ .{ .a = .{ .in = 0 }, .b = .{ .in = 1 }, .coef = mass[0] }, .{ .a = .{ .in = 2 }, .b = .{ .in = 3 }, .coef = -mass[1] }, .{ .a = .{ .in = 4 }, .coef = mass[2] }, .{ .a = .{ .out = 0 }, .coef = -mass[3] } };
    return .{ .limbs = 32, .coords = inputs(kind), .written = 1, .inputs = inputs(kind), .outputs = 1, .witnesses = 0, .modulus = .{ .constant = B.BN254_P }, .asymmetric_carries = true, .relations = &.{relation} };
}
pub fn commonGeometry(comptime kind: Kind) B.RelationGeometry {
    const d = envelope(kind);
    return B.deriveRelation(d, d.relations[0]);
}
pub const Node = struct { writer: ID, input: [10]ID, opcode: u8 };
pub const Transition = struct { kind: Kind, digit: i8, row_start: usize, point: [6]ID, line: [6]ID, line_scale: [3]i32 };
pub const Program = struct {
    doubles: [DOUBLE_ROWS]Node = undefined,
    adds: [ADD_ROWS]Node = undefined,
    transitions: [TRANSITIONS]Transition = undefined,
    double_count: usize = 0,
    add_count: usize = 0,
    transition_count: usize = 0,
    next: ID = INITIAL,
    final_point: [6]ID = undefined,
    fn append(self: *Program, comptime kind: Kind, state: [6]ID, q: [4]ID, digit: i8) [6]ID {
        const p = comptime Base.program(kind);
        var local: [40]ID = @splat(UNUSED);
        @memcpy(local[0..6], &state);
        if (kind == .doubling) {
            local[6] = 6;
            local[7] = 7;
            local[8] = 8;
        } else @memcpy(local[6..10], &q);
        const first = self.next;
        inline for (0..comptime Base.rows(kind)) |step| local[Base.initialCount(kind) + step] = first + step;
        const row_start = if (kind == .doubling) self.double_count else self.add_count;
        inline for (0..comptime Base.rows(kind)) |step| {
            var node = Node{ .writer = first + step, .input = @splat(UNUSED), .opcode = @intCast(if (kind == .doubling) PREFIX + step else step) };
            for (comptime Base.operandIds(kind, step), 0..) |id, i| if (id != Base.UNUSED) {
                node.input[i] = local[id];
            };
            if (kind == .doubling) {
                self.doubles[self.double_count] = node;
                self.double_count += 1;
            } else {
                self.adds[self.add_count] = node;
                self.add_count += 1;
            }
        }
        self.next += Base.rows(kind);
        var point: [6]ID = undefined;
        var line: [6]ID = undefined;
        for (p.point, p.line, &point, &line) |pi, li, *po, *lo| {
            po.* = local[pi];
            lo.* = local[li];
        }
        self.transitions[self.transition_count] = .{ .kind = kind, .digit = digit, .row_start = row_start, .point = point, .line = line, .line_scale = p.line_scale };
        self.transition_count += 1;
        return point;
    }
};
pub fn program() Program {
    @setEvalBranchQuota(10_000_000);
    var p = Program{};
    for (0..PREFIX) |opcode| {
        var node = Node{ .writer = @intCast(INITIAL + opcode), .input = @splat(UNUSED), .opcode = @intCast(opcode) };
        if (opcode < 2) node.input[0] = @intCast(2 + opcode) else {
            const ids: [4]ID = switch (opcode) {
                2, 3 => .{ 0, 1, 9, 10 },
                4, 5 => .{ 2, 3, 11, 12 },
                6, 7 => .{ 15, 16, 9, 10 },
                8, 9 => .{ 17, 18, 11, 12 },
                else => unreachable,
            };
            @memcpy(node.input[0..4], &ids);
        }
        p.doubles[p.double_count] = node;
        p.double_count += 1;
        p.next += 1;
    }
    var state: [6]ID = .{ 0, 1, 2, 3, 4, 5 };
    for (0..64) |index| {
        state = p.append(.doubling, state, @splat(UNUSED), 0);
        const digit = ATE[63 - index];
        if (digit != 0) state = p.append(.addition, state, if (digit == 1) .{ 0, 1, 2, 3 } else .{ 0, 1, 13, 14 }, digit);
    }
    state = p.append(.addition, state, .{ 15, 16, 17, 18 }, 2);
    state = p.append(.addition, state, .{ 19, 20, 21, 22 }, 3);
    p.final_point = state;
    std.debug.assert(p.next == VALUES and p.double_count == DOUBLE_ROWS and p.add_count == ADD_ROWS and p.transition_count == TRANSITIONS);
    return p;
}
pub fn fanout(p: *const Program) [VALUES]u32 {
    var counts: [VALUES]u32 = @splat(0);
    for (p.doubles) |node| for (node.input[0..6]) |id| {
        if (id != UNUSED) counts[id] += 1;
    };
    for (p.adds) |node| for (node.input) |id| {
        if (id != UNUSED) counts[id] += 1;
    };
    for (p.transitions) |transition| for (transition.line) |id| {
        counts[id] += 1;
    };
    for (p.final_point) |id| counts[id] += 1;
    return counts;
}
pub fn initialValues(q: [2]FQ2) ![INITIAL]u256 {
    var initial: [INITIAL]u256 = undefined;
    for (q, 0..) |pair, i| for (pair, 0..) |value, j| {
        if (value >= B.BN254_P) return error.NonCanonicalPreparationQ;
        initial[2 * i + j] = value;
    };
    initial[4] = 1;
    initial[5] = 0;
    initial[6] = (B.BN254_P + 1) / 2;
    initial[7] = Base.TWIST_B[0];
    initial[8] = Base.TWIST_B[1];
    @memcpy(initial[9..11], &PSI_X);
    @memcpy(initial[11..13], &PSI_Y);
    return initial;
}
