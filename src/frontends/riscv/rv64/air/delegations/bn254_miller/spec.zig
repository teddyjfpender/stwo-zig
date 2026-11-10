//! Four-pair immutable shared Miller source. No VM/production admission.
//! P/Q are initial values; every later preparation/line/accumulator is a writer.
const std = @import("std");
pub const Prep = @import("../bn254_g2/preparation/spec.zig");
pub const Dense = @import("../bn254_dense/spec.zig");
pub const B = Dense.B;
pub const ID = u32;
pub const NONE = std.math.maxInt(ID);
pub const GROUPS = 4;
pub const LINES = 87;
pub const INITIAL = GROUPS * 6 + 9;
pub const ONE: ID = GROUPS * 6;
pub const ZERO: ID = ONE + 1;
pub const SQUARES = 63;
pub const SPARSE_PRODUCTS = GROUPS * LINES - 1;
pub const SCALE_ROWS = GROUPS * LINES * 4;
pub const PREP_ROWS = GROUPS * (Prep.DOUBLE_ROWS + Prep.ADD_ROWS);
pub const G1_ROWS = GROUPS * 4;
pub const ROWS = PREP_ROWS + G1_ROWS + SCALE_ROWS + SQUARES * 12 + SPARSE_PRODUCTS * 12;
pub const VALUES = INITIAL + ROWS;
pub const Kind = enum { g1, prep_double, prep_add, scale, square, sparse };
pub fn inputs(kind: Kind) usize {
    return switch (kind) {
        .g1 => 3,
        .prep_double => Prep.inputs(.doubling),
        .prep_add => Prep.inputs(.addition),
        .scale => 2,
        .square => 12,
        .sparse => 18,
    };
}
pub fn terms(comptime kind: Kind, comptime opcode: usize) []const B.Term {
    if (kind == .prep_double) return Prep.terms(.doubling, opcode);
    if (kind == .prep_add) return Prep.terms(.addition, opcode);
    if (kind == .square) return Dense.terms(.square, opcode);
    if (kind == .sparse) {
        const out = comptime blk: {
            @setEvalBranchQuota(100_000);
            const indices = [_]usize{ 0, 1, 6, 7, 8, 9 };
            var list: [73]B.Term = undefined;
            var n: usize = 0;
            for (0..12) |a| for (indices, 0..) |b, j| {
                const coefficient = Dense.basis(a, b)[opcode];
                if (coefficient != 0) {
                    list[n] = .{ .a = .{ .in = @intCast(a) }, .b = .{ .in = @intCast(12 + j) }, .coef = coefficient };
                    n += 1;
                }
            };
            list[n] = .{ .a = .{ .out = 0 }, .coef = -1 };
            break :blk list[0 .. n + 1].*;
        };
        return &out;
    }
    if (kind == .scale) return &.{ .{ .a = .{ .in = 0 }, .b = .{ .in = 1 }, .coef = switch (opcode) {
        0 => -1,
        1 => 3,
        2 => 1,
        else => @compileError("scale opcode"),
    } }, .{ .a = .{ .out = 0 }, .coef = -1 } };
    return switch (opcode) {
        0 => &.{ .{ .a = .{ .in = 0 }, .b = .{ .in = 0 }, .coef = 1 }, .{ .a = .{ .out = 0 }, .coef = -1 } },
        1 => &.{ .{ .a = .{ .in = 0 }, .b = .{ .in = 1 }, .coef = 1 }, .{ .a = .{ .out = 0 }, .coef = -1 } },
        2 => &.{ .{ .a = .{ .in = 0 }, .b = .{ .in = 0 }, .coef = 1 }, .{ .a = .{ .out = 0 }, .coef = -1 } },
        3 => &.{ .{ .a = .{ .in = 0 }, .coef = 1 }, .{ .a = .{ .in = 1 }, .coef = -1 }, .{ .a = .{ .in = 2 }, .coef = -3 }, .{ .a = .{ .out = 0 }, .coef = -1 } },
        else => @compileError("G1 opcode"),
    };
}
pub const Node = struct { kind: Kind, opcode: u8, writer: ID, input: [24]ID = @splat(NONE), must_zero: bool = false };
pub const Vector = [12]ID;
pub const Line = struct { group: u8, ordinal: u8, raw: [6]ID, scaled: [6]ID, before: Vector, after: Vector, aliased_one: bool };
pub const Program = struct {
    nodes: [ROWS]Node = undefined,
    lines: [GROUPS * LINES]Line = undefined,
    squares: [SQUARES]Vector = undefined,
    next: ID = INITIAL,
    count: usize = 0,
    line_count: usize = 0,
    square_count: usize = 0,
    prep_base: [GROUPS]ID = undefined,
    checks: [GROUPS]ID = undefined,
    output: Vector = undefined,
    fn append(p: *Program, kind: Kind, opcode: u8, ids: []const ID, must_zero: bool) ID {
        const writer = p.next;
        var node = Node{ .kind = kind, .opcode = opcode, .writer = writer, .must_zero = must_zero };
        @memcpy(node.input[0..ids.len], ids);
        p.nodes[p.count] = node;
        p.count += 1;
        p.next += 1;
        return writer;
    }
    pub fn prepId(p: *const Program, group: usize, id: Prep.ID) ID {
        if (id < 4) return @intCast(group * 6 + 2 + id);
        if (id < Prep.INITIAL) return ONE + id - 4;
        return p.prep_base[group] + id - Prep.INITIAL;
    }
    fn prepNode(p: *Program, group: usize, kind: Kind, node: Prep.Node) void {
        var ids: [10]ID = @splat(NONE);
        for (node.input, &ids) |id, *target| if (id != Prep.UNUSED) {
            target.* = p.prepId(group, id);
        };
        const actual = p.append(kind, node.opcode, ids[0..inputs(kind)], false);
        std.debug.assert(actual == p.prepId(group, @intCast(node.writer)));
    }
    fn square(p: *Program, accumulator: Vector) Vector {
        var out: Vector = undefined;
        for (&out, 0..) |*id, coordinate| id.* = p.append(.square, @intCast(coordinate), &accumulator, false);
        p.squares[p.square_count] = out;
        p.square_count += 1;
        return out;
    }
    fn line(p: *Program, source: *const Prep.Program, group: usize, ordinal: usize, before: Vector) Vector {
        const transition = source.transitions[ordinal];
        std.debug.assert(transition.line_scale[2] == 1);
        var raw: [6]ID = undefined;
        for (transition.line, &raw) |id, *out| out.* = p.prepId(group, id);
        var scaled: [6]ID = undefined;
        for (0..4) |i| {
            const coefficient = transition.line_scale[i / 2];
            const opcode: u8 = if (coefficient == -1) 0 else if (coefficient == 3) 1 else if (coefficient == 1) 2 else unreachable;
            scaled[i] = p.append(.scale, opcode, &.{ raw[i], @intCast(group * 6 + (if (i < 2) @as(usize, 1) else 0)) }, false);
        }
        @memcpy(scaled[4..], raw[4..]);
        var after: Vector = undefined;
        const aliased = p.line_count == 0;
        if (aliased) {
            after = .{ scaled[0], scaled[1], ZERO, ZERO, ZERO, ZERO, scaled[2], scaled[3], scaled[4], scaled[5], ZERO, ZERO };
        } else {
            var ids: [18]ID = undefined;
            @memcpy(ids[0..12], &before);
            @memcpy(ids[12..], &scaled);
            for (&after, 0..) |*id, coordinate| id.* = p.append(.sparse, @intCast(coordinate), &ids, false);
        }
        p.lines[p.line_count] = .{ .group = @intCast(group), .ordinal = @intCast(ordinal), .raw = raw, .scaled = scaled, .before = before, .after = after, .aliased_one = aliased };
        p.line_count += 1;
        return after;
    }
};
pub fn program() Program {
    @setEvalBranchQuota(2_000_000);
    const prep = Prep.program();
    var p = Program{};
    for (0..GROUPS) |group| {
        const x: ID = @intCast(group * 6);
        const y = x + 1;
        const x2 = p.append(.g1, 0, &.{x}, false);
        const x3 = p.append(.g1, 1, &.{ x2, x }, false);
        const y2 = p.append(.g1, 2, &.{y}, false);
        p.checks[group] = p.append(.g1, 3, &.{ y2, x3, ONE }, true);
    }
    for (0..GROUPS) |group| {
        p.prep_base[group] = p.next;
        for (prep.doubles[0..Prep.PREFIX]) |node| p.prepNode(group, .prep_double, node);
        for (prep.transitions) |t| {
            if (t.kind == .doubling) {
                for (prep.doubles[t.row_start..][0..24]) |node| p.prepNode(group, .prep_double, node);
            } else {
                for (prep.adds[t.row_start..][0..22]) |node| p.prepNode(group, .prep_add, node);
            }
        }
    }
    var accumulator: Vector = @splat(ZERO);
    accumulator[0] = ONE;
    var ordinal: usize = 0;
    for (0..64) |i| {
        if (i != 0) accumulator = p.square(accumulator);
        for (0..GROUPS) |group| accumulator = p.line(&prep, group, ordinal, accumulator);
        ordinal += 1;
        if (Prep.ATE[63 - i] != 0) {
            for (0..GROUPS) |group| accumulator = p.line(&prep, group, ordinal, accumulator);
            ordinal += 1;
        }
    }
    for (0..2) |_| {
        for (0..GROUPS) |group| accumulator = p.line(&prep, group, ordinal, accumulator);
        ordinal += 1;
    }
    std.debug.assert(ordinal == LINES and p.line_count == GROUPS * LINES and p.square_count == SQUARES and p.count == ROWS and p.next == VALUES);
    p.output = accumulator;
    return p;
}
pub const Input = struct { p: [GROUPS][2]u256, q: [GROUPS][2][2]u256 };
pub fn initialValues(input: Input) ![INITIAL]u256 {
    var out: [INITIAL]u256 = undefined;
    for (0..GROUPS) |g| {
        for (input.p[g], 0..) |v, j| {
            if (v >= B.BN254_P) return error.NonCanonicalMillerP;
            out[g * 6 + j] = v;
        }
        const q = try Prep.initialValues(input.q[g]);
        @memcpy(out[g * 6 + 2 ..][0..4], q[0..4]);
        if (g == 0) @memcpy(out[ONE..][0..9], q[4..13]);
    }
    return out;
}

/// Every arithmetic read, G1 ZERO assertion and final z export has source-owned mass.
/// Later composite sources replace these exports with actual residue reader IDs.
pub fn fanout(p: *const Program) [VALUES]u32 {
    var counts: [VALUES]u32 = @splat(0);
    for (p.nodes) |node| for (node.input[0..inputs(node.kind)]) |id| {
        if (id != NONE) counts[id] += 1;
    };
    for (p.nodes) |node| if (node.must_zero) {
        counts[node.writer] += 1;
    };
    for (p.output) |id| counts[id] += 1;
    return counts;
}

/// Source-owned scalar expression exported for reviewed universal lowering.
/// It means sum(coefficient*a*(b or ONE)) = output. The normalizer must consume
/// ROM.nodes in order; this API does not admit producer-selected expressions.
pub const ScalarTerm = struct { a: ID, b: ?ID, coefficient: i32 };
pub const Expression = struct {
    terms: [145]ScalarTerm = undefined,
    len: usize = 0,
    output: ID,
    must_zero: bool,
};
pub fn expression(node: Node) Expression {
    @setEvalBranchQuota(1_000_000);
    inline for (comptime std.meta.tags(Kind)) |kind| if (node.kind == kind) {
        const count = comptime switch (kind) {
            .g1 => 4,
            .prep_double => Prep.rows(.doubling),
            .prep_add => Prep.rows(.addition),
            .scale => 3,
            .square, .sparse => 12,
        };
        inline for (0..count) |opcode| if (node.opcode == opcode) {
            var out = Expression{ .output = node.writer, .must_zero = node.must_zero };
            inline for (comptime terms(kind, opcode)) |term| {
                if (term.a == .in) {
                    out.terms[out.len] = .{ .a = node.input[term.a.in], .b = if (term.b) |b| node.input[b.in] else null, .coefficient = term.coef };
                    out.len += 1;
                } else comptime {
                    std.debug.assert(term.a.out == 0 and term.b == null and term.coef == -1);
                }
            }
            return out;
        };
    };
    unreachable;
}
