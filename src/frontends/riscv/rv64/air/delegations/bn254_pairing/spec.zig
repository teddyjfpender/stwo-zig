//! One source-owned canonical SSA DAG: four finite pairing inputs -> ONE.
//! Source only. No VM tag, physical proof, production or recursion admission.
const std = @import("std");
pub const M = @import("../bn254_miller/spec.zig");
pub const MW = @import("../bn254_miller/witness.zig");
pub const SG = @import("../bn254_g2/subgroup/spec.zig");
pub const R = @import("../bn254_residue/spec.zig");
pub const RW = @import("../bn254_residue/witness.zig");
pub const B = M.B;
pub const ID = u32;
pub const NONE = std.math.maxInt(ID);
pub const SG_ROM = SG.program();
const SG_ASSERTED = blk: {
    var flags: [SG.INITIAL + SG.MAX_NODES]bool = @splat(false);
    for (SG_ROM.assertions[0..SG_ROM.assertion_count]) |id| flags[id] = true;
    break :blk flags;
};
pub const LITERALS: struct { values: [36]u256, len: usize } = blk: {
    var values: [36]u256 = @splat(0);
    var len: usize = 0;
    const initial = M.initialValues(.{ .p = @splat(.{ 0, 0 }), .q = @splat(.{ .{ 0, 0 }, .{ 0, 0 } }) }) catch unreachable;
    for (initial[24..]) |value| {
        values[len] = value;
        len += 1;
    }
    for (R.Frobenius.POOL) |value| {
        var found = false;
        for (values[0..len]) |v| {
            if (v == value) found = true;
        }
        if (!found) {
            values[len] = value;
            len += 1;
        }
    }
    break :blk .{ .values = values, .len = len };
};
pub const INITIAL = 24 + LITERALS.len;
pub const SG_HINTS = 4 * 352;
pub const HINTS = SG_HINTS + R.PRIVATE_HINTS;
pub const ARITHMETIC = M.ROWS + 4 * (4390 - 352) + R.SQUARE_ROWS + R.MULTIPLY_ROWS + R.FROBENIUS_ROWS;
pub const ROWS = ARITHMETIC + HINTS;
pub const VALUES = INITIAL + ROWS;
pub const ASSERTIONS = 4 + 4 * 358 + 24;
pub const Kind = enum { g1, prep_double, prep_add, scale, square, sparse, subgroup, res_square, res_multiply, res_frobenius, hint };
pub const Hint = enum { none, inverse, provided };
pub const Node = struct { kind: Kind, opcode: u8, writer: ID, input: [24]ID = @splat(NONE), asserted: ?u8 = null, hint: Hint = .none, hint_denominator: ID = NONE };
pub const Assertion = struct { id: ID, value: u8 };
pub const Program = struct {
    nodes: [ROWS]Node = undefined,
    count: usize = 0,
    next: ID = INITIAL,
    assertions: [ASSERTIONS]Assertion = undefined,
    assertion_count: usize = 0,
    sg_base: [4]ID = undefined,
    residue_hints: ID = undefined,
    residue_base: ID = undefined,
    output: [12]ID = undefined,
    fn append(p: *Program, node_: Node) void {
        var node = node_;
        node.writer = p.next;
        p.nodes[p.count] = node;
        p.count += 1;
        p.next += 1;
        if (node.asserted) |value| {
            p.assertions[p.assertion_count] = .{ .id = node.writer, .value = value };
            p.assertion_count += 1;
        }
    }
    pub fn millerId(_: *const Program, id: M.ID) ID {
        if (id < 24) return id;
        if (id < M.INITIAL) return literalId(LITERALS.values[id - 24]);
        return @intCast(INITIAL + id - M.INITIAL);
    }
    pub fn subgroupId(p: *const Program, group: usize, id: SG.ID) ID {
        if (id < 4) return @intCast(group * 6 + 2 + id);
        if (id == 4) return literalId(SG.G2.TWIST_B[0]);
        if (id == 5) return literalId(SG.G2.TWIST_B[1]);
        if (id == 6) return literalId(1);
        return p.sg_base[group] + id - SG.INITIAL;
    }
    pub fn residueId(p: *const Program, id: R.ID) ID {
        if (id < 12) return p.millerId(MW.ROM.output[id]);
        if (id < R.INITIAL) return literalId(R.Frobenius.POOL[id - 12]);
        if (id < R.INITIAL + R.PRIVATE_HINTS) return @intCast(p.residue_hints + id - R.INITIAL);
        return @intCast(p.residue_base + id - R.INITIAL - R.PRIVATE_HINTS);
    }
};
pub fn literalId(value: u256) ID {
    for (LITERALS.values[0..LITERALS.len], 0..) |v, i| if (v == value) return @intCast(24 + i);
    unreachable;
}
pub fn inputs(kind: Kind) usize {
    return switch (kind) {
        .g1 => 3,
        .prep_double => 6,
        .prep_add => 10,
        .scale => 2,
        .square, .res_square => 12,
        .sparse => 18,
        .subgroup => 7,
        .res_multiply => 24,
        .res_frobenius => 4,
        .hint => 0,
    };
}
pub fn terms(comptime kind: Kind, comptime opcode: usize) []const B.Term {
    return switch (kind) {
        .g1 => M.terms(.g1, opcode),
        .prep_double => M.terms(.prep_double, opcode),
        .prep_add => M.terms(.prep_add, opcode),
        .scale => M.terms(.scale, opcode),
        .square => M.terms(.square, opcode),
        .sparse => M.terms(.sparse, opcode),
        .subgroup => SG.terms(.quadratic, opcode),
        .res_square => R.terms(.square, opcode),
        .res_multiply => R.terms(.multiply, opcode),
        .res_frobenius => R.terms(.frobenius, opcode),
        .hint => @compileError("canonical hints have no arithmetic expression"),
    };
}
pub fn opcodes(comptime kind: Kind) usize {
    return switch (kind) {
        .g1 => 4,
        .prep_double => M.Prep.rows(.doubling),
        .prep_add => M.Prep.rows(.addition),
        .scale => 3,
        .square, .sparse, .res_square, .res_multiply => 12,
        .subgroup => SG.OPCODES,
        .res_frobenius => 36,
        .hint => 0,
    };
}
pub fn program() Program {
    @setEvalBranchQuota(8_000_000);
    var p = Program{};
    for (MW.ROM.nodes) |old| {
        var node = Node{ .kind = @enumFromInt(@intFromEnum(old.kind)), .opcode = old.opcode, .writer = p.next, .asserted = if (old.must_zero) 0 else null };
        for (old.input, &node.input) |id, *to| if (id != M.NONE) {
            to.* = p.millerId(id);
        };
        const want = p.millerId(old.writer);
        p.append(node);
        std.debug.assert(p.next - 1 == want);
    }
    for (0..4) |group| {
        p.sg_base[group] = p.next;
        for (SG_ROM.nodes[0..SG_ROM.count]) |old| {
            var node = Node{ .kind = if (old.op == .hint_norm_inverse) .hint else .subgroup, .opcode = @intFromEnum(old.op), .writer = p.next };
            if (old.op == .hint_norm_inverse) {
                node.hint = .inverse;
                node.hint_denominator = p.subgroupId(group, old.input[0]);
            } else {
                for (old.input[0..SG.arity(old.op)], node.input[0..SG.arity(old.op)]) |id, *to| to.* = p.subgroupId(group, id);
            }
            if (SG_ASSERTED[old.writer]) node.asserted = 0;
            p.append(node);
        }
    }
    p.residue_hints = p.next;
    for (0..R.PRIVATE_HINTS) |_| p.append(.{ .kind = .hint, .opcode = 0, .writer = p.next, .hint = .provided });
    p.residue_base = p.next;
    for (RW.ROM.operations) |operation| {
        const kind: Kind = switch (operation.kind) {
            .square => .res_square,
            .multiply => .res_multiply,
            .frobenius => .res_frobenius,
        };
        for (0..12) |coordinate| {
            const old = switch (operation.kind) {
                .square => RW.ROM.squares[operation.row_start + coordinate],
                .multiply => RW.ROM.multiplies[operation.row_start + coordinate],
                .frobenius => RW.ROM.frobenius[operation.row_start + coordinate],
            };
            var node = Node{ .kind = kind, .opcode = old.opcode, .writer = p.next, .asserted = if (old.pin_one) @intFromBool(old.opcode == 0) else null };
            for (old.input[0..inputs(kind)], node.input[0..inputs(kind)]) |id, *to| to.* = p.residueId(id);
            const want = p.residueId(old.writer);
            p.append(node);
            std.debug.assert(p.next - 1 == want);
        }
    }
    for (RW.ROM.final, &p.output) |id, *to| to.* = p.residueId(id);
    std.debug.assert(p.count == ROWS and p.next == VALUES and p.assertion_count == ASSERTIONS);
    return p;
}
pub fn initialValues(input: M.Input) ![INITIAL]u256 {
    const m = try M.initialValues(input);
    for (input.p) |p| if (p[0] == 0 and p[1] == 0) return error.PairingG1InfinityExcluded;
    for (input.q) |q| {
        _ = try SG.initialValues(q);
    }
    var out: [INITIAL]u256 = undefined;
    @memcpy(out[0..24], m[0..24]);
    @memcpy(out[24..], LITERALS.values[0..LITERALS.len]);
    return out;
}
pub const ScalarTerm = M.ScalarTerm;
pub const Expression = struct { terms: [145]ScalarTerm = undefined, len: usize = 0, output: ID, asserted: ?u8 };
pub fn expression(node: Node) Expression {
    @setEvalBranchQuota(1_000_000);
    inline for (comptime std.meta.tags(Kind)) |kind| if (node.kind == kind and kind != .hint) {
        inline for (0..comptime opcodes(kind)) |opcode| if (node.opcode == opcode) {
            var out = Expression{ .output = node.writer, .asserted = node.asserted };
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
pub fn fanout(p: *const Program) [VALUES]u32 {
    var counts: [VALUES]u32 = @splat(0);
    for (p.nodes) |node| {
        if (node.kind != .hint) {
            const expression_ = expression(node);
            for (expression_.terms[0..expression_.len]) |term| {
                counts[term.a] += 1;
                if (term.b) |id| counts[id] += 1;
            }
        }
    }
    for (p.assertions) |obligation| counts[obligation.id] += 1;
    return counts;
}
