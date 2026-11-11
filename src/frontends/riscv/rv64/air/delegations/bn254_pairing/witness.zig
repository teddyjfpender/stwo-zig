//! One canonical value namespace; no native Miller/subgroup acceptance flags.
const std = @import("std");
const S = @import("spec.zig");
pub const ROM = S.program();
pub const Private = struct { seed: [12]u256, scale: [6]u256, inverse2: [12]u256 };
fn inverse(value: u256) !u256 {
    if (value == 0) return error.PairingZeroDenominator;
    var t: i512 = 0;
    var next: i512 = 1;
    var r: u256 = S.B.BN254_P;
    var nr = value;
    while (nr != 0) {
        const q = r / nr;
        const replacement = t - @as(i512, q) * next;
        t = next;
        next = replacement;
        const rest = r % nr;
        r = nr;
        nr = rest;
    }
    return @intCast(@mod(t, @as(i512, S.B.BN254_P)));
}
pub fn evaluate(values: []const u256, node: S.Node) u256 {
    const e = S.expression(node);
    var positive: S.B.Big = 0;
    var negative: S.B.Big = 0;
    for (e.terms[0..e.len]) |term| {
        const magnitude = @as(S.B.Big, values[term.a]) * (if (term.b) |id| values[id] else 1) * @as(u32, @intCast(@abs(term.coefficient)));
        if (term.coefficient > 0) positive += magnitude else negative += magnitude;
    }
    return @intCast((positive % S.B.BN254_P + S.B.BN254_P - negative % S.B.BN254_P) % S.B.BN254_P);
}
pub const Witness = struct {
    allocator: std.mem.Allocator,
    initial: [S.INITIAL]u256,
    values: []u256,
    pub fn init(a: std.mem.Allocator, input: S.M.Input, private: Private) !Witness {
        const initial = try S.initialValues(input);
        const values = try a.alloc(u256, S.VALUES);
        errdefer a.free(values);
        @memcpy(values[0..S.INITIAL], &initial);
        var at: usize = 0;
        for (ROM.nodes) |node| {
            if (node.kind == .hint) {
                const value = if (node.hint == .inverse) try inverse(values[node.hint_denominator]) else blk: {
                    const v = if (at < 12) private.seed[at] else if (at < 18) private.scale[at - 12] else private.inverse2[at - 18];
                    at += 1;
                    break :blk v;
                };
                if (value >= S.B.BN254_P) return error.NonCanonicalPairingHint;
                values[node.writer] = value;
            } else values[node.writer] = evaluate(values, node);
        }
        std.debug.assert(at == 30);
        return .{ .allocator = a, .initial = initial, .values = values };
    }
    pub fn deinit(w: *Witness) void {
        w.allocator.free(w.values);
        w.* = undefined;
    }
    pub fn result(w: *const Witness) [12]u256 {
        var out: [12]u256 = undefined;
        for (ROM.output, &out) |id, *v| v.* = w.values[id];
        return out;
    }
    pub fn satisfied(w: *const Witness) bool {
        if (!std.mem.eql(u256, w.values[0..S.INITIAL], &w.initial)) return false;
        for (ROM.nodes) |node| {
            if (w.values[node.writer] >= S.B.BN254_P) return false;
            if (node.kind != .hint and evaluate(w.values, node) != w.values[node.writer]) return false;
        }
        for (ROM.assertions) |obligation| if (w.values[obligation.id] != obligation.value) return false;
        return true;
    }
    pub const Mutation = enum { swapped_subgroup_q, disconnected_residue_z, hint_modulus_alias };
    /// Recompute all later fields coherently under one false source binding.
    pub fn corruptForTesting(w: *Witness, mutation: Mutation) !void {
        if (!@import("builtin").is_test) @compileError("test-only composite source attack");
        var alias_done = false;
        for (ROM.nodes) |original| {
            var node = original;
            if (mutation == .swapped_subgroup_q and node.writer >= ROM.sg_base[0] and node.writer < ROM.sg_base[1]) {
                for (&node.input) |*id| if (id.* >= 2 and id.* < 6) {
                    id.* += 6;
                };
            }
            if (mutation == .disconnected_residue_z and node.writer >= ROM.residueId(S.RW.ROM.scaled[0]) and node.writer < ROM.residueId(S.RW.ROM.scaled[0]) + 12) {
                for (node.input[0..12], 0..) |*id, i| id.* = S.literalId(if (i == 0) 1 else 0);
            }
            if (node.kind == .hint) {
                if (node.hint == .inverse) {
                    w.values[node.writer] = try inverse(w.values[node.hint_denominator]);
                    if (mutation == .hint_modulus_alias and !alias_done) {
                        w.values[node.writer] += S.B.BN254_P;
                        alias_done = true;
                    }
                }
            } else w.values[node.writer] = evaluate(w.values, node);
        }
    }
};
