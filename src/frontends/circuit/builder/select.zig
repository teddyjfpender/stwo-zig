//! Multiplexer over wires.
//!
//! Port of `select_by_index` in `crates/circuits/src/utils.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). The byte/word helpers of that
//! file live with their only user, `blake.zig`.

const std = @import("std");
const context_mod = @import("context.zig");

const Var = context_mod.Var;
const Error = context_mod.Error;

/// `select_by_index`: `values[index]`, where `index_bits` is the
/// little-endian bit decomposition of `index` (each a 0/1 wire) and
/// `values.len == 2^index_bits.len`. Costs `3(n - 1) + log2(n)` gates.
pub fn selectByIndex(comptime V: type, ctx: *context_mod.Context(V), values: []const Var, index_bits: []const Var) Error!Var {
    std.debug.assert(values.len == @as(usize, 1) << @intCast(index_bits.len));
    const layer = try ctx.scratch().dupe(Var, values);
    var layer_len = layer.len;
    for (index_bits) |bit| {
        const one_minus_bit = try ctx.sub(ctx.one(), bit);
        var i: usize = 0;
        while (i < layer_len) : (i += 2) {
            // ((one_minus_bit) * (left)) + ((bit) * (right))
            const left = try ctx.mul(one_minus_bit, layer[i]);
            const right = try ctx.mul(bit, layer[i + 1]);
            layer[i >> 1] = try ctx.add(left, right);
        }
        layer_len >>= 1;
    }
    return layer[0];
}

test "select: picks the indexed value and satisfies the circuit" {
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    const ivalue = @import("ivalue.zig");
    var ctx = try context_mod.Context(QM31).init(std.testing.allocator, 0);
    defer ctx.deinit();
    var values: [8]Var = undefined;
    for (&values, 0..) |*v, i| v.* = try ctx.guess(ivalue.qm31FromU32s(@intCast(10 + i), @intCast(i), 0, 1));
    for (0..8) |index| {
        var bits: [3]Var = undefined;
        for (&bits, 0..) |*bit, b| bit.* = try ctx.guess(ivalue.qm31FromU32s(@intCast((index >> @intCast(b)) & 1), 0, 0, 0));
        const selected = try selectByIndex(QM31, &ctx, &values, &bits);
        try std.testing.expect(ctx.get(selected).eql(ctx.get(values[index])));
    }
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
