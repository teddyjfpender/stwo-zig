//! Query selection: port of `crates/stark_verifier/src/select_queries.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).
//!
//! One M31 lane per query is drawn from the channel, its low bits are the
//! query index in the evaluation domain, and the index is turned into the
//! domain point by selecting generators bit by bit.

const std = @import("std");
const builder = @import("../builder/mod.zig");
const channel_mod = @import("channel.zig");
const circle = @import("circle.zig");

const Var = builder.Var;
const Context = builder.Context;
const Error = builder.context.Error;
const simd = builder.simd;
const Simd = simd.Simd;

const EXTENSION_DEGREE = simd.extension_degree;

/// `Queries`.
pub const Queries = struct {
    /// `bits[i]` holds bit `i` (LSB first) of every query index.
    bits: []const Simd,
    /// The evaluation-domain point of every query.
    points: circle.Point(Simd),
};

/// `get_query_selection_input_from_channel`: `ceil(n_queries / 8)` draws of
/// two QM31s, one M31 lane per query.
pub fn getQuerySelectionInputFromChannel(comptime V: type, ctx: *Context(V), channel: *channel_mod.Channel, n_queries: usize) Error!Simd {
    const n_draws = std.math.divCeil(usize, n_queries, 2 * EXTENSION_DEGREE) catch unreachable;
    const drawn = try ctx.scratch().alloc(Var, 2 * n_draws);
    for (0..n_draws) |i| {
        const pair = try channel.drawTwoQm31s(V, ctx);
        drawn[2 * i] = pair[0];
        drawn[2 * i + 1] = pair[1];
    }
    const n_qm31s = std.math.divCeil(usize, n_queries, EXTENSION_DEGREE) catch unreachable;
    if (n_qm31s % 2 == 1) try ctx.markAsUnused(drawn[n_qm31s]);
    return .fromPacked(drawn[0..n_qm31s], n_queries);
}

/// `select_queries`.
pub fn selectQueries(comptime V: type, ctx: *Context(V), input: Simd, log_domain_size: usize) Error!Queries {
    const bits = (try builder.extract_bits.extractBits(V, ctx, input, 31))[0..log_domain_size];

    // Start from the generator of the subgroup of size `2 * domain_size`,
    // which moves every point to the canonic coset.
    var point = try circle.generatorPointSimd(V, ctx, log_domain_size + 1, input.len);
    for (bits[1..], 1..) |bit, i| {
        const generator = try circle.generatorPointSimd(V, ctx, i, input.len);
        const point_if_bit = try circle.addPointsSimd(V, ctx, point, generator);
        point = .{
            .x = try simd.select(V, ctx, bit, point.x, point_if_bit.x),
            .y = try simd.select(V, ctx, bit, point.y, point_if_bit.y),
        };
    }
    // The first bit may negate `y`.
    const neg_y = try negSimd(V, ctx, point.y);
    point.y = try simd.select(V, ctx, bits[0], point.y, neg_y);
    return .{ .bits = bits, .points = point };
}

/// `eval!(context, -(x))` on a `Simd`: `0 - x` lane-wise, zero interned after `x`.
pub fn negSimd(comptime V: type, ctx: *Context(V), x: Simd) Error!Simd {
    return simd.sub(V, ctx, try simd.zero(V, ctx, x.len), x);
}

test {
    _ = @import("select_queries_test.zig");
}
