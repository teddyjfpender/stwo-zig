//! Sorting a query's column values into committed order: port of
//! `crates/stark_verifier/src/sort_queries.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).
//!
//! Each value is tagged with `(log_size << column_idx_bits | column_idx) * u`,
//! the tagged values go through one permutation sorted on the `u`
//! coordinate, and the sorted keys are range-checked once (the first query
//! of a tree) and then required equal for every later query.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const verify = @import("verify.zig");

const QM31 = core.fields.qm31.QM31;
const Var = builder.Var;
const Context = builder.Context;
const Error = builder.context.Error;
const simd = builder.simd;
const ivalue = builder.ivalue;
const M31Wrapper = builder.wrappers.M31Wrapper;

pub const QuerySorter = struct {
    /// `LOG_SIZE_BITS + column_idx_bits`; unused when sorting is skipped.
    key_bits: u32,
    /// Per column, its sort key; empty when sorting is skipped.
    sort_keys: []const Var,
    /// The sorted keys of the first sort; empty before it.
    sorted_keys: []const Var,

    /// `QuerySorter::new`: generates the sort keys of `column_log_sizes`.
    pub fn init(comptime V: type, ctx: *Context(V), column_log_sizes: []const Var) Error!QuerySorter {
        const column_idx_bits: u32 = std.math.log2_int(usize, std.math.ceilPowerOfTwoAssert(usize, @max(column_log_sizes.len, 1)));
        const key_bits = verify.LOG_SIZE_BITS + column_idx_bits;
        // Keys must fit in M31 and the diff range check must be sound.
        std.debug.assert(key_bits <= 30);
        return .{
            .key_bits = key_bits,
            .sort_keys = try generateSortKeys(V, ctx, column_log_sizes, column_idx_bits),
            .sorted_keys = &.{},
        };
    }

    /// `QuerySorter::skip_sorting`.
    pub fn skipSorting() QuerySorter {
        return .{ .key_bits = 0, .sort_keys = &.{}, .sorted_keys = &.{} };
    }

    /// `QuerySorter::sort`: the query values in committed order
    /// (scratch-owned).
    pub fn sort(self: *QuerySorter, comptime V: type, ctx: *Context(V), values: []const M31Wrapper(Var)) Error![]const M31Wrapper(Var) {
        if (self.sort_keys.len == 0) return values;
        std.debug.assert(values.len == self.sort_keys.len);
        const scratch = ctx.scratch();

        const tagged = try scratch.alloc(Var, values.len);
        for (tagged, values, self.sort_keys) |*out, value, key| out.* = try ctx.add(value.get(), key);
        const sorted = try ctx.permute(tagged, ivalue.sortByUCoordinate(V));

        const sorted_values = try scratch.alloc(M31Wrapper(Var), sorted.len);
        const sorted_keys = try scratch.alloc(Var, sorted.len);
        for (sorted, sorted_values, sorted_keys) |v, *value, *key| {
            const low = try ctx.pointwiseMul(v, ctx.one());
            value.* = .newUnsafe(low);
            key.* = try ctx.sub(v, low);
        }

        if (self.sorted_keys.len == 0) {
            // The first sort: range-check the order and keep it.
            try self.verifySortedKeys(V, ctx, sorted_keys);
            self.sorted_keys = sorted_keys;
        } else {
            for (sorted_keys, self.sorted_keys) |key, previous| try ctx.eq(key, previous);
        }
        return sorted_values;
    }

    /// `verify_sorted_keys`: every consecutive difference of the `u`-scaled
    /// keys lies in `[0, 2^key_bits)`, which (with `key_bits <= 30`) rejects
    /// every negative difference.
    fn verifySortedKeys(self: *const QuerySorter, comptime V: type, ctx: *Context(V), sorted_keys: []const Var) Error!void {
        if (sorted_keys.len == 0) return;
        const u_inverse = try ctx.constant(QM31.fromU32Unchecked(0, 0, 1, 0).inv() catch unreachable);
        const diffs = try ctx.scratch().alloc(M31Wrapper(Var), sorted_keys.len - 1);
        for (diffs, sorted_keys[0 .. sorted_keys.len - 1], sorted_keys[1..]) |*diff, current, next| {
            const u_diff = try ctx.sub(next, current);
            diff.* = .newUnsafe(try ctx.mul(u_diff, u_inverse));
        }
        const packed_diffs = try simd.pack(V, ctx, diffs);
        _ = try builder.extract_bits.extractBits(V, ctx, packed_diffs, self.key_bits);
    }
};

/// `generate_sort_keys`: `u * (log_size * 2^column_idx_bits + column_idx)`.
fn generateSortKeys(comptime V: type, ctx: *Context(V), column_log_sizes: []const Var, column_idx_bits: u32) Error![]const Var {
    const u = ctx.u();
    const shift = try ctx.constant(ivalue.qm31FromU32s(@as(u32, 1) << @intCast(column_idx_bits), 0, 0, 0));
    const keys = try ctx.scratch().alloc(Var, column_log_sizes.len);
    for (keys, column_log_sizes, 0..) |*key, log_size, column_idx| {
        const shifted_log_size = try ctx.mul(log_size, shift);
        const tag = try ctx.add(shifted_log_size, try ctx.constant(ivalue.qm31FromU32s(@intCast(column_idx), 0, 0, 0)));
        key.* = try ctx.mul(u, tag);
    }
    return keys;
}
