//! Yields and constrains every interned constant with arithmetic gates.
//!
//! Port of `crates/circuits/src/finalize_constants.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230), verbatim in gate order. All
//! constants derive from `u = (0, 0, 1, 0)`:
//!
//! - a `+1` chain `1+1=2, 2+1=3, …` up to the base `B = max(longest run of
//!   consecutive M31 constants from 0, min_base)`;
//! - base-`B` Horner decomposition for the other M31 constants;
//! - `x · (1,1,1,1)` for broadcast constants `(x, x, x, x)`;
//! - `a + b·i + (c + d·i)·u` over the basis `i = u² - 2`, `u`, `iu` for the rest.
//!
//! Order-bearing containers mirror upstream exactly:
//! - `IndexMap` is `AutoArrayHashMapUnmanaged`; `swap_remove` is `swapRemove`
//!   (the last entry moves into the hole) and `keys().next()` is `keys()[0]`;
//! - `IndexMap::retain` is `retainOrdered`, an order-preserving rebuild;
//! - the caches are unordered hash maps that are only probed, never iterated.
//!
//! The pass works on its own copies of the constant table, so
//! `Context.constant` keeps interning into the context's table afterwards.

const std = @import("std");
const stwo_core = @import("stwo_core");
const context_mod = @import("context.zig");
const ivalue = @import("ivalue.zig");

const Allocator = std.mem.Allocator;
const QM31 = stwo_core.fields.qm31.QM31;
const M31 = stwo_core.fields.m31.M31;
const Var = context_mod.Var;
const Error = context_mod.Error;

/// `DEFAULT_MIN_BASE`.
pub const default_min_base: u32 = 256;

/// `finalize_constants`: `finalizeConstantsWithMinBase` with the default base.
pub fn finalizeConstants(comptime V: type, ctx: *context_mod.Context(V)) Error!void {
    return finalizeConstantsWithMinBase(V, ctx, default_min_base);
}

const M31Constants = std.AutoArrayHashMapUnmanaged(u32, Var);
const Qm31Constants = std.AutoArrayHashMapUnmanaged(u128, Var);
const M31Cache = std.AutoHashMapUnmanaged(u32, Var);
const Qm31Cache = std.AutoHashMapUnmanaged(u128, Var);

fn Pass(comptime V: type) type {
    return struct {
        const Self = @This();
        const Ctx = context_mod.Context(V);

        ctx: *Ctx,
        gpa: Allocator,
        m31_constants: M31Constants = .empty,
        qm31_constants: Qm31Constants = .empty,
        m31_cache: M31Cache = .empty,
        qm31_cache: Qm31Cache = .empty,
        /// Always empty: the stand-in for upstream's `&mut IndexMap::new()`
        /// arguments, which make `from_constants_or_new` allocate fresh vars.
        no_constants: M31Constants = .empty,

        fn deinit(self: *Self) void {
            self.m31_constants.deinit(self.gpa);
            self.qm31_constants.deinit(self.gpa);
            self.m31_cache.deinit(self.gpa);
            self.qm31_cache.deinit(self.gpa);
            self.no_constants.deinit(self.gpa);
        }

        fn newConstantVar(self: *Self, value: QM31) Error!Var {
            return self.ctx.newVar(ivalue.fromQm31(V, value));
        }

        /// `from_constants_or_new` over the M31 table.
        fn m31FromConstantsOrNew(self: *Self, table: *M31Constants, value: u32) Error!Var {
            if (table.fetchSwapRemove(value)) |entry| return entry.value;
            return self.newConstantVar(QM31.fromBase(M31.fromCanonical(value)));
        }

        /// `from_constants_or_new` over the QM31 table.
        fn qm31FromConstantsOrNew(self: *Self, value: QM31) Error!Var {
            if (self.qm31_constants.fetchSwapRemove(context_mod.constantKey(value))) |entry| return entry.value;
            return self.newConstantVar(value);
        }

        /// `build_plus_one_chain`: `prev + 1 = val` for `val` in `2..=base`.
        fn buildPlusOneChain(self: *Self, base: u32) Error!void {
            const one_var = self.ctx.one();
            var prev_var = one_var;
            var value: u32 = 2;
            while (value <= base) : (value += 1) {
                const v = try self.m31FromConstantsOrNew(&self.m31_constants, value);
                try self.ctx.addInto(prev_var, one_var, v);
                try self.m31_cache.put(self.gpa, value, v);
                prev_var = v;
            }
            // The last chain value may not be needed by the circuit.
            try self.ctx.markAsMaybeUnused(prev_var);
        }

        /// `build_m31_from_base`: Horner evaluation of `value` in base `base`,
        /// caching every intermediate. `table` is where pending constants are
        /// drawn from (`m31_constants`, or the empty table).
        fn buildM31FromBase(self: *Self, table: *M31Constants, base: u32, value: u32) Error!Var {
            if (self.m31_cache.get(value)) |cached| return cached;

            // Base-`base` limbs, least significant first; at most 31 for base >= 2.
            var limbs: [32]u32 = undefined;
            var n_limbs: usize = 0;
            var remaining = value;
            while (remaining > 0) : (remaining /= base) {
                limbs[n_limbs] = remaining % base;
                n_limbs += 1;
            }
            std.debug.assert(n_limbs > 0);

            n_limbs -= 1;
            var acc = limbs[n_limbs];
            // Every limb is below `base`, so the +1 chain cached it.
            var acc_var = self.m31_cache.get(acc).?;
            const base_var = self.m31_cache.get(base).?;
            while (n_limbs > 0) {
                n_limbs -= 1;
                const limb = limbs[n_limbs];
                const limb_var = self.m31_cache.get(limb).?;

                const product = M31.fromCanonical(acc).mul(M31.fromCanonical(base)).v;
                const product_var = self.m31_cache.get(product) orelse blk: {
                    const v = try self.m31FromConstantsOrNew(table, product);
                    try self.ctx.mulInto(acc_var, base_var, v);
                    try self.m31_cache.put(self.gpa, product, v);
                    break :blk v;
                };

                const sum = M31.fromCanonical(product).add(M31.fromCanonical(limb)).v;
                const sum_var = self.m31_cache.get(sum) orelse blk: {
                    const v = try self.m31FromConstantsOrNew(table, sum);
                    try self.ctx.addInto(product_var, limb_var, v);
                    try self.m31_cache.put(self.gpa, sum, v);
                    break :blk v;
                };
                acc = sum;
                acc_var = sum_var;
            }
            std.debug.assert(!table.contains(value));
            return self.m31_cache.get(value).?;
        }

        /// `decompose_m31_constants`: builds the first pending constant until none is left.
        fn decomposeM31Constants(self: *Self, base: u32) Error!void {
            while (self.m31_constants.count() > 0) {
                _ = try self.buildM31FromBase(&self.m31_constants, base, self.m31_constants.keys()[0]);
            }
        }

        /// `decompose_broadcast_constants`: `x · (1,1,1,1) = (x,x,x,x)` for each
        /// broadcast constant, in table order; the other constants are retained
        /// in order (`IndexMap::retain`).
        fn decomposeBroadcastConstants(self: *Self, base: u32) Error!void {
            const ones_var = self.qm31_cache.get(context_mod.constantKey(QM31.fromU32Unchecked(1, 1, 1, 1))).?;
            var retained: Qm31Constants = .empty;
            errdefer retained.deinit(self.gpa);
            try retained.ensureTotalCapacity(self.gpa, self.qm31_constants.count());
            for (self.qm31_constants.keys(), self.qm31_constants.values()) |key, qm31_var| {
                const l = ivalue.limbs(context_mod.constantFromKey(key));
                if (!(l[0] == l[1] and l[1] == l[2] and l[2] == l[3])) {
                    retained.putAssumeCapacity(key, qm31_var);
                    continue;
                }
                const m31_var = try self.buildM31FromBase(&self.no_constants, base, l[0]);
                try self.ctx.mulInto(m31_var, ones_var, qm31_var);
                try self.qm31_cache.put(self.gpa, key, qm31_var);
            }
            self.qm31_constants.deinit(self.gpa);
            self.qm31_constants = retained;
        }

        /// `add_cm31_constant`: builds `a + b·i` and returns its variable.
        fn addCm31Constant(self: *Self, base: u32, i_var: Var, a: u32, b: u32) Error!Var {
            const a_var = try self.buildM31FromBase(&self.no_constants, base, a);
            const b_var = try self.buildM31FromBase(&self.no_constants, base, b);
            // `a + 0·i = a` is in the M31 cache only.
            if (b == 0) return a_var;

            const bi_key = context_mod.constantKey(QM31.fromU32Unchecked(0, b, 0, 0));
            const bi_var = self.qm31_cache.get(bi_key) orelse blk: {
                const v = try self.qm31FromConstantsOrNew(QM31.fromU32Unchecked(0, b, 0, 0));
                try self.ctx.mulInto(i_var, b_var, v);
                try self.qm31_cache.put(self.gpa, bi_key, v);
                break :blk v;
            };

            const a_plus_bi = QM31.fromU32Unchecked(a, b, 0, 0);
            const a_plus_bi_key = context_mod.constantKey(a_plus_bi);
            if (self.qm31_cache.get(a_plus_bi_key)) |cached| return cached;
            const v = try self.qm31FromConstantsOrNew(a_plus_bi);
            try self.ctx.addInto(a_var, bi_var, v);
            try self.qm31_cache.put(self.gpa, a_plus_bi_key, v);
            return v;
        }

        /// `decompose_qm31_constants`: `(a + b·i) + (c + d·i)·u` for each
        /// remaining constant, always taking the first pending entry.
        fn decomposeQm31Constants(self: *Self, base: u32) Error!void {
            const i_var = self.qm31_cache.get(context_mod.constantKey(QM31.fromU32Unchecked(0, 1, 0, 0))).?;
            const u_var = self.ctx.u();
            while (self.qm31_constants.count() > 0) {
                const value = context_mod.constantFromKey(self.qm31_constants.keys()[0]);
                const l = ivalue.limbs(value);
                const a_plus_bi_var = try self.addCm31Constant(base, i_var, l[0], l[1]);
                // `a + b·i` itself was built by `addCm31Constant`.
                if (l[2] == 0 and l[3] == 0) continue;
                const c_plus_di_var = try self.addCm31Constant(base, i_var, l[2], l[3]);

                const cu_plus_diu = QM31.fromU32Unchecked(0, 0, l[2], l[3]);
                const cu_key = context_mod.constantKey(cu_plus_diu);
                const cu_plus_diu_var = self.qm31_cache.get(cu_key) orelse blk: {
                    const v = try self.qm31FromConstantsOrNew(cu_plus_diu);
                    try self.ctx.mulInto(c_plus_di_var, u_var, v);
                    try self.qm31_cache.put(self.gpa, cu_key, v);
                    break :blk v;
                };

                const key = context_mod.constantKey(value);
                if (self.qm31_cache.contains(key)) continue;
                const v = try self.qm31FromConstantsOrNew(value);
                try self.ctx.addInto(a_plus_bi_var, cu_plus_diu_var, v);
                try self.qm31_cache.put(self.gpa, key, v);
            }
        }

        /// Builds a basis constant: drawn from the table or fresh, then cached.
        fn basisConstant(self: *Self, value: QM31) Error!Var {
            const v = try self.qm31FromConstantsOrNew(value);
            try self.qm31_cache.put(self.gpa, context_mod.constantKey(value), v);
            return v;
        }
    };
}

/// `find_max_consecutive`: the largest `N` such that `0..=N` are all M31
/// constants. The table contains 0.
fn findMaxConsecutive(gpa: Allocator, m31_constants: *const M31Constants) Allocator.Error!u32 {
    std.debug.assert(m31_constants.contains(0));
    const sorted = try gpa.dupe(u32, m31_constants.keys());
    defer gpa.free(sorted);
    std.mem.sort(u32, sorted, {}, std.sort.asc(u32));
    var n_consecutive: u32 = @intCast(sorted.len);
    for (sorted, 0..) |value, i| {
        if (value != i) {
            n_consecutive = @intCast(i);
            break;
        }
    }
    return n_consecutive - 1;
}

/// `finalize_constants_with_min_base`: yields and constrains every constant
/// of `ctx`, appending gates in upstream order.
pub fn finalizeConstantsWithMinBase(comptime V: type, ctx: *context_mod.Context(V), min_base: u32) Error!void {
    std.debug.assert(min_base >= 2);
    var pass: Pass(V) = .{ .ctx = ctx, .gpa = ctx.gpa };
    defer pass.deinit();

    // Split the constants into M31 values `(x, 0, 0, 0)` and the rest.
    for (ctx.constants.keys(), ctx.constants.values()) |key, v| {
        const l = ivalue.limbs(context_mod.constantFromKey(key));
        if (l[1] == 0 and l[2] == 0 and l[3] == 0) {
            try pass.m31_constants.put(pass.gpa, l[0], v);
        } else {
            try pass.qm31_constants.put(pass.gpa, key, v);
        }
    }
    const base = @max(try findMaxConsecutive(pass.gpa, &pass.m31_constants), min_base);

    // `0 + 0 = 0` yields zero.
    const zero_var = ctx.zero();
    try ctx.addInto(zero_var, zero_var, zero_var);
    try pass.m31_cache.put(pass.gpa, 0, pass.m31_constants.fetchSwapRemove(0).?.value);

    // `1 + 0 = 1` yields one; `u · 1 = u` yields `u` and constrains one. The
    // value of `u` is enforced by the public-output logup term of the next
    // verifier (`u` is an output from the constructor).
    const one_var = ctx.one();
    const u_var = ctx.u();
    try ctx.addInto(one_var, zero_var, one_var);
    try ctx.mulInto(u_var, one_var, u_var);
    try pass.qm31_cache.put(pass.gpa, context_mod.constantKey(context_mod.u_value), pass.qm31_constants.fetchSwapRemove(context_mod.constantKey(context_mod.u_value)).?.value);
    try pass.m31_cache.put(pass.gpa, 1, pass.m31_constants.fetchSwapRemove(1).?.value);

    try pass.buildPlusOneChain(base);
    try pass.decomposeM31Constants(base);
    std.debug.assert(pass.m31_constants.count() == 0);

    // The basis: `u·u = 2 + i`, `i = (2 + i) - 2`, `i + 1`, `(i + 1)·u = u + iu`,
    // `(i + 1) + (u + iu) = (1, 1, 1, 1)`. `2` exists because `min_base >= 2`.
    const two_var = pass.m31_cache.get(2).?;
    const i_plus_two_var = try pass.basisConstant(QM31.fromU32Unchecked(2, 1, 0, 0));
    try ctx.mulInto(u_var, u_var, i_plus_two_var);
    const i_var = try pass.basisConstant(QM31.fromU32Unchecked(0, 1, 0, 0));
    try ctx.subInto(i_plus_two_var, two_var, i_var);
    const i_plus_one_var = try pass.basisConstant(QM31.fromU32Unchecked(1, 1, 0, 0));
    try ctx.addInto(i_var, one_var, i_plus_one_var);
    const u_plus_iu_var = try pass.basisConstant(QM31.fromU32Unchecked(0, 0, 1, 1));
    try ctx.mulInto(i_plus_one_var, u_var, u_plus_iu_var);
    const ones_var = try pass.basisConstant(QM31.fromU32Unchecked(1, 1, 1, 1));
    // `ones` is unused when there is no broadcast constant.
    try ctx.markAsMaybeUnused(ones_var);
    try ctx.addInto(i_plus_one_var, u_plus_iu_var, ones_var);

    try pass.decomposeBroadcastConstants(base);
    try pass.decomposeQm31Constants(base);
    std.debug.assert(pass.qm31_constants.count() == 0);
}

test {
    _ = @import("finalize_constants_test.zig");
}
