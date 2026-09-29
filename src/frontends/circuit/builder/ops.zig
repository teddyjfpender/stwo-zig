//! Composite arithmetic on wires.
//!
//! The non-primitive part of `crates/circuits/src/ops.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230); the primitive gates are
//! methods of `Context`.
//!
//! Upstream writes these with the `eval!` macro. Its evaluation order is the
//! parity contract and every function below spells it out: for `(x) op (y)`
//! the left subtree is emitted first, then the right, then the operation; a
//! literal becomes `ctx.constant(literal)` at the point it is evaluated;
//! `-(x)` emits `x`, then `sub(zero, x)`.

const std = @import("std");
const stwo_core = @import("stwo_core");
const context_mod = @import("context.zig");
const wrappers = @import("wrappers.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const Var = context_mod.Var;
const Error = context_mod.Error;
const U32Wrapper = wrappers.U32Wrapper;

/// `eval!(ctx, -(x))`: `0 - x`.
pub fn neg(comptime V: type, ctx: *context_mod.Context(V), x: Var) Error!Var {
    return ctx.sub(ctx.zero(), x);
}

/// `cond_flip`: `(a, b)` when `selector` is 0 and `(b, a)` when it is 1.
/// Assumes `selector` is 0 or 1.
pub fn condFlip(comptime V: type, ctx: *context_mod.Context(V), selector: Var, a: Var, b: Var) Error![2]Var {
    // diff = (selector) * ((b) - (a))
    const b_minus_a = try ctx.sub(b, a);
    const diff = try ctx.mul(selector, b_minus_a);
    const res_a = try ctx.add(a, diff);
    const res_b = try ctx.sub(b, diff);
    return .{ res_a, res_b };
}

/// `cond_flip_u32`: `condFlip` on `u32` wires.
pub fn condFlipU32(comptime V: type, ctx: *context_mod.Context(V), selector: Var, a: U32Wrapper(Var), b: U32Wrapper(Var)) Error![2]U32Wrapper(Var) {
    const flipped = try condFlip(V, ctx, selector, a.get(), b.get());
    return .{ .newUnsafe(flipped[0]), .newUnsafe(flipped[1]) };
}

/// `conj`: `a + b·i + c·u + d·iu` becomes `a + b·i - c·u - d·iu`.
pub fn conj(comptime V: type, ctx: *context_mod.Context(V), x: Var) Error!Var {
    const coefs = try ctx.constant(QM31.fromU32Unchecked(1, 1, 0, 0).sub(QM31.fromU32Unchecked(0, 0, 1, 1)));
    return ctx.pointwiseMul(x, coefs);
}

/// `im`: `z = a + b·i + c·u + d·iu` becomes `(c + d·i)·u = (z - conj(z)) / 2`.
pub fn im(comptime V: type, ctx: *context_mod.Context(V), x: Var) Error!Var {
    const coefs = try ctx.constant(QM31.fromU32Unchecked(0, 0, 1, 1));
    return ctx.pointwiseMul(x, coefs);
}

/// `from_partial_evals`: `(v0, v1, v2, v3)` becomes `v0 + v1·i + v2·u + v3·iu`.
/// The inputs need not lie in M31.
pub fn fromPartialEvals(comptime V: type, ctx: *context_mod.Context(V), evals: [4]Var) Error!Var {
    const i = try ctx.constant(QM31.fromU32Unchecked(0, 1, 0, 0));
    const u = try ctx.constant(QM31.fromU32Unchecked(0, 0, 1, 0));
    const iu = try ctx.constant(QM31.fromU32Unchecked(0, 0, 0, 1));
    // (((v0) + ((v1) * (i))) + ((v2) * (u))) + ((v3) * (iu))
    const v1_i = try ctx.mul(evals[1], i);
    const acc0 = try ctx.add(evals[0], v1_i);
    const v2_u = try ctx.mul(evals[2], u);
    const acc1 = try ctx.add(acc0, v2_u);
    const v3_iu = try ctx.mul(evals[3], iu);
    return ctx.add(acc1, v3_iu);
}

test {
    _ = @import("ops_test.zig");
}
