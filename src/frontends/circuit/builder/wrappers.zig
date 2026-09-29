//! Range-typed wires: values known to be an M31, a `u16` or a `u32`.
//!
//! Port of `crates/circuits/src/wrappers.rs` (https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230). A wrapper records a range
//! invariant in the type; the invariant holds for guessed wrappers because
//! guessing registers the range constraint that `finalize` emits, and for
//! constants by construction. `newUnsafe` asserts nothing.
//!
//! A `u32` is the QM31 `(low_u16, high_u16, 0, 0)`. Guessing one guesses the
//! two limbs as U16s and recombines them as `low + high·i`.

const std = @import("std");
const stwo_core = @import("stwo_core");
const context_mod = @import("context.zig");
const ivalue = @import("ivalue.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const Var = context_mod.Var;
const Error = context_mod.Error;

fn Wrapper(comptime T: type, comptime name: []const u8) type {
    return struct {
        const Self = @This();
        inner: T,

        pub fn newUnsafe(inner: T) Self {
            return .{ .inner = inner };
        }

        pub fn get(self: Self) T {
            return self.inner;
        }

        /// Upstream `Debug`, e.g. `U32([7])`.
        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            comptime if (T != Var) @compileError("only wire wrappers render");
            try writer.print(name ++ "({f})", .{self.inner});
        }
    };
}

/// A value in the base field M31.
pub fn M31Wrapper(comptime T: type) type {
    return Wrapper(T, "M31");
}

/// A 16-bit unsigned integer `(value, 0, 0, 0)`.
pub fn U16Wrapper(comptime T: type) type {
    return Wrapper(T, "U16");
}

/// A 32-bit unsigned integer `(low_u16, high_u16, 0, 0)`.
pub fn U32Wrapper(comptime T: type) type {
    return Wrapper(T, "U32");
}

/// `M31Wrapper::from_m31`: embeds a base-field element.
pub fn m31Value(comptime V: type, value: M31) M31Wrapper(V) {
    return .newUnsafe(ivalue.fromQm31(V, QM31.fromBase(value)));
}

/// `IValue::pack_u32` as a wrapper value.
pub fn u32Value(comptime V: type, value: u32) U32Wrapper(V) {
    return .newUnsafe(ivalue.packU32(V, value));
}

/// `M31Wrapper::const_m31`.
pub fn constM31(comptime V: type, ctx: *context_mod.Context(V), value: M31) Error!M31Wrapper(Var) {
    return .newUnsafe(try ctx.constant(QM31.fromBase(value)));
}

/// `M31Wrapper::mul`: `a * b`, with the builder's index-only peepholes.
pub fn mulM31(comptime V: type, ctx: *context_mod.Context(V), a: M31Wrapper(Var), b: M31Wrapper(Var)) Error!M31Wrapper(Var) {
    return .newUnsafe(try ctx.mul(a.inner, b.inner));
}

/// `Guess for M31Wrapper`: constrained to M31 at finalization.
pub fn guessM31(comptime V: type, ctx: *context_mod.Context(V), value: M31Wrapper(V)) Error!M31Wrapper(Var) {
    return .newUnsafe(try ctx.guessM31(value.inner));
}

/// `Guess for U16Wrapper`: constrained to `[0, 2^16)` at finalization.
pub fn guessU16(comptime V: type, ctx: *context_mod.Context(V), value: U16Wrapper(V)) Error!U16Wrapper(Var) {
    return .newUnsafe(try ctx.guessU16(value.inner));
}

/// `U32Wrapper::const_u32`: the constant `(low, high, 0, 0)`.
pub fn constU32(comptime V: type, ctx: *context_mod.Context(V), value: u32) Error!U32Wrapper(Var) {
    return .newUnsafe(try ctx.constant(ivalue.packU32(QM31, value)));
}

/// `Guess for U32Wrapper`: guesses the low then the high limb as U16s, then
/// returns `low + high·i` (`i` interned after both guesses).
pub fn guessU32(comptime V: type, ctx: *context_mod.Context(V), value: U32Wrapper(V)) Error!U32Wrapper(Var) {
    const word = ivalue.unpackU32(V, value.inner);
    const low = try guessU16(V, ctx, .newUnsafe(ivalue.fromQm31(V, QM31.fromU32Unchecked(word & 0xFFFF, 0, 0, 0))));
    const high = try guessU16(V, ctx, .newUnsafe(ivalue.fromQm31(V, QM31.fromU32Unchecked(word >> 16, 0, 0, 0))));
    const i = try ctx.constant(QM31.fromU32Unchecked(0, 1, 0, 0));
    const high_times_i = try ctx.mul(high.inner, i);
    return .newUnsafe(try ctx.add(low.inner, high_times_i));
}

/// `U32Wrapper::get_value`.
pub fn u32ValueOf(comptime V: type, ctx: *const context_mod.Context(V), wire: U32Wrapper(Var)) U32Wrapper(V) {
    return .newUnsafe(ctx.get(wire.inner));
}

// Tests: `crates/circuits/src/wrappers_test.rs`.

const testing = @import("testing.zig");
const NoValue = ivalue.NoValue;

test "wrappers: M31 guess circuit" {
    var ctx = try context_mod.Context(NoValue).init(std.testing.allocator, 0);
    defer ctx.deinit();
    const res = try guessM31(NoValue, &ctx, .newUnsafe(.{}));
    try ctx.finalizeGuessedVars();
    try testing.expectFormat("M31([3])", res);
    try testing.expectConstants(NoValue, &ctx,
        \\{
        \\    (0 + 0i) + (0 + 0i)u: [0],
        \\    (1 + 0i) + (0 + 0i)u: [1],
        \\    (0 + 0i) + (1 + 0i)u: [2],
        \\}
    );
    try testing.expectCircuit(&ctx.circuit,
        \\[3] = [3] x [1]
        \\output [2]
        \\
    );
}

test "wrappers: U16 guess circuit" {
    var ctx = try context_mod.Context(NoValue).init(std.testing.allocator, 0);
    defer ctx.deinit();
    const res = try guessU16(NoValue, &ctx, .newUnsafe(.{}));
    try ctx.finalizeGuessedVars();
    try testing.expectFormat("U16([3])", res);
    try testing.expectCircuit(&ctx.circuit,
        \\[3] = m31_to_u32([3])
        \\output [2]
        \\
    );
}

test "wrappers: U32 guess circuit" {
    var ctx = try context_mod.Context(NoValue).init(std.testing.allocator, 0);
    defer ctx.deinit();
    const res = try guessU32(NoValue, &ctx, .newUnsafe(.{}));
    try ctx.finalizeGuessedVars();
    try testing.expectFormat("U32([7])", res);
    try testing.expectConstants(NoValue, &ctx,
        \\{
        \\    (0 + 0i) + (0 + 0i)u: [0],
        \\    (1 + 0i) + (0 + 0i)u: [1],
        \\    (0 + 0i) + (1 + 0i)u: [2],
        \\    (0 + 1i) + (0 + 0i)u: [5],
        \\}
    );
    try testing.expectCircuit(&ctx.circuit,
        \\[7] = [3] + [6]
        \\[6] = [4] * [5]
        \\[3] = m31_to_u32([3])
        \\[4] = m31_to_u32([4])
        \\output [2]
        \\
    );
}

test "wrappers: U32 guess recombines the limbs in value mode" {
    var ctx = try context_mod.Context(QM31).init(std.testing.allocator, 0);
    defer ctx.deinit();
    for ([_]u32{ 0, 0xFFFF, 0x1_0000, 0xDEAD_BEEF, 0xFFFF_FFFF }) |word| {
        const wire = try guessU32(QM31, &ctx, u32Value(QM31, word));
        try std.testing.expectEqual(word, ivalue.unpackU32(QM31, u32ValueOf(QM31, &ctx, wire).get()));
    }
    const constant = try constU32(QM31, &ctx, 0x0001_0002);
    try std.testing.expect(ctx.get(constant.get()).eql(QM31.fromU32Unchecked(2, 1, 0, 0)));
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
