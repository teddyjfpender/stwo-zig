//! The M2 circuit builder as `CairoStatement`'s builder facade `B`.
//!
//! Each member is the single builder call the Rust statement makes
//! (`crates/cairo_verifier/src/statement.rs`, https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230); the table in
//! `cairo_statement.zig` names them. The facade only unwraps the typed
//! wrappers (`M31Wrapper`, `U32Wrapper`, `HashValue`) the Rust signatures
//! carry; it adds no gates, constants or guesses of its own, so a statement
//! built through it numbers its variables as the Rust one does.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const logup = @import("../stark_verifier/logup.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const blake = builder.blake;
const simd = builder.simd;
const wrappers = builder.wrappers;

/// `CairoStatement`'s `B` over `Context(V)`, `V` = `QM31` (values) or
/// `NoValue` (topology).
pub fn BuilderFacade(comptime V: type) type {
    return struct {
        pub const Context = builder.Context(V);
        pub const Var = builder.Var;
        pub const Simd = simd.Simd;

        pub fn zero(ctx: *Context) Var {
            return ctx.zero();
        }

        pub fn one(ctx: *Context) Var {
            return ctx.one();
        }

        pub fn constant(ctx: *Context, value: QM31) !Var {
            return ctx.constant(value);
        }

        /// `U32Wrapper::const_u32`.
        pub fn constU32(ctx: *Context, value: u32) !Var {
            return (try wrappers.constU32(V, ctx, value)).get();
        }

        /// `HashValue::<QM31>::constant`.
        pub fn constHash(ctx: *Context, words: [8]u32) ![8]Var {
            return unwrapHash(try blake.constantHash(V, ctx, blake.hashValue(QM31, words)));
        }

        /// `M31Wrapper::from_m31(value).guess`.
        pub fn guessM31(ctx: *Context, value: M31) !Var {
            return (try wrappers.guessM31(V, ctx, wrappers.m31Value(V, value))).get();
        }

        /// `HashValue::<Value>::guess`; `null` is `HashValue::no_value()`,
        /// which only a topology build may pass.
        pub fn guessHash(ctx: *Context, value: ?[8]u32) ![8]Var {
            const words = value orelse if (V == builder.NoValue) [_]u32{0} ** 8 else return error.MissingWitness;
            return unwrapHash(try blake.guessHash(V, ctx, blake.hashValue(V, words)));
        }

        pub fn setOutputs(ctx: *Context, vars: []const Var) !void {
            return ctx.setOutputs(vars);
        }

        pub fn add(ctx: *Context, a: Var, b: Var) !Var {
            return ctx.add(a, b);
        }

        pub fn sub(ctx: *Context, a: Var, b: Var) !Var {
            return ctx.sub(a, b);
        }

        pub fn mul(ctx: *Context, a: Var, b: Var) !Var {
            return ctx.mul(a, b);
        }

        /// `ops::eq`.
        pub fn eq(ctx: *Context, a: Var, b: Var) !void {
            return ctx.eq(a, b);
        }

        pub fn simdFromPacked(_: *Context, vars: []const Var, len: usize) !Simd {
            return Simd.fromPacked(vars, len);
        }

        /// `Simd::pack` over `M31Wrapper` lanes.
        pub fn simdPack(ctx: *Context, vars: []const Var) !Simd {
            const lanes = try ctx.scratch().alloc(wrappers.M31Wrapper(Var), vars.len);
            for (lanes, vars) |*lane, v| lane.* = .newUnsafe(v);
            return simd.pack(V, ctx, lanes);
        }

        pub fn simdUnpack(ctx: *Context, value: Simd) ![]Var {
            return simd.unpack(V, ctx, value);
        }

        pub fn simdUnpackIdx(ctx: *Context, value: Simd, idx: usize) !Var {
            return simd.unpackIdx(V, ctx, value, idx);
        }

        pub fn simdSub(ctx: *Context, a: Simd, b: Simd) !Simd {
            return simd.sub(V, ctx, a, b);
        }

        pub fn simdMul(ctx: *Context, a: Simd, b: Simd) !Simd {
            return simd.mul(V, ctx, a, b);
        }

        pub fn combineBits(ctx: *Context, bits: []const Simd) !Simd {
            return simd.combineBits(V, ctx, bits);
        }

        pub fn extractBits(ctx: *Context, value: Simd, n_bits: u32) ![]Simd {
            return builder.extract_bits.extractBits(V, ctx, value, n_bits);
        }

        pub fn m31ToU32(ctx: *Context, input: Var) !Var {
            return (try blake.m31ToU32(V, ctx, input)).get();
        }

        /// `blake::blake2s_u32s` over `U32Wrapper` words.
        pub fn blake2sU32s(ctx: *Context, words: []const Var, n_bytes: usize) ![8]Var {
            const message = try ctx.scratch().alloc(wrappers.U32Wrapper(Var), words.len);
            for (message, words) |*word, v| word.* = .newUnsafe(v);
            return unwrapHash(try blake.blake2sU32s(V, ctx, message, n_bytes));
        }

        /// `logup::logup_use_term`: the inverse of `combine_term`.
        pub fn logupUseTerm(ctx: *Context, element: []const Var, interaction_elements: [2]Var) !Var {
            return ctx.inv(try logup.combineTerm(Context, ctx, element, interaction_elements));
        }

        fn unwrapHash(hash: blake.HashValue(Var)) [8]Var {
            var vars: [8]Var = undefined;
            for (&vars, hash.words) |*v, word| v.* = word.get();
            return vars;
        }
    };
}
