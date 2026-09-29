//! The builder circuits of rungs R1 and R2, ported from the oracle's
//! `tools/stwo-circuit-oracle-rs/src/gadgets/cases.rs`.
//!
//! Every case is written once, generically over the value type, and built in
//! value mode (`QM31`) and topology mode (`NoValue`). Inputs enter only
//! through the guessing API, as upstream verifier circuits introduce witness
//! data. Each builder call below is in the oracle's order; `eval!`
//! expressions are expanded left subtree, right subtree, operation.

const std = @import("std");
const stwo_core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");

const builder = circuit.builder;
const blake = builder.blake;
const ops = builder.ops;
const simd = builder.simd;
const wrappers = builder.wrappers;
const ivalue = builder.ivalue;

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const P = stwo_core.fields.m31.Modulus;
const Var = builder.Var;
const Simd = simd.Simd;
const Error = builder.context.Error || error{OutputCountMismatch};

pub const Case = union(enum) {
    default_context,
    reserved_outputs,
    arithmetic_peepholes,
    constants,
    wrappers,
    blake2s_u32s: usize,
    blake2s_qm31: struct { n_bytes: usize, reduce: bool },
    extract_bits: u32,
    simd_ops,
    select_by_index,
    sort_by_u_permutation,
    reduce_hash_value,
    circuit_hash,

    /// The oracle's case name.
    pub fn name(self: Case, buffer: []u8) []const u8 {
        return switch (self) {
            .blake2s_u32s => |n| std.fmt.bufPrint(buffer, "blake2s_u32s_{d}b", .{n}) catch unreachable,
            .blake2s_qm31 => |c| std.fmt.bufPrint(buffer, "blake2s_{s}_{d}b", .{ if (c.reduce) "m31" else "qm31", c.n_bytes }) catch unreachable,
            .extract_bits => |n| std.fmt.bufPrint(buffer, "extract_bits_{d}", .{n}) catch unreachable,
            else => @tagName(self),
        };
    }

    /// `Context::new(n_reserved)` argument.
    pub fn nReserved(self: Case) usize {
        return if (self == .reserved_outputs) 8 else 0;
    }

    /// Builds the case into `ctx`; returns the variables whose values the
    /// checkpoint records (scratch-owned).
    pub fn build(self: Case, comptime V: type, ctx: *builder.Context(V)) Error![]const Var {
        return switch (self) {
            .default_context => &.{},
            .reserved_outputs => reservedOutputs(V, ctx),
            .arithmetic_peepholes => arithmeticPeepholes(V, ctx),
            .constants => constantsCase(V, ctx),
            .wrappers => wrappersCase(V, ctx),
            .blake2s_u32s => |n_bytes| blake2sU32sCase(V, ctx, n_bytes),
            .blake2s_qm31 => |c| blake2sQm31Case(V, ctx, c.n_bytes, c.reduce),
            .extract_bits => |n_bits| extractBitsCase(V, ctx, n_bits),
            .simd_ops => simdOps(V, ctx),
            .select_by_index => selectByIndexCase(V, ctx),
            .sort_by_u_permutation => sortByUPermutation(V, ctx),
            .reduce_hash_value => reduceHashValueCase(V, ctx),
            .circuit_hash => circuitHashCase(V, ctx),
        };
    }
};

/// `CASES`, in the oracle's order.
pub const cases = [_]Case{
    .default_context,
    .reserved_outputs,
    .arithmetic_peepholes,
    .constants,
    .wrappers,
    .{ .blake2s_u32s = 0 },
    .{ .blake2s_u32s = 4 },
    .{ .blake2s_u32s = 44 },
    .{ .blake2s_u32s = 64 },
    .{ .blake2s_u32s = 65 },
    .{ .blake2s_u32s = 128 },
    .{ .blake2s_qm31 = .{ .n_bytes = 44, .reduce = false } },
    .{ .blake2s_qm31 = .{ .n_bytes = 66, .reduce = true } },
    .{ .extract_bits = 8 },
    .{ .extract_bits = 31 },
    .simd_ops,
    .select_by_index,
    .sort_by_u_permutation,
    .reduce_hash_value,
    .circuit_hash,
};

fn value(comptime V: type, a: u32, b: u32, c: u32, d: u32) V {
    return ivalue.fromQm31(V, ivalue.qm31FromU32s(a, b, c, d));
}

/// Hash words at or above `P`, so the in-circuit `reduce_hash_value` must reduce.
const reduce_hash_words = [8]u32{ P, P + 1, std.math.maxInt(u32), 0x8000_0000, P - 1, 0, 1, 0xdead_beef };

fn guessU32(comptime V: type, ctx: *builder.Context(V), word: u32) Error!wrappers.U32Wrapper(Var) {
    return wrappers.guessU32(V, ctx, wrappers.u32Value(V, word));
}

fn guessHash(comptime V: type, ctx: *builder.Context(V), words: [8]u32) Error!blake.HashValue(Var) {
    return blake.guessHash(V, ctx, blake.hashValue(V, words));
}

fn hashVars(comptime V: type, ctx: *builder.Context(V), hash: blake.HashValue(Var)) Error![]const Var {
    const out = try ctx.scratch().alloc(Var, 8);
    for (out, hash.words) |*v, w| v.* = w.get();
    return out;
}

/// Packs `values` four to a QM31 (zero-padded) and guesses each wire.
fn guessM31s(comptime V: type, ctx: *builder.Context(V), values: []const u32) Error!Simd {
    const n = std.math.divCeil(usize, values.len, 4) catch unreachable;
    const data = try ctx.scratch().alloc(Var, n);
    for (data, 0..) |*v, i| {
        var lanes = [_]u32{0} ** 4;
        for (0..4) |j| {
            if (4 * i + j < values.len) lanes[j] = values[4 * i + j];
        }
        v.* = try ctx.guess(value(V, lanes[0], lanes[1], lanes[2], lanes[3]));
    }
    return .fromPacked(data, values.len);
}

/// `message_bytes`: `(7i + 3) mod 256`.
pub fn messageByte(i: usize) u8 {
    return @truncate(7 * i + 3);
}

/// `message_words(message_bytes(n))`: little-endian words, the last zero-padded.
fn messageWord(n_bytes: usize, w: usize) u32 {
    var le: [4]u8 = @splat(0);
    for (0..4) |j| {
        if (4 * w + j < n_bytes) le[j] = messageByte(4 * w + j);
    }
    return std.mem.readInt(u32, &le, .little);
}

/// `m31_message_words`: `0x01010101·(i + 3) & P`, the last word masked to `n_bytes`.
fn m31MessageWords(buffer: []u32, n_bytes: usize) []const u32 {
    const n = std.math.divCeil(usize, n_bytes, 4) catch unreachable;
    const words = buffer[0..n];
    for (words, 0..) |*w, i| w.* = (@as(u32, 0x0101_0101) *% @as(u32, @intCast(i + 3))) & P;
    const tail = n_bytes % 4;
    if (tail != 0) words[n - 1] &= (@as(u32, 1) << @intCast(8 * tail)) - 1;
    return words;
}

fn reservedOutputs(comptime V: type, ctx: *builder.Context(V)) Error![]const Var {
    var digest: [8]u32 = undefined;
    for (&digest, 0..) |*w, i| w.* = 0x0f0e_0d0c ^ (@as(u32, @intCast(i)) * 0x1111_1111);
    const vars = try hashVars(V, ctx, try guessHash(V, ctx, digest));
    try ctx.setOutputs(vars);
    return vars;
}

fn arithmeticPeepholes(comptime V: type, ctx: *builder.Context(V)) Error![]const Var {
    const zero = ctx.zero();
    const one = ctx.one();
    const a = try ctx.guess(value(V, 7, 0, 0, 0));
    const b = try ctx.guess(value(V, 3, 1, 4, 1));
    const c = try ctx.guess(value(V, P - 1, 5, 0, 9));
    const selector = try ctx.guess(value(V, 1, 0, 0, 0));

    // Index-only peepholes: none of these emits a gate.
    const a0 = try ctx.add(a, zero);
    const b0 = try ctx.add(zero, b);
    const a1 = try ctx.mul(a, one);
    const b1 = try ctx.mul(one, b);
    const z = try ctx.mul(zero, c);
    // `sub` and `pointwise_mul` never elide.
    const a_minus_zero = try ctx.sub(a, zero);
    const pw_one = try ctx.pointwiseMul(b, one);

    const sum = try ctx.add(a0, b0);
    const sum_swapped = try ctx.add(b1, a1);
    try ctx.eq(sum, sum_swapped);
    // ((a) * (b)) - (1)
    const ab = try ctx.mul(a, b);
    const expr = try ctx.sub(ab, try ctx.constant(QM31.one()));
    // -(c)
    const negated = try ops.neg(V, ctx, c);
    const quotient = try ctx.div(a, b);
    const inverse = try ctx.inv(c);
    const conjugate = try ops.conj(V, ctx, b);
    const imaginary = try ops.im(V, ctx, c);
    const combined = try ops.fromPartialEvals(V, ctx, .{ a, a_minus_zero, pw_one, sum });
    const flipped = try ops.condFlip(V, ctx, selector, a, b);
    return ctx.scratch().dupe(Var, &.{ z, expr, negated, quotient, inverse, conjugate, imaginary, combined, flipped[0], flipped[1] });
}

fn constantsCase(comptime V: type, ctx: *builder.Context(V)) Error![]const Var {
    const qm31_constants = [_]QM31{
        ivalue.qm31FromU32s(2, 0, 0, 0),
        ivalue.qm31FromU32s(4, 0, 0, 0),
        ivalue.qm31FromU32s(37, 0, 0, 0),
        ivalue.qm31FromU32s(300, 0, 0, 0),
        ivalue.qm31FromU32s(1_000_000, 0, 0, 0),
        ivalue.qm31FromU32s(P - 1, 0, 0, 0),
        ivalue.qm31FromU32s(11, 11, 11, 11),
        ivalue.qm31FromU32s(0, 1, 0, 0),
        ivalue.qm31FromU32s(0, 0, 0, 1),
        ivalue.qm31FromU32s(1, 2, 3, 4),
        ivalue.qm31FromU32s(0, 7, 0, 0),
        // Interned: the second request returns the first variable.
        ivalue.qm31FromU32s(37, 0, 0, 0),
    };
    const x = try ctx.guess(value(V, 5, 6, 7, 8));
    const out = try ctx.scratch().alloc(Var, qm31_constants.len);
    for (out, qm31_constants) |*v, constant| v.* = try ctx.mul(x, try ctx.constant(constant));
    return out;
}

fn wrappersCase(comptime V: type, ctx: *builder.Context(V)) Error![]const Var {
    const u16_value = try wrappers.guessU16(V, ctx, .newUnsafe(value(V, 0xbeef, 0, 0, 0)));
    const u32_value = try guessU32(V, ctx, 0xdead_beef);
    const u32_const = try wrappers.constU32(V, ctx, 0x0001_0002);
    const m31_value = try wrappers.guessM31(V, ctx, wrappers.m31Value(V, M31.fromCanonical(P - 2)));
    const m31_const = try wrappers.constM31(V, ctx, M31.fromCanonical(12345));
    const m31_product = try wrappers.mulM31(V, ctx, m31_value, m31_const);
    return ctx.scratch().dupe(Var, &.{ u16_value.get(), u32_value.get(), u32_const.get(), m31_value.get(), m31_product.get() });
}

fn blake2sU32sCase(comptime V: type, ctx: *builder.Context(V), n_bytes: usize) Error![]const Var {
    const n_words = std.math.divCeil(usize, n_bytes, 4) catch unreachable;
    const words = try ctx.scratch().alloc(wrappers.U32Wrapper(Var), n_words);
    for (words, 0..) |*w, i| w.* = try guessU32(V, ctx, messageWord(n_bytes, i));
    return hashVars(V, ctx, try blake.blake2sU32s(V, ctx, words, n_bytes));
}

fn blake2sQm31Case(comptime V: type, ctx: *builder.Context(V), n_bytes: usize, reduce: bool) Error![]const Var {
    var buffer: [32]u32 = undefined;
    const input = (try guessM31s(V, ctx, m31MessageWords(&buffer, n_bytes))).data;
    if (reduce) {
        const hash = try blake.blake2sM31(V, ctx, input, n_bytes);
        return ctx.scratch().dupe(Var, &.{ hash.low, hash.high });
    }
    return hashVars(V, ctx, try blake.blake2s(V, ctx, input, n_bytes));
}

fn extractBitsCase(comptime V: type, ctx: *builder.Context(V), n_bits: u32) Error![]const Var {
    const lanes: []const u32 = if (n_bits == 31) &.{ 0, 1, P - 1, 0x5555_5555, 0x4000_0000 } else &.{ 0, 1, 0x80, 0xff, 0x5a };
    const input = try guessM31s(V, ctx, lanes);
    const bits = try builder.extract_bits.extractBits(V, ctx, input, n_bits);
    var out: std.ArrayListUnmanaged(Var) = .empty;
    for (bits) |bit| try out.appendSlice(ctx.scratch(), bit.data);
    return out.items;
}

fn simdOps(comptime V: type, ctx: *builder.Context(V)) Error![]const Var {
    const a = try guessM31s(V, ctx, &.{ 1, 2, 3, 4, 5, 6 });
    const b = try guessM31s(V, ctx, &.{ 7, 9, 11, 13, 15, 17 });
    const bits = try guessM31s(V, ctx, &.{ 1, 0, 1, 1, 0, 1 });
    const high_bits = try guessM31s(V, ctx, &.{ 0, 1, 1, 0, 0, 1 });

    const sum = try simd.add(V, ctx, a, b);
    const difference = try simd.sub(V, ctx, b, a);
    const product = try simd.mul(V, ctx, a, b);
    const three = try wrappers.constM31(V, ctx, M31.fromCanonical(3));
    const scaled = try simd.scalarMul(V, ctx, a, three);
    const inverse = try simd.inv(V, ctx, b);
    const selected = try simd.select(V, ctx, bits, a, b);
    try simd.assertBits(V, ctx, bits);
    const powers = try simd.pow2(V, ctx, &.{ bits, high_bits });
    const combined = try simd.combineBits(V, ctx, &.{ bits, high_bits });
    const repeated = try simd.repeat(V, ctx, M31.fromCanonical(9), 6);
    const lane = try simd.unpackIdx(V, ctx, sum, 5);
    const unpacked = try simd.unpack(V, ctx, product);
    const wrapped = try ctx.scratch().alloc(wrappers.M31Wrapper(Var), unpacked.len);
    for (wrapped, unpacked) |*w, v| w.* = .newUnsafe(v);
    const repacked = try simd.pack(V, ctx, wrapped);
    try simd.eq(V, ctx, repacked, product);

    var out: std.ArrayListUnmanaged(Var) = .empty;
    try out.append(ctx.scratch(), lane);
    for ([_]Simd{ sum, difference, scaled, inverse, selected, powers, combined, repeated }) |s| try out.appendSlice(ctx.scratch(), s.data);
    return out.items;
}

fn selectByIndexCase(comptime V: type, ctx: *builder.Context(V)) Error![]const Var {
    var values: [8]Var = undefined;
    for (&values, 0..) |*v, i| v.* = try ctx.guess(value(V, @intCast(10 + i), @intCast(i), 0, 1));
    // Index 5 = 0b101, little-endian bits.
    var bits: [3]Var = undefined;
    for (&bits, [_]u32{ 1, 0, 1 }) |*v, bit| v.* = try ctx.guess(value(V, bit, 0, 0, 0));
    return ctx.scratch().dupe(Var, &.{try builder.select.selectByIndex(V, ctx, &values, &bits)});
}

fn sortByUPermutation(comptime V: type, ctx: *builder.Context(V)) Error![]const Var {
    var inputs: [5]Var = undefined;
    for (&inputs, [_][2]u32{ .{ 1, 9 }, .{ 2, 3 }, .{ 3, 7 }, .{ 4, 3 }, .{ 5, 0 } }) |*v, au| v.* = try ctx.guess(value(V, au[0], 0, au[1], 0));
    return ctx.permute(&inputs, ivalue.sortByUCoordinate(V));
}

fn reduceHashValueCase(comptime V: type, ctx: *builder.Context(V)) Error![]const Var {
    const hash = try guessHash(V, ctx, reduce_hash_words);
    const reduced = try blake.reduceHashValue(V, ctx, hash);
    return ctx.scratch().dupe(Var, &.{ reduced.low, reduced.high });
}

/// `compute_circuit_hash` of `crates/circuit_verifier/src/circuit_hash.rs`
/// for the `circuit_hash_test.rs` golden: log blowup 3 and component log
/// sizes `[eq 17, qm31_ops 21, triple_xor 17, m31_to_u32 18, blake_g_gate 20,
/// xor8 16, xor12 20, xor4 8, xor7 14, xor9 18, range_check_16 16]`, packed
/// one byte each after the blowup byte into three little-endian words. The
/// production gadget belongs to the circuit-verifier statement (M5); this
/// harness replays its builder calls: the config words as constants, then
/// `blake2s_u32s(config || root)` over 44 bytes.
fn circuitHashCase(comptime V: type, ctx: *builder.Context(V)) Error![]const Var {
    var root_words: [8]u32 = undefined;
    for (&root_words, 0..) |*w, i| w.* = @intCast(i);
    const root = try guessHash(V, ctx, root_words);
    const config_bytes = [12]u8{ 3, 17, 21, 17, 18, 20, 16, 20, 8, 14, 18, 16 };
    var message: [11]wrappers.U32Wrapper(Var) = undefined;
    for (message[0..3], 0..) |*w, i| w.* = try wrappers.constU32(V, ctx, std.mem.readInt(u32, config_bytes[4 * i ..][0..4], .little));
    @memcpy(message[3..], &root.words);
    return hashVars(V, ctx, try blake.blake2sU32s(V, ctx, &message, 4 * message.len));
}
