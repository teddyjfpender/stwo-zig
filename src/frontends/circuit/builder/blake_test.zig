//! Tests of `blake.zig`: `crates/circuits/src/blake_test.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230), with digests cross-checked
//! against std's Blake2s-256.

const std = @import("std");
const stwo_core = @import("stwo_core");
const context_mod = @import("context.zig");
const blake = @import("blake.zig");
const ivalue = @import("ivalue.zig");
const testing = @import("testing.zig");
const wrappers = @import("wrappers.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const Var = context_mod.Var;
const TraceContext = context_mod.Context(QM31);
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;
const gpa = std.testing.allocator;

test "blake: blake2s_m31 over 66 bytes, with upstream stats" {
    for ([_]bool{ false, true }) |wrong_output| {
        var ctx = try TraceContext.init(gpa, 0);
        defer ctx.deinit();
        var input: [5]Var = undefined;
        for (&input, 0..) |*v, i| {
            const base: u32 = @intCast(4 * i + 1);
            v.* = try ctx.guess(if (i < 4) ivalue.qm31FromU32s(base, base + 1, base + 2, base + 3) else ivalue.qm31FromU32s(17, 0, 0, 0));
        }
        var bytes: [66]u8 = @splat(0);
        for (0..17) |word| bytes[4 * word] = @intCast(word + 1);
        var digest: [32]u8 = undefined;
        Blake2s256.hash(&bytes, &digest, .{});
        // `reduce_to_m31` then `qm31_from_bytes`: each word reduced modulo P.
        var expected = digest;
        for (0..8) |w| std.mem.writeInt(u32, expected[4 * w ..][0..4], ivalue.limbs(ivalue.qm31FromU32s(std.mem.readInt(u32, digest[4 * w ..][0..4], .little), 0, 0, 0))[0], .little);
        if (wrong_output) expected[0] += 1;

        const output = try blake.blake2sM31(QM31, &ctx, &input, 66);
        const out0 = try ctx.guess(blake.qm31FromBytes(expected[0..16].*));
        const out1 = try ctx.guess(blake.qm31FromBytes(expected[16..32].*));
        try ctx.eq(output.low, out0);
        try ctx.eq(output.high, out1);

        try std.testing.expectEqual(context_mod.Stats{
            .equals = 2,
            .add = 14,
            .sub = 0,
            .mul = 37,
            .inv = 0,
            .div = 0,
            .pointwise_mul = 36,
            .guess = 7,
            .blake_updates = 2,
            .permutation_inputs = 0,
            // The constructor marks `u` as an output.
            .outputs = 1,
            .triple_xor = 16,
            .m31_to_u32 = 20,
        }, ctx.stats);

        try ctx.finalize(false);
        try std.testing.expectEqual(null, try ctx.circuit.firstYieldViolation(gpa));
        try std.testing.expectEqual(!wrong_output, try ctx.isCircuitValid());
    }
}

test "blake: blake2s over 64 bytes equals the host hash" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const message = [16]u32{
        930933030,  1766240503, 3660871006, 388409270, 1948594622, 3119396969, 3924579183, 2089920034,
        3857888532, 929304360,  1810891574, 860971754, 1822893775, 2008495810, 2958962335, 2340515744,
    };
    var values: [4]QM31 = undefined;
    for (&values, 0..) |*value, i| value.* = ivalue.qm31FromU32s(message[4 * i], message[4 * i + 1], message[4 * i + 2], message[4 * i + 3]);
    const expected = ivalue.blake2s(QM31, &values, 64);
    var input: [4]Var = undefined;
    for (&input, values) |*v, value| v.* = try ctx.guess(value);
    const output = try blake.blake2s(QM31, &ctx, &input, 64);
    for (output.words, expected) |word, e| {
        const guessed = try ctx.guess(e);
        try ctx.eq(word.get(), guessed);
    }
    try ctx.finalize(false);
    try std.testing.expectEqual(null, try ctx.circuit.firstYieldViolation(gpa));
    try std.testing.expect(try ctx.isCircuitValid());
}

test "blake: HashValue guess keeps every raw u32 word" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    // Words exercising both limbs, including 0x0000 and 0xFFFF in either.
    const words = [8]u32{ 0x0000_0001, 0x1234_5678, 0xFFFF_FFFF, 0xDEAD_BEEF, 0x0000_FFFF, 0xFFFF_0000, 0xCAFE_BABE, 0x8000_0001 };
    var digest: [32]u8 = undefined;
    for (words, 0..) |word, i| std.mem.writeInt(u32, digest[4 * i ..][0..4], word, .little);
    const guessed = try blake.guessHash(QM31, &ctx, blake.hashValueFromDigest(QM31, digest));
    // No reduction modulo P, unlike `ReducedHashValue`.
    for (guessed.words, words) |w, word| try std.testing.expectEqual(word, ivalue.unpackU32(QM31, ctx.get(w.get())));
    try ctx.finalizeGuessedVars();
    try testing.expectCircuit(&ctx.circuit,
        \\[7] = [3] + [6]
        \\[11] = [8] + [10]
        \\[15] = [12] + [14]
        \\[19] = [16] + [18]
        \\[23] = [20] + [22]
        \\[27] = [24] + [26]
        \\[31] = [28] + [30]
        \\[35] = [32] + [34]
        \\[6] = [4] * [5]
        \\[10] = [9] * [5]
        \\[14] = [13] * [5]
        \\[18] = [17] * [5]
        \\[22] = [21] * [5]
        \\[26] = [25] * [5]
        \\[30] = [29] * [5]
        \\[34] = [33] * [5]
        \\[3] = m31_to_u32([3])
        \\[4] = m31_to_u32([4])
        \\[8] = m31_to_u32([8])
        \\[9] = m31_to_u32([9])
        \\[12] = m31_to_u32([12])
        \\[13] = m31_to_u32([13])
        \\[16] = m31_to_u32([16])
        \\[17] = m31_to_u32([17])
        \\[20] = m31_to_u32([20])
        \\[21] = m31_to_u32([21])
        \\[24] = m31_to_u32([24])
        \\[25] = m31_to_u32([25])
        \\[28] = m31_to_u32([28])
        \\[29] = m31_to_u32([29])
        \\[32] = m31_to_u32([32])
        \\[33] = m31_to_u32([33])
        \\output [2]
        \\
    );
}

test "blake: blake2s_u32s equals std Blake2s at block boundaries" {
    for ([_]usize{ 0, 1, 4, 63, 64, 65, 128 }) |n_bytes| {
        var ctx = try TraceContext.init(gpa, 0);
        defer ctx.deinit();
        var bytes: [128]u8 = undefined;
        for (&bytes, 0..) |*byte, i| byte.* = @truncate(7 * i + 3);
        const n_words = std.math.divCeil(usize, n_bytes, 4) catch unreachable;
        var message: [32]wrappers.U32Wrapper(Var) = undefined;
        for (message[0..n_words], 0..) |*word, w| {
            var le: [4]u8 = @splat(0);
            for (0..4) |j| {
                if (4 * w + j < n_bytes) le[j] = bytes[4 * w + j];
            }
            word.* = try wrappers.guessU32(QM31, &ctx, wrappers.u32Value(QM31, std.mem.readInt(u32, &le, .little)));
        }
        const output = try blake.blake2sU32s(QM31, &ctx, message[0..n_words], n_bytes);
        var digest: [32]u8 = undefined;
        Blake2s256.hash(bytes[0..n_bytes], &digest, .{});
        for (output.words, 0..) |word, i| try std.testing.expectEqual(std.mem.readInt(u32, digest[4 * i ..][0..4], .little), ivalue.unpackU32(QM31, ctx.get(word.get())));
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
    }
}

test "blake: reduced digests and constant hashes build valid circuits" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    var digest: [32]u8 = undefined;
    for (&digest, 0..) |*byte, i| byte.* = @truncate(0xF7 *% i +% 1);
    // The host reduction equals the in-circuit one on the same digest.
    const expected = blake.reducedHashValueFromDigest(digest);
    const hash = try blake.guessHash(QM31, &ctx, blake.hashValueFromDigest(QM31, digest));
    const reduced = try blake.reduceHashValue(QM31, &ctx, hash);
    const guessed = try blake.guessReducedHash(QM31, &ctx, expected);
    try ctx.eq(reduced.low, guessed.low);
    try ctx.eq(reduced.high, guessed.high);
    // Constant words intern once each, in order.
    const constant = try blake.constantHash(QM31, &ctx, blake.hashValueFromDigest(QM31, digest));
    const again = try blake.constantHash(QM31, &ctx, blake.hashValueFromDigest(QM31, digest));
    for (constant.words, again.words, hash.words) |c, a, h| {
        try std.testing.expectEqual(c.get(), a.get());
        try std.testing.expect(ctx.get(c.get()).eql(ctx.get(h.get())));
    }
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
