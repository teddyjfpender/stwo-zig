//! Byte-exact SHA256(SHA256(header[80])) in the S31 circuit builder.
//!
//! Every input and output byte is reconstructed from constrained bits. The
//! three compression blocks and both padding lengths are fixed by the source
//! type; no witness value can select a different schedule or block count.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const sha = @import("s31_sha_provider").compression;

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Var = circuit.builder.Var;

const Bits = [32]Var;
const Word = struct {
    low: Var,
    high: Var,
    value: u32,
    constant: bool = false,
    bits: ?Bits = null,
};

fn hint(comptime V: type, value: u32) V {
    return circuit.builder.ivalue.fromQm31(V, QM31.fromBase(M31.fromCanonical(value)));
}

fn constWord(comptime V: type, ctx: *circuit.builder.Context(V), value: u32) !Word {
    return .{
        .low = try ctx.constant(QM31.fromBase(M31.fromCanonical(value & 0xffff))),
        .high = try ctx.constant(QM31.fromBase(M31.fromCanonical(value >> 16))),
        .value = value,
        .constant = true,
    };
}

fn valueOf(comptime V: type, ctx: *circuit.builder.Context(V), low: Var, high: Var) u32 {
    if (comptime V == QM31)
        return ctx.get(low).toM31Array()[0].toU32() | (ctx.get(high).toM31Array()[0].toU32() << 16);
    return 0;
}

fn fromInput(comptime V: type, ctx: *circuit.builder.Context(V), low: Var, high: Var) Word {
    return .{ .low = low, .high = high, .value = valueOf(V, ctx, low, high) };
}

fn combineHalf(comptime V: type, ctx: *circuit.builder.Context(V), bits: *const Bits, start: usize) !Var {
    const two = try ctx.constant(QM31.fromBase(M31.fromCanonical(2)));
    var result = bits[start + 15];
    var i: usize = 15;
    while (i > 0) {
        i -= 1;
        result = try ctx.add(try ctx.mul(result, two), bits[start + i]);
    }
    return result;
}

fn bitsOf(comptime V: type, ctx: *circuit.builder.Context(V), word: *Word) !Bits {
    if (word.bits) |cached| return cached;
    var bits: Bits = undefined;
    for (&bits, 0..) |*bit, i| {
        const value = (word.value >> @intCast(i)) & 1;
        if (word.constant) {
            bit.* = if (value == 0) ctx.zero() else ctx.one();
        } else {
            bit.* = try ctx.newVar(hint(V, value));
            // A field element satisfying b²=b is exactly 0 or 1.
            try ctx.mulInto(bit.*, bit.*, bit.*);
        }
    }
    if (!word.constant) {
        try ctx.eq(try combineHalf(V, ctx, &bits, 0), word.low);
        try ctx.eq(try combineHalf(V, ctx, &bits, 16), word.high);
    }
    word.bits = bits;
    return bits;
}

fn fromBits(comptime V: type, ctx: *circuit.builder.Context(V), bits: Bits, value: u32) !Word {
    return .{
        .low = try combineHalf(V, ctx, &bits, 0),
        .high = try combineHalf(V, ctx, &bits, 16),
        .value = value,
        .bits = bits,
    };
}

fn swapBytes(comptime V: type, ctx: *circuit.builder.Context(V), word: *Word) !Word {
    const bits = try bitsOf(V, ctx, word);
    var swapped: Bits = undefined;
    for (&swapped, 0..) |*bit, i| bit.* = bits[(3 - i / 8) * 8 + i % 8];
    return fromBits(V, ctx, swapped, @byteSwap(word.value));
}

fn booleanBit(comptime V: type, ctx: *circuit.builder.Context(V), value: u32) !Var {
    const out = try ctx.newVar(hint(V, value));
    try ctx.mulInto(out, out, out);
    return out;
}

fn add(comptime V: type, ctx: *circuit.builder.Context(V), a: Word, b: Word) !Word {
    if (a.constant and b.constant) return constWord(V, ctx, a.value +% b.value);
    const value = a.value +% b.value;
    const low = (try circuit.builder.wrappers.guessU16(V, ctx, .newUnsafe(hint(V, value & 0xffff)))).get();
    const high = (try circuit.builder.wrappers.guessU16(V, ctx, .newUnsafe(hint(V, value >> 16)))).get();
    const carry_low = try booleanBit(V, ctx, @intFromBool((a.value & 0xffff) + (b.value & 0xffff) >= 1 << 16));
    const carry_high = try booleanBit(V, ctx, @intFromBool((a.value >> 16) + (b.value >> 16) +
        @as(u32, @intFromBool((a.value & 0xffff) + (b.value & 0xffff) >= 1 << 16)) >= 1 << 16));
    const base = try ctx.constant(QM31.fromBase(M31.fromCanonical(1 << 16)));
    try ctx.eq(try ctx.add(a.low, b.low), try ctx.add(low, try ctx.mul(base, carry_low)));
    try ctx.eq(try ctx.add(try ctx.add(a.high, b.high), carry_low), try ctx.add(high, try ctx.mul(base, carry_high)));
    return .{ .low = low, .high = high, .value = value };
}

fn xorBit(comptime V: type, ctx: *circuit.builder.Context(V), a: Var, b: Var) !Var {
    const ab = try ctx.mul(a, b);
    return ctx.sub(try ctx.add(a, b), try ctx.add(ab, ab));
}

fn xor3(comptime V: type, ctx: *circuit.builder.Context(V), a: Var, b: Var, c: Var) !Var {
    return xorBit(V, ctx, try xorBit(V, ctx, a, b), c);
}

fn sigma(comptime V: type, ctx: *circuit.builder.Context(V), word: *Word, comptime kind: enum { small0, small1, big0, big1 }) !Word {
    const source = try bitsOf(V, ctx, word);
    var result: Bits = undefined;
    for (&result, 0..) |*out, i| {
        const a, const b, const c = switch (kind) {
            .small0 => .{ source[(i + 7) % 32], source[(i + 18) % 32], if (i + 3 < 32) source[i + 3] else ctx.zero() },
            .small1 => .{ source[(i + 17) % 32], source[(i + 19) % 32], if (i + 10 < 32) source[i + 10] else ctx.zero() },
            .big0 => .{ source[(i + 2) % 32], source[(i + 13) % 32], source[(i + 22) % 32] },
            .big1 => .{ source[(i + 6) % 32], source[(i + 11) % 32], source[(i + 25) % 32] },
        };
        out.* = try xor3(V, ctx, a, b, c);
    }
    const value = switch (kind) {
        .small0 => sha.sigmaSmall0(word.value),
        .small1 => sha.sigmaSmall1(word.value),
        .big0 => sha.sigmaBig0(word.value),
        .big1 => sha.sigmaBig1(word.value),
    };
    return fromBits(V, ctx, result, value);
}

fn choose(comptime V: type, ctx: *circuit.builder.Context(V), e: *Word, f: *Word, g: *Word) !Word {
    const eb = try bitsOf(V, ctx, e);
    const fb = try bitsOf(V, ctx, f);
    const gb = try bitsOf(V, ctx, g);
    var result: Bits = undefined;
    for (&result, eb, fb, gb) |*out, x, y, z|
        out.* = try ctx.add(z, try ctx.mul(x, try ctx.sub(y, z)));
    return fromBits(V, ctx, result, sha.choose(e.value, f.value, g.value));
}

fn majority(comptime V: type, ctx: *circuit.builder.Context(V), a: *Word, b: *Word, c: *Word) !Word {
    const abits = try bitsOf(V, ctx, a);
    const bbits = try bitsOf(V, ctx, b);
    const cbits = try bitsOf(V, ctx, c);
    var result: Bits = undefined;
    for (&result, abits, bbits, cbits) |*out, x, y, z| {
        const xy = try ctx.mul(x, y);
        const x_xor_y = try ctx.sub(try ctx.add(x, y), try ctx.add(xy, xy));
        out.* = try ctx.add(xy, try ctx.mul(z, x_xor_y));
    }
    return fromBits(V, ctx, result, sha.majority(a.value, b.value, c.value));
}

fn compress(comptime V: type, ctx: *circuit.builder.Context(V), initial: [8]Word, block: [16]Word) ![8]Word {
    var words: [64]Word = undefined;
    @memcpy(words[0..16], &block);
    for (16..64) |t| {
        const s1 = try sigma(V, ctx, &words[t - 2], .small1);
        const s0 = try sigma(V, ctx, &words[t - 15], .small0);
        words[t] = try add(V, ctx, try add(V, ctx, try add(V, ctx, s1, words[t - 7]), s0), words[t - 16]);
    }
    var state = initial;
    for (0..64) |t| {
        const s1 = try sigma(V, ctx, &state[4], .big1);
        const choice = try choose(V, ctx, &state[4], &state[5], &state[6]);
        const t1 = try add(V, ctx, try add(V, ctx, try add(V, ctx, try add(V, ctx, state[7], s1), choice), try constWord(V, ctx, sha.round_constants[t])), words[t]);
        const s0 = try sigma(V, ctx, &state[0], .big0);
        const majority_word = try majority(V, ctx, &state[0], &state[1], &state[2]);
        const t2 = try add(V, ctx, s0, majority_word);
        const next_a = try add(V, ctx, t1, t2);
        const next_e = try add(V, ctx, state[3], t1);
        const old = state;
        state = .{ next_a, old[0], old[1], old[2], next_e, old[4], old[5], old[6] };
    }
    for (&state, initial) |*word, base| word.* = try add(V, ctx, word.*, base);
    return state;
}

/// Input is forty little-endian u16 limbs of the serialized 80-byte header.
/// Output is sixteen little-endian u16 limbs of the raw double-SHA digest.
pub fn hashHeader(comptime V: type, ctx: *circuit.builder.Context(V), input: []const Var) ![16]Var {
    if (input.len != 40) return error.InvalidHeaderLength;
    var header_words: [20]Word = undefined;
    for (&header_words, 0..) |*word, i| {
        var input_word = fromInput(V, ctx, input[2 * i], input[2 * i + 1]);
        word.* = try swapBytes(V, ctx, &input_word);
    }
    var initial: [8]Word = undefined;
    for (&initial, sha.initial_state) |*word, value| word.* = try constWord(V, ctx, value);
    const first = try compress(V, ctx, initial, header_words[0..16].*);
    var second_block: [16]Word = undefined;
    @memcpy(second_block[0..4], header_words[16..20]);
    second_block[4] = try constWord(V, ctx, 0x8000_0000);
    for (second_block[5..15]) |*word| word.* = try constWord(V, ctx, 0);
    second_block[15] = try constWord(V, ctx, 80 * 8);
    const first_digest = try compress(V, ctx, first, second_block);
    var third_block: [16]Word = undefined;
    @memcpy(third_block[0..8], &first_digest);
    third_block[8] = try constWord(V, ctx, 0x8000_0000);
    for (third_block[9..15]) |*word| word.* = try constWord(V, ctx, 0);
    third_block[15] = try constWord(V, ctx, 32 * 8);
    var second_digest = try compress(V, ctx, initial, third_block);
    var output: [16]Var = undefined;
    for (&second_digest, 0..) |*word, i| {
        const swapped = try swapBytes(V, ctx, word);
        output[2 * i] = swapped.low;
        output[2 * i + 1] = swapped.high;
    }
    return output;
}

test "byte-exact double SHA of an eighty-byte header" {
    const allocator = std.testing.allocator;
    var header: [80]u8 = undefined;
    for (&header, 0..) |*byte, i| byte.* = @truncate(i * 37 + 11);
    var ctx = try circuit.builder.Context(QM31).init(allocator, 1);
    defer ctx.deinit();
    var input: [40]Var = undefined;
    for (&input, 0..) |*word, i| {
        const value = std.mem.readInt(u16, header[2 * i ..][0..2], .little);
        word.* = (try circuit.builder.wrappers.guessU16(QM31, &ctx, .newUnsafe(hint(QM31, value)))).get();
    }
    const output = try hashHeader(QM31, &ctx, &input);
    var actual: [32]u8 = undefined;
    for (output, 0..) |word, i| {
        const value: u16 = @intCast(ctx.get(word).toM31Array()[0].toU32());
        std.mem.writeInt(u16, actual[2 * i ..][0..2], value, .little);
    }
    var first: [32]u8 = undefined;
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&header, &first, .{});
    std.crypto.hash.sha2.Sha256.hash(&first, &expected, .{});
    try ctx.setOutputs(&.{output[0]});
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
    try std.testing.expectEqualDeep(expected, actual);
}
