//! Bit-exact crypto equations for streaming memory-source authentication.
//! Bits are little-endian within bytes and words. Callers must constrain every
//! external bit; computed bits follow Boolean XOR/AND and modular carry logic.
//! No digest oracle or unconstrained compression output is used here.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const sha = @import("../../air/guest_precompile/sha256_compression.zig");
const topology = @import("blake3_compression_plan.zig");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");

pub fn Algebra(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Byte = [8]S;
        pub const Word = [32]S;
        pub const Digest = [32]Byte;
        pub const State = [8]Word;
        pub fn scalar(value: u32) S {
            return S.fromBase(M.fromCanonical(value));
        }
        pub fn bit(value: bool) S {
            return scalar(@intFromBool(value));
        }
        pub fn byte(value: u8) Byte {
            var out: Byte = undefined;
            for (&out, 0..) |*v, i| v.* = bit((value >> @intCast(i)) & 1 != 0);
            return out;
        }
        pub fn word(value: u32) Word {
            var out: Word = undefined;
            for (&out, 0..) |*v, i| v.* = bit((value >> @intCast(i)) & 1 != 0);
            return out;
        }
        pub fn digest(value: [32]u8) Self.Digest {
            var out: Self.Digest = undefined;
            for (&out, value) |*v, b| v.* = byte(b);
            return out;
        }
        pub fn xorBit(a: S, b: S) S {
            return a.add(b).sub(scalar(2).mul(a).mul(b));
        }
        pub fn xorWord(a: Self.Word, b: Self.Word) Self.Word {
            var out: Self.Word = undefined;
            for (&out, a, b) |*v, x, y| v.* = xorBit(x, y);
            return out;
        }
        pub fn rotate(a: Self.Word, n: u5) Self.Word {
            var out: Self.Word = undefined;
            for (&out, 0..) |*v, i| v.* = a[(i + @as(usize, n)) % 32];
            return out;
        }
        pub fn shift(a: Self.Word, n: u5) Self.Word {
            var out: Self.Word = undefined;
            for (&out, 0..) |*v, i| v.* = if (i + n < 32) a[i + n] else S.zero();
            return out;
        }
        pub fn add(a: Self.Word, b: Self.Word) Self.Word {
            var out: Self.Word = undefined;
            var carry = S.zero();
            for (&out, a, b) |*v, x, y| {
                const different = xorBit(x, y);
                // Read both source bits and the old carry before publishing
                // the result bit. This is safe even when an optimized return
                // slot aliases one of the input word buffers.
                const next_carry = x.mul(y).add(different.mul(carry));
                const sum = xorBit(different, carry);
                carry = next_carry;
                v.* = sum;
            }
            return out; // discard the 33rd carry: exact modulo 2^32
        }
        pub fn fromBytes(bytes: [4]Self.Byte, comptime endian: @import("std").builtin.Endian) Self.Word {
            var out: Self.Word = undefined;
            for (0..4) |i| @memcpy(out[i * 8 ..][0..8], &bytes[if (endian == .little) i else 3 - i]);
            return out;
        }
        pub fn toBytes(value: Self.Word, comptime endian: @import("std").builtin.Endian) [4]Self.Byte {
            var out: [4]Self.Byte = undefined;
            for (0..4) |i| out[if (endian == .little) i else 3 - i] = value[i * 8 ..][0..8].*;
            return out;
        }
        pub fn shaInitial() Self.State {
            var out: Self.State = undefined;
            for (&out, sha.initial_state) |*v, x| v.* = word(x);
            return out;
        }
        fn small(a: Self.Word, comptime first: u5, comptime second: u5, comptime third: u5) Self.Word {
            return xorWord(xorWord(rotate(a, first), rotate(a, second)), shift(a, third));
        }
        fn big(a: Self.Word, comptime first: u5, comptime second: u5, comptime third: u5) Self.Word {
            return xorWord(xorWord(rotate(a, first), rotate(a, second)), rotate(a, third));
        }
        pub fn shaCompress(initial: Self.State, block: [64]Self.Byte) Self.State {
            var schedule: [64]Self.Word = undefined;
            for (0..16) |i| schedule[i] = fromBytes(block[i * 4 ..][0..4].*, .big);
            for (16..64) |i| schedule[i] = add(add(small(schedule[i - 2], 17, 19, 10), schedule[i - 7]), add(small(schedule[i - 15], 7, 18, 3), schedule[i - 16]));
            var state = initial;
            for (0..64) |i| {
                var choose: Self.Word = undefined;
                var majority: Self.Word = undefined;
                for (&choose, &majority, 0..) |*c, *m, j| {
                    c.* = state[4][j].mul(state[5][j]).add(S.one().sub(state[4][j]).mul(state[6][j]));
                    m.* = state[0][j].mul(state[1][j]).add(xorBit(state[0][j], state[1][j]).mul(state[2][j]));
                }
                const t1 = add(add(add(state[7], big(state[4], 6, 11, 25)), choose), add(word(sha.round_constants[i]), schedule[i]));
                const t2 = add(big(state[0], 2, 13, 22), majority);
                const next_a = add(t1, t2);
                const next_e = add(state[3], t1);
                // Descending assignment preserves every old state word until
                // its last use. Do not construct a mixed old/new aggregate
                // directly into the state return slot.
                var position: usize = 8;
                while (position > 1) {
                    position -= 1;
                    state[position] = if (position == 4) next_e else state[position - 1];
                }
                state[0] = next_a;
            }
            for (&state, initial) |*v, x| v.* = add(v.*, x);
            return state;
        }
        pub fn shaDigest(state: Self.State) Self.Digest {
            var out: Self.Digest = undefined;
            for (state, 0..) |value, i| @memcpy(out[i * 4 ..][0..4], &toBytes(value, .big));
            return out;
        }
        /// One streaming raw block. Tail padding is derived from the public
        /// total byte length, never supplied as private SHA message bytes.
        /// For len%64>=56 the terminal call compresses two blocks.
        pub fn shaChunk(initial: Self.State, raw: [64]Self.Byte, used: usize, total_bytes: u64, terminal: bool) !Self.State {
            if (used > 64 or (!terminal and used != 64) or (terminal and (used == 64 or used != total_bytes % 64)) or total_bytes > @divFloor(@as(u64, @import("std").math.maxInt(u64)), 8)) return error.InvalidSourceShaChunk;
            if (!terminal) return shaCompress(initial, raw);
            var block: [64]Self.Byte = undefined;
            for (&block, 0..) |*v, i| v.* = if (i < used) raw[i] else byte(0);
            block[used] = byte(0x80);
            const bit_length = total_bytes * 8;
            if (used < 56) {
                for (0..8) |i| block[56 + i] = byte(@truncate(bit_length >> @intCast(56 - 8 * i)));
                return shaCompress(initial, block);
            }
            const chained = shaCompress(initial, block);
            block = @splat(byte(0));
            for (0..8) |i| block[56 + i] = byte(@truncate(bit_length >> @intCast(56 - 8 * i)));
            return shaCompress(chained, block);
        }
        pub fn blakeCompress(initial: [32]Self.Word) [16]Self.Word {
            const plan = topology.canonical();
            var wires: [topology.WIRE_COUNT]Self.Word = undefined;
            @memcpy(wires[0..32], &initial);
            for (plan.g) |call| {
                var a = wires[call.input[0]];
                var b = wires[call.input[1]];
                var c = wires[call.input[2]];
                var d = wires[call.input[3]];
                a = add(add(a, b), wires[call.input[4]]);
                d = rotate(xorWord(d, a), 16);
                c = add(c, d);
                b = rotate(xorWord(b, c), 12);
                a = add(add(a, b), wires[call.input[5]]);
                d = rotate(xorWord(d, a), 8);
                c = add(c, d);
                b = rotate(xorWord(b, c), 7);
                const result = [4]Self.Word{ a, b, c, d };
                for (call.output, result) |id, value| wires[id] = value;
            }
            for (plan.xor) |call| wires[call.output] = xorWord(wires[call.input[0]], wires[call.input[1]]);
            var out: [16]Self.Word = undefined;
            for (&out, plan.output) |*v, id| v.* = wires[id];
            return out;
        }
        /// Exact normal BLAKE3 for canonical 48-byte leaf/108-byte node frames.
        pub fn blakeFrame(raw: []const Self.Byte) !Self.Digest {
            if (raw.len != 48 and raw.len != 108) return error.InvalidSourceBlakeFrame;
            const iv = [8]u32{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
            var cv: Self.State = undefined;
            for (&cv, iv) |*v, x| v.* = word(x);
            const blocks = (raw.len + 63) / 64;
            var output: [16]Self.Word = undefined;
            for (0..blocks) |block_index| {
                const offset = block_index * 64;
                const used: usize = @min(64, raw.len - offset);
                var block: [64]Self.Byte = @splat(byte(0));
                @memcpy(block[0..used], raw[offset..][0..used]);
                var initial: [32]Self.Word = undefined;
                @memcpy(initial[0..8], &cv);
                for (0..4) |i| initial[8 + i] = word(iv[i]);
                initial[12] = word(0);
                initial[13] = word(0);
                initial[14] = word(@intCast(used));
                initial[15] = word((if (block_index == 0) @as(u32, 1) else 0) | (if (block_index + 1 == blocks) @as(u32, 2 | 8) else 0));
                for (0..16) |i| initial[16 + i] = fromBytes(block[i * 4 ..][0..4].*, .little);
                output = blakeCompress(initial);
                @memcpy(&cv, output[0..8]);
            }
            var result: Self.Digest = undefined;
            for (output[0..8], 0..) |value, i| @memcpy(result[i * 4 ..][0..4], &toBytes(value, .little));
            return result;
        }
        fn header(comptime n: usize, tag: u32) [n]Self.Byte {
            var out: [n]Self.Byte = @splat(byte(0));
            for (tree.DOMAIN, 0..) |value, i| out[i] = byte(value);
            @memcpy(out[32..36], &toBytes(word(2), .little));
            @memcpy(out[36..40], &toBytes(word(tag), .little));
            @memcpy(out[40..44], &toBytes(word(@intFromEnum(tree.Kind.memory)), .little));
            return out;
        }
        pub fn leaf(value: Self.Word) Self.Digest {
            var frame = header(48, 1);
            @memcpy(frame[44..48], &toBytes(value, .little));
            return blakeFrame(&frame) catch unreachable;
        }
        pub fn node(left: Self.Digest, right: Self.Digest) Self.Digest {
            var frame = header(108, 2);
            @memcpy(frame[44..76], &left);
            @memcpy(frame[76..108], &right);
            return blakeFrame(&frame) catch unreachable;
        }
        pub fn select(flag: S, a: Self.Digest, b: Self.Digest) Self.Digest {
            var out: Self.Digest = undefined;
            for (&out, a, b) |*v, x, y| for (v, x, y) |*o, p, q| {
                o.* = p.add(flag.mul(q.sub(p)));
            };
            return out;
        }
    };
}
