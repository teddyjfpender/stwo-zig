//! Dedicated-AIR circuit twin of the explicitly named native Poseidon channel.
const std = @import("std");
const core = @import("stwo_core");
const B = @import("stwo_circuit_frontend").builder;
const S = @import("sponge.zig");
const Q = core.fields.qm31.QM31;
const Var = B.Var;
const Word = B.wrappers.U32Wrapper(Var);
pub fn ForContext(comptime Context: type, comptime degree: usize) type {
    return ForVersion(Context, degree, 1);
}
pub fn ForContextV2(comptime Context: type, comptime degree: usize) type {
    return ForVersion(Context, degree, 2);
}
fn ForVersion(comptime Context: type, comptime degree: usize, comptime version: u8) type {
    if (degree != 4 and degree != 8) @compileError("unqualified Poseidon secure field");
    return struct {
        pub const Felt = [degree / 4]Var;
        pub const Hash = S.Hash;
        const Self = @This();
        const Sponge = S.ForContext(Context);
        const Secure = if (degree == 4) Q else core.fields.om31.OM31;
        const Native = if (version == 1) core.channel.poseidon2_m31.ForField(Secure) else core.channel.poseidon2_m31.ForFieldV2(Secure);
        digest: Hash,
        n_draws: Native.Counter = 0,
        pub fn init(ctx: *Context) !Self {
            const words = try core.crypto.poseidon2_m31_sponge.decode(Native.init().digestBytes());
            var digest: Hash = undefined;
            for (&digest, words) |*v, word| v.* = try ctx.algebra().constant(Q.fromBase(word));
            return .{ .digest = digest };
        }
        fn start(self: Self, ctx: *Context, domain: S.Domain) !Sponge {
            var s = try Sponge.init(ctx, domain);
            try s.absorbMany(&self.digest);
            return s;
        }
        fn update(self: *Self, digest: Hash) void {
            self.digest = digest;
            self.n_draws = 0;
        }
        pub fn mixRoot(self: *Self, ctx: *Context, root: Hash) !void {
            var s = try self.start(ctx, .mix_root);
            try s.absorbMany(&root);
            self.update(try s.finish());
        }
        pub fn mixConstU32s(self: *Self, ctx: *Context, words: []const u32) !void {
            var s = try self.start(ctx, .mix_words);
            for (words) |word| try s.absorbConstU32(word);
            self.update(try s.finish());
        }
        /// Explicit shape/range constraints also reject forged unsafe wrappers.
        fn absorbWord(s: *Sponge, word: Word) !void {
            const a = s.context.algebra();
            const wires = [1]Var{word.get()};
            const lanes = B.simd.Simd.fromPacked(&wires, 4);
            for (0..4) |i| {
                const part = try B.simd.unpackIdx(Q, a, lanes, i);
                if (i < 2) {
                    const checked = try a.guessU16(if (a.trace_only) B.ivalue.placeholder(Q) else a.get(part));
                    try a.eq(part, checked);
                    try s.absorb(checked);
                } else try a.eq(part, a.zero());
            }
        }
        pub fn mixU32s(self: *Self, ctx: *Context, words: []const Word) !void {
            var s = try self.start(ctx, .mix_words);
            for (words) |word| try absorbWord(&s, word);
            self.update(try s.finish());
        }
        pub fn mixU64(self: *Self, ctx: *Context, lo: Word, hi: Word) !void {
            try self.mixU32s(ctx, &.{ lo, hi });
        }
        pub fn mixFelts(self: *Self, ctx: *Context, values: []const Felt) !void {
            var s = try self.start(ctx, .mix_felts);
            for (values) |value| {
                const lanes = B.simd.Simd.fromPacked(&value, degree);
                for (0..degree) |i| try s.absorb(try B.simd.unpackIdx(Q, ctx.algebra(), lanes, i));
            }
            self.update(try s.finish());
        }
        pub fn drawCanonicalWords(self: *Self, ctx: *Context) ![8]Var {
            var s = try self.start(ctx, .draw);
            if (version == 1) try s.absorbConstU64(self.n_draws) else try s.absorbConstU32(self.n_draws);
            self.n_draws = try std.math.add(Native.Counter, self.n_draws, 1);
            const result = try s.finish();
            return result[0..8].*;
        }
        pub fn drawU32s(self: *Self, ctx: *Context) ![8]Word {
            const drawn = try self.drawCanonicalWords(ctx);
            var out: [8]Word = undefined;
            for (&out, drawn) |*word, base| word.* = try B.blake.m31ToU32(Q, ctx.algebra(), base);
            return out;
        }
        pub fn drawSecureFelt(self: *Self, ctx: *Context) !Felt {
            const drawn = try self.drawCanonicalWords(ctx);
            var out: Felt = undefined;
            for (&out, 0..) |*wire, i| wire.* = try B.ops.fromPartialEvals(Q, ctx.algebra(), drawn[4 * i ..][0..4].*);
            return out;
        }
        pub fn drawQueryBits(self: *Self, ctx: *Context, log: u32, count: usize) !@import("stwo_circuit_frontend").native_verifier.channel.QueryBits {
            if (log == 0 or log > 30 or count == 0) return error.InvalidPoseidonQueryShape;
            const a = ctx.algebra();
            const scratch = a.scratch();
            const words = try scratch.alloc(B.wrappers.M31Wrapper(Var), count);
            var at: usize = 0;
            while (at < count) {
                const block = try self.drawCanonicalWords(ctx);
                for (block) |word| {
                    if (at == count) break;
                    words[at] = .newUnsafe(word);
                    at += 1;
                }
            }
            const packed_words = try B.simd.pack(Q, a, words);
            const all = try B.extract_bits.extractBits(Q, a, packed_words, 31);
            for (all[log..]) |unused| try B.simd.markPartlyUsed(Q, a, unused);
            const unpacked = try scratch.alloc([]const Var, log);
            for (unpacked, all[0..log]) |*bits, bit| bits.* = try B.simd.unpack(Q, a, bit);
            return .{ .bits = all[0..log], .unpacked = unpacked, .n_queries = count };
        }
        pub fn pow(self: *Self, ctx: *Context, bits: u32, nonce: [2]Word) !void {
            if (bits > 30) return error.UnsupportedPoseidonPow;
            const a = ctx.algebra();
            if (bits == 0) {
                try a.eq(nonce[0].get(), a.zero());
                try a.eq(nonce[1].get(), a.zero());
            } else {
                var s = try self.start(ctx, .pow);
                try s.absorbConstU32(bits);
                try absorbWord(&s, nonce[0]);
                try absorbWord(&s, nonce[1]);
                const out = try s.finish();
                const one = [1]Var{out[0]};
                const split = try B.extract_bits.extractBits(Q, a, B.simd.Simd.fromPacked(&one, 1), 31);
                for (split[0..bits]) |bit| for (bit.data) |wire| {
                    try a.eq(wire, a.zero());
                };
                for (split[bits..]) |unused| try B.simd.markPartlyUsed(Q, a, unused);
            }
            try self.mixU64(ctx, nonce[0], nonce[1]);
        }
    };
}
