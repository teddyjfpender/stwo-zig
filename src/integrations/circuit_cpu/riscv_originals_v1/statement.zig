//! A direct ORIGINAL_JOIN certificate, distinct from a NativeParent wrapper.
//! It commits the admitted original roster and exact closure program together
//! with the execution span. No nonexistent NativeParent key/root is named.
const std = @import("std");
const b = @import("stwo_circuit_frontend").builder;
const Hash = b.blake3_channel_reuse_v1;
const Span = @import("../../../frontends/riscv/recursion/block_v8_window_root_statement_v1.zig").WindowSpan;
pub const Digest = [32]u8;
pub const DOMAIN: u32 = 0x52384f4a;
pub const VERSION: u32 = 1;
pub const ROLE: u32 = 3;
pub const WORDS: usize = 133;
pub const production_active = false;
pub const W = b.wrappers.U32Wrapper(b.Var);
pub const Statement = struct {
    span: Span,
    roster_id: Digest,
    closure_id: Digest,
    source_count: u32,
    pub fn validate(v: Statement) !void {
        try v.span.validate();
        if (v.source_count < 3 or v.source_count > 64) return error.InvalidOriginalJoinStatement;
    }
    pub fn encodeWords(v: Statement) ![WORDS]u32 {
        try v.validate();
        var words: [WORDS]u32 = undefined;
        words[0..8].* = .{ DOMAIN, VERSION, ROLE, 70, 26, 1, @intCast(v.span.first_cycle), @intCast(v.span.cycles) };
        digestWords(words[8..16], v.span.elf_sha256);
        digestWords(words[16..24], v.span.incoming_snapshot_id);
        digestWords(words[24..32], v.span.outgoing_snapshot_id);
        words[32] = v.span.initial_cpu.pc;
        @memcpy(words[33..65], &v.span.initial_cpu.regs);
        words[65] = v.span.final_cpu.pc;
        @memcpy(words[66..98], &v.span.final_cpu.regs);
        words[98] = @intFromBool(v.span.initial_policy_id != null);
        words[99] = @intFromBool(v.span.terminal_policy_id != null);
        digestWords(words[100..108], v.span.initial_policy_id orelse @splat(0));
        digestWords(words[108..116], v.span.terminal_policy_id orelse @splat(0));
        digestWords(words[116..124], v.roster_id);
        digestWords(words[124..132], v.closure_id);
        words[132] = v.source_count;
        return words;
    }
    pub fn digest(v: Statement) !Digest {
        const words = try v.encodeWords();
        var hasher = std.crypto.hash.Blake3.init(.{});
        for (words) |word| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            hasher.update(&bytes);
        }
        var out: Digest = undefined;
        hasher.final(&out);
        return out;
    }
    pub fn allocate(v: Statement, comptime V: type, ctx: *b.Context(V)) !Wires {
        const values = try v.encodeWords();
        var result: Wires = undefined;
        for (&result.words, values) |*wire, value| {
            wire.* = try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, value));
            try ctx.eq(wire.get(), (try b.wrappers.constU32(V, ctx, value)).get());
        }
        return result;
    }
};
pub const Wires = struct {
    words: [WORDS]W,
    pub fn digest(v: Wires, comptime V: type, ctx: *b.Context(V)) !Hash.Digest {
        return Hash.hashWords(V, ctx, &v.words);
    }
    /// Exact byte limbs for the old closure DAG's CPU boundary ports, derived
    /// from the SAME statement words used by the public output hash.
    pub fn cpuBytes(v: Wires, comptime V: type, ctx: *b.Context(V)) ![264]b.Var {
        var bytes: [264]b.Var = undefined;
        for (v.words[32..98], 0..) |word, i| {
            const bits = try b.extract_bits.extractBits(V, ctx, b.simd.Simd.fromPacked(&.{word.get()}, 2), 16);
            for (0..4) |byte| {
                var value = ctx.zero();
                for (0..8) |bit| {
                    const scalar = try b.simd.unpackIdx(V, ctx, bits[8 * (byte % 2) + bit], byte / 2);
                    const power = try ctx.constant(@import("stwo_core").fields.qm31.QM31.fromU32Unchecked(@as(u32, 1) << @intCast(bit), 0, 0, 0));
                    value = try ctx.add(value, try ctx.mul(scalar, power));
                }
                bytes[4 * i + byte] = value;
            }
        }
        return bytes;
    }
};
fn digestWords(words: []u32, value: Digest) void {
    std.debug.assert(words.len == 8);
    for (words, 0..) |*word, i| word.* = std.mem.readInt(u32, value[4 * i ..][0..4], .little);
}
