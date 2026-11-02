//! Admitted Keccak-256 sponge service (ethereum_services_v3, tag 0x0003_0130).
//!
//! Promotes the execution-only candidate (`candidate_curves.zig`) with the
//! restrictions the Word16 sponge bridge proves (see
//! design/riscv-proving-stack/rv64-keccak-sponge-service.md):
//! - packet {state, in, len, flags} at an 8-aligned `a0`;
//! - `state` 8-aligned, all 25 words readable and writable (rights 3), also
//!   for fresh calls (the bridge performs one atomic read+write per word);
//! - `in` any alignment, `len < 2^20`; the covering words of [in, in+len)
//!   readable;
//! - flags bit0 = finalize (Keccak 0x01 .. 0x80 padding of the tail), bit1 =
//!   fresh (zero initial state); other bits trap;
//! - without finalize `len` is a nonzero multiple of 136 (at least one
//!   permutation per call);
//! - packet, state and message words pairwise disjoint (every RAM access of
//!   the call shares the ECALL clock, so an alias is unprovable).
//! Every check precedes the single state store; a trapping call changes nothing.
//! The executor is witness only: the bridge and the Keccak-f truth re-derive
//! every output.
const std = @import("std");
const memory = @import("../memory.zig");
const machine = @import("../machine.zig");
const profile = @import("../execution_profile.zig");

pub const TAG: u64 = profile.KECCAK_SPONGE_TAG;
pub const RATE: u64 = 136;
pub const RATE_LANES = 17;
pub const LANES = 25;
pub const FINALIZE: u64 = 1;
pub const FRESH: u64 = 2;
/// Largest admitted message per call; a guest absorbs longer messages in
/// whole-block calls without finalize.
pub const MAX_LEN: u64 = (1 << 20) - 1;

pub const Error = error{ KeccakSpongeDomain, KeccakSpongeLength, KeccakSpongeOverlap };

pub const Packet = struct {
    state: u64,
    input: u64,
    len: u64,
    flags: u64,
    pub fn finalize(self: Packet) bool {
        return self.flags & FINALIZE != 0;
    }
    pub fn fresh(self: Packet) bool {
        return self.flags & FRESH != 0;
    }
    /// One permutation per full block plus one for the padded tail.
    pub fn permutations(self: Packet) u64 {
        return self.len / RATE + @intFromBool(self.finalize());
    }
    /// Aligned address of the first message word.
    pub fn base(self: Packet) u64 {
        return self.input & ~@as(u64, 7);
    }
    pub fn shift(self: Packet) u3 {
        return @truncate(self.input);
    }
    /// Words covering [input, input + len); zero for an empty message.
    pub fn words(self: Packet) u64 {
        if (self.len == 0) return 0;
        return (@as(u64, self.shift()) + self.len - 1) / 8 + 1;
    }
};

/// Pure ABI checks on the packet words (no memory access).
pub fn validatePacket(pointer: u64, p: Packet) (Error || memory.Error)!void {
    if (pointer & 7 != 0 or p.state & 7 != 0) return error.MisalignedAddress;
    if (p.flags & ~(FINALIZE | FRESH) != 0) return error.KeccakSpongeDomain;
    if (p.len > MAX_LEN) return error.KeccakSpongeLength;
    if (!p.finalize() and (p.len == 0 or p.len % RATE != 0)) return error.KeccakSpongeDomain;
    _ = try memory.endAddress(pointer, 32);
    _ = try memory.endAddress(p.state, 8 * LANES);
    if (p.len != 0) _ = try memory.endAddress(p.base(), 8 * p.words());
    const packet_end = pointer + 32;
    const state_end = p.state + 8 * LANES;
    if (overlaps(pointer, packet_end, p.state, state_end)) return error.KeccakSpongeOverlap;
    if (p.len != 0) {
        const m0 = p.base();
        const m1 = m0 + 8 * p.words();
        if (overlaps(pointer, packet_end, m0, m1) or overlaps(p.state, state_end, m0, m1)) return error.KeccakSpongeOverlap;
    }
}
fn overlaps(a0: u64, a1: u64, b0: u64, b1: u64) bool {
    return a0 < b1 and b0 < a1;
}

pub fn permute(st: *[25]u64) void {
    var k = std.crypto.core.keccak.KeccakF(1600){ .st = st.* };
    k.permute();
    st.* = k.st;
}

/// Message byte `t` of a call, from the covering words `words` (word 0 at
/// `base`), with the Keccak padding of the final block when finalizing.
pub fn blockBytes(p: Packet, words: []const u64, block: u64, out: *[RATE]u8) void {
    const last_full = p.len / RATE;
    for (out, 0..) |*b, i| {
        const t = block * RATE + i;
        b.* = if (t < p.len) byteAt(words, @as(u64, p.shift()) + t) else 0;
    }
    if (p.finalize() and block == last_full) {
        out[p.len - block * RATE] ^= 0x01;
        out[RATE - 1] ^= 0x80;
    }
}
pub fn byteAt(words: []const u64, stream: u64) u8 {
    return @truncate(words[stream / 8] >> @intCast(8 * (stream % 8)));
}
pub fn absorbBlock(st: *[25]u64, block: *const [RATE]u8) void {
    for (0..RATE_LANES) |l| st[l] ^= std.mem.readInt(u64, block[8 * l ..][0..8], .little);
}

/// Runs the whole call on `state` (the initial state, zero if fresh), writing
/// each permutation's input and output when `perms` is non-null.
pub fn run(p: Packet, state: *[25]u64, words: []const u64, perms: ?[][2][25]u64) void {
    if (p.fresh()) state.* = @splat(0);
    var block: [RATE]u8 = undefined;
    for (0..p.permutations()) |k| {
        blockBytes(p, words, k, &block);
        absorbBlock(state, &block);
        if (perms) |out| out[k][0] = state.*;
        permute(state);
        if (perms) |out| out[k][1] = state.*;
    }
}

/// One admitted call. The ECALL step (pointer, tag, clock) is the whole tape
/// record; provers replay the call on their chronological RAM ledger.
pub const Call = struct {
    clock: u64,
    pc: u64,
    pointer: u64,
    pub fn tag(_: Call) u64 {
        return TAG;
    }
    pub fn retirement(self: Call) machine.Retirement {
        const Word = @import("../word.zig").Word;
        return .{ .clock = self.clock, .pc = Word.fromInt(self.pc), .next_pc = Word.fromInt(self.pc +% 4), .immediate = Word.fromInt(0), .instruction = 0x73, .opcode = .ECALL, .rs1 = profile.POINTER_REGISTER, .rs2 = profile.TAG_REGISTER, .lhs = Word.fromInt(self.pointer), .rhs = Word.fromInt(TAG), .rd = 0, .previous_rd = Word.fromInt(0), .result = Word.fromInt(0), .writes_rd = false, .branch_taken = false, .memory = null };
    }
};
/// Executed call: the packet and the state before the call (state words are
/// the only written words; packet and message words are unchanged).
pub const Event = struct { call: Call, packet: Packet, state_before: [25]u64 };

fn word(mem: *memory.Memory, address: u64) memory.Error!u64 {
    return mem.load(address, 8);
}
/// Reads, checks and executes one call. On error nothing has changed.
pub fn execute(a: std.mem.Allocator, mem: *memory.Memory, pointer: u64) (Error || memory.Error)!struct { packet: Packet, state_before: [25]u64 } {
    if (pointer & 7 != 0) return error.MisalignedAddress;
    _ = try memory.endAddress(pointer, 32);
    try mem.mappings.check(pointer, 32, .read);
    const p = Packet{ .state = try word(mem, pointer), .input = try word(mem, pointer + 8), .len = try word(mem, pointer + 16), .flags = try word(mem, pointer + 24) };
    try validatePacket(pointer, p);
    try mem.mappings.check(p.state, 8 * LANES, .read);
    try mem.mappings.check(p.state, 8 * LANES, .write);
    const count = p.words();
    if (count != 0) try mem.mappings.check(p.base(), 8 * count, .read);
    const words = try a.alloc(u64, count);
    defer a.free(words);
    for (words, 0..) |*w, j| w.* = try word(mem, p.base() + 8 * j);
    var before: [25]u64 = undefined;
    for (&before, 0..) |*w, l| w.* = try word(mem, p.state + 8 * l);
    var state = before;
    run(p, &state, words, null);
    try mem.storeWords(p.state, &state);
    return .{ .packet = p, .state_before = before };
}

// ---------------------------------------------------------------- tests
const testing = std.testing;
const BASE: u64 = 0x2000_0000;
fn testMemory() !memory.Memory {
    var mem = memory.Memory.init(testing.allocator, .{});
    errdefer mem.deinit();
    try mem.map(.{ .start = BASE, .size = 8 * memory.PAGE_SIZE, .permissions = .{ .read = true, .write = true } });
    return mem;
}
fn packetAt(mem: *memory.Memory, at: u64, state: u64, input: u64, len: u64, flags: u64) !void {
    try mem.storeWords(at, &.{ state, input, len, flags });
}
fn digest(mem: *memory.Memory, state: u64) ![32]u8 {
    var out: [32]u8 = undefined;
    for (0..4) |l| std.mem.writeInt(u64, out[8 * l ..][0..8], try mem.load(state + 8 * l, 8), .little);
    return out;
}

test "admitted keccak_sponge equals Keccak-256 for many lengths and alignments" {
    var mem = try testMemory();
    defer mem.deinit();
    var data: [700]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 131 +% 7);
    const input = BASE + 0x1000;
    const state = BASE + 0x100;
    const pkt = BASE;
    for (0..8) |shift| {
        try mem.initialize(input + shift, &data);
        var len: u64 = 0;
        while (len < 560) : (len += if (len < 300) 1 else 7) {
            try packetAt(&mem, pkt, state, input + shift, len, FINALIZE | FRESH);
            _ = try execute(testing.allocator, &mem, pkt);
            var want: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(data[0..len], &want, .{});
            try testing.expectEqualSlices(u8, &want, &(try digest(&mem, state)));
        }
    }
}

test "admitted keccak_sponge: split absorb and finalize, traps change nothing" {
    var mem = try testMemory();
    defer mem.deinit();
    var data: [372]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 17 +% 3);
    const input = BASE + 0x1003;
    const state = BASE + 0x100;
    try mem.initialize(input, &data);
    try packetAt(&mem, BASE, state, input, 272, FRESH);
    _ = try execute(testing.allocator, &mem, BASE);
    try packetAt(&mem, BASE, state, input + 272, 100, FINALIZE);
    _ = try execute(testing.allocator, &mem, BASE);
    var want: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&data, &want, .{});
    try testing.expectEqualSlices(u8, &want, &(try digest(&mem, state)));
    const before = try digest(&mem, state);
    // Without finalize: length must be a nonzero multiple of 136.
    try packetAt(&mem, BASE, state, input, 100, 0);
    try testing.expectError(error.KeccakSpongeDomain, execute(testing.allocator, &mem, BASE));
    try packetAt(&mem, BASE, state, input, 0, 0);
    try testing.expectError(error.KeccakSpongeDomain, execute(testing.allocator, &mem, BASE));
    try packetAt(&mem, BASE, state, input, 136, 4);
    try testing.expectError(error.KeccakSpongeDomain, execute(testing.allocator, &mem, BASE));
    try packetAt(&mem, BASE, state, input, MAX_LEN + 1, FINALIZE);
    try testing.expectError(error.KeccakSpongeLength, execute(testing.allocator, &mem, BASE));
    // Message overlapping the state or the packet.
    try packetAt(&mem, BASE, state, state + 199, 1, FINALIZE);
    try testing.expectError(error.KeccakSpongeOverlap, execute(testing.allocator, &mem, BASE));
    try packetAt(&mem, BASE, state, BASE + 31, 2, FINALIZE);
    try testing.expectError(error.KeccakSpongeOverlap, execute(testing.allocator, &mem, BASE));
    try packetAt(&mem, BASE, BASE + 24, input, 2, FINALIZE);
    try testing.expectError(error.KeccakSpongeOverlap, execute(testing.allocator, &mem, BASE));
    // Unaligned state, unmapped message end.
    try packetAt(&mem, BASE, state + 4, input, 2, FINALIZE);
    try testing.expectError(error.MisalignedAddress, execute(testing.allocator, &mem, BASE));
    try packetAt(&mem, BASE, state, BASE + 8 * memory.PAGE_SIZE - 3, 8, FINALIZE);
    try testing.expectError(error.UnmappedAddress, execute(testing.allocator, &mem, BASE));
    try testing.expectEqualSlices(u8, &before, &(try digest(&mem, state)));
}

test "empty message hashes to the Keccak-256 empty digest" {
    var mem = try testMemory();
    defer mem.deinit();
    try packetAt(&mem, BASE, BASE + 0x100, BASE + 0x1005, 0, FINALIZE | FRESH);
    _ = try execute(testing.allocator, &mem, BASE);
    var want: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash("", &want, .{});
    try testing.expectEqualSlices(u8, &want, &(try digest(&mem, BASE + 0x100)));
}
