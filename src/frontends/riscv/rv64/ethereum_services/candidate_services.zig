//! Execution-only CANDIDATE services for profile `ethereum_services_v3_candidate`.
//!
//! These services exist only in the execution census tool. The prover does not
//! admit them, no compact tape or proof witness ever records them, and results
//! that use them are evidence for a service proposal, never promotable.
//! ABI: autoresearch/guest_efficiency/CONTEXT.md ("Candidate services").
//! `a0` = 8-byte aligned packet of little-endian u64 fields, `a7` = tag, all
//! registers preserved, packet updated in place, one retired instruction.
//!
//! Clarifications (also in autoresearch/guest_efficiency/notes/candidate-services-abi.md):
//! - Bulk pointers (memcpy dst/src, memset dst, memcmp a/b) have no alignment
//!   requirement. `len == 0` touches no memory and needs no mapping.
//! - Reads require `read` permission over the whole source range; writes
//!   require `write` permission over the whole destination range. All checks
//!   precede any architectural change, so a trapping call changes nothing.
//! - memcmp `bytes` counts examined bytes (first difference index + 1, or len).
//! - sha256_compress packet (96 bytes, 12 u64): bytes 0..32 are the eight
//!   state words H0..H7 as little-endian u32 (H0 in the low half of u64[0]),
//!   bytes 32..96 are the 64-byte message block in stream order (the usual
//!   SHA-256 big-endian word parse applies to them). Only the state changes.
//! - arith256: packet a,b,c,lo,hi (20 u64, 4 little-endian limbs each);
//!   writes lo, hi. arith256_mod: a,b,c,m,r; writes r (r = 0 when m = 0).
const std = @import("std");
const machine = @import("../machine.zig");
const memory = @import("../memory.zig");
const profile = @import("../execution_profile.zig");
/// Curve, field and Keccak-sponge candidates (tags 0x0003_01xx).
const curves = @import("candidate_curves.zig");

pub const MEMCPY_TAG: u64 = 0x0003_0001;
pub const MEMSET_TAG: u64 = 0x0003_0002;
pub const MEMCMP_TAG: u64 = 0x0003_0003;
pub const SHA256_COMPRESS_TAG: u64 = 0x0003_0010;
pub const ARITH256_TAG: u64 = 0x0003_0020;
pub const ARITH256_MOD_TAG: u64 = 0x0003_0021;
/// One call may move at most this many bytes (the mapped-memory ceiling).
pub const MAX_BULK_BYTES: u64 = 256 * 1024 * 1024;

pub const Kind = enum { memcpy, memset, memcmp, sha256_compress, arith256, arith256_mod, bn254_g1_add, bn254_g1_double, bn254_fp2_mul, bls12_381_g1_add, bls12_381_g1_double, bls12_381_fp2_mul, arith384_mod, arith384_mont, keccak_sponge };
pub const Use = struct { calls: u64 = 0, bytes: u64 = 0 };
/// Serialized as `candidate_service_calls: {name: {calls, bytes}}`.
pub const Counts = struct {
    memcpy: Use = .{},
    memset: Use = .{},
    memcmp: Use = .{},
    sha256_compress: Use = .{},
    arith256: Use = .{},
    arith256_mod: Use = .{},
    bn254_g1_add: Use = .{},
    bn254_g1_double: Use = .{},
    bn254_fp2_mul: Use = .{},
    bls12_381_g1_add: Use = .{},
    bls12_381_g1_double: Use = .{},
    bls12_381_fp2_mul: Use = .{},
    arith384_mod: Use = .{},
    arith384_mont: Use = .{},
    keccak_sponge: Use = .{},
    fn of(self: *Counts, kind: Kind) *Use {
        return switch (kind) {
            inline else => |k| &@field(self, @tagName(k)),
        };
    }
    /// The six original services are always reported; the curve candidates
    /// only once called, so reports of guests that do not use them (and cost
    /// files that do not price them) are unchanged.
    pub fn jsonStringify(self: Counts, jws: anytype) !void {
        try jws.beginObject();
        inline for (std.meta.fields(Counts)) |field| {
            const use = @field(self, field.name);
            if (comptime !@hasField(curves.Kind, field.name)) {
                try jws.objectField(field.name);
                try jws.write(use);
            } else if (use.calls != 0) {
                try jws.objectField(field.name);
                try jws.write(use);
            }
        }
        try jws.endObject();
    }
};
pub const Error = memory.Error || curves.Error || error{ UnsupportedService, ServiceCounterOverflow, CandidateLengthLimit };

pub fn kindOf(tag: u64) ?Kind {
    return switch (tag) {
        MEMCPY_TAG => .memcpy,
        MEMSET_TAG => .memset,
        MEMCMP_TAG => .memcmp,
        SHA256_COMPRESS_TAG => .sha256_compress,
        ARITH256_TAG => .arith256,
        ARITH256_MOD_TAG => .arith256_mod,
        else => if (curves.kindOf(tag)) |k| switch (k) {
            inline else => |c| @field(Kind, @tagName(c)),
        } else null,
    };
}

/// Execute the candidate ECALL at `cpu.pc`. The caller has already established
/// that the current instruction is an ECALL whose tag no admitted service owns
/// and that the retirement budget allows one more instruction. On error nothing
/// (memory, CPU, counters) has changed.
pub fn step(a: std.mem.Allocator, cpu: *machine.Cpu, mem: *memory.Memory, counts: *Counts) Error!Kind {
    const kind = kindOf(cpu.read(profile.TAG_REGISTER)) orelse return error.UnsupportedService;
    const use = counts.of(kind);
    if (use.calls == std.math.maxInt(u64)) return error.ServiceCounterOverflow;
    const bytes = try execute(a, kind, cpu.read(profile.POINTER_REGISTER), mem);
    use.calls += 1;
    use.bytes +|= bytes;
    cpu.pc +%= 4;
    cpu.retired += 1;
    return kind;
}

/// Returns the byte count reported for the call.
pub fn execute(a: std.mem.Allocator, kind: Kind, pointer: u64, mem: *memory.Memory) Error!u64 {
    if (pointer & 7 != 0) return error.MisalignedAddress;
    switch (kind) {
        .memcpy => {
            const p = try readPacket(3, mem, pointer);
            const dst = p[0];
            const src = p[1];
            const len = p[2];
            if (len == 0) return 0;
            if (len > MAX_BULK_BYTES) return error.CandidateLengthLimit;
            try mem.mappings.check(src, len, .read);
            try mem.mappings.check(dst, len, .write);
            const buffer = try a.alloc(u8, @intCast(len));
            defer a.free(buffer);
            // Snapshot the whole source first: memmove-safe for any overlap.
            try readBytes(mem, src, buffer);
            try writeBytes(a, mem, dst, buffer);
            return len;
        },
        .memset => {
            const p = try readPacket(3, mem, pointer);
            const len = p[2];
            if (len == 0) return 0;
            if (len > MAX_BULK_BYTES) return error.CandidateLengthLimit;
            try mem.mappings.check(p[0], len, .write);
            const buffer = try a.alloc(u8, @intCast(len));
            defer a.free(buffer);
            @memset(buffer, @truncate(p[1]));
            try writeBytes(a, mem, p[0], buffer);
            return len;
        },
        .memcmp => {
            const p = try readPacket(4, mem, pointer);
            try mem.mappings.check(pointer + 24, 8, .write);
            const len = p[2];
            var result: i64 = 0;
            var examined: u64 = 0;
            if (len != 0) {
                if (len > MAX_BULK_BYTES) return error.CandidateLengthLimit;
                try mem.mappings.check(p[0], len, .read);
                try mem.mappings.check(p[1], len, .read);
                const buffer = try a.alloc(u8, @intCast(2 * len));
                defer a.free(buffer);
                const lhs = buffer[0..@intCast(len)];
                const rhs = buffer[@intCast(len)..];
                try readBytes(mem, p[0], lhs);
                try readBytes(mem, p[1], rhs);
                examined = len;
                if (std.mem.indexOfDiff(u8, lhs, rhs)) |i| {
                    examined = i + 1;
                    result = if (lhs[i] < rhs[i]) -1 else 1;
                }
            }
            try mem.storeWords(pointer + 24, &.{@bitCast(result)});
            return examined;
        },
        .sha256_compress => {
            const p = try readPacket(12, mem, pointer);
            try mem.mappings.check(pointer, 32, .write);
            var state: [8]u32 = undefined;
            for (&state, 0..) |*word, i| word.* = @truncate(p[i / 2] >> @intCast(32 * (i % 2)));
            var block: [64]u8 = undefined;
            for (0..8) |i| std.mem.writeInt(u64, block[8 * i ..][0..8], p[4 + i], .little);
            sha256Compress(&state, &block);
            var out: [4]u64 = undefined;
            for (&out, 0..) |*word, i| word.* = @as(u64, state[2 * i]) | (@as(u64, state[2 * i + 1]) << 32);
            try mem.storeWords(pointer, &out);
            return 64;
        },
        .arith256 => {
            const p = try readPacket(20, mem, pointer);
            try mem.mappings.check(pointer + 96, 64, .write);
            const r = mulAdd(limbs(p[0..4]), limbs(p[4..8]), limbs(p[8..12]));
            var out: [8]u64 = undefined;
            for (&out, 0..) |*word, i| word.* = @truncate(r >> @intCast(64 * i));
            try mem.storeWords(pointer + 96, &out);
            return 0;
        },
        .arith256_mod => {
            const p = try readPacket(20, mem, pointer);
            try mem.mappings.check(pointer + 128, 32, .write);
            const r = mulAddMod(limbs(p[0..4]), limbs(p[4..8]), limbs(p[8..12]), limbs(p[12..16]));
            var out: [4]u64 = undefined;
            for (&out, 0..) |*word, i| word.* = @truncate(r >> @intCast(64 * i));
            try mem.storeWords(pointer + 128, &out);
            return 0;
        },
        inline else => |k| return curves.execute(@field(curves.Kind, @tagName(k)), pointer, mem),
    }
}

fn readPacket(comptime n: usize, mem: *memory.Memory, pointer: u64) Error![n]u64 {
    _ = try memory.endAddress(pointer, n * 8);
    try mem.mappings.check(pointer, n * 8, .read);
    var words: [n]u64 = undefined;
    for (&words, 0..) |*word, i| word.* = try mem.load(pointer + 8 * i, 8);
    return words;
}

/// Permission over [address, address + out.len) is checked by the caller.
/// Aligned backing words are read directly so that edge words partly outside
/// the checked range never require their own mapping.
fn readBytes(mem: *memory.Memory, address: u64, out: []u8) Error!void {
    var i: usize = 0;
    while (i < out.len) {
        const current = address + i;
        const base = current & ~@as(u64, 7);
        const word = mem.backing.load(base, 8).value;
        var k: usize = @intCast(current - base);
        while (k < 8 and i < out.len) : (k += 1) {
            out[i] = @truncate(word >> @intCast(8 * k));
            i += 1;
        }
    }
}

/// Permission over [address, address + bytes.len) is checked by the caller.
/// Bytes of edge words outside the range keep their previous values. Pages are
/// reserved atomically by `Pages.storeWords` before any byte changes.
fn writeBytes(a: std.mem.Allocator, mem: *memory.Memory, address: u64, bytes: []const u8) Error!void {
    const first = address & ~@as(u64, 7);
    const last = (try memory.endAddress(address, bytes.len)) | 7;
    const count: usize = @intCast((last - first + 1) / 8);
    const words = try a.alloc(u64, count);
    defer a.free(words);
    words[0] = mem.backing.load(first, 8).value;
    words[count - 1] = mem.backing.load(last - 7, 8).value;
    const offset: usize = @intCast(address - first);
    for (bytes, offset..) |byte, k| {
        const word = &words[k / 8];
        const shift: u6 = @intCast(8 * (k % 8));
        word.* = (word.* & ~(@as(u64, 0xff) << shift)) | (@as(u64, byte) << shift);
    }
    try mem.backing.storeWords(first, words);
}

fn limbs(words: []const u64) u256 {
    var value: u256 = 0;
    for (words, 0..) |word, i| value |= @as(u256, word) << @intCast(64 * i);
    return value;
}

pub fn mulAdd(x: u256, y: u256, z: u256) u512 {
    return @as(u512, x) * @as(u512, y) + @as(u512, z);
}

pub fn mulAddMod(x: u256, y: u256, z: u256, m: u256) u256 {
    if (m == 0) return 0;
    return @truncate(mulAdd(x, y, z) % @as(u512, m));
}

const K256 = [64]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/// FIPS 180-4 section 6.2.2, one block. Independent of std's Sha256 so the
/// test vectors exercise this code, not the library.
pub fn sha256Compress(state: *[8]u32, block: *const [64]u8) void {
    var w: [64]u32 = undefined;
    for (0..16) |t| w[t] = std.mem.readInt(u32, block[4 * t ..][0..4], .big);
    for (16..64) |t| {
        const s0 = std.math.rotr(u32, w[t - 15], 7) ^ std.math.rotr(u32, w[t - 15], 18) ^ (w[t - 15] >> 3);
        const s1 = std.math.rotr(u32, w[t - 2], 17) ^ std.math.rotr(u32, w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16] +% s0 +% w[t - 7] +% s1;
    }
    var v = state.*;
    for (0..64) |t| {
        const s1 = std.math.rotr(u32, v[4], 6) ^ std.math.rotr(u32, v[4], 11) ^ std.math.rotr(u32, v[4], 25);
        const ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
        const t1 = v[7] +% s1 +% ch +% K256[t] +% w[t];
        const s0 = std.math.rotr(u32, v[0], 2) ^ std.math.rotr(u32, v[0], 13) ^ std.math.rotr(u32, v[0], 22);
        const maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        const t2 = s0 +% maj;
        // Build into a temporary: result-location semantics would alias `v`.
        const next = [8]u32{ t1 +% t2, v[0], v[1], v[2], v[3] +% t1, v[4], v[5], v[6] };
        v = next;
    }
    for (state, v) |*h, x| h.* +%= x;
}

// ---------------------------------------------------------------- tests

test {
    _ = curves;
}

test "candidate counts report curve services only once called" {
    var counts = Counts{};
    counts.memcpy.calls = 2;
    const plain = try std.json.Stringify.valueAlloc(testing.allocator, counts, .{});
    defer testing.allocator.free(plain);
    try testing.expectEqualStrings("{\"memcpy\":{\"calls\":2,\"bytes\":0},\"memset\":{\"calls\":0,\"bytes\":0},\"memcmp\":{\"calls\":0,\"bytes\":0},\"sha256_compress\":{\"calls\":0,\"bytes\":0},\"arith256\":{\"calls\":0,\"bytes\":0},\"arith256_mod\":{\"calls\":0,\"bytes\":0}}", plain);
    counts.keccak_sponge = .{ .calls = 1, .bytes = 136 };
    const with = try std.json.Stringify.valueAlloc(testing.allocator, counts, .{});
    defer testing.allocator.free(with);
    try testing.expect(std.mem.endsWith(u8, with, "\"arith256_mod\":{\"calls\":0,\"bytes\":0},\"keccak_sponge\":{\"calls\":1,\"bytes\":136}}"));
}

const testing = std.testing;
const BASE: u64 = 0x1000_0000;
const SIZE: u64 = 4 * memory.PAGE_SIZE;

fn testMemory() !memory.Memory {
    var mem = memory.Memory.init(testing.allocator, .{});
    errdefer mem.deinit();
    try mem.map(.{ .start = BASE, .size = SIZE, .permissions = .{ .read = true, .write = true } });
    try mem.map(.{ .start = BASE + SIZE, .size = memory.PAGE_SIZE, .permissions = .{ .read = true } });
    var pattern: [SIZE]u8 = undefined;
    for (&pattern, 0..) |*b, i| b.* = @truncate(i *% 131 +% 7);
    try mem.initialize(BASE, &pattern);
    return mem;
}

fn putWords(mem: *memory.Memory, address: u64, words: []const u64) !void {
    try mem.storeWords(address, words);
}

fn getBytes(mem: *memory.Memory, address: u64, out: []u8) !void {
    for (out, 0..) |*b, i| b.* = @intCast(try mem.load(address + i, 1));
}

fn call(mem: *memory.Memory, tag: u64, packet: u64) !Kind {
    var cpu = machine.Cpu.init(0x100, 0);
    cpu.regs[profile.TAG_REGISTER] = tag;
    cpu.regs[profile.POINTER_REGISTER] = packet;
    var counts = Counts{};
    const kind = try step(testing.allocator, &cpu, mem, &counts);
    try testing.expectEqual(@as(u64, 0x104), cpu.pc);
    try testing.expectEqual(@as(u64, 1), cpu.retired);
    try testing.expectEqual(@as(u64, 1), counts.of(kind).calls);
    try testing.expectEqual(tag, cpu.regs[profile.TAG_REGISTER]);
    try testing.expectEqual(packet, cpu.regs[profile.POINTER_REGISTER]);
    return kind;
}

test "candidate memcpy is memmove-safe for both overlap directions and any alignment" {
    var mem = try testMemory();
    defer mem.deinit();
    const packet = BASE + SIZE - 64;
    for ([_][2]u64{ .{ 0x103, 0x100 }, .{ 0x100, 0x105 }, .{ 0x201, 0x7ff }, .{ 0x7ff, 0x201 } }) |pair| {
        for ([_]u64{ 1, 7, 9, 100, 1500 }) |len| {
            var before: [SIZE]u8 = undefined;
            try getBytes(&mem, BASE, &before);
            var expected = before;
            const d: usize = @intCast(pair[0]);
            const s: usize = @intCast(pair[1]);
            var tmp: [1500]u8 = undefined;
            @memcpy(tmp[0..@intCast(len)], before[s..][0..@intCast(len)]);
            @memcpy(expected[d..][0..@intCast(len)], tmp[0..@intCast(len)]);
            try putWords(&mem, packet, &.{ BASE + pair[0], BASE + pair[1], len });
            _ = try call(&mem, MEMCPY_TAG, packet);
            var after: [SIZE]u8 = undefined;
            try getBytes(&mem, BASE, &after);
            // The packet itself lives in the region; it must be unchanged.
            @memcpy(expected[@intCast(packet - BASE)..][0..24], after[@intCast(packet - BASE)..][0..24]);
            try testing.expectEqualSlices(u8, &expected, &after);
            var p: [3]u64 = undefined;
            for (&p, 0..) |*w, i| w.* = try mem.load(packet + 8 * i, 8);
            try testing.expectEqual([3]u64{ BASE + pair[0], BASE + pair[1], len }, p);
        }
    }
}

test "candidate bulk services check permissions before any change" {
    var mem = try testMemory();
    defer mem.deinit();
    var counts = Counts{};
    var cpu = machine.Cpu.init(0x100, 0);
    cpu.regs[profile.TAG_REGISTER] = MEMCPY_TAG;
    cpu.regs[profile.POINTER_REGISTER] = BASE;
    var before: [SIZE]u8 = undefined;
    // Destination crosses into the read-only page: denied, nothing written.
    try putWords(&mem, BASE, &.{ BASE + SIZE - 8, BASE + 64, 16 });
    try getBytes(&mem, BASE, &before);
    try testing.expectError(error.AccessDenied, step(testing.allocator, &cpu, &mem, &counts));
    var after: [SIZE]u8 = undefined;
    try getBytes(&mem, BASE, &after);
    try testing.expectEqualSlices(u8, &before, &after);
    try testing.expectEqual(@as(u64, 0x100), cpu.pc);
    try testing.expectEqual(@as(u64, 0), counts.memcpy.calls);
    // Reading from the read-only page is allowed; reading past it is not.
    try putWords(&mem, BASE, &.{ BASE + 64, BASE + SIZE, 16 });
    _ = try step(testing.allocator, &cpu, &mem, &counts);
    try putWords(&mem, BASE, &.{ BASE + 64, BASE + SIZE + memory.PAGE_SIZE - 8, 16 });
    try testing.expectError(error.UnmappedAddress, step(testing.allocator, &cpu, &mem, &counts));
    // Misaligned packet and unknown tags trap.
    cpu.regs[profile.POINTER_REGISTER] = BASE + 4;
    try testing.expectError(error.MisalignedAddress, step(testing.allocator, &cpu, &mem, &counts));
    cpu.regs[profile.POINTER_REGISTER] = BASE;
    cpu.regs[profile.TAG_REGISTER] = 0x0003_0004;
    try testing.expectError(error.UnsupportedService, step(testing.allocator, &cpu, &mem, &counts));
    // Zero length touches nothing, even with wild pointers.
    cpu.regs[profile.TAG_REGISTER] = MEMSET_TAG;
    try putWords(&mem, BASE, &.{ 0xdead_0000_0000, 0x41, 0 });
    _ = try step(testing.allocator, &cpu, &mem, &counts);
    try testing.expectEqual(@as(u64, 1), counts.memset.calls);
    try testing.expectEqual(@as(u64, 0), counts.memset.bytes);
}

test "candidate memset fills exactly the range with the low byte" {
    var mem = try testMemory();
    defer mem.deinit();
    const packet = BASE + 0x3000;
    try putWords(&mem, packet, &.{ BASE + 0x105, 0x1c3, 21 });
    var before: [64]u8 = undefined;
    try getBytes(&mem, BASE + 0x100, &before);
    _ = try call(&mem, MEMSET_TAG, packet);
    var after: [64]u8 = undefined;
    try getBytes(&mem, BASE + 0x100, &after);
    for (after, before, 0..) |x, y, i| try testing.expectEqual(if (i >= 5 and i < 26) @as(u8, 0xc3) else y, x);
}

test "candidate memcmp returns the lexicographic sign of the first difference" {
    var mem = try testMemory();
    defer mem.deinit();
    const packet = BASE + 0x3000;
    const lhs = BASE + 0x201;
    const rhs = BASE + 0x403;
    var data: [40]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i * 37 + 1);
    for (data, 0..) |b, i| {
        try mem.store(lhs + i, 1, b);
        try mem.store(rhs + i, 1, b);
    }
    try putWords(&mem, packet, &.{ lhs, rhs, 40, 0x5555 });
    _ = try call(&mem, MEMCMP_TAG, packet);
    try testing.expectEqual(@as(u64, 0), try mem.load(packet + 24, 8));
    try mem.store(rhs + 17, 1, data[17] +% 1);
    _ = try call(&mem, MEMCMP_TAG, packet);
    try testing.expectEqual(@as(i64, -1), @as(i64, @bitCast(try mem.load(packet + 24, 8))));
    try putWords(&mem, packet, &.{ rhs, lhs, 40, 0 });
    _ = try call(&mem, MEMCMP_TAG, packet);
    try testing.expectEqual(@as(i64, 1), @as(i64, @bitCast(try mem.load(packet + 24, 8))));
    // Difference beyond len is invisible; the byte comparison is unsigned.
    try putWords(&mem, packet, &.{ rhs, lhs, 17, 7 });
    _ = try call(&mem, MEMCMP_TAG, packet);
    try testing.expectEqual(@as(u64, 0), try mem.load(packet + 24, 8));
    try mem.store(lhs, 1, 0x80);
    try mem.store(rhs, 1, 0x7f);
    try putWords(&mem, packet, &.{ lhs, rhs, 3, 0 });
    _ = try call(&mem, MEMCMP_TAG, packet);
    try testing.expectEqual(@as(i64, 1), @as(i64, @bitCast(try mem.load(packet + 24, 8))));
    var counts = Counts{};
    var cpu = machine.Cpu.init(0, 0);
    cpu.regs[profile.TAG_REGISTER] = MEMCMP_TAG;
    cpu.regs[profile.POINTER_REGISTER] = packet;
    _ = try step(testing.allocator, &cpu, &mem, &counts);
    try testing.expectEqual(@as(u64, 1), counts.memcmp.bytes);
}

const SHA256_IV = [8]u32{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

test "candidate sha256_compress matches FIPS 180-4 abc and a two-block message" {
    var mem = try testMemory();
    defer mem.deinit();
    const packet = BASE + 0x800;
    var block: [64]u8 = @splat(0);
    block[0] = 'a';
    block[1] = 'b';
    block[2] = 'c';
    block[3] = 0x80;
    block[63] = 24;
    var words: [12]u64 = undefined;
    for (0..4) |i| words[i] = @as(u64, SHA256_IV[2 * i]) | (@as(u64, SHA256_IV[2 * i + 1]) << 32);
    for (0..8) |i| words[4 + i] = std.mem.readInt(u64, block[8 * i ..][0..8], .little);
    try putWords(&mem, packet, &words);
    _ = try call(&mem, SHA256_COMPRESS_TAG, packet);
    const expected = [8]u32{ 0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad };
    for (0..8) |i| try testing.expectEqual(expected[i], @as(u32, @intCast(try mem.load(packet + 4 * i, 4))));
    for (0..8) |i| try testing.expectEqual(words[4 + i], try mem.load(packet + 32 + 8 * i, 8));
    // Cross-check a two-block message against std's SHA-256.
    var message: [100]u8 = undefined;
    for (&message, 0..) |*b, i| b.* = @truncate(i * 7 + 3);
    var padded: [128]u8 = @splat(0);
    @memcpy(padded[0..100], &message);
    padded[100] = 0x80;
    std.mem.writeInt(u64, padded[120..128], 800, .big);
    var state = SHA256_IV;
    sha256Compress(&state, padded[0..64]);
    sha256Compress(&state, padded[64..128]);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&message, &digest, .{});
    for (0..8) |i| try testing.expectEqual(std.mem.readInt(u32, digest[4 * i ..][0..4], .big), state[i]);
}

test "candidate arith256 satisfies big-integer identities" {
    var mem = try testMemory();
    defer mem.deinit();
    const packet = BASE + 0x900;
    const max: u256 = std.math.maxInt(u256);
    const cases = [_][3]u256{
        .{ max, max, max }, // (2^256-1)^2 + 2^256-1 = 2^512 - 2^256
        .{ 0, max, 5 },
        .{ 1 << 255, 2, 0 },
        .{ 0x1234_5678_9abc_def0_0fed_cba9_8765_4321, 0xdead_beef_0123_4567_89ab_cdef_f00d_cafe << 100, 0xffff_ffff },
    };
    for (cases) |c| {
        var words: [20]u64 = @splat(0x7777);
        for (0..3) |k| for (0..4) |i| {
            words[4 * k + i] = @truncate(c[k] >> @intCast(64 * i));
        };
        try putWords(&mem, packet, &words);
        _ = try call(&mem, ARITH256_TAG, packet);
        var lo: u256 = 0;
        var hi: u256 = 0;
        for (0..4) |i| {
            lo |= @as(u256, try mem.load(packet + 96 + 8 * i, 8)) << @intCast(64 * i);
            hi |= @as(u256, try mem.load(packet + 128 + 8 * i, 8)) << @intCast(64 * i);
        }
        try testing.expectEqual(mulAdd(c[0], c[1], c[2]), (@as(u512, hi) << 256) | lo);
        for (0..12) |i| try testing.expectEqual(words[i], try mem.load(packet + 8 * i, 8));
    }
    try testing.expectEqual((@as(u512, 1) << 512 - 1) - (@as(u512, 1) << 256) + 1 + ((@as(u512, 1) << 511) - 1), mulAdd(max, max, max));
    // Distributivity: a*(b+1) + c == (a*b + c) + a when b+1 does not wrap.
    try testing.expectEqual(mulAdd(cases[3][0], cases[3][1] + 1, 9), mulAdd(cases[3][0], cases[3][1], 9) + cases[3][0]);
}

test "candidate arith256_mod reduces a*b+c, and m = 0 gives 0" {
    var mem = try testMemory();
    defer mem.deinit();
    const packet = BASE + 0xa00;
    const p: u256 = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;
    const max: u256 = std.math.maxInt(u256);
    const cases = [_][4]u256{
        .{ p - 1, p - 1, 0, p }, // (-1)^2 = 1
        .{ max, max, max, p },
        .{ 3, 5, 7, 0 },
        .{ max, max, max, max }, // == 0 since a ≡ 0
        .{ 12345, 67890, 11, 1 << 200 },
    };
    const expected = [_]u256{ 1, @truncate(mulAdd(max, max, max) % p), 0, 0, 12345 * 67890 + 11 };
    for (cases, expected) |c, want| {
        var words: [20]u64 = @splat(0x3333);
        for (0..4) |k| for (0..4) |i| {
            words[4 * k + i] = @truncate(c[k] >> @intCast(64 * i));
        };
        try putWords(&mem, packet, &words);
        _ = try call(&mem, ARITH256_MOD_TAG, packet);
        var r: u256 = 0;
        for (0..4) |i| r |= @as(u256, try mem.load(packet + 128 + 8 * i, 8)) << @intCast(64 * i);
        try testing.expectEqual(want, r);
        for (0..16) |i| try testing.expectEqual(words[i], try mem.load(packet + 8 * i, 8));
    }
    // Fermat: a^(p-1) = 1 mod p via repeated arith256_mod squaring semantics.
    var acc: u256 = 1;
    var base: u256 = 0x1234567;
    var e: u256 = p - 1;
    while (e != 0) : (e >>= 1) {
        if (e & 1 == 1) acc = mulAddMod(acc, base, 0, p);
        base = mulAddMod(base, base, 0, p);
    }
    try testing.expectEqual(@as(u256, 1), acc);
}
