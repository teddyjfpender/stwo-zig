//! Execution-only CANDIDATE curve, field and sponge services for profile
//! `ethereum_services_v3_candidate` (dispatched from candidate_services.zig).
//!
//! Like every candidate service these exist only in the execution tool; the
//! prover does not admit them and results that use them are never promotable.
//! ABI: autoresearch/guest_efficiency/notes/candidate-curves-abi.md. Granularity
//! mirrors ZisK's precompiles (Bn254CurveAdd/Dbl, Bn254ComplexMul,
//! Bls12_381CurveAdd/Dbl, Bls12_381ComplexMul, Arith384Mod) plus a Montgomery
//! variant of Arith384Mod and a Keccak-256 sponge.
//!
//! Common rules:
//! - `a0` = 8-byte aligned packet of little-endian u64 words. Every packet word
//!   except the sponge's `len` and `flags` is a pointer to an 8-byte aligned
//!   operand; operands are little-endian u64 limbs (4 per 256-bit, 6 per 384-bit
//!   value, limb 0 least significant). A point or Fp2 element is two values,
//!   x then y (c0 then c1), contiguous.
//! - All inputs are read and all preconditions checked before the single
//!   output store; a trapping call changes nothing. The output may alias inputs.
//! - Precondition violations trap `CandidateDomain` (an AIR would be
//!   unsatisfiable; the guest must not issue such a call).
const std = @import("std");
const memory = @import("../memory.zig");

pub const BN254_G1_ADD_TAG: u64 = 0x0003_0100;
pub const BN254_G1_DOUBLE_TAG: u64 = 0x0003_0101;
pub const BN254_FP2_MUL_TAG: u64 = 0x0003_0102;
pub const BLS12_381_G1_ADD_TAG: u64 = 0x0003_0110;
pub const BLS12_381_G1_DOUBLE_TAG: u64 = 0x0003_0111;
pub const BLS12_381_FP2_MUL_TAG: u64 = 0x0003_0112;
pub const ARITH384_MOD_TAG: u64 = 0x0003_0120;
pub const ARITH384_MONT_TAG: u64 = 0x0003_0121;
pub const KECCAK_SPONGE_TAG: u64 = 0x0003_0130;

pub const KECCAK_RATE: u64 = 136;
pub const SPONGE_FINALIZE: u64 = 1;
pub const SPONGE_FRESH: u64 = 2;
/// Same ceiling as the bulk-memory candidates.
pub const MAX_SPONGE_BYTES: u64 = 256 * 1024 * 1024;

pub const Kind = enum { bn254_g1_add, bn254_g1_double, bn254_fp2_mul, bls12_381_g1_add, bls12_381_g1_double, bls12_381_fp2_mul, arith384_mod, arith384_mont, keccak_sponge };
pub const Error = memory.Error || error{ CandidateDomain, CandidateLengthLimit };

pub fn kindOf(tag: u64) ?Kind {
    return switch (tag) {
        BN254_G1_ADD_TAG => .bn254_g1_add,
        BN254_G1_DOUBLE_TAG => .bn254_g1_double,
        BN254_FP2_MUL_TAG => .bn254_fp2_mul,
        BLS12_381_G1_ADD_TAG => .bls12_381_g1_add,
        BLS12_381_G1_DOUBLE_TAG => .bls12_381_g1_double,
        BLS12_381_FP2_MUL_TAG => .bls12_381_fp2_mul,
        ARITH384_MOD_TAG => .arith384_mod,
        ARITH384_MONT_TAG => .arith384_mont,
        KECCAK_SPONGE_TAG => .keccak_sponge,
        else => null,
    };
}

pub const BN254_P: u256 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
pub const BLS12_381_P: u384 = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

/// Prime-field arithmetic on canonical values (< p).
pub fn Field(comptime T: type, comptime p: T) type {
    const W = std.meta.Int(.unsigned, 2 * @bitSizeOf(T));
    return struct {
        pub const P = p;
        pub fn add(a: T, b: T) T {
            const s = @as(W, a) + b;
            return @intCast(if (s >= p) s - p else s);
        }
        pub fn sub(a: T, b: T) T {
            return if (a >= b) a - b else p - (b - a);
        }
        pub fn mul(a: T, b: T) T {
            return @intCast(@as(W, a) * b % p);
        }
        /// Reduces any value of the full width.
        pub fn reduce(a: T) T {
            return a % p;
        }
        pub fn inv(a: T) T {
            return invMod(T, a, p);
        }
    };
}

/// Inverse of `a` modulo odd `m` with gcd(a, m) = 1, a != 0 (binary extended Euclid).
pub fn invMod(comptime T: type, a: T, m: T) T {
    const W = std.meta.Int(.unsigned, @bitSizeOf(T) + 1);
    var u = a % m;
    var v = m;
    var x1: T = 1;
    var x2: T = 0;
    const half = struct {
        fn f(x: T, mod: T) T {
            return if (x & 1 == 0) x >> 1 else @intCast((@as(W, x) + mod) >> 1);
        }
    }.f;
    const subm = struct {
        fn f(x: T, y: T, mod: T) T {
            return if (x >= y) x - y else mod - (y - x);
        }
    }.f;
    while (u != 1 and v != 1) {
        while (u & 1 == 0) {
            u >>= 1;
            x1 = half(x1, m);
        }
        while (v & 1 == 0) {
            v >>= 1;
            x2 = half(x2, m);
        }
        if (u >= v) {
            u -= v;
            x1 = subm(x1, x2, m);
        } else {
            v -= u;
            x2 = subm(x2, x1, m);
        }
    }
    return if (u == 1) x1 else x2;
}

pub const Bn254 = Field(u256, BN254_P);
pub const Bls = Field(u384, BLS12_381_P);

/// Affine short-Weierstrass (a = 0) chord rule. Precondition x1 != x2.
pub fn affineAdd(comptime F: type, comptime T: type, x1: T, y1: T, x2: T, y2: T) [2]T {
    const l = F.mul(F.sub(y2, y1), F.inv(F.sub(x2, x1)));
    const x3 = F.sub(F.sub(F.mul(l, l), x1), x2);
    return .{ x3, F.sub(F.mul(l, F.sub(x1, x3)), y1) };
}

/// Affine tangent rule for a = 0. Precondition y != 0.
pub fn affineDouble(comptime F: type, comptime T: type, x: T, y: T) [2]T {
    const xx = F.mul(x, x);
    const l = F.mul(F.add(F.add(xx, xx), xx), F.inv(F.add(y, y)));
    const x3 = F.sub(F.mul(l, l), F.add(x, x));
    return .{ x3, F.sub(F.mul(l, F.sub(x, x3)), y) };
}

/// Fp2 = Fp[u]/(u^2 + 1) product on canonical coefficients.
pub fn fp2Mul(comptime F: type, comptime T: type, a: [2]T, b: [2]T) [2]T {
    return .{ F.sub(F.mul(a[0], b[0]), F.mul(a[1], b[1])), F.add(F.mul(a[0], b[1]), F.mul(a[1], b[0])) };
}

/// a * b * 2^-384 mod m for odd m (m = 1 gives 0). Any a, b < 2^384.
pub fn mont384(a: u384, b: u384, m: u384) u384 {
    std.debug.assert(m & 1 == 1);
    if (m == 1) return 0;
    const t: u384 = @intCast(@as(u768, a) * b % m);
    const r_mod: u384 = @intCast((@as(u768, 1) << 384) % m);
    const r_inv = invMod(u384, r_mod, m);
    return @intCast(@as(u768, t) * r_inv % m);
}

/// (a * b + c) mod m; m = 0 gives 0.
pub fn mod384(a: u384, b: u384, c: u384, m: u384) u384 {
    if (m == 0) return 0;
    return @intCast((@as(u768, a) * b + c) % m);
}

const R384_MOD_P: u384 = @intCast((@as(u768, 1) << 384) % BLS12_381_P);
fn blsToMont(x: u384) u384 {
    return Bls.mul(x, R384_MOD_P);
}
fn blsFromMont(x: u384) u384 {
    return Bls.mul(x, Bls.inv(R384_MOD_P));
}

// ------------------------------------------------------------ memory glue

fn word(mem: *memory.Memory, address: u64) Error!u64 {
    return mem.load(address, 8);
}

fn pointerWord(mem: *memory.Memory, address: u64) Error!u64 {
    const p = try word(mem, address);
    if (p & 7 != 0) return error.MisalignedAddress;
    return p;
}

fn readValue(comptime T: type, mem: *memory.Memory, address: u64) Error!T {
    const limbs = @bitSizeOf(T) / 64;
    _ = try memory.endAddress(address, limbs * 8);
    try mem.mappings.check(address, limbs * 8, .read);
    var value: T = 0;
    for (0..limbs) |i| value |= @as(T, try mem.load(address + 8 * i, 8)) << @intCast(64 * i);
    return value;
}

fn readPair(comptime T: type, mem: *memory.Memory, address: u64) Error![2]T {
    const size = @bitSizeOf(T) / 8;
    return .{ try readValue(T, mem, address), try readValue(T, mem, address + size) };
}

fn storeValues(comptime T: type, comptime n: usize, mem: *memory.Memory, address: u64, values: [n]T) Error!void {
    const limbs = @bitSizeOf(T) / 64;
    var words: [n * limbs]u64 = undefined;
    for (values, 0..) |v, k| for (0..limbs) |i| {
        words[k * limbs + i] = @truncate(v >> @intCast(64 * i));
    };
    try mem.storeWords(address, &words);
}

fn canonical(comptime T: type, values: []const T, p: T) Error!void {
    for (values) |v| if (v >= p) return error.CandidateDomain;
}

/// Execute one call; returns the reported byte count (0 except for the sponge).
/// `pointer` is the packet address (a0). On error nothing has changed.
pub fn execute(kind: Kind, pointer: u64, mem: *memory.Memory) Error!u64 {
    if (pointer & 7 != 0) return error.MisalignedAddress;
    switch (kind) {
        .bn254_g1_add, .bls12_381_g1_add => {
            const r = try pointerWord(mem, pointer);
            const p = try pointerWord(mem, pointer + 8);
            const q = try pointerWord(mem, pointer + 16);
            if (kind == .bn254_g1_add) {
                const a = try readPair(u256, mem, p);
                const b = try readPair(u256, mem, q);
                try canonical(u256, &(a ++ b), BN254_P);
                if (a[0] == b[0]) return error.CandidateDomain;
                try storeValues(u256, 2, mem, r, affineAdd(Bn254, u256, a[0], a[1], b[0], b[1]));
            } else {
                const a = try readPair(u384, mem, p);
                const b = try readPair(u384, mem, q);
                try canonical(u384, &(a ++ b), BLS12_381_P);
                if (a[0] == b[0]) return error.CandidateDomain;
                // Montgomery residues in and out; the chord rule commutes with x -> xR.
                const s = affineAdd(Bls, u384, blsFromMont(a[0]), blsFromMont(a[1]), blsFromMont(b[0]), blsFromMont(b[1]));
                try storeValues(u384, 2, mem, r, .{ blsToMont(s[0]), blsToMont(s[1]) });
            }
            return 0;
        },
        .bn254_g1_double, .bls12_381_g1_double => {
            const r = try pointerWord(mem, pointer);
            const p = try pointerWord(mem, pointer + 8);
            if (kind == .bn254_g1_double) {
                const a = try readPair(u256, mem, p);
                try canonical(u256, &a, BN254_P);
                if (a[1] == 0) return error.CandidateDomain;
                try storeValues(u256, 2, mem, r, affineDouble(Bn254, u256, a[0], a[1]));
            } else {
                const a = try readPair(u384, mem, p);
                try canonical(u384, &a, BLS12_381_P);
                if (a[1] == 0) return error.CandidateDomain;
                const s = affineDouble(Bls, u384, blsFromMont(a[0]), blsFromMont(a[1]));
                try storeValues(u384, 2, mem, r, .{ blsToMont(s[0]), blsToMont(s[1]) });
            }
            return 0;
        },
        .bn254_fp2_mul => {
            const r = try pointerWord(mem, pointer);
            const a = try readPair(u256, mem, try pointerWord(mem, pointer + 8));
            const b = try readPair(u256, mem, try pointerWord(mem, pointer + 16));
            // Inputs need not be canonical (as ZisK's Bn254ComplexMul); output is.
            const ra = [2]u256{ Bn254.reduce(a[0]), Bn254.reduce(a[1]) };
            const rb = [2]u256{ Bn254.reduce(b[0]), Bn254.reduce(b[1]) };
            try storeValues(u256, 2, mem, r, fp2Mul(Bn254, u256, ra, rb));
            return 0;
        },
        .bls12_381_fp2_mul => {
            const r = try pointerWord(mem, pointer);
            const a = try readPair(u384, mem, try pointerWord(mem, pointer + 8));
            const b = try readPair(u384, mem, try pointerWord(mem, pointer + 16));
            // Montgomery: r = a * b * 2^-384 per coefficient of the Fp2 product.
            const ra = [2]u384{ Bls.reduce(a[0]), Bls.reduce(a[1]) };
            const rb = [2]u384{ Bls.reduce(b[0]), Bls.reduce(b[1]) };
            const s = fp2Mul(Bls, u384, ra, rb);
            const r_inv = Bls.inv(R384_MOD_P);
            try storeValues(u384, 2, mem, r, .{ Bls.mul(s[0], r_inv), Bls.mul(s[1], r_inv) });
            return 0;
        },
        .arith384_mod => {
            const a = try readValue(u384, mem, try pointerWord(mem, pointer));
            const b = try readValue(u384, mem, try pointerWord(mem, pointer + 8));
            const c = try readValue(u384, mem, try pointerWord(mem, pointer + 16));
            const m = try readValue(u384, mem, try pointerWord(mem, pointer + 24));
            const r = try pointerWord(mem, pointer + 32);
            try storeValues(u384, 1, mem, r, .{mod384(a, b, c, m)});
            return 0;
        },
        .arith384_mont => {
            const a = try readValue(u384, mem, try pointerWord(mem, pointer));
            const b = try readValue(u384, mem, try pointerWord(mem, pointer + 8));
            const m = try readValue(u384, mem, try pointerWord(mem, pointer + 16));
            const r = try pointerWord(mem, pointer + 24);
            if (m & 1 == 0) return error.CandidateDomain;
            try storeValues(u384, 1, mem, r, .{mont384(a, b, m)});
            return 0;
        },
        .keccak_sponge => {
            const state_ptr = try pointerWord(mem, pointer);
            const input = try word(mem, pointer + 8);
            const len = try word(mem, pointer + 16);
            const flags = try word(mem, pointer + 24);
            if (flags & ~(SPONGE_FINALIZE | SPONGE_FRESH) != 0) return error.CandidateDomain;
            const finalize = flags & SPONGE_FINALIZE != 0;
            if (!finalize and len % KECCAK_RATE != 0) return error.CandidateDomain;
            if (len > MAX_SPONGE_BYTES) return error.CandidateLengthLimit;
            var st: [25]u64 = @splat(0);
            if (flags & SPONGE_FRESH == 0) {
                _ = try memory.endAddress(state_ptr, 200);
                try mem.mappings.check(state_ptr, 200, .read);
                for (&st, 0..) |*lane, i| lane.* = try word(mem, state_ptr + 8 * i);
            }
            try mem.mappings.check(state_ptr, 200, .write);
            if (len != 0) try mem.mappings.check(input, len, .read);
            var permutations: u64 = 0;
            var offset: u64 = 0;
            var block: [KECCAK_RATE]u8 = undefined;
            while (len - offset >= KECCAK_RATE) : (offset += KECCAK_RATE) {
                try readBytes(mem, input + offset, &block);
                absorb(&st, &block);
                permute(&st);
                permutations += 1;
            }
            if (finalize) {
                const rem: usize = @intCast(len - offset);
                @memset(&block, 0);
                if (rem != 0) try readBytes(mem, input + offset, block[0..rem]);
                block[rem] ^= 0x01;
                block[KECCAK_RATE - 1] ^= 0x80;
                absorb(&st, &block);
                permute(&st);
                permutations += 1;
            }
            try mem.storeWords(state_ptr, &st);
            return permutations * KECCAK_RATE;
        },
    }
}

/// Permission over the range is checked by the caller; reads backing words.
fn readBytes(mem: *memory.Memory, address: u64, out: []u8) Error!void {
    for (out, 0..) |*b, i| {
        const at = address + i;
        b.* = @truncate(mem.backing.load(at & ~@as(u64, 7), 8).value >> @intCast(8 * (at & 7)));
    }
}

fn absorb(st: *[25]u64, block: *const [KECCAK_RATE]u8) void {
    for (0..KECCAK_RATE / 8) |i| st[i] ^= std.mem.readInt(u64, block[8 * i ..][0..8], .little);
}

fn permute(st: *[25]u64) void {
    var k = std.crypto.core.keccak.KeccakF(1600){ .st = st.* };
    k.permute();
    st.* = k.st;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const BASE: u64 = 0x2000_0000;
const SIZE: u64 = 8 * memory.PAGE_SIZE;

fn testMemory() !memory.Memory {
    var mem = memory.Memory.init(testing.allocator, .{});
    errdefer mem.deinit();
    try mem.map(.{ .start = BASE, .size = SIZE, .permissions = .{ .read = true, .write = true } });
    try mem.map(.{ .start = BASE + SIZE, .size = memory.PAGE_SIZE, .permissions = .{ .read = true } });
    return mem;
}

fn put(comptime T: type, mem: *memory.Memory, address: u64, values: []const T) !void {
    for (values, 0..) |v, k| try storeValues(T, 1, mem, address + k * (@bitSizeOf(T) / 8), .{v});
}

fn get(comptime T: type, mem: *memory.Memory, address: u64) ![2]T {
    return readPair(T, mem, address);
}

fn run(mem: *memory.Memory, kind: Kind, packet: u64, words: []const u64) !u64 {
    try mem.storeWords(packet, words);
    return execute(kind, packet, mem);
}

// Vectors from an independent Python big-integer oracle (affine chord/tangent
// rules with pow(x, -1, p)); see notes/candidate-curves-abi.md.
const BN_G = [2]u256{ 1, 2 };
const BN_2G = [2]u256{ 0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3, 0x15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4 };
const BN_3G = [2]u256{ 0x0769bf9ac56bea3ff40232bcb1b6bd159315d84715b8e679f2d355961915abf0, 0x2ab799bee0489429554fdb7c8d086475319e63b40b9c5b57cdf1ff3dd9fe2261 };
const BN_5G = [2]u256{ 0x17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa9, 0x01e0559bacb160664764a357af8a9fe70baa9258e0b959273ffc5718c6d4cc7c };

test "candidate bn254 affine add and double match independent vectors" {
    var mem = try testMemory();
    defer mem.deinit();
    const packet = BASE;
    const p = BASE + 0x100;
    const q = BASE + 0x200;
    const r = BASE + 0x300;
    try put(u256, &mem, p, &BN_G);
    _ = try run(&mem, .bn254_g1_double, packet, &.{ r, p });
    try testing.expectEqual(BN_2G, try get(u256, &mem, r));
    _ = try run(&mem, .bn254_g1_add, packet, &.{ q, p, r });
    try testing.expectEqual(BN_3G, try get(u256, &mem, q));
    // In place: r = r + q (2G + 3G).
    _ = try run(&mem, .bn254_g1_add, packet, &.{ r, r, q });
    try testing.expectEqual(BN_5G, try get(u256, &mem, r));
    // Packet unchanged; inputs unchanged.
    try testing.expectEqual(BN_G, try get(u256, &mem, p));
    try testing.expectEqual(r, try mem.load(packet, 8));
    // Scalar multiplication by the group order with the services lands on -P
    // before the last addition: [r-1]G = -G.
    const order: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    var acc = BN_G;
    var i: usize = 253;
    while (i > 0) {
        i -= 1;
        acc = affineDouble(Bn254, u256, acc[0], acc[1]);
        if ((order - 1) >> @intCast(i) & 1 == 1) acc = affineAdd(Bn254, u256, acc[0], acc[1], BN_G[0], BN_G[1]);
    }
    try testing.expectEqual([2]u256{ 1, BN254_P - 2 }, acc);
}

test "candidate bn254 preconditions trap without changing memory" {
    var mem = try testMemory();
    defer mem.deinit();
    const packet = BASE;
    const p = BASE + 0x100;
    const r = BASE + 0x300;
    try put(u256, &mem, p, &BN_G);
    try put(u256, &mem, r, &.{ 7, 8 });
    // x1 == x2 (doubling or opposite points) is the guest's case.
    try testing.expectError(error.CandidateDomain, run(&mem, .bn254_g1_add, packet, &.{ r, p, p }));
    // Non-canonical coordinate.
    try put(u256, &mem, p + 0x80, &.{ BN254_P, 2 });
    try testing.expectError(error.CandidateDomain, run(&mem, .bn254_g1_add, packet, &.{ r, p, p + 0x80 }));
    // y = 0 doubling.
    try put(u256, &mem, p + 0x80, &.{ 5, 0 });
    try testing.expectError(error.CandidateDomain, run(&mem, .bn254_g1_double, packet, &.{ r, p + 0x80 }));
    try testing.expectEqual([2]u256{ 7, 8 }, try get(u256, &mem, r));
    // Misaligned operand pointer and read-only output.
    try testing.expectError(error.MisalignedAddress, run(&mem, .bn254_g1_double, packet, &.{ r + 4, p }));
    try testing.expectError(error.AccessDenied, run(&mem, .bn254_g1_double, packet, &.{ BASE + SIZE, p }));
    try testing.expectEqual([2]u256{ 7, 8 }, try get(u256, &mem, r));
}

test "candidate bn254 fp2_mul reduces any inputs and matches the oracle" {
    var mem = try testMemory();
    defer mem.deinit();
    const a = [2]u256{ 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef % BN254_P, 0x0fedcba987654321 };
    const b = [2]u256{ std.math.maxInt(u256), BN254_P + 5 };
    try put(u256, &mem, BASE + 0x100, &a);
    try put(u256, &mem, BASE + 0x200, &b);
    _ = try run(&mem, .bn254_fp2_mul, BASE, &.{ BASE + 0x100, BASE + 0x100, BASE + 0x200 });
    try testing.expectEqual([2]u256{ 0x04a6e10f2f5cedd0f63c4f1c0657a19031b2c94890d77384baa27703d745157f, 0x20142f504d56969f4838c806fb14b60b3a959595599052bc727ac73734717f4f }, try get(u256, &mem, BASE + 0x100));
    // Squaring (a and b alias) agrees with the field formula.
    _ = try run(&mem, .bn254_fp2_mul, BASE, &.{ BASE + 0x200, BASE + 0x100, BASE + 0x100 });
    const s = try get(u256, &mem, BASE + 0x100);
    try testing.expectEqual(fp2Mul(Bn254, u256, s, s), try get(u256, &mem, BASE + 0x200));
}

const BLS_G_MONT = [2]u384{ 0x120177419e0bfb75edce6ecc21dbf440f0ae6acdf3d0e747154f95c7143ba1c17817fc679976fff55cb38790fd530c16, 0x0bbc3efc5008a26a0e1c8c3fad0059c051ac582950405194dd595f13570725ce8c22631a7918fd8ebaac93d50ce72271 };
const BLS_2G_MONT = [2]u384{ 0x008895d26e6878526b552a39d7eb21fa54c664ae5b2b5d94d20bb47f00129603ea0583c4f3d65f953e978ce58a9ba3c, 0x06361c83f8d09b1525cfc2b522d11720aec6d1c9e7b1c895b86edfd16a5aa785da33c5393f1f6afc70110b3298293940 };
const BLS_3G_MONT = [2]u384{ 0x10be1306415708a06c6b6546b30bedba73d0b40052ff79d0cf259a9ef74a07e07e4e721b3a6e0766ce80364b3ee09382, 0x16389a58d0a15a392dc6f6f53c9c21a1e123a127d3eb6169ad710783f1ae7249d69151590093dd51f17a411f150c5168 };

test "candidate bls12_381 affine add and double in Montgomery form match the oracle" {
    var mem = try testMemory();
    defer mem.deinit();
    // The generator in Montgomery form is blst's (kzg.cpp's -[1]_1 shares x).
    try testing.expectEqual(BLS_G_MONT[0], blsToMont(0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb));
    try put(u384, &mem, BASE + 0x100, &BLS_G_MONT);
    _ = try run(&mem, .bls12_381_g1_double, BASE, &.{ BASE + 0x200, BASE + 0x100 });
    try testing.expectEqual(BLS_2G_MONT, try get(u384, &mem, BASE + 0x200));
    _ = try run(&mem, .bls12_381_g1_add, BASE, &.{ BASE + 0x200, BASE + 0x200, BASE + 0x100 });
    try testing.expectEqual(BLS_3G_MONT, try get(u384, &mem, BASE + 0x200));
    try testing.expectError(error.CandidateDomain, run(&mem, .bls12_381_g1_add, BASE, &.{ BASE + 0x200, BASE + 0x100, BASE + 0x100 }));
}

test "candidate bls12_381 fp2_mul and arith384 mont/mod match the oracle" {
    var mem = try testMemory();
    defer mem.deinit();
    const x = [2]u384{ (0x0123456789abcdef << 300) | 0xdeadbeef, (1 << 383) + 12345 };
    const y = [2]u384{ BLS12_381_P - 1, 7 };
    try put(u384, &mem, BASE + 0x100, &x);
    try put(u384, &mem, BASE + 0x200, &y);
    _ = try run(&mem, .bls12_381_fp2_mul, BASE, &.{ BASE + 0x300, BASE + 0x100, BASE + 0x200 });
    try testing.expectEqual([2]u384{ 0x0e8eca15de400aaad132d5a6114175ea16cb09db9e7e42bedef6bd5cbdbf6264583954f46c85c205d72b1ed67e5b6dba, 0x0cf55576f1a796f6b179b517c7d3969a7b6d027b18496200b5d91fd44a8af33d46a1d4eccb4d5d46f865957450d5e9ce }, try get(u384, &mem, BASE + 0x300));
    const big_a: u384 = std.math.maxInt(u384) - 2;
    const big_b: u384 = (1 << 383) | 99;
    const odd_m: u384 = std.math.maxInt(u384) - 0x3c;
    try put(u384, &mem, BASE + 0x100, &.{ big_a, big_b, BLS12_381_P, odd_m, 0xabc });
    // arith384_mont {a, b, m, r}
    _ = try run(&mem, .arith384_mont, BASE, &.{ BASE + 0x100, BASE + 0x130, BASE + 0x190, BASE + 0x400 });
    try testing.expectEqual(@as(u384, 0x064b8a7de6d1d60864b8a7de6d1d60864b8a7de6d1d60864b8a7de6d1d60864b8a7de6d1d60864b8a7de6d1d60864b90b), (try get(u384, &mem, BASE + 0x400))[0]);
    // arith384_mod {a, b, c, m, r}
    _ = try run(&mem, .arith384_mod, BASE, &.{ BASE + 0x100, BASE + 0x130, BASE + 0x1c0, BASE + 0x160, BASE + 0x400 });
    try testing.expectEqual(@as(u384, 0x04c9199b29c4af3ba587b3c67ec4a2ddf49a91c396c8741d4fdcc8190eafd3f7803b783a09e8837f7e2f8f9a0f5a13f6), (try get(u384, &mem, BASE + 0x400))[0]);
    // Montgomery identities on p: mont(x, R^2) = xR, mont(xR, 1) = x.
    const r2: u384 = @intCast((@as(u768, R384_MOD_P) * R384_MOD_P) % BLS12_381_P);
    try testing.expectEqual(blsToMont(12345), mont384(12345, r2, BLS12_381_P));
    try testing.expectEqual(@as(u384, 12345), mont384(blsToMont(12345), 1, BLS12_381_P));
    // Even modulus traps; m = 0 for arith384_mod gives 0.
    try put(u384, &mem, BASE + 0x190, &.{0});
    try testing.expectError(error.CandidateDomain, run(&mem, .arith384_mont, BASE, &.{ BASE + 0x100, BASE + 0x130, BASE + 0x190, BASE + 0x400 }));
    _ = try run(&mem, .arith384_mod, BASE, &.{ BASE + 0x100, BASE + 0x130, BASE + 0x1c0, BASE + 0x190, BASE + 0x400 });
    try testing.expectEqual(@as(u384, 0), (try get(u384, &mem, BASE + 0x400))[0]);
}

test "candidate keccak_sponge equals Keccak-256 for every length and alignment" {
    var mem = try testMemory();
    defer mem.deinit();
    var data: [700]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i * 29 + 11);
    const input = BASE + 0x1000;
    const state = BASE + 0x100;
    for ([_]u64{ 0, 3 }) |shift| {
        for (data, 0..) |b, i| try mem.store(input + shift + i, 1, b);
        for (0..560) |len| {
            const bytes = try run(&mem, .keccak_sponge, BASE, &.{ state, input + shift, len, SPONGE_FINALIZE | SPONGE_FRESH });
            try testing.expectEqual((len / 136 + 1) * 136, bytes);
            var want: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(data[0..len], &want, .{});
            var got: [32]u8 = undefined;
            for (0..4) |i| std.mem.writeInt(u64, got[8 * i ..][0..8], try mem.load(state + 8 * i, 8), .little);
            try testing.expectEqualSlices(u8, &want, &got);
        }
    }
    // Absorb two blocks, then finalize the tail in a second call (data now at input + 3).
    _ = try run(&mem, .keccak_sponge, BASE, &.{ state, input + 3, 272, SPONGE_FRESH });
    _ = try run(&mem, .keccak_sponge, BASE, &.{ state, input + 3 + 272, 100, SPONGE_FINALIZE });
    var want: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(data[0..372], &want, .{});
    for (0..4) |i| try testing.expectEqual(std.mem.readInt(u64, want[8 * i ..][0..8], .little), try mem.load(state + 8 * i, 8));
    // Non-final partial length and unknown flags trap; the state is untouched.
    const lane0 = try mem.load(state, 8);
    try testing.expectError(error.CandidateDomain, run(&mem, .keccak_sponge, BASE, &.{ state, input, 100, 0 }));
    try testing.expectError(error.CandidateDomain, run(&mem, .keccak_sponge, BASE, &.{ state, input, 136, 4 }));
    try testing.expectError(error.UnmappedAddress, run(&mem, .keccak_sponge, BASE, &.{ state, BASE + SIZE + memory.PAGE_SIZE - 8, 136, 0 }));
    try testing.expectEqual(lane0, try mem.load(state, 8));
}
