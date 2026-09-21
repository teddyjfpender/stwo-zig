//! Typed admission for Merkle hash families implemented by the Metal runtime.
//!
//! Every admitted family has a distinct runtime/AOT dispatch.  Seedless
//! Poseidon2-M31 is never coerced into the BLAKE2s seed ABI.

const std = @import("std");

pub const Blake2sParametersV1 = struct {
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
};

pub const FamilyV1 = enum(u32) {
    blake2s = 1,
    poseidon2_m31 = 2,
};

pub const ParametersV1 = struct {
    family: FamilyV1,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
    leaf_state_words: u32,
};

// These parameters are the state after the first, non-terminal 64-byte
// BLAKE2s block.  Derive them without consulting the process-wide BLAKE2s
// backend selector: hash-family admission is evaluated at comptime, while the
// selector is deliberately runtime mutable.  Scalar/SIMD selection changes
// only how this state is computed, never the state itself.
const BLAKE2S_IV = [8]u32{
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
};

const BLAKE2S_SIGMA = [10][16]u8{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

fn rotr32(x: u32, comptime bits: u5) u32 {
    const left_bits: u5 = @intCast((@as(u6, 32) - @as(u6, bits)) & 31);
    return (x >> bits) | (x << left_bits);
}

fn blake2sG(
    v: *[16]u32,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: u32,
    y: u32,
) void {
    v[a] = v[a] +% v[b] +% x;
    v[d] = rotr32(v[d] ^ v[a], 16);
    v[c] = v[c] +% v[d];
    v[b] = rotr32(v[b] ^ v[c], 12);
    v[a] = v[a] +% v[b] +% y;
    v[d] = rotr32(v[d] ^ v[a], 8);
    v[c] = v[c] +% v[d];
    v[b] = rotr32(v[b] ^ v[c], 7);
}

fn fixed64Seed(block: *const [64]u8) [8]u32 {
    // Ten compression rounds intentionally exceed Zig's default comptime
    // backward-branch budget. Scope the allowance to this fixed-domain seed
    // derivation instead of raising a package/global quota.
    @setEvalBranchQuota(10_000);
    var h = BLAKE2S_IV;
    h[0] ^= 0x01010020;

    var words: [16]u32 = undefined;
    for (&words, 0..) |*word, i| {
        word.* = std.mem.readInt(u32, block[i * 4 ..][0..4], .little);
    }

    var v: [16]u32 = undefined;
    for (0..8) |i| {
        v[i] = h[i];
        v[i + 8] = BLAKE2S_IV[i];
    }
    v[12] ^= 64;

    for (BLAKE2S_SIGMA) |sigma| {
        blake2sG(&v, 0, 4, 8, 12, words[sigma[0]], words[sigma[1]]);
        blake2sG(&v, 1, 5, 9, 13, words[sigma[2]], words[sigma[3]]);
        blake2sG(&v, 2, 6, 10, 14, words[sigma[4]], words[sigma[5]]);
        blake2sG(&v, 3, 7, 11, 15, words[sigma[6]], words[sigma[7]]);
        blake2sG(&v, 0, 5, 10, 15, words[sigma[8]], words[sigma[9]]);
        blake2sG(&v, 1, 6, 11, 12, words[sigma[10]], words[sigma[11]]);
        blake2sG(&v, 2, 7, 8, 13, words[sigma[12]], words[sigma[13]]);
        blake2sG(&v, 3, 4, 9, 14, words[sigma[14]], words[sigma[15]]);
    }
    for (0..8) |i| h[i] ^= v[i] ^ v[i + 8];
    return h;
}

pub fn blake2sParameters(comptime H: type) ?Blake2sParametersV1 {
    const blake = @import("stwo_core").vcs_lifted.blake2_merkle;
    const prefixed = H == blake.Blake2sMerkleHasher or
        H == blake.Blake2sM31MerkleHasher;
    const plain = H == blake.Blake2sPlainMerkleHasher or
        H == blake.Blake2sPlainM31MerkleHasher;
    const admitted_family = prefixed or plain;
    if (comptime !admitted_family) return null;
    if (comptime !@hasDecl(H, "leafSeed") or
        !@hasDecl(H, "nodeSeed") or
        !@hasDecl(H, "domainPrefixBytes"))
    {
        return null;
    }
    return .{
        .leaf_seed = fixed64Seed(&blake.LEAF_PREFIX),
        .node_seed = fixed64Seed(&blake.NODE_PREFIX),
        .domain_prefix_bytes = if (prefixed) blake.DOMAIN_PREFIX_BYTES else 0,
    };
}

pub fn parameters(comptime H: type) ?ParametersV1 {
    if (blake2sParameters(H)) |blake| return .{
        .family = .blake2s,
        .leaf_seed = blake.leaf_seed,
        .node_seed = blake.node_seed,
        .domain_prefix_bytes = blake.domain_prefix_bytes,
        .leaf_state_words = 8,
    };
    if (comptime !@hasDecl(H, "metal_commitment_hash_family_v1") or
        !@hasDecl(H, "Hash") or
        !@hasDecl(H, "NodeSeed") or
        !@hasDecl(H, "defaultWithInitialState") or
        !@hasDecl(H, "hashChildren") or
        !@hasDecl(H, "nodeSeed"))
    {
        return null;
    }
    if (comptime @TypeOf(H.metal_commitment_hash_family_v1) != u32 or
        H.metal_commitment_hash_family_v1 != @intFromEnum(FamilyV1.poseidon2_m31) or
        H.Hash != [8]u32 or H.NodeSeed != void)
    {
        return null;
    }
    return .{
        .family = .poseidon2_m31,
        .leaf_seed = .{0} ** 8,
        .node_seed = .{0} ** 8,
        .domain_prefix_bytes = 0,
        .leaf_state_words = 16,
    };
}

test "Metal hash domain admits exact Blake parameters and rejects seedless families" {
    const Blake = @import("stwo_core").vcs_lifted.blake2_merkle
        .Blake2sPrefixedMerkleHasher;
    const admitted = blake2sParameters(Blake).?;
    try std.testing.expectEqual(Blake.leafSeed(), admitted.leaf_seed);
    try std.testing.expectEqual(Blake.nodeSeed(), admitted.node_seed);
    try std.testing.expectEqual(
        Blake.domainPrefixBytes(),
        admitted.domain_prefix_bytes,
    );

    const Seedless = struct {
        pub const Hash = [8]u32;
        pub fn nodeSeed() void {}
    };
    try std.testing.expect(blake2sParameters(Seedless) == null);

    const BlakeShapedImposter = struct {
        pub const Hash = [8]u32;
        pub fn leafSeed() [8]u32 {
            return .{0} ** 8;
        }
        pub fn nodeSeed() [8]u32 {
            return .{0} ** 8;
        }
        pub fn domainPrefixBytes() u32 {
            return 64;
        }
    };
    try std.testing.expect(blake2sParameters(BlakeShapedImposter) == null);
}

test "Metal Blake domain parameters are comptime and backend invariant" {
    const blake = @import("stwo_core").vcs_lifted.blake2_merkle;
    inline for (.{
        blake.Blake2sMerkleHasher,
        blake.Blake2sM31MerkleHasher,
        blake.Blake2sPlainMerkleHasher,
        blake.Blake2sPlainM31MerkleHasher,
    }) |Blake| {
        const admitted = comptime blake2sParameters(Blake).?;
        try std.testing.expectEqual(
            Blake.leafSeedWithMode(.scalar),
            admitted.leaf_seed,
        );
        try std.testing.expectEqual(
            Blake.nodeSeedWithMode(.scalar),
            admitted.node_seed,
        );
        try std.testing.expectEqual(
            Blake.leafSeedWithMode(.simd),
            admitted.leaf_seed,
        );
        try std.testing.expectEqual(
            Blake.nodeSeedWithMode(.simd),
            admitted.node_seed,
        );
    }
}

test "Metal hash domain gives Poseidon a distinct seedless runtime family" {
    const PoseidonContract = struct {
        pub const Hash = [8]u32;
        pub const NodeSeed = void;
        pub const metal_commitment_hash_family_v1: u32 = 2;
        pub fn defaultWithInitialState() @This() {
            return .{};
        }
        pub fn hashChildren(_: anytype) Hash {
            return .{0} ** 8;
        }
        pub fn nodeSeed() void {}
    };
    const admitted = parameters(PoseidonContract).?;
    try std.testing.expectEqual(FamilyV1.poseidon2_m31, admitted.family);
    try std.testing.expectEqual(@as(u32, 16), admitted.leaf_state_words);
    try std.testing.expectEqual([_]u32{0} ** 8, admitted.leaf_seed);
}
