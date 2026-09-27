//! Recursion-oriented Poseidon2-M31 Fiat-Shamir and Merkle protocol.
//!
//! The recursive verifier must prove the hash operations performed by the
//! inner proof.  This suite therefore delegates to the exact pinned
//! Poseidon2 permutation consumed by the RISC-V Merkle/Poseidon AIR instead of
//! introducing a second permutation.  The construction is compatible with
//! Stark-V's recursion channel:
//!
//! - eight M31 rate words and eight capacity words;
//! - additive absorption with a one-word end marker;
//! - injective 16-bit splitting for unrestricted `u32` transcript words;
//! - draws domain-separated from mixing and indexed without feeding back;
//! - leaf and internal-node Merkle hashes in distinct domains.
//!
//! This module is protocol substrate.  Selecting it for production proofs is
//! a separate, explicit recursion profile decision.

const std = @import("std");
const stwo_core = @import("stwo_core");
const permutation = @import("../air/memory_commitment/poseidon2.zig");
const permutation_constants = @import("../air/memory_commitment/poseidon2_constants.zig");
pub const canonical_word_sponge = @import("poseidon2_canonical_word_sponge.zig");

const m31 = stwo_core.fields.m31;
const qm31 = stwo_core.fields.qm31;
const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const RATE: usize = 8;
pub const CAPACITY: usize = permutation.WIDTH - RATE;
pub const DRAW_TAG: u32 = 0x4452_4157; // "DRAW"
pub const LEAF_TAG: u32 = 1;
pub const MAX_POW_BITS: u32 = 32;
pub const PARAMETER_ID_DOMAIN: u32 = 0x5032_5041; // "P2PA"
pub const PARAMETER_WORD_COUNT: usize = 5 +
    permutation_constants.EXTERNAL_ROUND.len * permutation.WIDTH +
    permutation_constants.INTERNAL_ROUND.len +
    permutation_constants.INTERNAL_MATRIX.len;

comptime {
    std.debug.assert(permutation.WIDTH == 16);
    std.debug.assert(CAPACITY == RATE);
}

/// Canonical eight-word M31 digest.  Keeping the protocol value in words
/// avoids byte packing in the recursion witness and makes non-canonical states
/// unrepresentable through the public constructors in this module.
pub const Digest = [RATE]u32;
pub const Hash = Digest;

const Sponge = struct {
    state: permutation.State,
    filled: usize,

    fn init(capacity_tag: u32) Sponge {
        std.debug.assert(capacity_tag < m31.Modulus);
        const state = canonical_word_sponge.initialState(M31, M31.zero(), M31.fromCanonical(capacity_tag));
        return .{ .state = state, .filled = 0 };
    }

    fn absorbCanonical(self: *Sponge, word: u32) void {
        std.debug.assert(word < m31.Modulus);
        canonical_word_sponge.absorb(self, M31.fromCanonical(word));
    }

    pub fn permute(self: *Sponge) void {
        permutation.permute(&self.state);
    }

    fn finish(self: *Sponge) Hash {
        canonical_word_sponge.finish(self, M31.one());
        return stateDigest(self.state);
    }
};

fn stateDigest(state: permutation.State) Hash {
    var result: Hash = undefined;
    for (&result, state[0..RATE]) |*out, value| out.* = value.toU32();
    return result;
}

fn stateDigest4(state: permutation.State4) [4]Digest {
    var output: [4]Digest = undefined;
    for (state[0..RATE], 0..) |word, index| {
        inline for (0..4) |lane| output[lane][index] = word[lane];
    }
    return output;
}

/// Equal-length leaf sponges sharing only their execution schedule.
const LeafSponge4 = struct {
    state: permutation.State4 = .{@as(m31.Vec4u32, @splat(0))} ** permutation.WIDTH,
    filled: usize = 0,

    fn init() LeafSponge4 {
        var result = LeafSponge4{};
        result.state[permutation.WIDTH - 1] = @splat(LEAF_TAG);
        return result;
    }

    fn fromHashers(hashers: *const [4]MerkleHasher) LeafSponge4 {
        var result = LeafSponge4{ .filled = hashers[0].sponge.filled };
        for (0..permutation.WIDTH) |index| {
            var words: [4]u32 = undefined;
            inline for (0..4) |lane| {
                std.debug.assert(hashers[lane].sponge.filled == result.filled);
                words[lane] = hashers[lane].sponge.state[index].toU32();
            }
            result.state[index] = @bitCast(words);
        }
        return result;
    }

    fn writeHashers(self: *const LeafSponge4, hashers: *[4]MerkleHasher) void {
        inline for (0..4) |lane| {
            for (self.state, 0..) |word, index| hashers[lane].sponge.state[index] = M31.fromCanonical(word[lane]);
            hashers[lane].sponge.filled = self.filled;
        }
    }

    fn absorb(self: *LeafSponge4, words: [4]u32) void {
        for (words) |word| std.debug.assert(word < m31.Modulus);
        self.state[self.filled] = m31.addVec4(self.state[self.filled], @bitCast(words));
        self.filled += 1;
        if (self.filled == RATE) {
            permutation.permute4(&self.state);
            self.filled = 0;
        }
    }

    fn finish(self: *LeafSponge4) [4]Digest {
        self.absorb(.{1} ** 4);
        if (self.filled != 0) {
            permutation.permute4(&self.state);
            self.filled = 0;
        }
        return stateDigest4(self.state);
    }
};

fn absorbDigest(sponge: *Sponge, digest: Hash) void {
    for (digest) |word| sponge.absorbCanonical(word);
}

/// Hash canonical M31 words under a capacity-domain tag.
pub fn hashCanonicalWords(words: []const M31, capacity_tag: u32) Hash {
    var hasher = CanonicalWordHasher.init(capacity_tag);
    hasher.update(words);
    return hasher.finalize();
}

/// Allocation-free incremental form of `hashCanonicalWords`.
///
/// Canonical protocol encodings often select several disjoint ranges from a
/// larger fixed wire.  Hashing those ranges directly avoids a temporary
/// concatenation allocation while preserving byte-for-byte sponge semantics.
pub const CanonicalWordHasher = struct {
    sponge: Sponge,
    finished: bool = false,

    const Self = @This();

    pub fn init(capacity_tag: u32) Self {
        return .{ .sponge = Sponge.init(capacity_tag) };
    }

    pub fn update(self: *Self, words: []const M31) void {
        std.debug.assert(!self.finished);
        for (words) |word| self.sponge.absorbCanonical(word.toU32());
    }

    pub fn finalize(self: *Self) Hash {
        std.debug.assert(!self.finished);
        self.finished = true;
        return self.sponge.finish();
    }
};

/// Word-level form used by protocol identity encoders that have already
/// established canonicality.
pub fn hashCanonicalU32s(words: []const u32, capacity_tag: u32) Hash {
    var sponge = Sponge.init(capacity_tag);
    for (words) |word| sponge.absorbCanonical(word);
    return sponge.finish();
}

/// Exact scalar-permutation count for this sponge's canonical-word encoding.
/// This is a protocol profiler primitive: it lets hot paths maintain a checked
/// cost ledger without instrumenting or perturbing the permutation itself.
pub fn canonicalWordPermutationCount(word_count: usize) usize {
    // `finish` absorbs one marker, hence ceil((word_count + 1) / RATE).
    return word_count / RATE + 1;
}

/// Exact scalar-permutation count for `hashBytes` at the given byte length.
pub fn bytePermutationCount(byte_count: usize) usize {
    // One length word, injective two-byte limbs, and the final marker.
    const encoded_words = 1 + byte_count / 2 + byte_count % 2;
    return canonicalWordPermutationCount(encoded_words);
}

/// Semantic identity of every numeric parameter consumed by the pinned
/// Poseidon2-M31 permutation.  The surrounding hash-suite version binds the
/// matrix algorithms and sponge construction; this digest prevents a constant
/// edit from retaining the same recursion protocol identity.
pub fn parameterId() Hash {
    var words: [PARAMETER_WORD_COUNT]u32 = undefined;
    var at: usize = 0;
    words[at] = @intCast(permutation.WIDTH);
    at += 1;
    words[at] = @intCast(RATE);
    at += 1;
    words[at] = @intCast(permutation_constants.EXTERNAL_ROUND.len);
    at += 1;
    words[at] = @intCast(permutation_constants.INTERNAL_ROUND.len);
    at += 1;
    words[at] = 5; // x^5 S-box
    at += 1;
    for (permutation_constants.EXTERNAL_ROUND) |round| {
        for (round) |constant| {
            words[at] = constant;
            at += 1;
        }
    }
    for (permutation_constants.INTERNAL_ROUND) |constant| {
        words[at] = constant;
        at += 1;
    }
    for (permutation_constants.INTERNAL_MATRIX) |diagonal| {
        words[at] = diagonal;
        at += 1;
    }
    std.debug.assert(at == words.len);
    return hashCanonicalU32s(&words, PARAMETER_ID_DOMAIN);
}

/// Hash arbitrary bytes without reducing unrestricted machine words into
/// M31.  The byte length is absorbed first and each following word contains
/// at most two little-endian bytes, so the encoding is injective including
/// trailing zero bytes.
pub fn hashBytes(bytes: []const u8, capacity_tag: u32) Hash {
    std.debug.assert(bytes.len <= std.math.maxInt(u32));
    var sponge = Sponge.init(capacity_tag);
    sponge.absorbCanonical(@intCast(bytes.len));
    var at: usize = 0;
    while (at < bytes.len) : (at += 2) {
        const high = if (at + 1 < bytes.len)
            @as(u32, bytes[at + 1]) << 8
        else
            0;
        sponge.absorbCanonical(@as(u32, bytes[at]) | high);
    }
    return sponge.finish();
}

/// Poseidon2-M31 Fiat-Shamir channel.
pub const Channel = struct {
    digest: Hash = [_]u32{0} ** RATE,
    n_draws: u32 = 0,

    const Self = @This();

    pub fn drawCount(self: Self) u32 {
        return self.n_draws;
    }

    pub fn digestWords(self: Self) Hash {
        return self.digest;
    }

    /// Canonical little-endian representation for diagnostics and fixed wire
    /// identities.  Transcript operations consume words directly.
    pub fn digestBytes(self: Self) [RATE * @sizeOf(u32)]u8 {
        var bytes: [RATE * @sizeOf(u32)]u8 = undefined;
        for (self.digest, 0..) |word, index| {
            std.mem.writeInt(
                u32,
                bytes[index * @sizeOf(u32) ..][0..@sizeOf(u32)],
                word,
                .little,
            );
        }
        return bytes;
    }

    fn replaceDigest(self: *Self, digest: Hash) void {
        self.digest = digest;
        self.n_draws = 0;
    }

    fn mixCanonicalWords(self: *Self, words: []const u32) void {
        var sponge = Sponge.init(0);
        absorbDigest(&sponge, self.digest);
        for (words) |word| sponge.absorbCanonical(word);
        self.replaceDigest(sponge.finish());
    }

    /// Absorbs already-canonical M31 words without the unrestricted-u32 limb
    /// split. This is the checked seam used by the schedule-driven recursive
    /// transcript replay; ordinary host integers must continue through
    /// `mixU32s`.
    pub fn mixCanonicalM31Words(self: *Self, words: []const M31) void {
        self.mixCanonicalM31Slices(&.{words});
    }

    /// Streaming form of `mixCanonicalM31Words` for protocol frames assembled
    /// from fixed headers and borrowed payloads. Slice boundaries are not
    /// encoded and therefore do not alter the transcript.
    pub fn mixCanonicalM31Slices(
        self: *Self,
        slices: []const []const M31,
    ) void {
        var sponge = Sponge.init(0);
        absorbDigest(&sponge, self.digest);
        for (slices) |words| {
            for (words) |word| sponge.absorbCanonical(word.toU32());
        }
        self.replaceDigest(sponge.finish());
    }

    pub fn mixU32s(self: *Self, data: []const u32) void {
        var sponge = Sponge.init(0);
        absorbDigest(&sponge, self.digest);
        for (data) |word| {
            // Reduction modulo p would alias p with zero.  Two canonical
            // 16-bit limbs retain all 32 input bits injectively.
            sponge.absorbCanonical(word & 0xffff);
            sponge.absorbCanonical(word >> 16);
        }
        self.replaceDigest(sponge.finish());
    }

    pub fn mixU64(self: *Self, value: u64) void {
        self.mixU32s(&.{
            @truncate(value),
            @truncate(value >> 32),
        });
    }

    pub fn mixFelts(self: *Self, felts: []const QM31) void {
        var sponge = Sponge.init(0);
        absorbDigest(&sponge, self.digest);
        for (felts) |felt| {
            for (felt.toM31Array()) |coordinate| {
                sponge.absorbCanonical(coordinate.toU32());
            }
        }
        self.replaceDigest(sponge.finish());
    }

    pub fn drawU32s(self: *Self) Hash {
        var sponge = Sponge.init(0);
        absorbDigest(&sponge, self.digest);
        sponge.absorbCanonical(self.n_draws);
        sponge.absorbCanonical(DRAW_TAG);
        self.n_draws +%= 1;
        return sponge.finish();
    }

    pub fn drawSecureFelt(self: *Self) QM31 {
        const words = self.drawU32s();
        return QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]);
    }

    pub fn drawSecureFelts(
        self: *Self,
        allocator: std.mem.Allocator,
        n_felts: usize,
    ) ![]QM31 {
        const output = try allocator.alloc(QM31, n_felts);
        var produced: usize = 0;
        while (produced < output.len) {
            const words = self.drawU32s();
            var at: usize = 0;
            while (at + qm31.SECURE_EXTENSION_DEGREE <= RATE and
                produced < output.len) : (at += qm31.SECURE_EXTENSION_DEGREE)
            {
                output[produced] = QM31.fromU32Unchecked(
                    words[at],
                    words[at + 1],
                    words[at + 2],
                    words[at + 3],
                );
                produced += 1;
            }
        }
        return output;
    }

    pub fn verifyPowNonce(self: Self, n_bits: u32, nonce: u64) bool {
        if (n_bits > MAX_POW_BITS) return false;
        var candidate = self;
        candidate.mixU64(nonce);
        return @ctz(candidate.drawU32s()[0]) >= n_bits;
    }

    /// Sponge state that every proof-of-work candidate starts from: a fresh
    /// zero-tagged sponge with this digest absorbed and permuted.  `mixU64`
    /// then absorbs the four 16-bit nonce halves and the finishing one before
    /// its permutation, and `drawU32s` absorbs the resulting digest, a draw
    /// counter of zero, `DRAW_TAG`, and the finishing one.  A device search
    /// replays exactly those steps; see `powCandidateWordFromPrefix`.
    pub fn powPrefixState(self: Self) [permutation.WIDTH]u32 {
        var sponge = Sponge.init(0);
        absorbDigest(&sponge, self.digest);
        std.debug.assert(sponge.filled == 0);
        var words: [permutation.WIDTH]u32 = undefined;
        for (&words, sponge.state) |*word, value| word.* = value.toU32();
        return words;
    }

    /// Host restatement of the device candidate check; `verifyPowNonce` on
    /// the same channel must agree bit for bit.
    pub fn powCandidateWordFromPrefix(prefix: [permutation.WIDTH]u32, nonce: u64) u32 {
        var state: permutation.State = undefined;
        for (&state, prefix) |*lane, word| lane.* = M31.fromCanonical(word);
        const low: u32 = @truncate(nonce);
        const high: u32 = @truncate(nonce >> 32);
        state[0] = state[0].add(M31.fromCanonical(low & 0xffff));
        state[1] = state[1].add(M31.fromCanonical(low >> 16));
        state[2] = state[2].add(M31.fromCanonical(high & 0xffff));
        state[3] = state[3].add(M31.fromCanonical(high >> 16));
        state[4] = state[4].add(M31.one());
        permutation.permute(&state);
        var draw = [_]M31{M31.zero()} ** permutation.WIDTH;
        @memcpy(draw[0..RATE], state[0..RATE]);
        permutation.permute(&draw);
        draw[1] = draw[1].add(M31.fromCanonical(DRAW_TAG));
        draw[2] = draw[2].add(M31.one());
        permutation.permute(&draw);
        return draw[0].toU32();
    }

    /// Deterministic lowest-nonce search.  Recursion profiles use at most 16
    /// bits; a parallel/search-specialized implementation can be introduced
    /// behind the same semantics after the protocol is fixed.
    pub fn grind(self: Self, n_bits: u32) u64 {
        if (n_bits > MAX_POW_BITS)
            @panic("Poseidon2-M31 PoW cannot request more than 32 bits");
        var nonce: u64 = 0;
        while (!self.verifyPowNonce(n_bits, nonce)) nonce +%= 1;
        return nonce;
    }
};

/// Incremental lifted-Merkle leaf hasher.
pub const MerkleHasher = struct {
    sponge: Sponge,

    pub const Hash = Digest;
    /// Backend-neutral numeric protocol tag.  A commitment backend may admit
    /// this family only when it implements the exact pinned Poseidon2-M31
    /// permutation and leaf sponge; the tag is not a substitute for proof or
    /// root verification.
    pub const metal_commitment_hash_family_v1: u32 = 2;
    pub const Children = struct { left: Digest, right: Digest };
    /// Poseidon internal nodes begin directly from their two child digests, so
    /// there is no prehashed byte-domain state to carry between calls.  A void
    /// seed still exposes the optimized/parallel lifted-Merkle contract.
    pub const NodeSeed = void;

    const Self = @This();

    pub fn defaultWithInitialState() Self {
        return .{ .sponge = Sponge.init(LEAF_TAG) };
    }

    pub fn hashChildren(children: Children) Digest {
        var state = [_]M31{M31.zero()} ** permutation.WIDTH;
        for (children.left, 0..) |word, index| {
            std.debug.assert(word < m31.Modulus);
            state[index] = M31.fromCanonical(word);
        }
        for (children.right, 0..) |word, index| {
            std.debug.assert(word < m31.Modulus);
            state[RATE + index] = M31.fromCanonical(word);
        }
        permutation.permute(&state);
        return stateDigest(state);
    }

    pub fn nodeSeed() NodeSeed {
        return {};
    }

    pub fn hashChildrenWithSeed(_: NodeSeed, children: Children) Digest {
        return hashChildren(children);
    }

    pub fn hashChildrenWithSeed4(
        _: NodeSeed,
        children: *const [8]Digest,
    ) [4]Digest {
        var state: permutation.State4 = undefined;
        for (0..permutation.WIDTH) |index| {
            var words: [4]u32 = undefined;
            inline for (0..4) |lane| {
                words[lane] = children[2 * lane + index / RATE][index % RATE];
                std.debug.assert(words[lane] < m31.Modulus);
            }
            state[index] = @bitCast(words);
        }
        permutation.permute4(&state);
        return stateDigest4(state);
    }

    pub fn leafSeed() NodeSeed {
        return {};
    }

    /// Four equally sized messages of canonical little-endian M31 words.
    pub fn hashPackedLeavesWithSeed4(_: NodeSeed, messages: *const [4][]const u8) [4]Digest {
        const byte_count = messages[0].len;
        std.debug.assert(byte_count % @sizeOf(M31) == 0);
        for (messages) |message| std.debug.assert(message.len == byte_count);
        var sponge = LeafSponge4.init();
        var offset: usize = 0;
        while (offset < byte_count) : (offset += @sizeOf(M31)) {
            var words: [4]u32 = undefined;
            inline for (0..4) |lane| words[lane] = std.mem.readInt(u32, messages[lane][offset..][0..4], .little);
            sponge.absorb(words);
        }
        return sponge.finish();
    }

    /// Direct equivalent of packing four consecutive leaf rows.
    pub fn hashDirectM31LeavesWithSeed4(_: NodeSeed, columns: anytype, position: usize) [4]Digest {
        var sponge = LeafSponge4.init();
        for (columns) |column| {
            var words: [4]u32 = undefined;
            inline for (0..4) |lane| words[lane] = column.values[position + lane].toU32();
            sponge.absorb(words);
        }
        return sponge.finish();
    }

    pub fn updateLeaf(self: *Self, column_values: []const M31) void {
        for (column_values) |value| {
            self.sponge.absorbCanonical(value.toU32());
        }
    }

    /// Incremental streaming groups retain the scalar state representation.
    /// Arbitrary caller states with different rate offsets use scalar updates.
    pub fn updateM31Columns4(hashers: *[4]Self, columns: anytype, position: usize) void {
        for (hashers) |hasher| {
            if (hasher.sponge.filled != hashers[0].sponge.filled) {
                inline for (0..4) |lane| for (columns) |column| {
                    hashers[lane].updateLeaf(column.values[position + lane ..][0..1]);
                };
                return;
            }
        }
        var sponge = LeafSponge4.fromHashers(hashers);
        for (columns) |column| {
            var words: [4]u32 = undefined;
            inline for (0..4) |lane| words[lane] = column.values[position + lane].toU32();
            sponge.absorb(words);
        }
        sponge.writeHashers(hashers);
    }

    pub fn finalize4(hashers: *[4]Self) [4]Digest {
        for (hashers) |hasher| {
            if (hasher.sponge.filled != hashers[0].sponge.filled) {
                var output: [4]Digest = undefined;
                inline for (0..4) |lane| output[lane] = hashers[lane].finalize();
                return output;
            }
        }
        var sponge = LeafSponge4.fromHashers(hashers);
        const output = sponge.finish();
        sponge.writeHashers(hashers);
        return output;
    }

    pub fn finalize(self: *Self) Digest {
        return self.sponge.finish();
    }
};

/// Merkle/channel coupling used by the generic PCS.
pub const MerkleChannel = struct {
    pub fn mixRoot(channel: *Channel, root: Digest) void {
        channel.mixCanonicalWords(&root);
    }
};

test "recursion Poseidon2: canonical Stark-V conformance vector" {
    const words = [_]u32{ 1, 2 };
    try std.testing.expectEqual(
        Hash{
            1_683_618_890,
            22_281_548,
            1_108_016_194,
            1_368_459_274,
            926_884_817,
            1_781_577_565,
            1_099_953_524,
            427_524_185,
        },
        hashCanonicalU32s(&words, 10),
    );
}

test "recursion Poseidon2: incremental canonical hashing matches concatenation" {
    const words = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
        M31.fromCanonical(4),
        M31.fromCanonical(5),
        M31.fromCanonical(6),
        M31.fromCanonical(7),
        M31.fromCanonical(8),
        M31.fromCanonical(9),
    };
    var incremental = CanonicalWordHasher.init(17);
    incremental.update(words[0..2]);
    incremental.update(words[2..8]);
    incremental.update(words[8..]);
    try std.testing.expectEqual(
        hashCanonicalWords(&words, 17),
        incremental.finalize(),
    );
}

test "recursion Poseidon2: canonical channel slice boundaries are transparent" {
    const words = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
        M31.fromCanonical(4),
        M31.fromCanonical(5),
        M31.fromCanonical(6),
        M31.fromCanonical(7),
        M31.fromCanonical(8),
        M31.fromCanonical(9),
    };
    var contiguous = Channel{};
    var sliced = Channel{};
    contiguous.mixCanonicalM31Words(&words);
    sliced.mixCanonicalM31Slices(&.{ words[0..2], words[2..8], words[8..] });
    try std.testing.expectEqual(contiguous.digestWords(), sliced.digestWords());
    try std.testing.expectEqual(contiguous.n_draws, sliced.n_draws);
}

test "recursion Poseidon2: parameter identity is deterministic and nonzero" {
    const parameter_id = parameterId();
    try std.testing.expectEqual(parameter_id, parameterId());
    try std.testing.expect(!std.meta.eql(parameter_id, [_]u32{0} ** RATE));
    std.debug.print("\n  R-011 Poseidon2 parameters={any}\n", .{parameter_id});
}

test "recursion Poseidon2: channel draws are deterministic indexed and non-mutating" {
    var first = Channel{};
    var second = Channel{};
    first.mixU64(7);
    second.mixU64(7);
    const digest_before = first.digestWords();
    try std.testing.expectEqual(first.drawU32s(), second.drawU32s());
    try std.testing.expectEqual(first.drawU32s(), second.drawU32s());
    try std.testing.expectEqual(digest_before, first.digestWords());
    try std.testing.expectEqual(@as(u32, 2), first.n_draws);
}

test "recursion Poseidon2: unrestricted u32 encoding is injective across p" {
    var zero = Channel{};
    var modulus = Channel{};
    zero.mixU32s(&.{0});
    modulus.mixU32s(&.{m31.Modulus});
    try std.testing.expect(!std.meta.eql(zero.digestWords(), modulus.digestWords()));
}

test "recursion Poseidon2: byte hashing binds length and trailing zeros" {
    const short = hashBytes(&.{1}, 12);
    const padded = hashBytes(&.{ 1, 0 }, 12);
    const changed = hashBytes(&.{2}, 12);
    try std.testing.expect(!std.meta.eql(short, padded));
    try std.testing.expect(!std.meta.eql(short, changed));
    try std.testing.expectEqual(short, hashBytes(&.{1}, 12));
}

test "recursion Poseidon2: leaf and node domains are separated" {
    const child = Hash{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const node = MerkleHasher.hashChildren(.{ .left = child, .right = child });
    var leaf = MerkleHasher.defaultWithInitialState();
    var values: [RATE * 2]M31 = undefined;
    for (&values, 0..) |*value, index| {
        value.* = M31.fromCanonical(child[index % RATE]);
    }
    leaf.updateLeaf(&values);
    try std.testing.expect(!std.meta.eql(node, leaf.finalize()));
}

test "recursion Poseidon2: SIMD nodes preserve canonical scalar hashes" {
    var random_source = std.Random.DefaultPrng.init(0x4e_4f44_4534);
    const random = random_source.random();
    for (0..8) |batch| {
        var children: [8]Digest = undefined;
        for (&children, 0..) |*child, index| for (child) |*word| {
            word.* = if (batch == 0) (if (index % 2 == 0) 0 else m31.Modulus - 1) else random.intRangeLessThan(u32, 0, m31.Modulus);
        };
        const actual = MerkleHasher.hashChildrenWithSeed4(MerkleHasher.nodeSeed(), &children);
        for (actual, 0..) |digest, lane| try std.testing.expectEqualDeep(
            MerkleHasher.hashChildren(.{ .left = children[2 * lane], .right = children[2 * lane + 1] }),
            digest,
        );
    }
}

test "recursion Poseidon2: SIMD packed direct and incremental leaves match scalar" {
    const Column = struct { values: []const M31 };
    var values: [64][6]M31 = undefined;
    var columns: [64]Column = undefined;
    var packed_bytes: [4][64 * @sizeOf(M31) + 1]u8 = undefined;
    var random_source = std.Random.DefaultPrng.init(0x4c_4541_4634);
    const random = random_source.random();
    for (0..3) |pattern| {
        for (&values, &columns, 0..) |*column_values, *column, index| {
            for (column_values, 0..) |*value, lane| value.* = M31.fromCanonical(switch (pattern) {
                0 => 0,
                1 => if ((index + lane) % 3 == 0) m31.Modulus - 1 else 1,
                else => if (index % 8 == 7) 0 else random.intRangeLessThan(u32, 0, m31.Modulus),
            });
            column.* = .{ .values = column_values };
            for (0..4) |lane| std.mem.writeInt(u32, packed_bytes[lane][1 + index * 4 ..][0..4], column_values[1 + lane].toU32(), .little);
        }
        for ([_]usize{ 0, 1, 7, 8, 9, 16, 31, 32, 33, 64 }) |count| {
            var messages: [4][]const u8 = undefined;
            var expected: [4]Digest = undefined;
            for (0..4) |lane| {
                messages[lane] = packed_bytes[lane][1..][0 .. count * 4];
                var scalar = MerkleHasher.defaultWithInitialState();
                for (columns[0..count]) |column| scalar.updateLeaf(column.values[1 + lane ..][0..1]);
                expected[lane] = scalar.finalize();
            }
            try std.testing.expectEqualDeep(expected, MerkleHasher.hashPackedLeavesWithSeed4(MerkleHasher.leafSeed(), &messages));
            try std.testing.expectEqualDeep(expected, MerkleHasher.hashDirectM31LeavesWithSeed4(MerkleHasher.leafSeed(), columns[0..count], 1));
            var incremental = [_]MerkleHasher{MerkleHasher.defaultWithInitialState()} ** 4;
            var start: usize = 0;
            while (start < count) {
                const end = @min(count, start + 3);
                MerkleHasher.updateM31Columns4(&incremental, columns[start..end], 1);
                start = end;
            }
            MerkleHasher.updateM31Columns4(&incremental, columns[0..0], 1);
            try std.testing.expectEqualDeep(expected, MerkleHasher.finalize4(&incremental));
        }
        var unequal = [_]MerkleHasher{MerkleHasher.defaultWithInitialState()} ** 4;
        for (&unequal, 0..) |*hasher, lane| hasher.updateLeaf(values[0][0..lane]);
        var scalar = unequal;
        MerkleHasher.updateM31Columns4(&unequal, columns[0..9], 1);
        var expected: [4]Digest = undefined;
        for (&scalar, 0..) |*hasher, lane| {
            for (columns[0..9]) |column| hasher.updateLeaf(column.values[1 + lane ..][0..1]);
            expected[lane] = hasher.finalize();
        }
        try std.testing.expectEqualDeep(expected, MerkleHasher.finalize4(&unequal));
    }
}

test "recursion Poseidon2: lifted Merkle contract and packed leaves" {
    comptime stwo_core.vcs_lifted.merkle_hasher.assertMerkleHasherLifted(
        MerkleHasher,
    );
    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
        QM31.fromU32Unchecked(13, 14, 15, 16),
    };
    const first = stwo_core.vcs_lifted.packLeaf(MerkleHasher, values);
    const second = stwo_core.vcs_lifted.packLeaf(MerkleHasher, values);
    try std.testing.expectEqual(first, second);
}

test "recursion Poseidon2: PoW search returns the canonical lowest nonce" {
    var channel = Channel{};
    channel.mixU32s(&.{ 1, 2, 3 });
    const nonce = channel.grind(8);
    try std.testing.expect(channel.verifyPowNonce(8, nonce));
    if (nonce != 0) try std.testing.expect(!channel.verifyPowNonce(8, nonce - 1));
}

test "poseidon2 channel proof-of-work prefix replay matches verifyPowNonce" {
    var prng = std.Random.DefaultPrng.init(0x9051_d0e5);
    const random = prng.random();
    for (0..64) |_| {
        var channel = Channel{};
        var words: [5]u32 = undefined;
        for (&words) |*word| word.* = random.int(u32);
        channel.mixU32s(&words);
        const prefix = channel.powPrefixState();
        for (0..64) |_| {
            const nonce = if (random.boolean()) random.int(u64) else random.int(u16);
            var candidate = channel;
            candidate.mixU64(nonce);
            const expected = candidate.drawU32s()[0];
            try std.testing.expectEqual(expected, Channel.powCandidateWordFromPrefix(prefix, nonce));
            for ([_]u32{ 1, 4, 8, 16 }) |bits| {
                try std.testing.expectEqual(
                    channel.verifyPowNonce(bits, nonce),
                    @ctz(Channel.powCandidateWordFromPrefix(prefix, nonce)) >= bits,
                );
            }
        }
        const found = channel.grind(6);
        try std.testing.expect(@ctz(Channel.powCandidateWordFromPrefix(prefix, found)) >= 6);
        var lower: u64 = 0;
        while (lower < found) : (lower += 1)
            try std.testing.expect(@ctz(Channel.powCandidateWordFromPrefix(prefix, lower)) < 6);
    }
}
