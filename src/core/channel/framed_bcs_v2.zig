//! Candidate S31NAT9F transcript channel. No installed proof selector uses it.
//!
//! This is the native byte peer of S31's `pcs_fri_framed_bcs_v2.py` model.
//! It retains the selected raw Gate channel untouched. Role and event framing
//! prevents equal *inputs* among modeled roles; this module does not prove a
//! BCS/ROM reduction or assign native security bits.
const std = @import("std");
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;
const uniform_queries = @import("../queries/uniform_v1.zig");

pub const Digest32 = [32]u8;
pub const domain = "S31BCS2";
pub const reserved_proof_magic = "S31NAT9F";
pub const m31_modulus: u32 = (@as(u32, 1) << 31) - 1;
pub const challenge_block_cap: u64 = 8;

pub const Role = enum(u8) {
    field_absorb = 1,
    root_absorb = 2,
    nonce_absorb = 3,
    raw_word_draw = 4,
    pow_prefix = 5,
    pow_trial = 6,
    merkle_leaf = 7,
    merkle_parent = 8,
    tree_context = 9,
    statement = 10,
};

pub const Error = error{
    LengthOverflow,
    EventOverflow,
    InvalidFieldLimbs,
    InvalidDifficulty,
    InvalidNonce,
    InvalidStage,
    ChallengeBlockLimit,
};

/// Verifier-derived statement material. The caller must obtain these full
/// 32-byte digests from its trusted key and checked proof geometry, never from
/// unvalidated proof bytes. A future selector must freeze their derivation.
pub const StatementBinding = struct {
    key_digest: Digest32,
    circuit_digest: Digest32,
    fri_config_digest: Digest32,
    source_tree_descriptors: [4]Digest32,
    line_profile_digest: Digest32,

    pub const encoded_len: usize = 8 + 8 * 32;

    pub fn encode(self: StatementBinding) [encoded_len]u8 {
        var out: [encoded_len]u8 = undefined;
        var offset: usize = 0;
        @memcpy(out[offset..][0..8], reserved_proof_magic);
        offset += 8;
        inline for (.{ self.key_digest, self.circuit_digest, self.fri_config_digest }) |digest| {
            @memcpy(out[offset..][0..32], &digest);
            offset += 32;
        }
        for (self.source_tree_descriptors) |digest| {
            @memcpy(out[offset..][0..32], &digest);
            offset += 32;
        }
        @memcpy(out[offset..][0..32], &self.line_profile_digest);
        return out;
    }
};

fn beginHash(role: Role, event: u64, payload_len: u64) Blake2s256 {
    var hasher = Blake2s256.init(.{});
    hasher.update(domain);
    hasher.update(&.{@intFromEnum(role)});
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, payload_len, .little);
    hasher.update(&bytes);
    std.mem.writeInt(u64, &bytes, event, .little);
    hasher.update(&bytes);
    return hasher;
}

fn finishHash(hasher: *Blake2s256) Digest32 {
    var digest: Digest32 = undefined;
    hasher.final(&digest);
    return digest;
}

/// The frame length covers the concatenation of all payload parts. No
/// allocation or implicit field conversion occurs in the hash path.
pub fn hashFrameParts(role: Role, event: u64, parts: []const []const u8) Error!Digest32 {
    var payload_len: u64 = 0;
    for (parts) |part| {
        const part_len = std.math.cast(u64, part.len) orelse return error.LengthOverflow;
        payload_len = std.math.add(u64, payload_len, part_len) catch return error.LengthOverflow;
    }
    var hasher = beginHash(role, event, payload_len);
    for (parts) |part| hasher.update(part);
    return finishHash(&hasher);
}

pub fn hashRoot(digest: Digest32, event: u64, root: Digest32) Digest32 {
    return hashFrameParts(.root_absorb, event, &.{ &digest, &root }) catch unreachable;
}

pub fn hashField(digest: Digest32, event: u64, limbs: []const u32) Error!Digest32 {
    if (limbs.len % 4 != 0) return error.InvalidFieldLimbs;
    for (limbs) |limb| if (limb >= m31_modulus) return error.InvalidFieldLimbs;
    const n = std.math.cast(u64, limbs.len) orelse return error.LengthOverflow;
    const limbs_bytes = std.math.mul(u64, n, 4) catch return error.LengthOverflow;
    const payload_len = std.math.add(u64, 32, limbs_bytes) catch return error.LengthOverflow;
    var hasher = beginHash(.field_absorb, event, payload_len);
    hasher.update(&digest);
    for (limbs) |limb| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, limb, .little);
        hasher.update(&bytes);
    }
    return finishHash(&hasher);
}

pub fn hashNonce(digest: Digest32, event: u64, nonce: u64) Digest32 {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, nonce, .little);
    return hashFrameParts(.nonce_absorb, event, &.{ &digest, &bytes }) catch unreachable;
}

pub fn hashPowPrefix(digest: Digest32, event: u64, difficulty: u32) Digest32 {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, difficulty, .little);
    return hashFrameParts(.pow_prefix, event, &.{ &digest, &bytes }) catch unreachable;
}

pub fn hashPowTrial(prefix: Digest32, event: u64, nonce: u64) Digest32 {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, nonce, .little);
    return hashFrameParts(.pow_trial, event, &.{ &prefix, &bytes }) catch unreachable;
}

/// Return eight exactly uniform canonical M31 residues, or reject the entire
/// block. Each residue has exactly two accepted u32 preimages: r and r+p.
/// The two excluded words are 2p and 2p+1. This is deliberately separate
/// from the power-of-two FRI index sampler, which masks raw words directly.
pub fn canonicalM31Block(raw: [8]u32) ?[8]u32 {
    var out: [8]u32 = undefined;
    for (raw, 0..) |word, i| {
        if (word >= 2 * m31_modulus) return null;
        out[i] = if (word >= m31_modulus) word - m31_modulus else word;
    }
    return out;
}

fn drawExactM31Block(draw: anytype) (Error || uniform_queries.Error)![8]u32 {
    var used: u64 = 0;
    while (used < challenge_block_cap) : (used += 1) {
        const raw = try draw.drawRawU32sChecked();
        if (canonicalM31Block(raw)) |canonical| return canonical;
    }
    return error.ChallengeBlockLimit;
}

/// The first 128 little-endian output bits are the v2 candidate PoW value.
/// The exact bit predicate and two-barrier grinding budget still need a ROM
/// reduction before this profile can be selected.
pub const PowBarrier = struct {
    prefix_event: u64,
    trial_event: u64,
    difficulty: u32,
    prefix: Digest32,

    pub fn trialHash(self: PowBarrier, nonce: u64) Digest32 {
        return hashPowTrial(self.prefix, self.trial_event, nonce);
    }

    pub fn accepts(self: PowBarrier, nonce: u64) bool {
        if (self.difficulty > 128) return false;
        const trial = self.trialHash(nonce);
        const low = std.mem.readInt(u128, trial[0..16], .little);
        return @ctz(low) >= self.difficulty;
    }
};

/// Stage counts are verifier-owned and fail before a `u64` event wraps.
/// One PoW barrier reserves a prefix event and a trial event; all candidate
/// nonces reuse the trial event with distinct nonce bytes. On success the
/// accepted nonce is absorbed at a third event. The query stage is terminal.
pub const FramedBcsChannelV2 = struct {
    digest: Digest32,
    next_event: u64,
    pending_pow: ?PowBarrier,
    active_draw: ?uniform_queries.FramedQueryWordChannelV1,
    pow_barriers_done: u8,
    query_started: bool,
    failed: bool,

    const Self = @This();

    pub fn init(statement: StatementBinding) Self {
        const payload = statement.encode();
        const initial_digest = hashFrameParts(.statement, 0, &.{&payload}) catch unreachable;
        return .{
            .digest = initial_digest,
            .next_event = 1,
            .pending_pow = null,
            .active_draw = null,
            .pow_barriers_done = 0,
            .query_started = false,
            .failed = false,
        };
    }

    fn available(self: Self, count: u64) Error!void {
        if (self.failed or self.query_started or self.pending_pow != null or self.active_draw != null)
            return error.InvalidStage;
        if (count > std.math.maxInt(u64) - self.next_event) return error.EventOverflow;
    }

    /// One nonterminal draw stage may consume multiple checked raw blocks.
    /// Finish it before any mix or PoW event. Only the exact canonical M31
    /// sampler is public here; raw words stay inside this module.
    pub fn beginChallengeDraw(self: *Self) Error!void {
        try self.available(1);
        self.active_draw = uniform_queries.FramedQueryWordChannelV1.init(self.digest, self.next_event);
        self.next_event += 1;
    }

    /// Two QM31 values as eight canonical M31 limbs, four per value. The
    /// verifier-owned cap is frozen in this module. Under an ideal oracle,
    /// one block rejects with probability at most 2^-28; exhausting eight
    /// independent blocks is at most 2^-224 per stage. This is a completeness
    /// term and does not by itself establish the selected T64 work factor.
    pub fn drawChallengeQM31Limbs(self: *Self) (Error || uniform_queries.Error)![8]u32 {
        if (self.failed) return error.InvalidStage;
        if (self.active_draw) |*draw| {
            return drawExactM31Block(draw) catch |err| {
                self.failed = true;
                return err;
            };
        }
        return error.InvalidStage;
    }

    pub fn endChallengeDraw(self: *Self) Error!void {
        if (self.failed) return error.InvalidStage;
        const draw = self.active_draw orelse return error.InvalidStage;
        if (draw.next_block == 0) return error.InvalidStage;
        self.active_draw = null;
    }

    pub fn mixRoot(self: *Self, root: Digest32) Error!void {
        try self.available(1);
        self.digest = hashRoot(self.digest, self.next_event, root);
        self.next_event += 1;
    }

    pub fn mixField(self: *Self, limbs: []const u32) Error!void {
        try self.available(1);
        const next_digest = try hashField(self.digest, self.next_event, limbs);
        self.digest = next_digest;
        self.next_event += 1;
    }

    pub fn beginPow(self: *Self, difficulty: u32) Error!PowBarrier {
        if (difficulty > 128) return error.InvalidDifficulty;
        if (self.pow_barriers_done >= 2) return error.InvalidStage;
        // Reserve the nonce-absorption event as well, so a begun PoW cannot
        // become impossible to complete through event-counter exhaustion.
        try self.available(3);
        const barrier = PowBarrier{
            .prefix_event = self.next_event,
            .trial_event = self.next_event + 1,
            .difficulty = difficulty,
            .prefix = hashPowPrefix(self.digest, self.next_event, difficulty),
        };
        self.next_event += 2;
        self.pending_pow = barrier;
        return barrier;
    }

    pub fn acceptPowNonce(self: *Self, nonce: u64) Error!void {
        const barrier = self.pending_pow orelse return error.InvalidStage;
        if (!barrier.accepts(nonce)) return error.InvalidNonce;
        if (self.next_event == std.math.maxInt(u64)) return error.EventOverflow;
        self.digest = hashNonce(self.digest, self.next_event, nonce);
        self.next_event += 1;
        self.pending_pow = null;
        self.pow_barriers_done += 1;
    }

    /// Reuses P08's checked, exact 60-byte raw-word frame. The caller may
    /// pass the returned channel to `drawUniformQueriesV1`; no legacy M31
    /// reduction or modulo-biased sampler is used here.
    pub fn beginQueries(self: *Self) Error!uniform_queries.FramedQueryWordChannelV1 {
        if (self.pow_barriers_done != 2) return error.InvalidStage;
        try self.available(1);
        const query_event = self.next_event;
        self.next_event += 1;
        self.query_started = true;
        return uniform_queries.FramedQueryWordChannelV1.init(self.digest, query_event);
    }
};

fn expectHex(expected_hex: []const u8, actual: []const u8) !void {
    var expected_bytes: [32]u8 = undefined;
    const expected = try std.fmt.hexToBytes(&expected_bytes, expected_hex);
    try std.testing.expectEqualSlices(u8, expected, actual);
}

fn zeroStatement() StatementBinding {
    return .{
        .key_digest = [_]u8{0} ** 32,
        .circuit_digest = [_]u8{0} ** 32,
        .fri_config_digest = [_]u8{0} ** 32,
        .source_tree_descriptors = [_]Digest32{[_]u8{0} ** 32} ** 4,
        .line_profile_digest = [_]u8{0} ** 32,
    };
}

fn expectStatementChanges(base_digest: Digest32, changed: StatementBinding) !void {
    const other = FramedBcsChannelV2.init(changed);
    try std.testing.expect(!std.mem.eql(u8, &base_digest, &other.digest));
}

test "statement encoding binds every verifier-owned digest before fixed root" {
    const base = zeroStatement();
    const payload = base.encode();
    try std.testing.expectEqual(@as(usize, 264), payload.len);
    try std.testing.expectEqualSlices(u8, reserved_proof_magic, payload[0..8]);
    const base_channel = FramedBcsChannelV2.init(base);
    var changed = base;
    changed.key_digest[0] = 1;
    try expectStatementChanges(base_channel.digest, changed);
    changed = base;
    changed.circuit_digest[0] = 1;
    try expectStatementChanges(base_channel.digest, changed);
    changed = base;
    changed.fri_config_digest[0] = 1;
    try expectStatementChanges(base_channel.digest, changed);
    for (0..4) |i| {
        changed = base;
        changed.source_tree_descriptors[i][0] = 1;
        try expectStatementChanges(base_channel.digest, changed);
    }
    changed = base;
    changed.line_profile_digest[0] = 1;
    try expectStatementChanges(base_channel.digest, changed);
}

test "framed Gate transcript matches independent Python vectors" {
    var channel = FramedBcsChannelV2.init(zeroStatement());
    try expectHex("667b272f99f769be23d49cd20b59b07c31cbaa64cdb21243be1a3ba533117f7b", &channel.digest);
    try std.testing.expectEqual(@as(u64, 1), channel.next_event);
    var root: Digest32 = undefined;
    for (&root, 0..) |*byte, i| byte.* = @intCast(i);
    try channel.mixRoot(root);
    try expectHex("ded398cba3dcfbc1d7bc7f3665095df4592783b9b959f178e7c83c90e6a0bf22", &channel.digest);
    try channel.mixField(&.{ 0, 1, 2, 3, 4, 5, 6, 7 });
    try expectHex("2a8b5677e1e85eba2bd7115a056b64e42a2c6994c34d727a7561fd85c17d6cf4", &channel.digest);
    const pow = try channel.beginPow(8);
    try std.testing.expectEqual(@as(u64, 3), pow.prefix_event);
    try std.testing.expectEqual(@as(u64, 4), pow.trial_event);
    try std.testing.expect(!pow.accepts(0));
    try std.testing.expect(pow.accepts(208));
    const trial = pow.trialHash(208);
    try expectHex("0008c9d8fbf16a8b0e07ab8d1014e7bb2d908d2c2480bac2c5d58704275c1ebc", &trial);
    try std.testing.expectError(error.InvalidNonce, channel.acceptPowNonce(0));
    try std.testing.expectError(error.InvalidStage, channel.mixRoot(root));
    try channel.acceptPowNonce(208);
    try expectHex("8f8fbf3dfef5d5a9c3114ce1dc24d0c2fdf267505a49c3e34d1ef9b05e1071c3", &channel.digest);
    try channel.beginChallengeDraw();
    try std.testing.expectError(error.InvalidStage, channel.mixRoot(root));
    const challenge = try channel.drawChallengeQM31Limbs();
    try std.testing.expectEqualSlices(u32, &.{ 1160083078, 1314119153, 2063071219, 1990532807, 1142217875, 1843007419, 1727724682, 2009280112 }, &challenge);
    try channel.endChallengeDraw();
    try std.testing.expectError(error.InvalidStage, channel.beginQueries());
    const fri_pow = try channel.beginPow(5);
    try std.testing.expectEqual(@as(u64, 7), fri_pow.prefix_event);
    try std.testing.expectEqual(@as(u64, 8), fri_pow.trial_event);
    try std.testing.expect(fri_pow.accepts(56));
    const fri_trial = fri_pow.trialHash(56);
    try expectHex("606c2ea7e898ec35f9537dad79b322f4350e65cce8c475d49905bc463df7afac", &fri_trial);
    try channel.acceptPowNonce(56);
    try expectHex("b796eb344e1bd31d1195e3ead5a223bcedce99dbf1fd6ba9e31a3e8d86292a31", &channel.digest);
    try std.testing.expectError(error.InvalidStage, channel.beginPow(5));
    var query_channel = try channel.beginQueries();
    try std.testing.expectEqual(@as(u64, 10), query_channel.event);
    const words = try query_channel.drawRawU32sChecked();
    try std.testing.expectEqualSlices(u32, &.{ 3947679439, 1829446566, 490830632, 1496175002, 657318768, 3034657462, 3081425507, 2605001983 }, &words);
    try std.testing.expectError(error.InvalidStage, channel.mixRoot(root));
}

test "framed channel rejects noncanonical limbs, stage misuse and event wrap" {
    var channel = FramedBcsChannelV2.init(zeroStatement());
    try std.testing.expectError(error.InvalidFieldLimbs, channel.mixField(&.{ 1, 2, 3 }));
    try std.testing.expectError(error.InvalidFieldLimbs, channel.mixField(&.{ m31_modulus, 0, 0, 0 }));
    try std.testing.expectEqual(@as(u64, 1), channel.next_event);
    try std.testing.expectError(error.InvalidStage, channel.acceptPowNonce(0));
    try std.testing.expectError(error.InvalidDifficulty, channel.beginPow(129));
    channel.next_event = std.math.maxInt(u64) - 1;
    try std.testing.expectError(error.EventOverflow, channel.beginPow(0));
    try channel.mixRoot([_]u8{0} ** 32);
    try std.testing.expectError(error.EventOverflow, channel.mixRoot([_]u8{0} ** 32));
}

test "exact M31 challenge rejects first raw block and consumes its counter" {
    const Fixture = struct {
        cursor: u32 = 0,
        pub fn drawRawU32sChecked(self: *@This()) uniform_queries.Error![8]u32 {
            defer self.cursor += 1;
            if (self.cursor == 0) return .{ 2 * m31_modulus, 0, 0, 0, 0, 0, 0, 0 };
            return .{ 0, m31_modulus, 1, m31_modulus + 1, 2, m31_modulus + 2, 3, m31_modulus + 3 };
        }
    };
    var fixture = Fixture{};
    const canonical = try drawExactM31Block(&fixture);
    try std.testing.expectEqualSlices(u32, &.{ 0, 0, 1, 1, 2, 2, 3, 3 }, &canonical);
    try std.testing.expectEqual(@as(u32, 2), fixture.cursor);
    try std.testing.expect(canonicalM31Block(.{ 2 * m31_modulus + 1, 0, 0, 0, 0, 0, 0, 0 }) == null);
    try std.testing.expectEqual(@as(u64, 8), challenge_block_cap);

    const AlwaysReject = struct {
        cursor: u32 = 0,
        pub fn drawRawU32sChecked(self: *@This()) uniform_queries.Error![8]u32 {
            self.cursor += 1;
            return .{ 2 * m31_modulus, 0, 0, 0, 0, 0, 0, 0 };
        }
    };
    var rejected = AlwaysReject{};
    try std.testing.expectError(error.ChallengeBlockLimit, drawExactM31Block(&rejected));
    try std.testing.expectEqual(@as(u32, 8), rejected.cursor);
}

fn mixPatternRoot(channel: *FramedBcsChannelV2, event: u64) !void {
    try std.testing.expectEqual(event, channel.next_event);
    const root = [_]u8{@intCast(event)} ** 32;
    try channel.mixRoot(root);
}

fn mixPatternField(channel: *FramedBcsChannelV2, event: u64) !void {
    try std.testing.expectEqual(event, channel.next_event);
    try channel.mixField(&.{ 0, 1, 2, 3 });
}

fn drawPatternChallenge(channel: *FramedBcsChannelV2, event: u64, expected_first: u32) !void {
    try std.testing.expectEqual(event, channel.next_event);
    try channel.beginChallengeDraw();
    const limbs = try channel.drawChallengeQM31Limbs();
    try std.testing.expectEqual(expected_first, limbs[0]);
    try channel.endChallengeDraw();
}

test "paired Gate candidate event plan matches Python four-root two-track schedule" {
    var channel = FramedBcsChannelV2.init(zeroStatement());
    // Event ordinals are from candidate_paired_gate_plan((17, 16)). The
    // statement is event 0; no proof selector currently calls this schedule.
    try mixPatternRoot(&channel, 1); // fixed
    try mixPatternRoot(&channel, 2); // circuit identity
    try mixPatternField(&channel, 3); // public outputs
    try mixPatternRoot(&channel, 4); // main
    const interaction_pow = try channel.beginPow(0); // events 5, 6
    try std.testing.expectEqual(@as(u64, 5), interaction_pow.prefix_event);
    try std.testing.expectEqual(@as(u64, 6), interaction_pow.trial_event);
    try channel.acceptPowNonce(0); // event 7
    try drawPatternChallenge(&channel, 8, 1822750541); // lookup pair
    try mixPatternField(&channel, 9); // interaction claim
    try mixPatternRoot(&channel, 10); // interaction root
    try drawPatternChallenge(&channel, 11, 640893609); // composition gamma
    try mixPatternRoot(&channel, 12); // composition root
    try drawPatternChallenge(&channel, 13, 1454020928); // OOD seed
    try mixPatternField(&channel, 14); // sampled values
    try drawPatternChallenge(&channel, 15, 590385924); // common batch lambda
    try drawPatternChallenge(&channel, 16, 1174171810); // fold alpha h17
    try mixPatternRoot(&channel, 17); // original line root h17
    try mixPatternRoot(&channel, 18); // own quotient line root h17
    try drawPatternChallenge(&channel, 19, 452219042); // fold alpha h16
    try mixPatternField(&channel, 20); // original terminal coefficients
    try mixPatternField(&channel, 21); // quotient terminal coefficients
    const fri_pow = try channel.beginPow(0); // events 22, 23
    try std.testing.expectEqual(@as(u64, 22), fri_pow.prefix_event);
    try std.testing.expectEqual(@as(u64, 23), fri_pow.trial_event);
    try channel.acceptPowNonce(0); // event 24
    try expectHex("84bbf452bd2097fe94c0310fe2030f5ff985fb52fa1d9dc8cbeedc2af9ed464f", &channel.digest);
    var queries = try channel.beginQueries(); // event 25
    try std.testing.expectEqual(@as(u64, 25), queries.event);
    const raw = try queries.drawRawU32sChecked();
    try std.testing.expectEqual(@as(u32, 1533884970), raw[0]);
}
