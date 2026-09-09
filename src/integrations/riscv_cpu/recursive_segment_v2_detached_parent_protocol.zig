//! Shared native/standalone transcript for the small detached two-child parent.
//! Profiles are explicitly admitted separately from CSP. Key hashes authorize
//! nothing unless pinned independently by callers.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const recursion = frontend.recursion;
const continuation = recursion.span_continuation_v1;
const cohort = @import("recursive_segment_v2_detached_parent_cohort.zig");
const manifest_mod = cohort.manifest_mod;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const payload = @import("recursive_detached_payload_v1.zig");
pub const VERSION: u32 = 2;
pub const DEVELOPMENT_ONLY = true;
pub const PCS_CONFIG = recursion.outer_parent_child_admission.OUTER_PCS_CONFIG;
pub const PUBLIC_SCOPE: u32 = 3;
pub const ExpectedV1 = continuation.Words;
pub const PublicationMode = continuation.Mode;
pub const ClaimsV1 = cohort.ClaimsV1;
pub const ProfileV1 = enum(u8) {
    detached_continuation_development_q3_v2 = 2,
    recursive_q193_v1 = 3,
    pub fn pcsConfig(self: ProfileV1) core.pcs.PcsConfig {
        return switch (self) {
            .detached_continuation_development_q3_v2 => PCS_CONFIG,
            .recursive_q193_v1 => recursion.protocol.PCS_CONFIG,
        };
    }
    pub fn interactionPowBits(self: ProfileV1) u32 {
        return switch (self) {
            .detached_continuation_development_q3_v2 => 0,
            .recursive_q193_v1 => recursion.protocol.INTERACTION_POW_BITS,
        };
    }
};
pub const mixInteractionPow = @import("recursive_detached_claims_v1.zig").mixInteractionPow;

pub const KeyV1 = struct {
    version: u32 = VERSION,
    profile: ProfileV1 = .detached_continuation_development_q3_v2,
    publication_mode: PublicationMode = .root,
    pcs_config: core.pcs.PcsConfig = PCS_CONFIG,
    manifest: manifest_mod.Manifest,
    parameters: cohort.ParametersV1,
    preprocessed_root: recursion.poseidon2_channel.Digest,
    child_key_sha256: [2][32]u8,

    pub fn validate(self: *const KeyV1) !void {
        _ = try self.identity();
    }

    pub fn identity(self: *const KeyV1) ![32]u8 {
        if (self.version != VERSION or !std.meta.eql(self.pcs_config, self.profile.pcsConfig())) return error.DetachedParentProfileMismatch;
        try self.parameters.validate(&self.manifest);
        if (std.mem.allEqual(u32, &self.preprocessed_root, 0)) return error.DetachedParentKeyMismatch;
        for (self.preprocessed_root) |word| if (word >= core.fields.m31.Modulus) return error.DetachedParentKeyMismatch;
        for (self.child_key_sha256) |pin| if (std.mem.allEqual(u8, &pin, 0)) return error.DetachedParentKeyMismatch;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(switch (self.profile) {
            .detached_continuation_development_q3_v2 => "stwo-zig/segment-v2-detached-two-child-development-parent/v2\x00",
            .recursive_q193_v1 => "stwo-zig/segment-v2-detached-two-child-q193-parent/v1\x00",
        });
        for ([_]u32{ VERSION, @intFromEnum(self.profile), @intFromEnum(self.publication_mode), continuation.VERSION, manifest_mod.FORMAT_VERSION, PUBLIC_SCOPE, continuation.WORD_COUNT, self.pcs_config.pow_bits, self.pcs_config.fri_config.log_blowup_factor, self.pcs_config.fri_config.log_last_layer_degree_bound, @intCast(self.pcs_config.fri_config.n_queries), self.pcs_config.fri_config.fold_step }) |word| hashWord(&hash, word);
        if (self.profile == .recursive_q193_v1) hashWord(&hash, self.profile.interactionPowBits());
        hash.update(&self.manifest.seal);
        hash.update(&recursion.air.universal_challenges.registryOrderDigest());
        for (recursion.protocol.PROTOCOL_ID_WORDS) |word| hashWord(&hash, word);
        for (self.preprocessed_root) |word| hashWord(&hash, word);
        for (self.child_key_sha256) |pin| hash.update(&pin);
        hashWord(&hash, self.parameters.poseidon_active_rows);
        for (self.parameters.words, 0..) |words, row| {
            hashWord(&hash, @intCast(row));
            hashWord(&hash, @intCast(words.len));
            for (words) |word| hashWord(&hash, word.toU32());
        }
        return hash.finalResult();
    }
};

pub fn validateExpected(expected: *const ExpectedV1) !void {
    try continuation.validate(expected, .intermediate);
}

pub fn publicTuple(index: usize, word: M31) [3]M31 {
    return .{ M31.fromCanonical(PUBLIC_SCOPE), M31.fromCanonical(@intCast(index)), word };
}

/// Every published word is requested exactly once by the admitted routing AIR,
/// including words whose arithmetic fanout is zero. No producer scalar enters.
pub fn publicBoundary(expected: *const ExpectedV1, relations: *const cohort.Relations) !QM31 {
    try validateExpected(expected);
    const relation = try relations.getExact(.recursion_statement_word);
    var result = QM31.zero();
    for (expected, 0..) |word, index| {
        const denominator = try relation.combineBase(&publicTuple(index, word));
        result = result.add(try denominator.inv());
    }
    return result;
}

/// Called after the fixed and main tree commitments, before relation draws.
pub fn mixAdmission(channel: anytype, key: *const KeyV1, expected: *const ExpectedV1) !void {
    const identity = try key.identity();
    try continuation.validate(expected, key.publication_mode);
    payload.begin(channel, .admission_header);
    channel.mixU32s(&.{ 0x4450_4131, VERSION, manifest_mod.COMPONENT_COUNT, PUBLIC_SCOPE, expected.len });
    var pin_words: [8]u32 = undefined;
    for (&pin_words, 0..) |*word, index| word.* = std.mem.readInt(u32, identity[index * 4 ..][0..4], .little);
    payload.begin(channel, .key_identity);
    channel.mixU32s(&pin_words);
    var words: [continuation.WORD_COUNT]u32 = undefined;
    for (&words, expected) |*word, value| word.* = value.toU32();
    payload.begin(channel, .expected_u32);
    channel.mixU32s(&words);
}

/// Independent challenges separate all47 tuple domains. Exact global LogUp
/// closure is checked using STARK-bound row claims and derived public requests;
/// there is no freely supplied per-domain decomposition or boundary receipt.
pub fn mixClaimsAndBoundary(channel: anytype, key: *const KeyV1, expected: *const ExpectedV1, claims: ClaimsV1, relations: *const cohort.Relations) !void {
    _ = try claims.vector(&key.manifest);
    const boundary = try publicBoundary(expected, relations);
    var total = boundary;
    for (claims.values) |claim| total = total.add(claim);
    if (!total.isZero()) return error.DetachedParentClaimClosureMismatch;
    payload.begin(channel, .claims_header);
    channel.mixU32s(&.{ 0x4450_4331, VERSION, manifest_mod.COMPONENT_COUNT });
    payload.begin(channel, .claims);
    channel.mixFelts(&claims.values);
    payload.begin(channel, .boundary_header);
    channel.mixU32s(&.{ 0x4450_4231, VERSION, PUBLIC_SCOPE, expected.len, 2 });
    payload.begin(channel, .boundary);
    channel.mixFelts(&.{boundary});
    payload.begin(channel, .partials);
    channel.mixFelts(&claims.poseidon_partials);
}

fn hashWord(hash: anytype, word: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, word, .little);
    hash.update(&bytes);
}
