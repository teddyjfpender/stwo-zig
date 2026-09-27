//! Research-only joint proof-of-work authority for an R-008 split session.
//!
//! The current R-007 manifest derives its shared relation challenge directly
//! from the canonical session digest.  A production split protocol instead
//! needs one joint PoW, after every leaf Tree 0/1 root is frozen, which also
//! precedes and influences that shared challenge.  This module specifies and
//! tests that ordering without changing the accepted V1 manifest or either
//! production proof path.

const std = @import("std");
const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const base_transcript = @import("../../air/transcript/mod.zig");
const aggregation_challenge = @import("../../aggregation/challenge.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const aggregation_manifest = @import("../../aggregation/manifest.zig");
const aggregation_types = @import("../../aggregation/types.zig");
const aggregation_wire = @import("../../aggregation/wire.zig");

pub const RESEARCH_ONLY = true;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const CHANGES_MANIFEST_V1 = false;
pub const JOINT_POW_PRECEDES_SHARED_RELATION = true;
pub const LEAF_BINDING_IS_IN_PRODUCTION_TRANSCRIPT = false;
pub const JOINT_POW_BITS: u32 = base_transcript.INTERACTION_POW_BITS;
pub const format_version: u32 = 1;

pub const Digest = aggregation_hash.Digest;
pub const ChallengeContextV1 = aggregation_challenge.ChallengeContextV1;
pub const LeafRole = aggregation_types.LeafRole;

/// Little-endian `STWJPW1\0`, followed by the candidate format, PoW strength,
/// and digest word count. The canonical session digest follows this frame.
pub const joint_pow_domain_words = [6]u32{
    0x4a57_5453,
    0x0031_5750,
    format_version,
    JOINT_POW_BITS,
    8,
    2,
};

/// Little-endian `STWJLF1\0`, followed by the candidate format and fixed word
/// count. The runtime frame binds the session, PoW result, shared relation,
/// selected role/index, and canonical descriptor digest in one channel mix.
pub const leaf_binding_domain_words = [5]u32{
    0x4a57_5453,
    0x0031_464c,
    format_version,
    49,
    2,
};

pub const PreparedJointChallengeV1 = struct {
    session_digest: Digest,
    interaction_pow: u64,
    pow_context_digest: Digest,
    relation_context: ChallengeContextV1,

    pub fn validate(
        self: PreparedJointChallengeV1,
        session: *const aggregation_manifest.PreparedSessionV1,
    ) !void {
        _ = try verify(session, self);
    }
};

/// Mine the canonical lowest nonce for the complete manifest, mix it, and
/// only then derive the one `(z, alpha)` pair shared by every split leaf.
pub fn prepare(
    session: *const aggregation_manifest.PreparedSessionV1,
) !PreparedJointChallengeV1 {
    try validatePreparedSession(session);
    var channel = powPrefix(session.session_digest);
    const interaction_pow = channel.grind(JOINT_POW_BITS);
    channel.mixU64(interaction_pow);
    const pow_context_digest = channel.digestBytes();
    return .{
        .session_digest = session.session_digest,
        .interaction_pow = interaction_pow,
        .pow_context_digest = pow_context_digest,
        .relation_context = aggregation_challenge.derive(pow_context_digest),
    };
}

/// Replay the session-wide prefix. An invalid nonce is rejected before it is
/// mixed; the returned challenge is independently re-derived rather than
/// trusted from the candidate artifact.
pub fn verify(
    session: *const aggregation_manifest.PreparedSessionV1,
    prepared: PreparedJointChallengeV1,
) !ChallengeContextV1 {
    try validatePreparedSession(session);
    if (!aggregation_hash.eql(prepared.session_digest, session.session_digest))
        return error.SessionMismatch;

    var channel = powPrefix(session.session_digest);
    if (!channel.verifyPowNonce(JOINT_POW_BITS, prepared.interaction_pow))
        return error.InvalidJointProofOfWork;
    channel.mixU64(prepared.interaction_pow);

    const pow_context_digest = channel.digestBytes();
    if (!aggregation_hash.eql(
        prepared.pow_context_digest,
        pow_context_digest,
    )) return error.PowContextMismatch;

    const expected = aggregation_challenge.derive(pow_context_digest);
    if (!challengeEql(prepared.relation_context, expected))
        return error.RelationContextMismatch;
    return expected;
}

/// Bind one already-validated manifest member into a role-local transcript.
/// All checks precede the only channel mutation, preserving failure atomicity.
pub fn mixLeafBinding(
    channel: anytype,
    session: *const aggregation_manifest.PreparedSessionV1,
    prepared: PreparedJointChallengeV1,
    leaf_index: u32,
    expected_role: LeafRole,
) !void {
    const relation = try verify(session, prepared);
    const leaf = try session.leaf(leaf_index);
    if (leaf.descriptor.role != expected_role) return error.LeafRoleMismatch;

    const descriptor_digest = aggregation_wire.hashDescriptor(leaf.descriptor);
    if (!aggregation_hash.eql(descriptor_digest, leaf.descriptor_digest))
        return error.PreparedSessionMutated;

    var words: [leaf_binding_domain_words[3]]u32 = undefined;
    var cursor: usize = 0;
    appendWords(&words, &cursor, &leaf_binding_domain_words);
    appendDigest(&words, &cursor, session.session_digest);
    appendDigest(&words, &cursor, prepared.pow_context_digest);
    appendU64(&words, &cursor, prepared.interaction_pow);
    appendDigest(&words, &cursor, relation.challenge_context_digest);
    appendWords(&words, &cursor, &relation.z.limbs);
    appendWords(&words, &cursor, &relation.alpha.limbs);
    words[cursor] = leaf_index;
    cursor += 1;
    words[cursor] = @intFromEnum(expected_role);
    cursor += 1;
    appendDigest(&words, &cursor, descriptor_digest);
    std.debug.assert(cursor == words.len);
    channel.mixU32s(&words);
}

fn validatePreparedSession(
    session: *const aggregation_manifest.PreparedSessionV1,
) !void {
    if (aggregation_hash.isZero(session.session_digest))
        return error.ZeroSessionDigest;
    if (session.leaves.len != session.header.leaf_count or
        !aggregation_types.validLeafCount(session.leaves.len))
    {
        return error.InvalidPreparedSession;
    }
    if (!aggregation_hash.eql(
        aggregation_manifest.hashCanonical(session),
        session.session_digest,
    )) return error.PreparedSessionMutated;

    const old_v1_challenge = aggregation_challenge.derive(
        session.session_digest,
    );
    if (!challengeEql(session.challenge, old_v1_challenge))
        return error.PreparedSessionMutated;

    for (session.leaves, 0..) |leaf, index| {
        if (leaf.descriptor.leaf_index != index)
            return error.PreparedSessionMutated;
        if (!aggregation_hash.eql(
            leaf.descriptor_digest,
            aggregation_wire.hashDescriptor(leaf.descriptor),
        ) or !aggregation_hash.eql(
            leaf.statement_leaf_digest,
            aggregation_manifest.statementLeafDigest(
                @intCast(index),
                leaf.descriptor.leaf_statement_digest,
            ),
        ) or !aggregation_hash.eql(
            leaf.artifact_leaf_digest,
            aggregation_manifest.artifactLeafDigest(
                @intCast(index),
                leaf.descriptor.leaf_air_artifact_digest,
            ),
        )) return error.PreparedSessionMutated;
    }
}

fn powPrefix(session_digest: Digest) Blake2sChannel {
    var channel = Blake2sChannel{};
    channel.mixU32s(&joint_pow_domain_words);
    var words: [8]u32 = undefined;
    digestToWords(&words, session_digest);
    channel.mixU32s(&words);
    return channel;
}

fn challengeEql(lhs: ChallengeContextV1, rhs: ChallengeContextV1) bool {
    return aggregation_hash.eql(lhs.session_digest, rhs.session_digest) and
        aggregation_hash.eql(
            lhs.challenge_context_digest,
            rhs.challenge_context_digest,
        ) and
        aggregation_types.SecureFelt.eql(lhs.z, rhs.z) and
        aggregation_types.SecureFelt.eql(lhs.alpha, rhs.alpha);
}

fn appendDigest(
    destination: []u32,
    cursor: *usize,
    digest: Digest,
) void {
    var words: [8]u32 = undefined;
    digestToWords(&words, digest);
    appendWords(destination, cursor, &words);
}

fn digestToWords(destination: *[8]u32, digest: Digest) void {
    inline for (0..destination.len) |index| {
        const offset = index * @sizeOf(u32);
        destination[index] = std.mem.readInt(
            u32,
            digest[offset..][0..@sizeOf(u32)],
            .little,
        );
    }
}

fn appendU64(destination: []u32, cursor: *usize, value: u64) void {
    destination[cursor.*] = @truncate(value);
    destination[cursor.* + 1] = @truncate(value >> 32);
    cursor.* += 2;
}

fn appendWords(
    destination: []u32,
    cursor: *usize,
    source: []const u32,
) void {
    @memcpy(destination[cursor.*..][0..source.len], source);
    cursor.* += source.len;
}
