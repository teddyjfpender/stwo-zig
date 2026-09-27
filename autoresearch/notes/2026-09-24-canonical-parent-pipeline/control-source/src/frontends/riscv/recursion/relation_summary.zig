//! Shadow-only, session-bound cross-proof relation summaries for R-007.
//!
//! This codec authenticates the native data boundary a future recursive
//! verifier must constrain. It does not verify either leaf proof and it is not
//! wired into the production prover or verifier. `PairAuthorityV1` must be
//! constructed from independently verified statement, proof-byte, and
//! transcript identities; accepting identities supplied beside a proof would
//! leave the summary detached.

const std = @import("std");
const aggregation_hash = @import("../aggregation/hash.zig");
const aggregation_types = @import("../aggregation/types.zig");

pub const NATIVE_REFERENCE_ONLY = true;
pub const RECURSIVE_PROOF_VERIFICATION = false;
pub const PRODUCTION_ACTIVATION = false;

pub const Digest = [32]u8;
pub const SecureFelt = aggregation_types.SecureFelt;

pub const MAGIC = [8]u8{ 'S', 'T', 'W', 'R', 'L', 'S', 0, 0 };
pub const FORMAT_VERSION: u16 = 1;
pub const KNOWN_FLAGS: u16 = 0;
pub const CHILD_COUNT: u8 = 2;
pub const RELATION_TOTAL_COUNT: u8 = 1;
pub const MAX_PAIR_INDEX: u32 = aggregation_types.MAX_LEAVES / CHILD_COUNT - 1;

pub const RELATION_SCHEMA_ID: u32 = aggregation_types.RELATION_SCHEMA_ID;
pub const RELATION_SCHEMA_VERSION: u16 =
    aggregation_types.RELATION_SCHEMA_VERSION;
pub const RELATION_ARITY: u16 = aggregation_types.RELATION_ARITY;
pub const M31_MODULUS: u32 = aggregation_types.M31_MODULUS;

pub const RELATION_NAME = "stwo.riscv.guest_poseidon2_io";
pub const RELATION_DOMAIN_DIGEST_DOMAIN =
    "stwo-zig/recursion/relation-domain/v1\x00";
pub const LEAF_DIGEST_DOMAIN =
    "stwo-zig/recursion/leaf-relation-summary/v1\x00";
pub const PAIR_DIGEST_DOMAIN =
    "stwo-zig/recursion/pair-relation-summary/v1\x00";

pub const HEADER_ENCODED_LEN: usize = 16;
pub const RELATION_TOTAL_ENCODED_LEN: usize = 32;
pub const LEAF_RECORD_ENCODED_LEN: usize = 268;
pub const PAIR_ENCODED_LEN: usize =
    HEADER_ENCODED_LEN + CHILD_COUNT * LEAF_RECORD_ENCODED_LEN;

pub const HeaderOffset = struct {
    pub const magic: usize = 0;
    pub const version: usize = 8;
    pub const flags: usize = 10;
    pub const child_count: usize = 12;
    pub const relation_total_count: usize = 13;
    pub const reserved: usize = 14;
};

pub const LeafOffset = struct {
    pub const session_digest: usize = 0;
    pub const challenge_context_digest: usize = 32;
    pub const relation_domain_digest: usize = 64;
    pub const statement_digest: usize = 96;
    pub const proof_digest: usize = 128;
    pub const transcript_digest: usize = 160;
    pub const call_commitment: usize = 192;
    pub const leaf_index: usize = 224;
    pub const pair_index: usize = 228;
    pub const child_position: usize = 232;
    pub const role: usize = 233;
    pub const reserved: usize = 234;
    pub const relation_total: usize = 236;
};

pub const RelationOffset = struct {
    pub const schema_id: usize = 0;
    pub const schema_version: usize = 4;
    pub const arity: usize = 6;
    pub const event_count: usize = 8;
    pub const signed_total: usize = 16;
};

pub const ChildPosition = enum(u8) {
    left = 0,
    right = 1,
};

pub const LeafRole = enum(u8) {
    core_component = 1,
    poseidon2_precompile = 2,
};

/// One ordered relation total. V1 deliberately admits only the guest
/// Poseidon2 relation fixed by ADR-0030; a general relation registry is a new
/// format, not an extension through spare array capacity.
pub const RelationTotalV1 = struct {
    schema_id: u32 = RELATION_SCHEMA_ID,
    schema_version: u16 = RELATION_SCHEMA_VERSION,
    arity: u16 = RELATION_ARITY,
    event_count: u64,
    signed_total: SecureFelt,
};

pub const LeafRelationSummaryV1 = struct {
    session_digest: Digest,
    challenge_context_digest: Digest,
    relation_domain_digest: Digest,
    leaf_statement_digest: Digest,
    leaf_proof_digest: Digest,
    leaf_transcript_digest: Digest,
    public_call_commitment: Digest,
    leaf_index: u32,
    pair_index: u32,
    child_position: ChildPosition,
    role: LeafRole,
    reserved: u16 = 0,
    relation_totals: [RELATION_TOTAL_COUNT]RelationTotalV1,
};

pub const PairRelationSummaryV1 = struct {
    children: [CHILD_COUNT]LeafRelationSummaryV1,
};

/// Verifier-owned identity for one accepted leaf. The proof digest is SHA-256
/// of canonical proof bytes in the current native evidence path; the statement
/// and transcript digests are the existing 32-byte statement and replayed
/// channel identities. The codec treats all three as opaque protocol values.
pub const LeafIdentityV1 = struct {
    statement_digest: Digest,
    proof_digest: Digest,
    transcript_digest: Digest,
};

/// External authority reconstructed from an admitted session manifest and two
/// independently verified leaves. This is intentionally not serialized inside
/// the summary: self-authenticating expected values would provide no binding.
pub const PairAuthorityV1 = struct {
    session_digest: Digest,
    challenge_context_digest: Digest,
    relation_domain_digest: Digest,
    pair_index: u32,
    public_call_commitment: Digest,
    event_count: u64,
    children: [CHILD_COUNT]LeafIdentityV1,

    pub fn validate(self: PairAuthorityV1) Error!void {
        try requireDigest(self.session_digest);
        try requireDigest(self.challenge_context_digest);
        try requireDigest(self.relation_domain_digest);
        try requireDigest(self.public_call_commitment);
        if (!digestEql(
            self.relation_domain_digest,
            canonicalRelationDomainDigest(),
        )) return error.RelationDomainMismatch;
        try validatePairIndex(self.pair_index);
        try validateEventCount(self.event_count);
        try validateCallCommitment(
            self.public_call_commitment,
            self.event_count,
        );
        for (self.children) |identity| {
            try requireDigest(identity.statement_digest);
            try requireDigest(identity.proof_digest);
            try requireDigest(identity.transcript_digest);
        }
        if (sameLeafIdentity(self.children[0], self.children[1]))
            return error.DuplicateChildIdentity;
    }
};

pub const Error = error{
    AuthorityCallCommitmentMismatch,
    AuthorityChallengeContextMismatch,
    AuthorityCountMismatch,
    AuthorityPairIndexMismatch,
    AuthorityRelationDomainMismatch,
    AuthoritySessionMismatch,
    BufferTooSmall,
    CallCommitmentMismatch,
    CallCountOutOfRange,
    ChallengeContextMismatch,
    ChildIndexMismatch,
    ChildIndexOverflow,
    ChildRelationCountMismatch,
    ChildOrderMismatch,
    DuplicateChildIdentity,
    EmptyCommitmentForNonEmptyCalls,
    IncorrectBufferLength,
    InvalidChildCount,
    InvalidLength,
    InvalidMagic,
    InvalidRelationCount,
    NonCanonicalEmptyCallCommitment,
    NonCanonicalM31,
    NonZeroEmptyRelationTotal,
    NonZeroReserved,
    PairIndexMismatch,
    ProofIdentityMismatch,
    RelationArityMismatch,
    RelationDomainMismatch,
    RelationNotClosed,
    RelationSchemaMismatch,
    RelationVersionMismatch,
    SessionMismatch,
    StatementIdentityMismatch,
    TranscriptIdentityMismatch,
    UnknownChildPosition,
    UnknownFlags,
    UnknownLeafRole,
    UnsupportedVersion,
    ZeroDigest,
};

pub const AllocationError = std.mem.Allocator.Error || Error;

pub fn canonicalRelationDomainDigest() Digest {
    var sink = aggregation_hash.HashSink.init(RELATION_DOMAIN_DIGEST_DOMAIN);
    sink.writeAll(RELATION_NAME) catch unreachable;
    writeU32(&sink, RELATION_SCHEMA_ID) catch unreachable;
    writeU16(&sink, RELATION_SCHEMA_VERSION) catch unreachable;
    writeU16(&sink, RELATION_ARITY) catch unreachable;
    return sink.finalize();
}

pub fn validatePair(
    authority: PairAuthorityV1,
    summary: PairRelationSummaryV1,
) Error!void {
    try authority.validate();
    try validateWire(summary);
    const left = summary.children[0];
    if (!digestEql(left.session_digest, authority.session_digest))
        return error.AuthoritySessionMismatch;
    if (!digestEql(
        left.challenge_context_digest,
        authority.challenge_context_digest,
    )) return error.AuthorityChallengeContextMismatch;
    if (!digestEql(
        left.relation_domain_digest,
        authority.relation_domain_digest,
    )) return error.AuthorityRelationDomainMismatch;
    if (left.pair_index != authority.pair_index)
        return error.AuthorityPairIndexMismatch;
    if (!digestEql(
        left.public_call_commitment,
        authority.public_call_commitment,
    )) return error.AuthorityCallCommitmentMismatch;
    if (left.relation_totals[0].event_count != authority.event_count)
        return error.AuthorityCountMismatch;

    for (summary.children, authority.children) |child, identity| {
        if (!digestEql(child.leaf_statement_digest, identity.statement_digest))
            return error.StatementIdentityMismatch;
        if (!digestEql(child.leaf_proof_digest, identity.proof_digest))
            return error.ProofIdentityMismatch;
        if (!digestEql(child.leaf_transcript_digest, identity.transcript_digest))
            return error.TranscriptIdentityMismatch;
    }
}

pub fn encodePairInto(
    summary: PairRelationSummaryV1,
    destination: []u8,
) Error!usize {
    if (destination.len != PAIR_ENCODED_LEN)
        return error.IncorrectBufferLength;
    // Fail before the first store so malformed summaries cannot partially
    // overwrite caller-owned output.
    try validateWire(summary);
    var sink = SliceSink{ .destination = destination };
    try writePair(&sink, summary);
    std.debug.assert(sink.offset == PAIR_ENCODED_LEN);
    return sink.offset;
}

/// Exactly one allocation after validation; ownership transfers to the caller.
pub fn encodePairAlloc(
    allocator: std.mem.Allocator,
    summary: PairRelationSummaryV1,
) AllocationError![]u8 {
    try validateWire(summary);
    const bytes = try allocator.alloc(u8, PAIR_ENCODED_LEN);
    errdefer allocator.free(bytes);
    _ = try encodePairInto(summary, bytes);
    return bytes;
}

pub fn decodePair(bytes: []const u8) Error!PairRelationSummaryV1 {
    if (bytes.len != PAIR_ENCODED_LEN) return error.InvalidLength;
    var reader = Reader{ .bytes = bytes };
    const magic = try reader.take(MAGIC.len);
    if (!std.mem.eql(u8, magic, &MAGIC)) return error.InvalidMagic;
    if (try reader.readU16() != FORMAT_VERSION) return error.UnsupportedVersion;
    if (try reader.readU16() != KNOWN_FLAGS) return error.UnknownFlags;
    if (try reader.readU8() != CHILD_COUNT) return error.InvalidChildCount;
    if (try reader.readU8() != RELATION_TOTAL_COUNT)
        return error.InvalidRelationCount;
    if (try reader.readU16() != 0) return error.NonZeroReserved;

    var result: PairRelationSummaryV1 = undefined;
    for (&result.children) |*child| child.* = try readLeaf(&reader);
    if (reader.offset != bytes.len) return error.InvalidLength;
    try validateWire(result);
    return result;
}

/// Blake2s-256 over the exact canonical pair encoder with a distinct domain.
pub fn pairDigest(summary: PairRelationSummaryV1) Error!Digest {
    try validateWire(summary);
    var sink = aggregation_hash.HashSink.init(PAIR_DIGEST_DOMAIN);
    try writePair(&sink, summary);
    return sink.finalize();
}

/// Child identity used by a recursive parent; left/right position remains in
/// the preimage and therefore swapping children changes both leaf digests.
pub fn leafDigest(summary: LeafRelationSummaryV1) Error!Digest {
    try validateLeaf(summary);
    var sink = aggregation_hash.HashSink.init(LEAF_DIGEST_DOMAIN);
    try writeLeaf(&sink, summary);
    return sink.finalize();
}

fn validateWire(summary: PairRelationSummaryV1) Error!void {
    for (summary.children) |child| try validateLeaf(child);
    const left = summary.children[0];
    const right = summary.children[1];
    if (left.child_position != .left or left.role != .core_component or
        right.child_position != .right or
        right.role != .poseidon2_precompile)
    {
        return error.ChildOrderMismatch;
    }
    if (left.pair_index != right.pair_index) return error.PairIndexMismatch;
    const first_index = pairFirstLeaf(left.pair_index) catch
        return error.ChildIndexOverflow;
    if (left.leaf_index != first_index or right.leaf_index != first_index + 1)
        return error.ChildIndexMismatch;
    if (!digestEql(left.session_digest, right.session_digest))
        return error.SessionMismatch;
    if (!digestEql(
        left.challenge_context_digest,
        right.challenge_context_digest,
    )) return error.ChallengeContextMismatch;
    if (!digestEql(left.relation_domain_digest, right.relation_domain_digest))
        return error.RelationDomainMismatch;
    if (!digestEql(left.public_call_commitment, right.public_call_commitment))
        return error.CallCommitmentMismatch;
    if (left.relation_totals[0].event_count !=
        right.relation_totals[0].event_count)
    {
        return error.ChildRelationCountMismatch;
    }
    if (sameLeafIdentity(
        .{
            .statement_digest = left.leaf_statement_digest,
            .proof_digest = left.leaf_proof_digest,
            .transcript_digest = left.leaf_transcript_digest,
        },
        .{
            .statement_digest = right.leaf_statement_digest,
            .proof_digest = right.leaf_proof_digest,
            .transcript_digest = right.leaf_transcript_digest,
        },
    )) return error.DuplicateChildIdentity;
    if (!left.relation_totals[0].signed_total
        .add(right.relation_totals[0].signed_total).isZero())
    {
        return error.RelationNotClosed;
    }
}

fn validateLeaf(summary: LeafRelationSummaryV1) Error!void {
    try requireDigest(summary.session_digest);
    try requireDigest(summary.challenge_context_digest);
    try requireDigest(summary.relation_domain_digest);
    try requireDigest(summary.leaf_statement_digest);
    try requireDigest(summary.leaf_proof_digest);
    try requireDigest(summary.leaf_transcript_digest);
    try requireDigest(summary.public_call_commitment);
    if (!digestEql(
        summary.relation_domain_digest,
        canonicalRelationDomainDigest(),
    )) return error.RelationDomainMismatch;
    if (summary.reserved != 0) return error.NonZeroReserved;
    try validatePairIndex(summary.pair_index);
    const expected = pairFirstLeaf(summary.pair_index) catch
        return error.ChildIndexOverflow;
    const position: u32 = @intFromEnum(summary.child_position);
    if (summary.leaf_index != expected + position)
        return error.ChildIndexMismatch;
    const total = summary.relation_totals[0];
    if (total.schema_id != RELATION_SCHEMA_ID)
        return error.RelationSchemaMismatch;
    if (total.schema_version != RELATION_SCHEMA_VERSION)
        return error.RelationVersionMismatch;
    if (total.arity != RELATION_ARITY) return error.RelationArityMismatch;
    try validateEventCount(total.event_count);
    try total.signed_total.validate();
    try validateCallCommitment(
        summary.public_call_commitment,
        total.event_count,
    );
    if (total.event_count == 0 and !total.signed_total.isZero())
        return error.NonZeroEmptyRelationTotal;
}

fn validatePairIndex(pair_index: u32) Error!void {
    if (pair_index > MAX_PAIR_INDEX) return error.ChildIndexOverflow;
}

fn pairFirstLeaf(pair_index: u32) error{ChildIndexOverflow}!u32 {
    return std.math.mul(u32, pair_index, CHILD_COUNT) catch
        return error.ChildIndexOverflow;
}

fn validateEventCount(count: u64) Error!void {
    const doubled = std.math.mul(u64, count, 2) catch
        return error.CallCountOutOfRange;
    if (doubled >= M31_MODULUS) return error.CallCountOutOfRange;
}

fn validateCallCommitment(commitment: Digest, count: u64) Error!void {
    const empty = aggregation_hash.emptyCallCommitment();
    if (count == 0) {
        if (!digestEql(commitment, empty))
            return error.NonCanonicalEmptyCallCommitment;
    } else if (digestEql(commitment, empty)) {
        return error.EmptyCommitmentForNonEmptyCalls;
    }
}

fn requireDigest(digest: Digest) Error!void {
    if (aggregation_hash.isZero(digest)) return error.ZeroDigest;
}

fn sameLeafIdentity(left: LeafIdentityV1, right: LeafIdentityV1) bool {
    return digestEql(left.statement_digest, right.statement_digest) and
        digestEql(left.proof_digest, right.proof_digest) and
        digestEql(left.transcript_digest, right.transcript_digest);
}

fn digestEql(left: Digest, right: Digest) bool {
    return aggregation_hash.eql(left, right);
}

fn writePair(sink: anytype, summary: PairRelationSummaryV1) !void {
    try sink.writeAll(&MAGIC);
    try writeU16(sink, FORMAT_VERSION);
    try writeU16(sink, KNOWN_FLAGS);
    try sink.writeAll(&.{CHILD_COUNT});
    try sink.writeAll(&.{RELATION_TOTAL_COUNT});
    try writeU16(sink, 0);
    for (summary.children) |child| try writeLeaf(sink, child);
}

fn writeLeaf(sink: anytype, summary: LeafRelationSummaryV1) !void {
    try sink.writeAll(&summary.session_digest);
    try sink.writeAll(&summary.challenge_context_digest);
    try sink.writeAll(&summary.relation_domain_digest);
    try sink.writeAll(&summary.leaf_statement_digest);
    try sink.writeAll(&summary.leaf_proof_digest);
    try sink.writeAll(&summary.leaf_transcript_digest);
    try sink.writeAll(&summary.public_call_commitment);
    try writeU32(sink, summary.leaf_index);
    try writeU32(sink, summary.pair_index);
    try sink.writeAll(&.{@intFromEnum(summary.child_position)});
    try sink.writeAll(&.{@intFromEnum(summary.role)});
    try writeU16(sink, summary.reserved);
    for (summary.relation_totals) |total| try writeRelationTotal(sink, total);
}

fn writeRelationTotal(sink: anytype, total: RelationTotalV1) !void {
    try writeU32(sink, total.schema_id);
    try writeU16(sink, total.schema_version);
    try writeU16(sink, total.arity);
    try writeU64(sink, total.event_count);
    for (total.signed_total.limbs) |limb| try writeU32(sink, limb);
}

fn readLeaf(reader: *Reader) Error!LeafRelationSummaryV1 {
    const session_digest = try reader.readDigest();
    const challenge_context_digest = try reader.readDigest();
    const relation_domain_digest = try reader.readDigest();
    const leaf_statement_digest = try reader.readDigest();
    const leaf_proof_digest = try reader.readDigest();
    const leaf_transcript_digest = try reader.readDigest();
    const public_call_commitment = try reader.readDigest();
    const leaf_index = try reader.readU32();
    const pair_index = try reader.readU32();
    const child_position = std.meta.intToEnum(
        ChildPosition,
        try reader.readU8(),
    ) catch return error.UnknownChildPosition;
    const role = std.meta.intToEnum(
        LeafRole,
        try reader.readU8(),
    ) catch return error.UnknownLeafRole;
    const reserved = try reader.readU16();
    var relation_totals: [RELATION_TOTAL_COUNT]RelationTotalV1 = undefined;
    for (&relation_totals) |*total| total.* = try readRelationTotal(reader);
    return .{
        .session_digest = session_digest,
        .challenge_context_digest = challenge_context_digest,
        .relation_domain_digest = relation_domain_digest,
        .leaf_statement_digest = leaf_statement_digest,
        .leaf_proof_digest = leaf_proof_digest,
        .leaf_transcript_digest = leaf_transcript_digest,
        .public_call_commitment = public_call_commitment,
        .leaf_index = leaf_index,
        .pair_index = pair_index,
        .child_position = child_position,
        .role = role,
        .reserved = reserved,
        .relation_totals = relation_totals,
    };
}

fn readRelationTotal(reader: *Reader) Error!RelationTotalV1 {
    const schema_id = try reader.readU32();
    const schema_version = try reader.readU16();
    const arity = try reader.readU16();
    const event_count = try reader.readU64();
    var limbs: [4]u32 = undefined;
    for (&limbs) |*limb| limb.* = try reader.readU32();
    return .{
        .schema_id = schema_id,
        .schema_version = schema_version,
        .arity = arity,
        .event_count = event_count,
        .signed_total = .{ .limbs = limbs },
    };
}

const SliceSink = struct {
    destination: []u8,
    offset: usize = 0,

    fn writeAll(self: *SliceSink, bytes: []const u8) Error!void {
        const end = std.math.add(usize, self.offset, bytes.len) catch
            return error.BufferTooSmall;
        if (end > self.destination.len) return error.BufferTooSmall;
        @memcpy(self.destination[self.offset..end], bytes);
        self.offset = end;
    }
};

const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn take(self: *Reader, len: usize) Error![]const u8 {
        const end = std.math.add(usize, self.offset, len) catch
            return error.InvalidLength;
        if (end > self.bytes.len) return error.InvalidLength;
        defer self.offset = end;
        return self.bytes[self.offset..end];
    }

    fn readU8(self: *Reader) Error!u8 {
        return (try self.take(1))[0];
    }

    fn readU16(self: *Reader) Error!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .little);
    }

    fn readU32(self: *Reader) Error!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }

    fn readU64(self: *Reader) Error!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }

    fn readDigest(self: *Reader) Error!Digest {
        var result: Digest = undefined;
        @memcpy(&result, try self.take(result.len));
        return result;
    }
};

fn writeU16(sink: anytype, value: u16) !void {
    var bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &bytes, value, .little);
    try sink.writeAll(&bytes);
}

fn writeU32(sink: anytype, value: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    try sink.writeAll(&bytes);
}

fn writeU64(sink: anytype, value: u64) !void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    try sink.writeAll(&bytes);
}

comptime {
    if (RELATION_TOTAL_ENCODED_LEN != 4 + 2 + 2 + 8 + 4 * 4)
        @compileError("R-007 relation-total wire size drifted");
    if (LEAF_RECORD_ENCODED_LEN != 7 * @sizeOf(Digest) + 4 + 4 + 1 + 1 + 2 +
        RELATION_TOTAL_COUNT * RELATION_TOTAL_ENCODED_LEN)
    {
        @compileError("R-007 leaf-summary wire size drifted");
    }
    if (PAIR_ENCODED_LEN != 552)
        @compileError("R-007 pair-summary wire size drifted");
}
