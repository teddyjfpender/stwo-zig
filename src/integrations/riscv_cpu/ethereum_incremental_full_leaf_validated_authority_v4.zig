//! Process-local validated authority for one full Ethereum V4 proof boundary.
//!
//! This owner joins the copied SegmentV2 lease to the independently opened
//! STWESG31, STWIMR04/STWIMT04, and STWIPR04 authorities.  It is deliberately
//! nonserializable.  The retained SHA identities prove custody relationships
//! only; all semantic admission occurs in `validateOwnedBoundary` before the
//! lease becomes observable.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_v4 = @import("ethereum_incremental_boundary_artifact_v4.zig");
const boundary_v4 = @import("ethereum_incremental_boundary_authority_v4.zig");
const capture_publication =
    @import("ethereum_incremental_capture_publication_v4.zig");
const lease_mod =
    @import("ethereum_incremental_full_leaf_validated_lease_v2.zig");
const profile_mod = @import("ethereum_incremental_full_leaf_profile_v4.zig");
const wire_publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");

const public_data = frontend.air.public_data;
const statement_v2 = frontend.air.statement_v2;
const ethereum_statement = frontend.air.guest_precompile.ethereum_statement;
const source_v3 = frontend.recursion.segment_leaf_local_authority_v3;
const witness_v3 = frontend.prover_mod.incremental_commitment_witness_v3;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const SERIALIZABLE = false;
pub const DIGEST_IS_ADMISSION = false;
pub const VALIDATED_TRANSCRIPT_FAST_PATH_AVAILABLE = true;
pub const VALIDATED_CODEC_FAST_PATH_AVAILABLE = true;
pub const VALIDATED_ORCHESTRATION_FAST_PATH_AVAILABLE = true;
pub const VALIDATED_COLD_VERIFIER_FAST_PATH_AVAILABLE = true;

const IDENTITY_DOMAIN =
    "stwo-zig/ethereum-incremental-full-leaf-validated-authority/v4\x00";
const CUSTODY_DOMAIN =
    "stwo-zig/ethereum-incremental-full-leaf-retained-custody/v4\x00";

pub const ValidationCountersV2 = lease_mod.ValidationCountersV2;
pub const CounterSnapshotV2 = lease_mod.CounterSnapshotV2;
pub const ValidatedLeaseV2 = lease_mod.ValidatedLeaseV2;

/// Borrowed durable/opened authorities required at the trust boundary. The
/// caller keeps every owner alive until `initOwned` returns; the returned
/// authority retains value identities and its own copied statement/public IO.
pub const RetainedCustodyV4 = struct {
    source_identity: capture_publication.ArtifactIdentityV4,
    source_metadata: *const source_v3.MetadataV3,
    capture: capture_publication.CommittedSegmentV4,
    public_wire: wire_publication.CommittedSegmentV4,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
    boundary_artifact: *const artifact_v4.OwnedArtifactV4,
    cold_boundary: *const artifact_v4.ColdReconstructionV4,
    boundary_witness: *const witness_v3.BoundaryWitnessV3,

    pub fn retainedSnapshots(
        self: RetainedCustodyV4,
    ) frontend.air.public_data_v2.PublicDataV2.RetainedSnapshots {
        return .{
            .entry = .{
                .id = self.source_metadata.entry.snapshot_id,
                .count = self.source_metadata.entry.snapshot_count,
                .root = self.source_metadata.entry.continuation_root,
            },
            .exit = .{
                .id = self.source_metadata.exit.snapshot_id,
                .count = self.source_metadata.exit.snapshot_count,
                .root = self.source_metadata.exit.continuation_root,
            },
        };
    }
};

pub const ValidatedAuthorityV4 = struct {
    lease: ValidatedLeaseV2,
    extension: ethereum_statement.Statement,
    profile: profile_mod.AuthorityV4,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
    custody_identity_sha256: [32]u8,
    identity_sha256: [32]u8,

    const Self = @This();

    pub fn initOwned(
        allocator: std.mem.Allocator,
        source_statement: *const statement_v2.RiscVStatementV2,
        source_role_public: *const public_data.PublicData,
        extension: *const ethereum_statement.Statement,
        profile: *const profile_mod.AuthorityV4,
        custody: RetainedCustodyV4,
        counters: ?*ValidationCountersV2,
    ) !Self {
        const context = ValidationContextV4{
            .extension = extension,
            .profile = profile,
            .custody = custody,
        };
        var lease = try ValidatedLeaseV2.initOwned(
            allocator,
            source_statement,
            source_role_public,
            custody.retainedSnapshots(),
            context,
            counters,
        );
        errdefer lease.deinit();
        var owned_public_authority = custody.public_authority;
        owned_public_authority.public_data = lease.rolePublic();
        var result = Self{
            .lease = lease,
            .extension = extension.*,
            .profile = profile.*,
            .public_authority = owned_public_authority,
            .custody_identity_sha256 = custodyIdentity(custody),
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = authorityIdentity(&result);
        try result.validateBorrowed();
        return result;
    }

    pub fn deinit(self: *Self) void {
        self.lease.deinit();
        self.* = undefined;
    }

    /// Constant-size process-local check. Full statement/profile/custody
    /// validation is intentionally not repeated inside proof stages.
    pub fn validateBorrowed(self: *const Self) !void {
        try self.lease.validateBorrowed();
        if (self.public_authority.public_data != self.lease.rolePublic() or
            !std.mem.eql(
                u8,
                &self.profile.identity_sha256,
                &self.lease.validation_binding_sha256,
            ) or
            std.mem.allEqual(u8, &self.custody_identity_sha256, 0) or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &authorityIdentity(self),
            ))
        {
            return error.InvalidIncrementalFullLeafValidatedAuthorityV4;
        }
    }

    pub fn statement(
        self: *const Self,
    ) *const statement_v2.RiscVStatementV2 {
        return self.lease.statement();
    }

    pub fn rolePublic(self: *const Self) *const public_data.PublicData {
        return self.lease.rolePublic();
    }

    pub fn profileAuthority(self: *const Self) *const profile_mod.AuthorityV4 {
        return &self.profile;
    }
};

const ValidationContextV4 = struct {
    extension: *const ethereum_statement.Statement,
    profile: *const profile_mod.AuthorityV4,
    custody: RetainedCustodyV4,

    pub fn validateOwnedBoundary(
        self: ValidationContextV4,
        statement: *const statement_v2.RiscVStatementV2,
        role_public: *const public_data.PublicData,
    ) ![32]u8 {
        try validateCustody(
            self.custody,
            statement,
            role_public,
            self.extension,
            self.profile,
        );
        // The statement owns the opaque frontend lease here. Profile,
        // transcript, codec, and orchestration validation all take the same
        // cached authenticated view without repeating canonical-wire work.
        try self.profile.validateAgainstStatement(
            statement,
            self.extension,
            role_public,
        );
        return self.profile.identity_sha256;
    }
};

fn validateCustody(
    custody: RetainedCustodyV4,
    statement: *const statement_v2.RiscVStatementV2,
    role_public: *const public_data.PublicData,
    extension: *const ethereum_statement.Statement,
    profile: *const profile_mod.AuthorityV4,
) !void {
    try custody.source_identity.validate(false);
    try custody.source_metadata.validate();
    try custody.capture.validate();
    try custody.public_wire.validate();
    try custody.public_authority.validate();
    try custody.boundary_artifact.validateCanonical(
        artifact_v4.default_limits,
    );

    const source = custody.source_metadata;
    const capture = custody.capture.segment;
    const wire = custody.public_wire.segment;
    const artifact = custody.boundary_artifact;
    const cold = custody.cold_boundary;
    const boundary = custody.boundary_witness;
    const roots = boundary.roots();
    const expected_boundary_rows = std.math.mul(
        usize,
        cold.transitions.len,
        2,
    ) catch return error.InvalidIncrementalFullLeafValidatedCustodyV4;
    if (custody.public_authority.public_data != role_public or
        !std.meta.eql(custody.capture.reference, wire.v4_segment_reference) or
        !std.meta.eql(capture.source, custody.source_identity) or
        !std.meta.eql(wire.source, custody.source_identity) or
        !std.mem.eql(
            u8,
            &capture.journal_record_sha256,
            &wire.journal_record_sha256,
        ) or
        capture.segment_index != source.segment_index or
        capture.segment_count != source.segment_count or
        wire.coordinate.segment_index != source.segment_index or
        wire.coordinate.segment_count != source.segment_count or
        artifact.coordinate.segment_index != source.segment_index or
        artifact.coordinate.segment_count != source.segment_count or
        profile.coordinate.segment_index != source.segment_index or
        profile.coordinate.segment_count != source.segment_count or
        capture.entry_root != source.entry.continuation_root or
        capture.exit_root != source.exit.continuation_root or
        artifact.continuation_roots.entry != source.entry.continuation_root or
        artifact.continuation_roots.exit != source.exit.continuation_root or
        !std.meta.eql(artifact.segment_public_wire_id, wire.wire_id) or
        !std.meta.eql(statement.public_data.wireId(), wire.wire_id) or
        !std.meta.eql(profile.segment_public_wire_id, wire.wire_id) or
        !std.mem.eql(
            u8,
            &artifact.content_sha256,
            &capture.artifact_content_sha256,
        ) or
        !std.mem.eql(
            u8,
            &artifact.transition_v2.content_sha256,
            &capture.transition_v2_content_sha256,
        ) or
        !std.mem.eql(
            u8,
            &profile.boundary_artifact_content_sha256,
            &artifact.content_sha256,
        ) or
        !std.meta.eql(cold.coordinate, artifact.coordinate) or
        !std.meta.eql(cold.segment_public_wire_id, wire.wire_id) or
        !std.mem.eql(
            u8,
            &cold.artifact_content_sha256,
            &artifact.content_sha256,
        ) or
        cold.sources.len != artifact.transition_v2.authority.touched_words.len or
        cold.transitions.len != cold.sources.len or
        roots.entry != artifact.continuation_roots.entry or
        roots.exit != artifact.continuation_roots.exit or
        boundary.rows().len != expected_boundary_rows or
        !std.meta.eql(profile.ethereum, extension.*))
    {
        return error.InvalidIncrementalFullLeafValidatedCustodyV4;
    }
}

fn custodyIdentity(value: RetainedCustodyV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CUSTODY_DOMAIN);
    hashArtifactIdentity(&hash, value.source_identity);
    hashArtifactIdentity(&hash, value.capture.reference);
    hashArtifactIdentity(&hash, value.public_wire.reference);
    hashArtifactIdentity(&hash, value.capture.segment.artifact);
    hashArtifactIdentity(&hash, value.public_wire.segment.wire_artifact);
    hash.update(&value.capture.segment.artifact_content_sha256);
    hash.update(&value.capture.segment.transition_v2_content_sha256);
    hash.update(&value.capture.segment.journal_record_sha256);
    hash.update(&value.public_wire.segment.journal_record_sha256);
    hash.update(&value.boundary_artifact.content_sha256);
    hashInt(&hash, u32, value.source_metadata.segment_index);
    hashInt(&hash, u32, value.source_metadata.segment_count);
    hashInt(&hash, u32, value.source_metadata.entry.continuation_root);
    hashInt(&hash, u32, value.source_metadata.exit.continuation_root);
    return hash.finalResult();
}

fn authorityIdentity(value: *const ValidatedAuthorityV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&value.lease.lease_identity_sha256);
    hash.update(&value.profile.identity_sha256);
    hash.update(&value.profile.ethereum_identity_sha256);
    hash.update(&value.profile.public_boundary_identity_sha256);
    hash.update(&value.custody_identity_sha256);
    return hash.finalResult();
}

fn hashArtifactIdentity(
    hash: *std.crypto.hash.sha2.Sha256,
    value: capture_publication.ArtifactIdentityV4,
) void {
    hashInt(hash, u64, value.byte_count);
    hash.update(&value.sha256);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or SERIALIZABLE or
        DIGEST_IS_ADMISSION or !VALIDATED_TRANSCRIPT_FAST_PATH_AVAILABLE or
        !VALIDATED_CODEC_FAST_PATH_AVAILABLE or
        !VALIDATED_ORCHESTRATION_FAST_PATH_AVAILABLE or
        !VALIDATED_COLD_VERIFIER_FAST_PATH_AVAILABLE)
    {
        @compileError("validated full Ethereum V4 authority drifted");
    }
}
