//! Fixed recursive witness retained beside one verified SegmentV2 capture.
//!
//! The dynamic proof capture remains owned by the surrounding artifact.  This
//! sidecar is pointer-free: it copies only the verifier-rebuilt claims, the
//! exact transcript relation draws, and the two ordered Poseidon2 partials.
//! Production minting is intentionally private to the outer engine after
//! `verifyWithProofCapture` succeeds.  Consumers can validate the fixed value,
//! but this module exposes no constructor from detached proof material.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const publication_mod = @import("recursive_segment_v2_verified_publication.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const manifest_mod = recursion.air.segment_outer_adapter_manifest_v2;
const cohort_protocol = recursion.segment_outer_cohort_v2;
const outer_admission = recursion.outer_parent_child_admission;
const universal = recursion.air.universal_challenges;

pub const Digest = channel.Digest;
pub const Publication = publication_mod.VerifiedSegmentV2PublicationV1;
pub const OuterProofCapture = publication_mod.OuterProofCapture;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 3;
pub const TRANSCRIPT_PREFIX_FORMAT_VERSION: u16 = 1;
pub const OUTER_ADMISSION_FORMAT_VERSION: u16 = 2;
pub const OUTER_ADMISSION_SCHEMA_VERSION: u16 = 1;
pub const CLAIM_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const RELATION_DRAW_COUNT: usize = universal.DRAW_COUNT;
pub const POSEIDON2_PARTIAL_COUNT: usize = 2;
pub const POSEIDON2_ROSTER_ROW: usize = 34;

pub const RELATION_DRAWS_ID_DOMAIN: u32 = 0x5357_5244; // "SWRD"
pub const POSEIDON2_PARTIALS_ID_DOMAIN: u32 = 0x5357_5032; // "SWP2"
pub const WITNESS_ID_DOMAIN: u32 = 0x5357_4954; // "SWIT"
pub const TRANSCRIPT_PREFIX_ID_DOMAIN: u32 = 0x5357_5450; // "SWTP"
pub const OUTER_ADMISSION_ID_DOMAIN: u32 = 0x5357_4f41; // "SWOA"
const SHA_ID_DOMAIN: u32 = 0x5357_5348; // "SWSH"

pub const POINTER_FREE = true;
pub const HEAP_ALLOCATIONS_PER_VALIDATE: usize = 0;
pub const RETAINED_PROOF_BYTES: usize = 0;
pub const PUBLIC_MINT_CONSTRUCTOR_AVAILABLE = false;
pub const CAPTURE_ID_HASHES_PER_PREFLIGHT: usize = 1;

pub const Error = publication_mod.Error || manifest_mod.Error ||
    cohort_protocol.Error || outer_admission.Error || universal.Error || error{
    ClaimSealMismatch,
    CaptureIdentityMismatch,
    InvalidCount,
    ManifestMismatch,
    NonCanonicalField,
    Poseidon2PartialMismatch,
    Poseidon2PartialsIdentityMismatch,
    PublicationLinkMismatch,
    RelationDrawsIdentityMismatch,
    TranscriptPrefixBoundaryMismatch,
    TranscriptPrefixIdentityMismatch,
    InvalidTranscriptPrefix,
    InvalidOuterAdmissionReceipt,
    OuterAdmissionIdentityMismatch,
    UnsupportedFormat,
    WitnessIdentityMismatch,
};

/// Pointer-free sidecar minted inside the successful SegmentV2 outer
/// verifier transaction. Unlike frozen V1 admission, this retains all 39
/// component claims and cannot silently project the appended V2 rows away.
pub const OuterAdmissionReceiptV2 = struct {
    format_version: u16 = OUTER_ADMISSION_FORMAT_VERSION,
    schema_version: u16 = OUTER_ADMISSION_SCHEMA_VERSION,
    claim_count: u8 = CLAIM_COUNT,
    padding: [3]u8 = .{ 0, 0, 0 },
    proof_id: Digest,
    capture_id: Digest,
    component_log_sizes: [CLAIM_COUNT]u32,
    pre_core_channel: outer_admission.ChannelCheckpointV1,
    claimed_sums: [CLAIM_COUNT]QM31,
    verifier_input_boundary: QM31,
    wire_closure: [2]QM31,
    interaction_pow_nonce: u64 = 0,
    receipt_id: Digest,

    pub fn validateAgainst(
        self: *const OuterAdmissionReceiptV2,
        publication: *const Publication,
        manifest: *const manifest_mod.Manifest,
        claimed_sums: *const [CLAIM_COUNT]QM31,
        transcript_prefix: *const TranscriptPrefixV1,
    ) Error!void {
        if (self.format_version != OUTER_ADMISSION_FORMAT_VERSION or
            self.schema_version != OUTER_ADMISSION_SCHEMA_VERSION or
            self.claim_count != CLAIM_COUNT or
            !std.mem.allEqual(u8, &self.padding, 0) or
            self.interaction_pow_nonce != 0 or
            !std.meta.eql(self.proof_id, publication.proof_id) or
            !std.meta.eql(self.capture_id, publication.capture_id) or
            !std.meta.eql(self.claimed_sums, claimed_sums.*))
        {
            return error.InvalidOuterAdmissionReceipt;
        }
        try self.pre_core_channel.validate();
        for (self.component_log_sizes, 0..) |actual, row| {
            const placement = manifest.placements[row] orelse
                return error.InvalidOuterAdmissionReceipt;
            if (actual != placement.geometry.log_size)
                return error.InvalidOuterAdmissionReceipt;
        }
        for (self.claimed_sums) |value| try requireCanonical(value);
        try requireCanonical(self.verifier_input_boundary);
        for (self.wire_closure) |value| try requireCanonical(value);
        if (!self.wire_closure[0].add(self.wire_closure[1]).isZero() or
            !self.wire_closure[1].eql(
                transcript_prefix.public_wire_boundary_claimed_sum,
            ))
        {
            return error.InvalidOuterAdmissionReceipt;
        }
        if (!std.meta.eql(
            self.receipt_id,
            outerAdmissionReceiptId(self, publication),
        )) return error.OuterAdmissionIdentityMismatch;
    }
};

/// Fixed verifier-local preimage for the SegmentV2 transcript frame between
/// Tree 1 and Tree 2. The trusted manifest and publication already retain the
/// aggregate manifest/plan/cohort seals; this value retains only the two
/// source-specific authorities, the exact core schedule, and the
/// relation-dependent public-wire boundary that cannot be inferred later.
pub const TranscriptPrefixV1 = struct {
    format_version: u16 = TRANSCRIPT_PREFIX_FORMAT_VERSION,
    schema_version: u16 = 1,
    padding: [4]u8 = .{ 0, 0, 0, 0 },

    noncore_authority_sha_id: [32]u8,
    core_authority_sha_id: [32]u8,
    core_layout_sha_id: [32]u8,
    core_call_buffer_sha_id: [32]u8,
    core_total_call_count: u32,
    public_wire_boundary_term_count: u32,
    public_wire_boundary_claimed_sum: QM31,
    public_wire_boundary_sha_id: [32]u8,
    transcript_prefix_id: Digest,

    pub fn init(
        noncore_authority_sha_id: [32]u8,
        core_authority_sha_id: [32]u8,
        core_layout_sha_id: [32]u8,
        core_call_buffer_sha_id: [32]u8,
        core_total_call_count: u32,
        public_wire_boundary: cohort_protocol.PublicWireBoundaryV2,
    ) Error!TranscriptPrefixV1 {
        try public_wire_boundary.validate();
        if (core_total_call_count == 0 or
            core_total_call_count >= m31.Modulus or
            public_wire_boundary.term_count >= m31.Modulus)
        {
            return error.InvalidTranscriptPrefix;
        }
        if (!std.mem.eql(
            u8,
            &core_authority_sha_id,
            &public_wire_boundary.source_authority_id,
        )) return error.TranscriptPrefixBoundaryMismatch;
        var result = TranscriptPrefixV1{
            .noncore_authority_sha_id = noncore_authority_sha_id,
            .core_authority_sha_id = core_authority_sha_id,
            .core_layout_sha_id = core_layout_sha_id,
            .core_call_buffer_sha_id = core_call_buffer_sha_id,
            .core_total_call_count = core_total_call_count,
            .public_wire_boundary_term_count = public_wire_boundary.term_count,
            .public_wire_boundary_claimed_sum = public_wire_boundary.claimed_sum,
            .public_wire_boundary_sha_id = public_wire_boundary.identity,
            .transcript_prefix_id = undefined,
        };
        result.transcript_prefix_id = try transcriptPrefixId(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const TranscriptPrefixV1) Error!void {
        if (self.format_version != TRANSCRIPT_PREFIX_FORMAT_VERSION or
            self.schema_version != 1 or
            !std.mem.allEqual(u8, &self.padding, 0) or
            self.core_total_call_count == 0 or
            self.core_total_call_count >= m31.Modulus or
            self.public_wire_boundary_term_count == 0 or
            self.public_wire_boundary_term_count >= m31.Modulus)
        {
            return error.InvalidTranscriptPrefix;
        }
        try requireSha(self.noncore_authority_sha_id);
        try requireSha(self.core_authority_sha_id);
        try requireSha(self.core_layout_sha_id);
        try requireSha(self.core_call_buffer_sha_id);
        try requireSha(self.public_wire_boundary_sha_id);
        try requireCanonical(self.public_wire_boundary_claimed_sum);
        const boundary = try cohort_protocol.PublicWireBoundaryV2.init(
            self.core_authority_sha_id,
            self.public_wire_boundary_term_count,
            self.public_wire_boundary_claimed_sum,
        );
        if (!std.mem.eql(
            u8,
            &boundary.identity,
            &self.public_wire_boundary_sha_id,
        )) return error.TranscriptPrefixBoundaryMismatch;
        if (!std.meta.eql(
            self.transcript_prefix_id,
            try transcriptPrefixId(self),
        )) return error.TranscriptPrefixIdentityMismatch;
    }
};

/// Complete artifact preflight. The capture is verifier-owned material, not
/// decoded proof bytes; its semantic identity is streamed exactly once.
pub fn preflight(
    capture: *const OuterProofCapture,
    publication: *const Publication,
    witness: *const RecursiveWitnessV1,
    manifest: *const manifest_mod.Manifest,
) Error!void {
    try publication.validate();
    try preflightAgainstValidatedPublication(
        capture,
        publication,
        witness,
        manifest,
    );
}

/// Requires `publication.validate()` (or the stricter temporal-child
/// admission built on it) to have succeeded in the caller.
pub fn preflightAgainstValidatedPublication(
    capture: *const OuterProofCapture,
    publication: *const Publication,
    witness: *const RecursiveWitnessV1,
    manifest: *const manifest_mod.Manifest,
) Error!void {
    try manifest.validate();
    try preflightAgainstValidatedPublicationAndManifest(
        capture,
        publication,
        witness,
        manifest,
    );
}

/// Requires both `publication.validate()` and `manifest.validate()` to have
/// succeeded in the caller. A temporal parent uses this form after validating
/// its one shared SegmentV2 manifest exactly once.
pub fn preflightAgainstValidatedPublicationAndManifest(
    capture: *const OuterProofCapture,
    publication: *const Publication,
    witness: *const RecursiveWitnessV1,
    manifest: *const manifest_mod.Manifest,
) Error!void {
    const capture_id = publication_mod.captureIdentity(capture);
    if (!std.meta.eql(capture_id, publication.capture_id) or
        !std.meta.eql(capture_id, witness.capture_id))
    {
        return error.CaptureIdentityMismatch;
    }
    try witness.validateAgainstValidatedPublicationAndManifest(
        publication,
        manifest,
    );
}

/// Pointer-free recursive input minted from values still local to the
/// successful verifier transaction.  It never owns or duplicates the dynamic
/// capture; the surrounding verified artifact retains that capture exactly.
pub const RecursiveWitnessV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    claim_count: u8 = CLAIM_COUNT,
    relation_draw_count: u8 = RELATION_DRAW_COUNT,
    poseidon2_partial_count: u8 = POSEIDON2_PARTIAL_COUNT,
    padding: [3]u8 = .{ 0, 0, 0 },

    proof_id: Digest,
    capture_id: Digest,
    statement_id: Digest,
    air_program_id: Digest,
    manifest_id: Digest,
    profile_id: Digest,

    claimed_sums: [CLAIM_COUNT]QM31,
    relation_draws: [RELATION_DRAW_COUNT]QM31,
    poseidon2_partials: [POSEIDON2_PARTIAL_COUNT]QM31,
    transcript_prefix: TranscriptPrefixV1,
    outer_admission: OuterAdmissionReceiptV2,

    /// Separate versioned seals prevent a sum-preserving partial mutation or
    /// detached relation schedule from hiding behind higher-level IDs.
    relation_draws_id: Digest,
    poseidon2_partials_id: Digest,
    witness_id: Digest,

    /// Standalone preflight. Parent engines that have already admitted the
    /// publication should use `validateAgainstValidatedPublication` to avoid
    /// repeating its statement and identity hashes.
    pub fn validateAgainst(
        self: *const RecursiveWitnessV1,
        publication: *const Publication,
        manifest: *const manifest_mod.Manifest,
    ) Error!void {
        try publication.validate();
        try self.validateAgainstValidatedPublication(publication, manifest);
    }

    /// Requires `publication.validate()` to have succeeded in the caller.
    /// This split keeps the temporal-parent preflight at one publication
    /// validation per child while retaining a safe standalone entry point.
    pub fn validateAgainstValidatedPublication(
        self: *const RecursiveWitnessV1,
        publication: *const Publication,
        manifest: *const manifest_mod.Manifest,
    ) Error!void {
        try manifest.validate();
        try self.validateAgainstValidatedPublicationAndManifest(
            publication,
            manifest,
        );
    }

    /// Requires both the publication and shared manifest to have been
    /// validated by the caller.
    pub fn validateAgainstValidatedPublicationAndManifest(
        self: *const RecursiveWitnessV1,
        publication: *const Publication,
        manifest: *const manifest_mod.Manifest,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.claim_count != CLAIM_COUNT or
            self.relation_draw_count != RELATION_DRAW_COUNT or
            self.poseidon2_partial_count != POSEIDON2_PARTIAL_COUNT or
            !std.mem.allEqual(u8, &self.padding, 0))
        {
            return error.UnsupportedFormat;
        }
        if (!std.meta.eql(self.proof_id, publication.proof_id) or
            !std.meta.eql(self.capture_id, publication.capture_id) or
            !std.meta.eql(self.statement_id, publication.statement_id) or
            !std.meta.eql(self.air_program_id, publication.air_program_id) or
            !std.meta.eql(self.manifest_id, publication.manifest_id) or
            !std.meta.eql(self.profile_id, publication.profile_id) or
            !std.meta.eql(self.witness_id, publication.recursive_witness_id))
        {
            return error.PublicationLinkMismatch;
        }
        if (!std.mem.eql(
            u8,
            &manifest.seal,
            &publication.manifest_sha_id,
        ) or !std.meta.eql(
            publication.manifest_id,
            publication_mod.expectedManifestId(manifest.seal),
        )) return error.ManifestMismatch;

        for (self.claimed_sums) |value| try requireCanonical(value);
        for (self.relation_draws) |value| try requireCanonical(value);
        for (self.poseidon2_partials) |value| try requireCanonical(value);
        try self.transcript_prefix.validate();

        var claims = try manifest_mod.ClaimVector.init(manifest);
        for (self.claimed_sums, 0..) |value, row|
            try claims.bind(@enumFromInt(row), value);
        try claims.sealClaims(manifest);
        if (!std.mem.eql(
            u8,
            &claims.seal,
            &publication.closure.claim_seal_sha_id,
        )) return error.ClaimSealMismatch;
        try self.outer_admission.validateAgainst(
            publication,
            manifest,
            &self.claimed_sums,
            &self.transcript_prefix,
        );

        const relations = universal.UniversalRelations.fromDraws(
            &self.relation_draws,
        );
        try relations.validate();
        if (!self.poseidon2_partials[0].add(self.poseidon2_partials[1]).eql(
            self.claimed_sums[POSEIDON2_ROSTER_ROW],
        )) return error.Poseidon2PartialMismatch;

        const expected_relation_draws_id = relationDrawsId(self, publication);
        if (!std.meta.eql(self.relation_draws_id, expected_relation_draws_id))
            return error.RelationDrawsIdentityMismatch;
        const expected_partials_id = poseidon2PartialsId(self, publication);
        if (!std.meta.eql(self.poseidon2_partials_id, expected_partials_id))
            return error.Poseidon2PartialsIdentityMismatch;
        if (!std.meta.eql(self.witness_id, witnessId(self, publication)))
            return error.WitnessIdentityMismatch;
    }
};

pub fn relationDrawsId(
    witness: *const RecursiveWitnessV1,
    publication: *const Publication,
) Digest {
    var hash = IdentityHasher.init(RELATION_DRAWS_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addU32(SCHEMA_VERSION);
    hash.addU32(RELATION_DRAW_COUNT);
    hash.digest(publication.proof_id);
    hash.digest(publication.capture_id);
    hash.digest(publication.manifest_id);
    hash.digest(publication.profile_id);
    hash.sha(publication.relation_registry_sha_id);
    for (witness.relation_draws) |value| hash.qm31(value);
    return hash.finalize();
}

pub fn poseidon2PartialsId(
    witness: *const RecursiveWitnessV1,
    publication: *const Publication,
) Digest {
    var hash = IdentityHasher.init(POSEIDON2_PARTIALS_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addU32(SCHEMA_VERSION);
    hash.addU32(POSEIDON2_PARTIAL_COUNT);
    hash.addU32(POSEIDON2_ROSTER_ROW);
    hash.digest(publication.proof_id);
    hash.digest(publication.capture_id);
    hash.digest(publication.manifest_id);
    hash.sha(publication.closure.generated_interactions_sha_id);
    hash.qm31(witness.claimed_sums[POSEIDON2_ROSTER_ROW]);
    for (witness.poseidon2_partials) |value| hash.qm31(value);
    return hash.finalize();
}

pub fn witnessId(
    witness: *const RecursiveWitnessV1,
    publication: *const Publication,
) Digest {
    var hash = IdentityHasher.init(WITNESS_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addU32(SCHEMA_VERSION);
    hash.addU32(CLAIM_COUNT);
    hash.addU32(RELATION_DRAW_COUNT);
    hash.addU32(POSEIDON2_PARTIAL_COUNT);
    hash.digest(witness.proof_id);
    hash.digest(witness.capture_id);
    hash.digest(witness.statement_id);
    hash.digest(witness.air_program_id);
    hash.digest(witness.manifest_id);
    hash.digest(witness.profile_id);
    hash.sha(publication.closure.claim_seal_sha_id);
    hash.sha(publication.closure.audit_sha_id);
    for (witness.claimed_sums) |value| hash.qm31(value);
    hash.digest(witness.relation_draws_id);
    hash.digest(witness.poseidon2_partials_id);
    hash.digest(witness.transcript_prefix.transcript_prefix_id);
    hash.digest(witness.outer_admission.receipt_id);
    return hash.finalize();
}

pub fn outerAdmissionReceiptId(
    receipt: *const OuterAdmissionReceiptV2,
    publication: *const Publication,
) Digest {
    var hash = IdentityHasher.init(OUTER_ADMISSION_ID_DOMAIN);
    hash.addU32(receipt.format_version);
    hash.addU32(receipt.schema_version);
    hash.addU32(receipt.claim_count);
    hash.digest(receipt.proof_id);
    hash.digest(receipt.capture_id);
    hash.digest(publication.statement_id);
    hash.digest(publication.air_program_id);
    hash.digest(publication.manifest_id);
    hash.digest(publication.profile_id);
    hash.digest(publication.verification_key_id);
    hash.addU32(CLAIM_COUNT);
    for (receipt.component_log_sizes) |log_size| hash.addU32(log_size);
    hash.digest(receipt.pre_core_channel.digest);
    hash.addU32(receipt.pre_core_channel.draw_count);
    for (receipt.claimed_sums) |value| hash.qm31(value);
    hash.qm31(receipt.verifier_input_boundary);
    for (receipt.wire_closure) |value| hash.qm31(value);
    hash.addU32(@as(u32, @intCast(receipt.interaction_pow_nonce)));
    return hash.finalize();
}

pub fn transcriptPrefixId(prefix: *const TranscriptPrefixV1) Error!Digest {
    if (prefix.core_total_call_count == 0 or
        prefix.core_total_call_count >= m31.Modulus or
        prefix.public_wire_boundary_term_count == 0 or
        prefix.public_wire_boundary_term_count >= m31.Modulus)
    {
        return error.InvalidTranscriptPrefix;
    }
    var hash = IdentityHasher.init(TRANSCRIPT_PREFIX_ID_DOMAIN);
    hash.addU32(prefix.format_version);
    hash.addU32(prefix.schema_version);
    hash.sha(prefix.noncore_authority_sha_id);
    hash.sha(prefix.core_authority_sha_id);
    hash.sha(prefix.core_layout_sha_id);
    hash.sha(prefix.core_call_buffer_sha_id);
    hash.addU32(prefix.core_total_call_count);
    hash.addU32(prefix.public_wire_boundary_term_count);
    hash.qm31(prefix.public_wire_boundary_claimed_sum);
    hash.sha(prefix.public_wire_boundary_sha_id);
    return hash.finalize();
}

fn requireCanonical(value: QM31) Error!void {
    for (value.toM31Array()) |word|
        if (word.toU32() >= m31.Modulus) return error.NonCanonicalField;
}

fn requireSha(value: [32]u8) Error!void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.InvalidTranscriptPrefix;
}

const IdentityHasher = struct {
    inner: channel.CanonicalWordHasher,

    fn init(domain: u32) IdentityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    fn addU32(self: *IdentityHasher, value: anytype) void {
        const exact: u32 = @intCast(value);
        std.debug.assert(exact < m31.Modulus);
        self.inner.update(&.{M31.fromCanonical(exact)});
    }

    fn digest(self: *IdentityHasher, value: Digest) void {
        for (value) |word| self.addU32(word);
    }

    fn sha(self: *IdentityHasher, value: [32]u8) void {
        self.digest(channel.hashBytes(&value, SHA_ID_DOMAIN));
    }

    fn qm31(self: *IdentityHasher, value: QM31) void {
        self.inner.update(&value.toM31Array());
    }

    fn finalize(self: *IdentityHasher) Digest {
        return self.inner.finalize();
    }
};

fn assertPointerFree(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer, .optional => @compileError("recursive witness retains a pointer"),
        .array => |array| assertPointerFree(array.child),
        .@"struct" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        .@"union" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        else => {},
    }
}

comptime {
    if (SCHEMA_VERSION != 3 or TRANSCRIPT_PREFIX_FORMAT_VERSION != 1 or
        OUTER_ADMISSION_FORMAT_VERSION != 2 or
        OUTER_ADMISSION_SCHEMA_VERSION != 1 or
        CLAIM_COUNT != 39 or RELATION_DRAW_COUNT != 94 or
        POSEIDON2_PARTIAL_COUNT != 2 or !POINTER_FREE or
        HEAP_ALLOCATIONS_PER_VALIDATE != 0 or RETAINED_PROOF_BYTES != 0 or
        PUBLIC_MINT_CONSTRUCTOR_AVAILABLE or
        CAPTURE_ID_HASHES_PER_PREFLIGHT != 1)
    {
        @compileError("SegmentV2 recursive-witness ABI drifted");
    }
    assertPointerFree(OuterAdmissionReceiptV2);
    assertPointerFree(RecursiveWitnessV1);
}

test "segment V2 recursive witness exposes no detached mint constructor" {
    try std.testing.expect(!@hasDecl(RecursiveWitnessV1, "init"));
    try std.testing.expect(!@hasDecl(@This(), "mint"));
    try std.testing.expect(POINTER_FREE);
    try std.testing.expectEqual(@as(usize, 39), CLAIM_COUNT);
    try std.testing.expectEqual(@as(usize, 94), RELATION_DRAW_COUNT);
    try std.testing.expectEqual(@as(usize, 2), POSEIDON2_PARTIAL_COUNT);
}
