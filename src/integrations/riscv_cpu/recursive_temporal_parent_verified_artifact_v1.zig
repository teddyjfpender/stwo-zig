//! Verifier-minted child sidecar for one accepted temporal-parent proof.
//!
//! The V3 publication predates multi-level aggregation.  This append-only
//! sidecar converts only the transaction-local successful-verifier capability
//! into the canonical `binary_node` child consumed by the temporal tree.  No
//! constructor accepts detached proof, transcript, closure, or statement
//! fields.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const contract = @import("recursive_binary_outer_contract.zig");
const publication_mod = @import("recursive_temporal_parent_publication_v3.zig");
const recursive_admission = @import("recursive_temporal_parent_recursive_admission_v1.zig");
const transcript_prefix_mod =
    @import("recursive_temporal_parent_transcript_prefix_v1.zig");

const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const admission = recursion.outer_parent_child_admission;
const channel = recursion.poseidon2_channel;
const temporal = recursion.temporal_pair_node;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 5;
pub const ROSTER_COUNT: u8 = temporal.COMPLETE_ROSTER_COUNT;
pub const PRODUCTION_ACTIVATION = false;
pub const PUBLIC_MINT_CONSTRUCTOR_AVAILABLE = false;
pub const HEAP_ALLOCATIONS_PER_MINT: usize = 0;

const PUBLICATION_ID_DOMAIN: u32 = 0x5450_5031; // "TPP1"
const AIR_PROGRAM_ID_DOMAIN: u32 = 0x5450_4131; // "TPA1"
const MANIFEST_ID_DOMAIN: u32 = 0x5450_4d31; // "TPM1"
const PROFILE_ID_DOMAIN: u32 = 0x5450_4631; // "TPF1"
const RECEIPT_ID_DOMAIN: u32 = 0x5450_5231; // "TPR1"
const CLAIMS_ID_DOMAIN: u32 = 0x5450_4331; // "TPC1"
const RELATION_ID_DOMAIN: u32 = 0x5450_4c31; // "TPL1"
const AUXILIARY_ID_DOMAIN: u32 = 0x5450_5831; // "TPX1"
const LINEAGE_ID_DOMAIN: u32 = 0x5450_4731; // "TPG1"
const ARTIFACT_ID_DOMAIN: u32 = 0x5450_5631; // "TPV1"

pub const Digest = channel.Digest;
pub const Publication = publication_mod.VerifiedPublicationV1;
pub const SuccessEvidence = contract.TemporalVerifierSuccessEvidenceV1;

pub const Error = temporal.Error || recursive_admission.Error || error{
    ArtifactIdentityMismatch,
    EvidenceMismatch,
    PublicationMismatch,
    UnsupportedFormat,
};

pub const VerifiedTemporalParentArtifactV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    parent_proof_verified: bool = true,
    production_activation: bool = PRODUCTION_ACTIVATION,
    padding: [2]u8 = .{ 0, 0 },
    publication_sha_id: [32]u8,
    publication_id: Digest,
    recursive_admission: recursive_admission.PreparedAdmissionV1,
    transcript_prefix: transcript_prefix_mod.PrefixV1,
    recursive_wire_bytes: u32,
    recursive_proof_id: Digest,
    child: temporal.VerifiedChildV2,
    child_id: Digest,
    artifact_id: Digest,

    pub fn validate(self: *const VerifiedTemporalParentArtifactV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !self.parent_proof_verified or self.production_activation or
            !std.mem.allEqual(u8, &self.padding, 0) or
            std.mem.allEqual(u8, &self.publication_sha_id, 0))
        {
            return error.UnsupportedFormat;
        }
        try requireDigest(self.publication_id);
        try requireDigest(self.recursive_proof_id);
        try requireDigest(self.child_id);
        try requireDigest(self.artifact_id);
        try self.recursive_admission.validateRetained();
        try self.transcript_prefix.validate();
        if (self.child.kind != .binary_node or
            self.child.scope != .complete_execution or
            !self.child.proof_present or
            self.child.roster_count != ROSTER_COUNT or
            self.recursive_wire_bytes == 0)
        {
            return error.ArtifactIdentityMismatch;
        }
        const statement = try self.child.statement();
        if (statement.slots.height == 0 or
            self.child.position != try temporal.positionForNextParent(statement) or
            !std.meta.eql(
                self.child.closure_receipt_id,
                try temporal.closureReceiptId(&self.child),
            ) or !std.meta.eql(self.child_id, try self.child.id()) or
            !std.meta.eql(self.artifact_id, artifactIdentity(self)))
        {
            return error.ArtifactIdentityMismatch;
        }
    }

    pub fn validateAgainst(
        self: *const VerifiedTemporalParentArtifactV1,
        publication: *const Publication,
    ) !void {
        try self.validate();
        try publication.validate();
        if (!std.mem.eql(
            u8,
            &self.publication_sha_id,
            &publication.publication_sha_id,
        ) or !std.meta.eql(
            self.publication_id,
            channel.hashBytes(
                &publication.publication_sha_id,
                PUBLICATION_ID_DOMAIN,
            ),
        ) or !std.meta.eql(self.child.statement_words, publication.statement_words) or
            !std.meta.eql(self.child.proof_id, publication.proof_id) or
            !std.meta.eql(self.child.capture_id, publication.capture_id) or
            !std.meta.eql(self.child.transcript_id, publication.transcript_id) or
            !std.meta.eql(
                self.recursive_admission.seal.capture_id,
                publication.capture_id,
            ) or !std.meta.eql(
            self.recursive_admission.seal.transcript_id,
            publication.transcript_id,
        ) or !std.meta.eql(
            self.recursive_admission.receipt.statement_id,
            publication.context.parent_statement_id,
        ) or !std.meta.eql(
            self.recursive_admission.receipt.verification_key_id,
            publication.context.parent_vk_id,
        ) or
            !std.meta.eql(self.child.session_id, publication.context.session_id) or
            !std.meta.eql(
                self.child.recursive_parent_vk_id,
                publication.context.parent_vk_id,
            ) or !std.meta.eql(
            self.child.verification_key_id,
            publication.context.parent_vk_id,
        ) or !std.mem.eql(
            u8,
            &self.transcript_prefix.manifest_sha_id,
            &publication.manifest_sha_id,
        )) return error.PublicationMismatch;
    }
};

/// The opaque verifier evidence is the mint capability.  It is created only
/// after native proof verification and consumed synchronously by the engine.
pub fn mintFromSuccessfulVerifier(
    evidence: *const SuccessEvidence,
    publication: *const Publication,
    admission_value: *const recursive_admission.PreparedAdmissionV1,
    transcript_prefix: *const transcript_prefix_mod.PrefixV1,
    capture: *const recursive_admission.OuterProofCapture,
) !VerifiedTemporalParentArtifactV1 {
    const verified = try contract.openTemporalVerifierSuccessEvidence(evidence);
    try publication.validate();
    try admission_value.validateAgainst(capture);
    try transcript_prefix.validate();
    if (!std.meta.eql(verified.proof_id, publication.proof_id) or
        !std.meta.eql(verified.capture_id, publication.capture_id) or
        !std.meta.eql(verified.transcript_id, publication.transcript_id) or
        !std.mem.eql(
            u8,
            &verified.canonical_proof_sha_id,
            &publication.canonical_proof_sha_id,
        ) or !std.mem.eql(
        u8,
        &verified.cohort_authority_sha_id,
        &publication.cohort_authority_sha_id,
    ) or !std.mem.eql(
        u8,
        &verified.manifest_sha_id,
        &publication.manifest_sha_id,
    ) or !std.mem.eql(
        u8,
        &verified.claims_sha_id,
        &publication.claims_sha_id,
    ) or !std.mem.eql(
        u8,
        &verified.generated_interactions_sha_id,
        &publication.generated_interactions_sha_id,
    ) or !std.mem.eql(
        u8,
        &verified.audit_sha_id,
        &publication.audit_sha_id,
    ) or !std.mem.eql(
        u8,
        &verified.closure_receipt_sha_id,
        &publication.closure_receipt_sha_id,
    ) or !std.mem.eql(
        u8,
        &verified.recursive_admission_sha_id,
        &admission_value.identity,
    )) return error.EvidenceMismatch;

    const recursive_wire_bytes = try admission.runtimeCanonicalByteCount(
        admission_value.seal,
        &admission_value.receipt,
        capture,
    );
    const recursive_proof_id = try admission.proofIdRuntime(
        admission_value.seal,
        &admission_value.receipt,
        capture,
    );

    const statement = try recursion.span_statement.SpanStatement
        .fromCanonicalWords(&publication.statement_words);
    const manifest_id = channel.hashBytes(
        &publication.manifest_sha_id,
        MANIFEST_ID_DOMAIN,
    );
    const air_program_id = channel.hashBytes(
        &publication.cohort_authority_sha_id,
        AIR_PROGRAM_ID_DOMAIN,
    );
    const claims_id = channel.hashBytes(
        &publication.claims_sha_id,
        CLAIMS_ID_DOMAIN,
    );
    const generated_id = channel.hashBytes(
        &publication.generated_interactions_sha_id,
        RELATION_ID_DOMAIN,
    );
    const audit_id = channel.hashBytes(
        &publication.audit_sha_id,
        RELATION_ID_DOMAIN + 1,
    );
    const closure_id = channel.hashBytes(
        &publication.closure_receipt_sha_id,
        AUXILIARY_ID_DOMAIN,
    );

    var child = temporal.VerifiedChildV2{
        .position = try temporal.positionForNextParent(statement),
        .kind = .binary_node,
        .scope = .complete_execution,
        .proof_present = true,
        .roster_count = ROSTER_COUNT,
        .session_id = publication.context.session_id,
        .job_id = try temporal.jobId(&publication.statement_words),
        .recursive_parent_vk_id = publication.context.parent_vk_id,
        .verification_key_id = publication.context.parent_vk_id,
        .air_program_id = air_program_id,
        .manifest_id = manifest_id,
        .profile_id = combine(
            PROFILE_ID_DOMAIN,
            &.{ recursion.protocol.PROTOCOL_ID_WORDS, manifest_id, air_program_id },
        ),
        .statement_words = publication.statement_words,
        .proof_id = publication.proof_id,
        .transcript_id = publication.transcript_id,
        .capture_id = publication.capture_id,
        .verifier_receipt_id = combine(RECEIPT_ID_DOMAIN, &.{
            publication.proof_id,
            publication.capture_id,
            publication.transcript_id,
            audit_id,
        }),
        .claimed_sums_id = claims_id,
        .relation_replay_id = combine(
            RELATION_ID_DOMAIN,
            &.{ generated_id, audit_id },
        ),
        .auxiliary_claim_seal_id = closure_id,
        .closure_receipt_id = undefined,
        .lineage_id = combine(LINEAGE_ID_DOMAIN, &.{
            publication.pair_authority_id,
            publication.context.child_lineage_ids[0],
            publication.context.child_lineage_ids[1],
        }),
        .closure_value = .{ 0, 0, 0, 0 },
    };
    child.closure_receipt_id = try temporal.closureReceiptId(&child);
    const child_id = try child.id();
    var result = VerifiedTemporalParentArtifactV1{
        .publication_sha_id = publication.publication_sha_id,
        .publication_id = channel.hashBytes(
            &publication.publication_sha_id,
            PUBLICATION_ID_DOMAIN,
        ),
        .recursive_admission = admission_value.*,
        .transcript_prefix = transcript_prefix.*,
        .recursive_wire_bytes = std.math.cast(u32, recursive_wire_bytes) orelse
            return error.ArtifactIdentityMismatch,
        .recursive_proof_id = recursive_proof_id,
        .child = child,
        .child_id = child_id,
        .artifact_id = undefined,
    };
    result.artifact_id = artifactIdentity(&result);
    try result.validateAgainst(publication);
    return result;
}

fn artifactIdentity(value: *const VerifiedTemporalParentArtifactV1) Digest {
    var hasher = IdentityHasher.init(ARTIFACT_ID_DOMAIN);
    hasher.addU32(value.format_version);
    hasher.addU32(value.schema_version);
    hasher.addU32(@intFromBool(value.parent_proof_verified));
    hasher.addU32(@intFromBool(value.production_activation));
    hasher.digest(channel.hashBytes(&value.publication_sha_id, PUBLICATION_ID_DOMAIN));
    hasher.digest(value.publication_id);
    hasher.digest(value.recursive_proof_id);
    hasher.addU32(value.recursive_wire_bytes);
    hasher.digest(value.recursive_admission.seal.profile_id);
    hasher.digest(value.recursive_admission.seal.receipt_id);
    hasher.digest(value.recursive_admission.seal.claimed_sums_id);
    hasher.digest(channel.hashBytes(
        &value.transcript_prefix.identity,
        ARTIFACT_ID_DOMAIN + 1,
    ));
    hasher.digest(value.child_id);
    hasher.digest(value.child.proof_id);
    hasher.digest(value.child.transcript_id);
    hasher.digest(value.child.capture_id);
    hasher.digest(value.child.closure_receipt_id);
    hasher.digest(value.child.lineage_id);
    return hasher.finalize();
}

fn combine(domain: u32, values: []const Digest) Digest {
    var hasher = IdentityHasher.init(domain);
    hasher.addU32(@intCast(values.len));
    for (values) |value| hasher.digest(value);
    return hasher.finalize();
}

fn requireDigest(value: Digest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.ArtifactIdentityMismatch;
        aggregate |= word;
    }
    if (aggregate == 0) return error.ArtifactIdentityMismatch;
}

const IdentityHasher = struct {
    inner: channel.CanonicalWordHasher,

    fn init(domain: u32) IdentityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    fn addU32(self: *IdentityHasher, value: u32) void {
        std.debug.assert(value < m31.Modulus);
        const words = [_]M31{M31.fromCanonical(value)};
        self.inner.update(&words);
    }

    fn digest(self: *IdentityHasher, value: Digest) void {
        var words: [channel.RATE]M31 = undefined;
        for (&words, value) |*word, raw| word.* = M31.fromCanonical(raw);
        self.inner.update(&words);
    }

    fn finalize(self: *IdentityHasher) Digest {
        return self.inner.finalize();
    }
};

fn assertPointerFree(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer => @compileError("temporal parent artifact retains a pointer"),
        .optional => |optional| assertPointerFree(optional.child),
        .array => |array| assertPointerFree(array.child),
        .@"struct" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        .@"union" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        else => {},
    }
}

comptime {
    if (PRODUCTION_ACTIVATION or PUBLIC_MINT_CONSTRUCTOR_AVAILABLE or
        HEAP_ALLOCATIONS_PER_MINT != 0)
    {
        @compileError("temporal parent verifier artifact ABI drifted");
    }
    assertPointerFree(VerifiedTemporalParentArtifactV1);
}

test "temporal parent artifact exposes no detached constructor" {
    try std.testing.expect(!@hasDecl(VerifiedTemporalParentArtifactV1, "init"));
    try std.testing.expect(!PUBLIC_MINT_CONSTRUCTOR_AVAILABLE);
}
