//! Pointer-free custody publication for one successfully verified 39-row
//! SegmentV2 outer proof.
//!
//! This module intentionally exposes no constructor.  The only production
//! mint belongs inside `recursive_segment_v2_outer_engine.EngineKernel`, after
//! `verifyWithProofCapture` has accepted the proof and while the verifier's
//! independently rebuilt cohort, claims, closure audit, transcript, and proof
//! capture are still local.  Consumers may validate a publication, but raw
//! proof bytes, a raw closure summary, or caller-selected context fields have
//! no promotion API here.
//!
//! The 39 proved components comprise the 36-row universal roster, two V2
//! boundary rows, and one committed verifier-input provider. Both counts are
//! retained explicitly; the temporal protocol continues to use the
//! universal-roster count in its closure identity.
//! Native Poseidon2-M31 identities and SHA-256 implementation receipts remain
//! differently typed throughout.  SHA bytes are absorbed injectively when a
//! native transitive identity is required; they are never reinterpreted as
//! field words.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const protocol = recursion.protocol;
const outer_admission = recursion.outer_parent_child_admission;
const span_statement = recursion.span_statement;
const temporal = recursion.temporal_pair_node;
const public_data_v2 = frontend.air.public_data_v2;

pub const Digest = channel.Digest;
pub const Sha256Digest = [32]u8;
pub const Qm31Words = [4]u32;
pub const OuterProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
    recursion.engine.Hasher,
);

pub const FORMAT_VERSION: u16 = 1;
pub const PUBLICATION_SCHEMA_VERSION: u16 = 2;
pub const CLOSURE_SCHEMA_VERSION: u16 = 2;
pub const STATEMENT_VERSION: u32 =
    public_data_v2.STATEMENT_TRANSCRIPT_VERSION;
pub const PROVED_COMPONENT_COUNT: u8 = 39;
pub const UNIVERSAL_ROSTER_COUNT: u8 = temporal.COMPLETE_ROSTER_COUNT;
pub const RELATION_DOMAIN_COUNT: u8 = 47;
pub const COMPLETE_COMPONENT_MASK: u64 =
    (@as(u64, 1) << PROVED_COMPONENT_COUNT) - 1;
pub const COMPLETE_DOMAIN_MASK: u64 =
    (@as(u64, 1) << RELATION_DOMAIN_COUNT) - 1;

pub const MANIFEST_ID_DOMAIN: u32 = 0x5356_4d46; // "SVMF"
pub const AIR_PROGRAM_ID_DOMAIN: u32 = 0x5356_4149; // "SVAI"
pub const PROFILE_ID_DOMAIN: u32 = 0x5356_5052; // "SVPR"
pub const CLAIMED_SUMS_ID_DOMAIN: u32 = 0x5356_434c; // "SVCL"
pub const RELATION_REPLAY_ID_DOMAIN: u32 = 0x5356_5252; // "SVRR"
pub const AUXILIARY_CLAIM_ID_DOMAIN: u32 = 0x5356_4158; // "SVAX"
pub const VERIFIER_RECEIPT_ID_DOMAIN: u32 = 0x5356_5652; // "SVVR"
pub const CONTEXT_ID_DOMAIN: u32 = 0x5356_4358; // "SVCX"
pub const PUBLICATION_ID_DOMAIN: u32 = 0x5356_5055; // "SVPU"

pub const HEAP_ALLOCATIONS_PER_VALIDATE: usize = 0;
pub const HEAP_ALLOCATIONS_PER_PUBLICATION: usize = 0;
pub const BORROWED_STORAGE_AFTER_PUBLICATION = false;
pub const POINTER_FREE_PUBLICATION = true;
pub const SUCCESSFUL_VERIFIER_TRANSACTION_REQUIRED = true;
pub const PUBLIC_MINT_CONSTRUCTOR_AVAILABLE = false;
pub const COMPLETE_SEGMENT_CHILD_CAPABILITY = true;
pub const COMPLETE_PARENT_CAPABILITY = false;
pub const RECURSIVE_WITNESS_REQUIRED = true;

pub const Error = temporal.Error || span_statement.Error || error{
    CapabilityEscalation,
    ClosureIdentityMismatch,
    ContextIdentityMismatch,
    EmptySha256Digest,
    InvalidClosure,
    InvalidCount,
    InvalidProofIdentity,
    NonCanonicalDigest,
    NonCanonicalField,
    PublicationIdentityMismatch,
    StatementIdentityMismatch,
    UnsupportedFormat,
    UnsupportedProofKind,
    UnsupportedProofScope,
};

/// Meaning of the proof at this boundary.  `complete_segment_v2` means all 39
/// rows of one segment leaf were proved and independently verified; it does
/// not mean that a temporal parent proof exists.
pub const ProofScopeV1 = enum(u8) {
    complete_segment_v2 = 1,
};

pub const ProofEncodingV1 = enum(u8) {
    canonical_postcard_v1 = 1,
};

/// Exact whole-cohort closure evidence retained by the successful verifier.
/// Every domain total is kept even though all valid totals are zero.  This
/// makes the zero result independently replayable without reducing a 47-way
/// statement to one aggregate scalar.
pub const VerifiedClosureReceiptV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = CLOSURE_SCHEMA_VERSION,
    proved_component_count: u8 = PROVED_COMPONENT_COUNT,
    universal_roster_count: u8 = UNIVERSAL_ROSTER_COUNT,
    relation_domain_count: u8 = RELATION_DOMAIN_COUNT,
    padding: [3]u8 = .{ 0, 0, 0 },
    checked_component_mask: u64 = COMPLETE_COMPONENT_MASK,
    checked_domain_mask: u64 = COMPLETE_DOMAIN_MASK,
    active_domain_mask: u64,
    logical_rows: u64,
    event_terms: u64,
    domain_totals: [RELATION_DOMAIN_COUNT]Qm31Words,
    framework_total: Qm31Words,

    /// Native identities derived inside the same verifier transaction.
    verifier_receipt_id: Digest,
    claimed_sums_id: Digest,
    relation_replay_id: Digest,
    auxiliary_claim_seal_id: Digest,

    /// Implementation receipts remain SHA-256 byte arrays.
    generated_interactions_sha_id: Sha256Digest,
    claim_seal_sha_id: Sha256Digest,
    audit_sha_id: Sha256Digest,

    /// Exact temporal closure ID.  It uses the universal roster count (36),
    /// while the fields above prove that all 39 physical components closed.
    closure_receipt_id: Digest,

    pub fn validate(self: *const VerifiedClosureReceiptV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != CLOSURE_SCHEMA_VERSION)
        {
            return error.UnsupportedFormat;
        }
        if (self.proved_component_count != PROVED_COMPONENT_COUNT or
            self.universal_roster_count != UNIVERSAL_ROSTER_COUNT or
            self.relation_domain_count != RELATION_DOMAIN_COUNT or
            self.checked_component_mask != COMPLETE_COMPONENT_MASK or
            self.checked_domain_mask != COMPLETE_DOMAIN_MASK or
            self.active_domain_mask & ~self.checked_domain_mask != 0 or
            !allZeroBytes(&self.padding) or self.logical_rows == 0 or
            self.event_terms == 0)
        {
            return error.InvalidCount;
        }
        try requireDigest(self.verifier_receipt_id);
        try requireDigest(self.claimed_sums_id);
        try requireDigest(self.relation_replay_id);
        try requireDigest(self.auxiliary_claim_seal_id);
        try requireDigest(self.closure_receipt_id);
        try requireSha256Digest(self.generated_interactions_sha_id);
        try requireSha256Digest(self.claim_seal_sha_id);
        try requireSha256Digest(self.audit_sha_id);
        for (self.domain_totals) |total| try requireZeroQm31(total);
        try requireZeroQm31(self.framework_total);
        const expected = try expectedTemporalClosureId(self);
        if (!std.meta.eql(self.closure_receipt_id, expected))
            return error.ClosureIdentityMismatch;
    }
};

/// Successful-verifier output for one SegmentV2 leaf.  It owns no allocation
/// and borrows no capture/cohort storage.  `complete_parent_capability` is
/// fixed false: this value is admissible as a temporal child, never as proof
/// that a temporal parent has already been constructed.
pub const VerifiedSegmentV2PublicationV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    publication_schema_version: u16 = PUBLICATION_SCHEMA_VERSION,
    statement_version: u32 = STATEMENT_VERSION,
    source_scope: ProofScopeV1 = .complete_segment_v2,
    proof_kind: temporal.ProofKind = .segment_leaf,
    proof_encoding: ProofEncodingV1 = .canonical_postcard_v1,
    outer_stark_verified: bool = true,
    complete_segment_child: bool = true,
    complete_parent_capability: bool = COMPLETE_PARENT_CAPABILITY,
    padding: [3]u8 = .{ 0, 0, 0 },
    proof_size_estimate: u64,
    /// Exact canonical byte stream identified before ownership of the proof
    /// moves into native verification.  `proof_size_estimate` is telemetry;
    /// these three fields are proof identity authority.
    canonical_proof_byte_count: u32,
    canonical_proof_sha_id: Sha256Digest,

    segment_index: u32,
    segment_count: u32,
    global_cycle_start: u32,
    global_cycle_end: u32,
    entry_continuation_root: u32,
    exit_continuation_root: u32,
    statement_words: span_statement.StatementWords,
    statement_id: Digest,
    session_id: Digest,
    job_id: Digest,
    position_id: Digest,
    segment_wire_id: Digest,
    entry_lineage_id: Digest,
    exit_lineage_id: Digest,
    lineage_id: Digest,
    source_context_id: Digest,
    recursive_parent_vk_id: Digest,
    verification_key_id: Digest,

    air_program_id: Digest,
    manifest_id: Digest,
    profile_id: Digest,
    capture_id: Digest,
    /// Identity of the fixed verifier-minted recursive witness. The witness
    /// binds all 39 claim values, all 94 raw relation draws, and both ordered
    /// Poseidon2 partials; raw values never enter through this publication.
    recursive_witness_id: Digest,
    transcript_id: Digest,
    verifier_context_id: Digest,
    proof_id: Digest,

    prepared_leaf_sha_id: Sha256Digest,
    cohort_authority_sha_id: Sha256Digest,
    manifest_sha_id: Sha256Digest,
    catalog_sha_id: Sha256Digest,
    relation_registry_sha_id: Sha256Digest,
    plan_sha_id: Sha256Digest,
    closure: VerifiedClosureReceiptV1,
    publication_id: Digest,

    pub fn temporalChildReady(
        self: *const VerifiedSegmentV2PublicationV1,
    ) bool {
        return self.outer_stark_verified and self.complete_segment_child and
            !self.complete_parent_capability;
    }

    pub fn completeParentReady(
        _: *const VerifiedSegmentV2PublicationV1,
    ) bool {
        return false;
    }

    pub fn validate(
        self: *const VerifiedSegmentV2PublicationV1,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.publication_schema_version != PUBLICATION_SCHEMA_VERSION or
            self.statement_version != STATEMENT_VERSION or
            !allZeroBytes(&self.padding))
        {
            return error.UnsupportedFormat;
        }
        if (self.source_scope != .complete_segment_v2)
            return error.UnsupportedProofScope;
        if (self.proof_kind != .segment_leaf)
            return error.UnsupportedProofKind;
        if (self.proof_encoding != .canonical_postcard_v1)
            return error.UnsupportedFormat;
        if (!self.outer_stark_verified or !self.complete_segment_child or
            self.complete_parent_capability or !self.temporalChildReady() or
            self.completeParentReady())
        {
            return error.CapabilityEscalation;
        }
        if (self.proof_size_estimate == 0 or
            self.canonical_proof_byte_count == 0 or self.segment_count == 0 or
            self.segment_index >= self.segment_count or
            self.global_cycle_end <= self.global_cycle_start)
        {
            return error.InvalidCount;
        }

        inline for (.{
            self.statement_id,
            self.session_id,
            self.job_id,
            self.position_id,
            self.segment_wire_id,
            self.entry_lineage_id,
            self.exit_lineage_id,
            self.lineage_id,
            self.source_context_id,
            self.recursive_parent_vk_id,
            self.verification_key_id,
            self.air_program_id,
            self.manifest_id,
            self.profile_id,
            self.capture_id,
            self.recursive_witness_id,
            self.transcript_id,
            self.verifier_context_id,
            self.proof_id,
        }) |value| try requireDigest(value);
        try requireSha256Digest(self.prepared_leaf_sha_id);
        try requireSha256Digest(self.canonical_proof_sha_id);
        try requireSha256Digest(self.cohort_authority_sha_id);
        try requireSha256Digest(self.manifest_sha_id);
        try requireSha256Digest(self.catalog_sha_id);
        try requireSha256Digest(self.relation_registry_sha_id);
        try requireSha256Digest(self.plan_sha_id);

        const statement = try span_statement.SpanStatement
            .fromCanonicalWords(&self.statement_words);
        const executed = switch (statement.body) {
            .empty => return error.UnsupportedProofKind,
            .executed => |value| value,
        };
        if (statement.slots.height != 0 or
            statement.slots.first != self.segment_index or
            executed.first_segment != self.segment_index or
            executed.segment_count != 1 or
            statement.job.segment_count != self.segment_count or
            executed.first_cycle != self.global_cycle_start or
            executed.endCycle() != self.global_cycle_end)
        {
            return error.StatementIdentityMismatch;
        }
        const expected_statement = try statementId(&self.statement_words);
        const expected_job = try temporal.jobId(&self.statement_words);
        if (!std.meta.eql(self.statement_id, expected_statement) or
            !std.meta.eql(self.job_id, expected_job))
        {
            return error.StatementIdentityMismatch;
        }

        try self.closure.validate();
        if (!std.meta.eql(
            self.manifest_id,
            expectedManifestId(self.manifest_sha_id),
        ) or !std.meta.eql(
            self.air_program_id,
            expectedAirProgramId(self),
        ) or !std.meta.eql(
            self.profile_id,
            expectedProfileId(self),
        ) or !std.meta.eql(
            self.closure.claimed_sums_id,
            expectedClaimedSumsId(self),
        ) or !std.meta.eql(
            self.closure.relation_replay_id,
            expectedRelationReplayId(self),
        ) or !std.meta.eql(
            self.closure.auxiliary_claim_seal_id,
            expectedAuxiliaryClaimSealId(self),
        ) or !std.meta.eql(
            self.verifier_context_id,
            expectedVerifierContextId(self),
        ) or !std.meta.eql(
            self.closure.verifier_receipt_id,
            expectedVerifierReceiptId(self),
        )) {
            return error.InvalidProofIdentity;
        }
        if (!std.meta.eql(
            self.closure.closure_receipt_id,
            try expectedTemporalClosureId(&self.closure),
        )) return error.ClosureIdentityMismatch;
        if (!std.meta.eql(
            self.publication_id,
            expectedPublicationId(self),
        )) return error.PublicationIdentityMismatch;
    }
};

/// Native manifest identity derived injectively from the SHA implementation
/// receipt.  This is conversion by hashing, not byte reinterpretation.
pub fn expectedManifestId(manifest_sha_id: Sha256Digest) Digest {
    return channel.hashBytes(&manifest_sha_id, MANIFEST_ID_DOMAIN);
}

/// Full semantic identity of the verifier-generated capture.  The caller may
/// invoke this only after successful native verification has constructed the
/// capture.  It is deliberately separate from the canonical proof-byte ID.
/// The preimage mirrors the fixed-wire admission identity and includes every
/// dynamic length, value, path, challenge, and query schedule coordinate.
pub fn captureIdentity(capture: *const OuterProofCapture) Digest {
    var hash = IdentityHasher.init(outer_admission.CAPTURE_ID_DOMAIN);
    hash.addU32(outer_admission.FORMAT_VERSION);
    hash.addUsize(capture.commitments.len);
    for (capture.commitments) |value| hash.digest(value);
    hash.addUsize(capture.column_log_sizes.len);
    for (capture.column_log_sizes) |logs| {
        hash.addUsize(logs.len);
        for (logs) |value| hash.addU32(value);
    }
    hash.addUsize(capture.sampled_points.len);
    for (capture.sampled_points) |columns| {
        hash.addUsize(columns.len);
        for (columns) |points| {
            hash.addUsize(points.len);
            for (points) |point| {
                hash.fieldQm31(point.x);
                hash.fieldQm31(point.y);
            }
        }
    }
    hash.addUsize(capture.sampled_values.len);
    for (capture.sampled_values) |value| hash.fieldQm31(value);
    hash.addUsize(capture.queried_values.len);
    for (capture.queried_values) |value| hash.addU32(value.toU32());
    hash.addUsize(capture.deep_answers.len);
    for (capture.deep_answers) |value| hash.fieldQm31(value);
    hash.addUsize(capture.trace_paths.len);
    for (capture.trace_paths) |paths| {
        hash.addU32(paths.path_depth);
        hash.addUsize(paths.positions.len);
        for (paths.positions) |position| hash.addUsize(position);
        hash.addUsize(paths.siblings.len);
        for (paths.siblings) |value| hash.digest(value);
    }
    hash.addUsize(capture.fri.layers.len);
    for (capture.fri.layers) |layer| {
        hash.digest(layer.commitment);
        hash.fieldQm31(layer.folding_alpha);
        hash.addU32(layer.fold_step);
        hash.addU32(layer.fold_width);
        hash.addU32(layer.path_depth);
        hash.addUsize(layer.query_count);
        hash.addUsize(layer.positions.len);
        for (layer.positions) |position| hash.addUsize(position);
        hash.addUsize(layer.values.len);
        for (layer.values) |value| hash.fieldQm31(value);
        hash.addUsize(layer.siblings.len);
        for (layer.siblings) |value| hash.digest(value);
    }
    hash.addUsize(capture.last_layer_coefficients.len);
    for (capture.last_layer_coefficients) |value| hash.fieldQm31(value);
    hash.addU64(capture.proof_of_work);
    hash.fieldQm31(capture.composition_randomness);
    hash.fieldQm31(capture.oods_seed);
    hash.fieldQm31(capture.deep_randomness);
    hash.addUsize(capture.queries.raw.len);
    for (capture.queries.raw) |position| hash.addUsize(position);
    hash.addUsize(capture.queries.unique.len);
    for (capture.queries.unique) |position| hash.addUsize(position);
    return hash.finalize();
}

pub fn expectedAirProgramId(
    publication: *const VerifiedSegmentV2PublicationV1,
) Digest {
    var hash = IdentityHasher.init(AIR_PROGRAM_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.digest(protocol.PROTOCOL_ID_WORDS);
    hash.addU32(PROVED_COMPONENT_COUNT);
    hash.addU32(UNIVERSAL_ROSTER_COUNT);
    hash.addU32(RELATION_DOMAIN_COUNT);
    hash.sha(publication.catalog_sha_id);
    hash.sha(publication.relation_registry_sha_id);
    return hash.finalize();
}

pub fn expectedProfileId(
    publication: *const VerifiedSegmentV2PublicationV1,
) Digest {
    var hash = IdentityHasher.init(PROFILE_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addU32(PROVED_COMPONENT_COUNT);
    hash.addU32(UNIVERSAL_ROSTER_COUNT);
    hash.addU32(RELATION_DOMAIN_COUNT);
    hash.addU32(outer_admission.INTERACTION_POW_BITS);
    hash.addU32(outer_admission.PCS_POW_BITS);
    hash.addU32(outer_admission.LOG_BLOWUP_FACTOR);
    hash.addU32(outer_admission.QUERY_COUNT);
    hash.addU32(outer_admission.FOLD_STEP);
    hash.addU32(outer_admission.LOG_LAST_LAYER_DEGREE_BOUND);
    hash.digest(publication.manifest_id);
    return hash.finalize();
}

pub fn expectedClaimedSumsId(
    publication: *const VerifiedSegmentV2PublicationV1,
) Digest {
    var hash = IdentityHasher.init(CLAIMED_SUMS_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addU32(PROVED_COMPONENT_COUNT);
    hash.sha(publication.closure.claim_seal_sha_id);
    return hash.finalize();
}

pub fn expectedRelationReplayId(
    publication: *const VerifiedSegmentV2PublicationV1,
) Digest {
    const closure = &publication.closure;
    var hash = IdentityHasher.init(RELATION_REPLAY_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addU32(RELATION_DOMAIN_COUNT);
    hash.addU64(closure.checked_domain_mask);
    hash.addU64(closure.active_domain_mask);
    hash.addU64(closure.logical_rows);
    hash.addU64(closure.event_terms);
    hash.digest(publication.recursive_witness_id);
    hash.sha(closure.audit_sha_id);
    for (closure.domain_totals) |value| hash.qm31(value);
    hash.qm31(closure.framework_total);
    return hash.finalize();
}

pub fn expectedAuxiliaryClaimSealId(
    publication: *const VerifiedSegmentV2PublicationV1,
) Digest {
    var hash = IdentityHasher.init(AUXILIARY_CLAIM_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.sha(publication.cohort_authority_sha_id);
    hash.sha(publication.plan_sha_id);
    hash.sha(publication.closure.generated_interactions_sha_id);
    hash.digest(publication.manifest_id);
    return hash.finalize();
}

pub fn expectedVerifierContextId(
    publication: *const VerifiedSegmentV2PublicationV1,
) Digest {
    var hash = IdentityHasher.init(CONTEXT_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addU32(PUBLICATION_SCHEMA_VERSION);
    hash.addU32(STATEMENT_VERSION);
    hash.digest(protocol.PROTOCOL_ID_WORDS);
    hash.digest(publication.statement_id);
    hash.digest(publication.session_id);
    hash.digest(publication.job_id);
    hash.digest(publication.position_id);
    hash.digest(publication.segment_wire_id);
    hash.digest(publication.entry_lineage_id);
    hash.digest(publication.exit_lineage_id);
    hash.digest(publication.lineage_id);
    hash.digest(publication.source_context_id);
    hash.digest(publication.recursive_parent_vk_id);
    hash.digest(publication.verification_key_id);
    hash.addU32(publication.segment_index);
    hash.addU32(publication.segment_count);
    hash.addU32(publication.global_cycle_start);
    hash.addU32(publication.global_cycle_end);
    hash.addU32(publication.entry_continuation_root);
    hash.addU32(publication.exit_continuation_root);
    return hash.finalize();
}

/// The receipt identity deliberately excludes `closure_receipt_id`: the
/// temporal closure ID includes this verifier receipt, so including it here
/// would create a circular preimage.  It binds the exact closure evidence
/// directly instead.
pub fn expectedVerifierReceiptId(
    publication: *const VerifiedSegmentV2PublicationV1,
) Digest {
    const closure = &publication.closure;
    var hash = IdentityHasher.init(VERIFIER_RECEIPT_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.digest(publication.verifier_context_id);
    hash.digest(publication.air_program_id);
    hash.digest(publication.manifest_id);
    hash.digest(publication.profile_id);
    hash.digest(publication.proof_id);
    hash.digest(publication.capture_id);
    hash.digest(publication.recursive_witness_id);
    hash.digest(publication.transcript_id);
    hash.addU32(publication.canonical_proof_byte_count);
    hash.sha(publication.canonical_proof_sha_id);
    hash.digest(closure.claimed_sums_id);
    hash.digest(closure.relation_replay_id);
    hash.digest(closure.auxiliary_claim_seal_id);
    hash.addU64(closure.checked_component_mask);
    hash.addU64(closure.checked_domain_mask);
    hash.addU64(closure.active_domain_mask);
    hash.addU64(closure.logical_rows);
    hash.addU64(closure.event_terms);
    hash.sha(publication.prepared_leaf_sha_id);
    hash.sha(publication.cohort_authority_sha_id);
    hash.sha(publication.manifest_sha_id);
    hash.sha(publication.catalog_sha_id);
    hash.sha(publication.relation_registry_sha_id);
    hash.sha(publication.plan_sha_id);
    hash.sha(closure.generated_interactions_sha_id);
    hash.sha(closure.claim_seal_sha_id);
    hash.sha(closure.audit_sha_id);
    for (closure.domain_totals) |value| hash.qm31(value);
    hash.qm31(closure.framework_total);
    return hash.finalize();
}

pub fn expectedTemporalClosureId(
    closure: *const VerifiedClosureReceiptV1,
) Error!Digest {
    // `closureReceiptId` consumes only these five fields.  Zero-initializing
    // the remaining pointer-free record avoids duplicating its protocol hash.
    var child = std.mem.zeroes(temporal.VerifiedChildV2);
    child.roster_count = closure.universal_roster_count;
    child.verifier_receipt_id = closure.verifier_receipt_id;
    child.claimed_sums_id = closure.claimed_sums_id;
    child.relation_replay_id = closure.relation_replay_id;
    child.auxiliary_claim_seal_id = closure.auxiliary_claim_seal_id;
    child.closure_value = closure.framework_total;
    return temporal.closureReceiptId(&child);
}

pub fn expectedPublicationId(
    publication: *const VerifiedSegmentV2PublicationV1,
) Digest {
    var hash = IdentityHasher.init(PUBLICATION_ID_DOMAIN);
    hash.addU32(publication.format_version);
    hash.addU32(publication.publication_schema_version);
    hash.addU32(publication.statement_version);
    hash.addU32(@intFromEnum(publication.source_scope));
    hash.addU32(@intFromEnum(publication.proof_kind));
    hash.addU32(@intFromEnum(publication.proof_encoding));
    hash.addU32(@intFromBool(publication.outer_stark_verified));
    hash.addU32(@intFromBool(publication.complete_segment_child));
    hash.addU32(@intFromBool(publication.complete_parent_capability));
    hash.addU64(publication.proof_size_estimate);
    hash.addU32(publication.canonical_proof_byte_count);
    hash.addU32(publication.segment_index);
    hash.addU32(publication.segment_count);
    hash.addU32(publication.global_cycle_start);
    hash.addU32(publication.global_cycle_end);
    hash.addU32(publication.entry_continuation_root);
    hash.addU32(publication.exit_continuation_root);
    hash.digest(publication.statement_id);
    hash.digest(publication.session_id);
    hash.digest(publication.job_id);
    hash.digest(publication.position_id);
    hash.digest(publication.segment_wire_id);
    hash.digest(publication.entry_lineage_id);
    hash.digest(publication.exit_lineage_id);
    hash.digest(publication.lineage_id);
    hash.digest(publication.source_context_id);
    hash.digest(publication.recursive_parent_vk_id);
    hash.digest(publication.verification_key_id);
    hash.digest(publication.air_program_id);
    hash.digest(publication.manifest_id);
    hash.digest(publication.profile_id);
    hash.digest(publication.capture_id);
    hash.digest(publication.recursive_witness_id);
    hash.digest(publication.transcript_id);
    hash.digest(publication.verifier_context_id);
    hash.digest(publication.proof_id);
    hash.sha(publication.canonical_proof_sha_id);
    hash.sha(publication.prepared_leaf_sha_id);
    hash.sha(publication.cohort_authority_sha_id);
    hash.sha(publication.manifest_sha_id);
    hash.sha(publication.catalog_sha_id);
    hash.sha(publication.relation_registry_sha_id);
    hash.sha(publication.plan_sha_id);
    hash.digest(publication.closure.verifier_receipt_id);
    hash.digest(publication.closure.claimed_sums_id);
    hash.digest(publication.closure.relation_replay_id);
    hash.digest(publication.closure.auxiliary_claim_seal_id);
    hash.digest(publication.closure.closure_receipt_id);
    return hash.finalize();
}

fn statementId(words: *const span_statement.StatementWords) Error!Digest {
    _ = try span_statement.SpanStatement.fromCanonicalWords(words);
    var canonical: [span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 = undefined;
    for (&canonical, words) |*destination, word| {
        const value = word.toU32();
        if (value >= m31.Modulus) return error.NonCanonicalField;
        destination.* = value;
    }
    return protocol.statementId(&canonical);
}

fn requireDigest(value: Digest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.NonCanonicalDigest;
        aggregate |= word;
    }
    if (aggregate == 0) return error.NonCanonicalDigest;
}

fn requireSha256Digest(value: Sha256Digest) Error!void {
    if (allZeroBytes(&value)) return error.EmptySha256Digest;
}

fn requireZeroQm31(value: Qm31Words) Error!void {
    for (value) |word| {
        if (word >= m31.Modulus) return error.NonCanonicalField;
        if (word != 0) return error.InvalidClosure;
    }
}

fn allZeroBytes(bytes: []const u8) bool {
    var aggregate: u8 = 0;
    for (bytes) |byte| aggregate |= byte;
    return aggregate == 0;
}

const IdentityHasher = struct {
    inner: channel.CanonicalWordHasher,

    fn init(domain: u32) IdentityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    fn addU32(self: *IdentityHasher, value: anytype) void {
        const exact: u32 = @intCast(value);
        std.debug.assert(exact < m31.Modulus);
        const words = [_]M31{M31.fromCanonical(exact)};
        self.inner.update(&words);
    }

    fn addU64(self: *IdentityHasher, value: u64) void {
        self.addU32(@as(u32, @truncate(value & 0xffff)));
        self.addU32(@as(u32, @truncate((value >> 16) & 0xffff)));
        self.addU32(@as(u32, @truncate((value >> 32) & 0xffff)));
        self.addU32(@as(u32, @truncate(value >> 48)));
    }

    fn addUsize(self: *IdentityHasher, value: usize) void {
        std.debug.assert(value <= std.math.maxInt(u32));
        self.addU32(@as(u32, @intCast(value)));
    }

    fn digest(self: *IdentityHasher, value: Digest) void {
        for (value) |word| self.addU32(word);
    }

    fn sha(self: *IdentityHasher, value: Sha256Digest) void {
        self.digest(channel.hashBytes(&value, MANIFEST_ID_DOMAIN));
    }

    fn qm31(self: *IdentityHasher, value: Qm31Words) void {
        for (value) |word| self.addU32(word);
    }

    fn fieldQm31(self: *IdentityHasher, value: QM31) void {
        self.inner.update(&value.toM31Array());
    }

    fn finalize(self: *IdentityHasher) Digest {
        return self.inner.finalize();
    }
};

fn assertPointerFree(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer, .optional => @compileError("verifier publication retains a pointer"),
        .array => |array| assertPointerFree(array.child),
        .@"struct" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        .@"union" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        else => {},
    }
}

comptime {
    if (PROVED_COMPONENT_COUNT != 39 or UNIVERSAL_ROSTER_COUNT != 36 or
        RELATION_DOMAIN_COUNT != 47 or !POINTER_FREE_PUBLICATION or
        !SUCCESSFUL_VERIFIER_TRANSACTION_REQUIRED or
        PUBLIC_MINT_CONSTRUCTOR_AVAILABLE or
        !COMPLETE_SEGMENT_CHILD_CAPABILITY or COMPLETE_PARENT_CAPABILITY or
        !RECURSIVE_WITNESS_REQUIRED or
        HEAP_ALLOCATIONS_PER_VALIDATE != 0 or
        HEAP_ALLOCATIONS_PER_PUBLICATION != 0 or
        BORROWED_STORAGE_AFTER_PUBLICATION)
    {
        @compileError("SegmentV2 verified-publication capability ABI drifted");
    }
    assertPointerFree(VerifiedClosureReceiptV1);
    assertPointerFree(VerifiedSegmentV2PublicationV1);
}

test "SegmentV2 verified publication exposes no public mint constructor" {
    try std.testing.expect(!@hasDecl(
        VerifiedSegmentV2PublicationV1,
        "init",
    ));
    try std.testing.expect(!@hasDecl(
        VerifiedSegmentV2PublicationV1,
        "publishInto",
    ));
    try std.testing.expect(!@hasDecl(@This(), "mint"));
    try std.testing.expect(POINTER_FREE_PUBLICATION);
    try std.testing.expect(SUCCESSFUL_VERIFIER_TRANSACTION_REQUIRED);
}
