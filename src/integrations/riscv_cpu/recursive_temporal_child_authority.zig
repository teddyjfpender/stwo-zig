//! Fail-closed custody bridge from one independently verified outer proof to
//! the V2 temporal-recursion child record.
//!
//! The bridge has two deliberately separate operations:
//!
//! * `inspectInto` validates the complete `VerifiedOuterProofV1`, re-derives
//!   the canonical outer-wire proof identity from that verifier publication,
//!   compares every shared candidate identity, validates the fixed wire, and
//!   publishes only fields that are already verifier-authenticated.
//! * `preflightClosureReceiptV2Into` validates the pointer-free 36-row closure
//!   receipt and publishes its exact SHA metadata without relabelling that
//!   native reconstruction as successful-verifier custody.
//! * `publishCurrentInto` additionally requires a production `complete_parent`
//!   proof. It cannot publish a `VerifiedChildV2` today because no successful
//!   binary verifier publishes the closure receipt or the native Poseidon
//!   temporal context. Child position is not caller context: it is derived
//!   canonically from the verifier-bound span slot.
//!
//! In particular, there is no API that accepts those missing values from a
//! caller and hashes them into apparent authority. The global-closure seam's
//! `[32]u8` SHA identities are not reinterpreted as the temporal protocol's
//! `[poseidon2_channel.RATE]u32` digest. A later successful-verifier receipt
//! must publish both identity families explicitly before a constructor may
//! consume it.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const outer = @import("recursive_fri_outer.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const admission = recursion.outer_parent_child_admission;
const fixed_wire = recursion.fixed_wire;
const global_closure = recursion.binary_global_closure_outer_source;
const temporal = recursion.temporal_pair_node;

pub const FORMAT_VERSION: u16 = 1;
pub const REQUIRED_CONTEXT_FORMAT_VERSION: u16 = 2;
pub const CLOSURE_PREFLIGHT_FORMAT_VERSION: u16 = 2;
pub const ROSTER_COUNT: usize = admission.CLAIMED_SUM_COUNT;
pub const GLOBAL_CLOSURE_DIGEST_BYTE_COUNT: usize = 32;
pub const NATIVE_TEMPORAL_DIGEST_WORD_COUNT: usize =
    recursion.poseidon2_channel.RATE;

pub const HEAP_ALLOCATIONS_PER_INSPECT: usize = 0;
pub const HEAP_ALLOCATIONS_PER_PUBLISH: usize = 0;
pub const HEAP_ALLOCATIONS_PER_CLOSURE_PREFLIGHT: usize = 0;
/// `VerifiedOuterProofV1.validateAndReplayRelations` and
/// `proofIdRuntime` each independently validate the capture. The second pass
/// is currently necessary: the fixed-wire proof ID must be tied to the exact
/// verifier capture, rather than merely to a caller-provided candidate header.
pub const CAPTURE_VALIDATION_PASSES_PER_INSPECT: usize = 2;

pub const PROTOCOL_SUBSTRATE_ONLY = true;
pub const VERIFIED_CHILD_PUBLICATION_AVAILABLE = false;
pub const AUTHENTICATED_TEMPORAL_CONTEXT_AVAILABLE = false;
pub const CLOSURE_RECEIPT_V2_PREFLIGHT_AVAILABLE = true;
pub const VERIFIED_COHORT_RECEIPT_AVAILABLE = false;
pub const NATIVE_TEMPORAL_DIGEST_PUBLICATION_AVAILABLE = false;
/// B1 is already live in the native proof transcript: `PublicData.mixInto`
/// absorbs the RVST domain and statement version before either commitment,
/// the VM profile binds the same pair, and the recursive leaf protocol aliases
/// that exact version.  It is therefore verifier-bound rather than a missing
/// caller context field.
pub const B1_STATEMENT_VERSION_TRANSCRIPT_BOUND =
    frontend.air.public_data.STATEMENT_TRANSCRIPT_VERSION ==
    recursion.protocol.LEAF_STATEMENT_VERSION;

comptime {
    if (!B1_STATEMENT_VERSION_TRANSCRIPT_BOUND)
        @compileError("native and recursive statement versions diverged");
}

pub const Error = error{
    AliasedWorkspace,
    AuthenticatedTemporalContextUnavailable,
    CandidatePublicationMismatch,
    CompleteParentProofUnavailable,
    EmptyStatementProof,
    GlobalClosureMismatch,
    NativeTemporalDigestPublicationUnavailable,
    VerifiedCohortReceiptUnavailable,
    WireClosureMismatch,
};

/// Machine-readable readiness ledger. A green structural adapter is not a
/// production recursive child unless every authority bit below is true.
pub const CapabilitiesV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    verified_outer_publication: bool,
    canonical_wire_admission: bool,
    statement_binding: bool,
    job_derivation: bool,
    whole_roster_closure: bool,
    complete_parent_prover_and_verifier: bool,
    statement_version_transcript_binding: bool,
    child_position_context_binding: bool,
    session_context_binding: bool,
    recursive_parent_vk_context_binding: bool,
    lineage_context_binding: bool,
    closure_receipt_v2_preflight: bool,
    closure_receipt_v2_verifier_custody: bool,
    native_temporal_digest_publication: bool,

    pub fn ready(self: CapabilitiesV1) bool {
        return self.format_version == FORMAT_VERSION and
            self.verified_outer_publication and
            self.canonical_wire_admission and
            self.statement_binding and
            self.job_derivation and
            self.whole_roster_closure and
            self.complete_parent_prover_and_verifier and
            self.statement_version_transcript_binding and
            self.child_position_context_binding and
            self.session_context_binding and
            self.recursive_parent_vk_context_binding and
            self.lineage_context_binding and
            self.closure_receipt_v2_preflight and
            self.closure_receipt_v2_verifier_custody and
            self.native_temporal_digest_publication;
    }
};

pub const CURRENT_CAPABILITIES = CapabilitiesV1{
    .verified_outer_publication = true,
    .canonical_wire_admission = true,
    .statement_binding = true,
    .job_derivation = true,
    .whole_roster_closure = true,
    .complete_parent_prover_and_verifier = admission.RECURSIVE_PARENT_PRODUCTION,
    .statement_version_transcript_binding = B1_STATEMENT_VERSION_TRANSCRIPT_BOUND,
    .child_position_context_binding = true,
    .session_context_binding = false,
    .recursive_parent_vk_context_binding = false,
    .lineage_context_binding = false,
    .closure_receipt_v2_preflight = true,
    .closure_receipt_v2_verifier_custody = false,
    .native_temporal_digest_publication = false,
};

/// Allocation-free structural result for a V2 global-closure receipt. Every
/// byte identity is retained in its native SHA representation. This is useful
/// for diagnostics and for defining the exact future verifier handoff; it is
/// deliberately not a temporal-child authority token.
pub const ClosureReceiptPreflightV2 = struct {
    format_version: u16 = CLOSURE_PREFLIGHT_FORMAT_VERSION,
    verifier_custody: bool = false,
    temporal_context_available: bool = false,
    source_authority_id: [GLOBAL_CLOSURE_DIGEST_BYTE_COUNT]u8,
    input_id: [GLOBAL_CLOSURE_DIGEST_BYTE_COUNT]u8,
    closure_id: [GLOBAL_CLOSURE_DIGEST_BYTE_COUNT]u8,
    context_seam_id: [GLOBAL_CLOSURE_DIGEST_BYTE_COUNT]u8,
    wire_source_authority_id: [GLOBAL_CLOSURE_DIGEST_BYTE_COUNT]u8,
    wire_snapshot_id: [GLOBAL_CLOSURE_DIGEST_BYTE_COUNT]u8,
    wire_tuple_provenance_id: [GLOBAL_CLOSURE_DIGEST_BYTE_COUNT]u8,
    wire_tuple_count: u32,
    verifier_input_source_authority_id: [GLOBAL_CLOSURE_DIGEST_BYTE_COUNT]u8,
    verifier_input_snapshot_id: [GLOBAL_CLOSURE_DIGEST_BYTE_COUNT]u8,
    verifier_input_tuple_provenance_id: [GLOBAL_CLOSURE_DIGEST_BYTE_COUNT]u8,
    verifier_input_tuple_count: u32,

    pub fn temporalPublicationReady(self: *const ClosureReceiptPreflightV2) bool {
        return VERIFIED_COHORT_RECEIPT_AVAILABLE and
            NATIVE_TEMPORAL_DIGEST_PUBLICATION_AVAILABLE and
            self.format_version == CLOSURE_PREFLIGHT_FORMAT_VERSION and
            self.verifier_custody and
            self.temporal_context_available;
    }
};

/// Validates a raw V2 global-closure receipt without converting its SHA byte
/// identities into Poseidon field digests. The destination is unchanged on
/// every error and the hot path allocates no memory.
pub fn preflightClosureReceiptV2Into(
    destination: *ClosureReceiptPreflightV2,
    receipt: *const global_closure.ClosureReceiptV2,
) !void {
    if (overlap(std.mem.asBytes(destination), std.mem.asBytes(receipt)))
        return error.AliasedWorkspace;
    try receipt.validate();

    // `validate` currently proves that this seam is the canonical unavailable
    // value. Do not call `requireTemporalContext` and then reinterpret its
    // byte arrays: even a future authenticated byte seam is not the native
    // temporal digest publication required by `VerifiedChildV2`.
    const boundaries = &receipt.public_boundaries;
    const staged = ClosureReceiptPreflightV2{
        .source_authority_id = receipt.source_authority_id,
        .input_id = receipt.input_id,
        .closure_id = receipt.closure_id,
        .context_seam_id = receipt.context_seam.identity,
        .wire_source_authority_id = boundaries.wire.source_authority_id,
        .wire_snapshot_id = boundaries.wire.snapshot_id,
        .wire_tuple_provenance_id = boundaries.wire.tuple_provenance_id,
        .wire_tuple_count = boundaries.wire.tuple_count,
        .verifier_input_source_authority_id = boundaries.verifier_input.source_authority_id,
        .verifier_input_snapshot_id = boundaries.verifier_input.snapshot_id,
        .verifier_input_tuple_provenance_id = boundaries.verifier_input.tuple_provenance_id,
        .verifier_input_tuple_count = boundaries.verifier_input.tuple_count,
    };
    destination.* = staged;
}

/// Exact preimage required from a future verifier-authenticated temporal
/// context. This is a protocol contract, not a current authority token.
///
/// A V2 outer receipt must publish and seal `authenticated_context_id`; the
/// digest preimage must include every other field below plus the verified
/// statement identity. Merely constructing this value or hashing it locally
/// must never make it admissible.
pub const RequiredContextV2 = struct {
    format_version: u16 = REQUIRED_CONTEXT_FORMAT_VERSION,
    statement_version: u32,
    session_id: temporal.Digest,
    recursive_parent_vk_id: temporal.Digest,
    lineage_id: temporal.Digest,
    statement_id: temporal.Digest,
    authenticated_context_id: temporal.Digest,
};

/// Schema the successful 36-row verifier must publish transactionally before
/// temporal admission can be enabled. No constructor or consumer of this type
/// exists today. In particular, the native Poseidon digests are separate from
/// the SHA identities retained by `closure_receipt`.
pub const RequiredSuccessfulVerifierPublicationV2 = struct {
    format_version: u16 = REQUIRED_CONTEXT_FORMAT_VERSION,
    statement_version: u32,
    source_scope: admission.ProofScope,
    proof_id: temporal.Digest,
    cohort_id: temporal.Digest,
    statement_id: temporal.Digest,
    job_id: temporal.Digest,
    session_id: temporal.Digest,
    recursive_parent_vk_id: temporal.Digest,
    lineage_id: temporal.Digest,
    authenticated_context_id: temporal.Digest,
    closure_receipt_sha_id: [GLOBAL_CLOSURE_DIGEST_BYTE_COUNT]u8,
    closure_receipt: global_closure.ClosureReceiptV2,
};

/// The complete subset of `VerifiedChildV2` that can be derived without any
/// caller-selected temporal context. `source_scope` remains the outer scope;
/// it is intentionally not relabelled as `complete_execution`.
pub const DerivedVerifierFieldsV1 = struct {
    source_scope: admission.ProofScope,
    kind: temporal.ProofKind,
    position: temporal.ChildPosition,
    roster_count: u8,
    statement_version: u32,
    statement_id: temporal.Digest,
    job_id: temporal.Digest,
    verification_key_id: temporal.Digest,
    air_program_id: temporal.Digest,
    manifest_id: temporal.Digest,
    profile_id: temporal.Digest,
    statement_words: recursion.span_statement.StatementWords,
    proof_id: temporal.Digest,
    transcript_id: temporal.Digest,
    capture_id: temporal.Digest,
    verifier_receipt_id: temporal.Digest,
    claimed_sums_id: temporal.Digest,
    relation_replay_id: temporal.Digest,
    auxiliary_claim_seal_id: temporal.Digest,
    closure_receipt_id: temporal.Digest,
    closure_value: fixed_wire.Qm31Wire,
};

/// Validates and derives every field currently available from verifier
/// custody. The destination remains byte-for-byte unchanged on every error.
/// `encoding_scratch` is the exact canonical-wire byte count and is the only
/// mutable workspace; this function performs no allocation.
pub fn inspectInto(
    comptime dimensions: fixed_wire.Dimensions,
    destination: *DerivedVerifierFieldsV1,
    encoding_scratch: []u8,
    verified: *const outer.VerifiedOuterProofV1,
    wire: *const admission.FixedOuterProofWireV1(dimensions),
    candidate: *const admission.BinaryPairCandidateV1,
) !void {
    dimensions.validate();
    try validateWorkspace(
        std.mem.asBytes(destination),
        encoding_scratch,
        verified,
        std.mem.asBytes(wire),
        std.mem.asBytes(candidate),
    );

    _ = try verified.validateAndReplayRelations();
    try candidate.validate();
    try validateCandidatePublicationBinding(verified, candidate);

    const expected_proof_id = try admission.proofIdRuntime(
        verified.seal,
        &verified.receipt,
        &verified.capture,
    );
    if (!std.meta.eql(expected_proof_id, candidate.proof_id))
        return error.CandidatePublicationMismatch;

    const statement = try recursion.span_statement.SpanStatement
        .fromCanonicalWords(&verified.statement_words);
    const kind: temporal.ProofKind = switch (statement.body) {
        .empty => return error.EmptyStatementProof,
        .executed => if (statement.slots.height == 0)
            .segment_leaf
        else
            .binary_node,
    };
    const closure_value = try checkedClosure(&verified.receipt);

    var staged = DerivedVerifierFieldsV1{
        .source_scope = verified.receipt.scope,
        .kind = kind,
        .position = try temporal.positionForNextParent(statement),
        .roster_count = @intCast(ROSTER_COUNT),
        .statement_version = recursion.protocol.LEAF_STATEMENT_VERSION,
        .statement_id = verified.receipt.statement_id,
        .job_id = try temporal.jobId(&verified.statement_words),
        .verification_key_id = verified.receipt.verification_key_id,
        .air_program_id = verified.receipt.air_program_id,
        .manifest_id = verified.receipt.manifest_id,
        .profile_id = candidate.profile_id,
        .statement_words = verified.statement_words,
        .proof_id = candidate.proof_id,
        .transcript_id = verified.seal.transcript_id,
        .capture_id = verified.seal.capture_id,
        .verifier_receipt_id = verified.seal.receipt_id,
        .claimed_sums_id = verified.seal.claimed_sums_id,
        .relation_replay_id = verified.relation_replay.identity,
        .auxiliary_claim_seal_id = verified.auxiliary_claim_seal.digest,
        .closure_receipt_id = undefined,
        .closure_value = closure_value,
    };
    staged.closure_receipt_id = try deriveClosureReceiptId(&staged);

    // `validateAgainst` performs all fallible payload work before writing its
    // canonical encoding. Keep it last so rejected metadata never dirties the
    // caller's scratch buffer either.
    try wire.validateAgainst(candidate, encoding_scratch);
    destination.* = staged;
}

/// Current fail-closed publication seam. It intentionally has no temporal
/// context argument: V1 has no verifier-bound context digest against which
/// such an argument could be authenticated.
pub fn publishCurrentInto(
    comptime dimensions: fixed_wire.Dimensions,
    destination: *temporal.VerifiedChildV2,
    derived_scratch: *DerivedVerifierFieldsV1,
    encoding_scratch: []u8,
    verified: *const outer.VerifiedOuterProofV1,
    wire: *const admission.FixedOuterProofWireV1(dimensions),
    candidate: *const admission.BinaryPairCandidateV1,
) !void {
    dimensions.validate();
    try validateWorkspace(
        std.mem.asBytes(destination),
        encoding_scratch,
        verified,
        std.mem.asBytes(wire),
        std.mem.asBytes(candidate),
    );
    if (overlap(std.mem.asBytes(destination), std.mem.asBytes(derived_scratch)) or
        overlap(std.mem.asBytes(derived_scratch), encoding_scratch) or
        overlap(std.mem.asBytes(derived_scratch), std.mem.asBytes(verified)) or
        overlap(std.mem.asBytes(derived_scratch), std.mem.asBytes(wire)) or
        overlap(std.mem.asBytes(derived_scratch), std.mem.asBytes(candidate)) or
        captureStorageOverlaps(
            std.mem.asBytes(derived_scratch),
            &verified.capture,
        ))
    {
        return error.AliasedWorkspace;
    }

    try inspectInto(
        dimensions,
        derived_scratch,
        encoding_scratch,
        verified,
        wire,
        candidate,
    );
    if (derived_scratch.source_scope != .complete_parent or
        candidate.scope != .complete_parent or
        !verified.productionReady() or
        !candidate.productionReady())
    {
        return error.CompleteParentProofUnavailable;
    }

    // The only path reaching this point after a future complete-parent
    // activation still lacks a proof-bound RequiredContextV2 publication.
    // Do not accept session/VK/lineage values beside the proof.
    return error.AuthenticatedTemporalContextUnavailable;
}

/// Strict landing point for the V2 global-closure shape. A raw receipt is
/// fully preflighted, but cannot be promoted into verifier custody. This API
/// therefore has no success path until the binary verifier exposes a
/// `RequiredSuccessfulVerifierPublicationV2`-equivalent transaction and the
/// temporal digest fields are native proof publications.
///
/// `destination` remains byte-for-byte unchanged on every current path.
/// `encoding_scratch` is ordinary canonical-wire workspace and may contain the
/// wire encoding after a successful structural preflight.
pub fn publishFromRawClosureV2Into(
    comptime dimensions: fixed_wire.Dimensions,
    destination: *temporal.VerifiedChildV2,
    encoding_scratch: []u8,
    verified: *const outer.VerifiedOuterProofV1,
    wire: *const admission.FixedOuterProofWireV1(dimensions),
    candidate: *const admission.BinaryPairCandidateV1,
    closure_receipt: *const global_closure.ClosureReceiptV2,
) !void {
    dimensions.validate();
    try validateClosureWorkspace(
        std.mem.asBytes(destination),
        encoding_scratch,
        verified,
        std.mem.asBytes(wire),
        std.mem.asBytes(candidate),
        closure_receipt,
    );

    var derived: DerivedVerifierFieldsV1 = undefined;
    try inspectInto(
        dimensions,
        &derived,
        encoding_scratch,
        verified,
        wire,
        candidate,
    );
    var closure_preflight: ClosureReceiptPreflightV2 = undefined;
    try preflightClosureReceiptV2Into(&closure_preflight, closure_receipt);
    std.debug.assert(!closure_preflight.temporalPublicationReady());

    // The naked receipt is intentionally insufficient even if its structural
    // closure is valid. It was not issued transactionally by the successful
    // 36-row verifier and carries no native temporal digests.
    return error.VerifiedCohortReceiptUnavailable;
}

fn validateCandidatePublicationBinding(
    verified: *const outer.VerifiedOuterProofV1,
    candidate: *const admission.BinaryPairCandidateV1,
) !void {
    const receipt = &verified.receipt;
    const shape = candidate.shape;
    if (candidate.scope != receipt.scope or
        shape.scope != receipt.scope or
        !std.meta.eql(shape.air_program_id, receipt.air_program_id) or
        !std.meta.eql(shape.manifest_id, receipt.manifest_id) or
        !std.meta.eql(shape.statement_id, receipt.statement_id) or
        !std.meta.eql(
            shape.verification_key_id,
            receipt.verification_key_id,
        ) or
        !std.meta.eql(shape.component_log_sizes, receipt.component_log_sizes) or
        !std.meta.eql(candidate.profile_id, verified.seal.profile_id) or
        !std.meta.eql(candidate.capture_id, verified.seal.capture_id) or
        !std.meta.eql(candidate.receipt_id, verified.seal.receipt_id) or
        !std.meta.eql(candidate.transcript_id, verified.seal.transcript_id) or
        !std.meta.eql(candidate.claimed_sums_id, verified.seal.claimed_sums_id) or
        !std.meta.eql(
            candidate.verifier_input_boundary,
            verified.seal.verifier_input_boundary,
        ))
    {
        return error.CandidatePublicationMismatch;
    }
}

fn checkedClosure(
    receipt: *const admission.VerifierReceiptV1,
) !fixed_wire.Qm31Wire {
    // The native verifier checks these two independent equations. Recheck
    // them at the trust boundary so a detached but self-consistent receipt
    // cannot be reinterpreted as temporal whole-execution closure.
    const wire_total = qm31FromCanonicalWire(receipt.wire_closure[0]).add(
        qm31FromCanonicalWire(receipt.wire_closure[1]),
    );
    if (!wire_total.isZero()) return error.WireClosureMismatch;

    var global_total = qm31FromCanonicalWire(
        receipt.verifier_input_boundary,
    ).add(qm31FromCanonicalWire(receipt.wire_closure[1]));
    for (receipt.claimed_sums) |claim|
        global_total = global_total.add(qm31FromCanonicalWire(claim));
    if (!global_total.isZero()) return error.GlobalClosureMismatch;
    return .{ 0, 0, 0, 0 };
}

fn deriveClosureReceiptId(
    fields: *const DerivedVerifierFieldsV1,
) !temporal.Digest {
    const zero_digest: temporal.Digest =
        [_]u32{0} ** recursion.poseidon2_channel.RATE;
    var child = temporal.VerifiedChildV2{
        .position = .left,
        .kind = fields.kind,
        .scope = .complete_execution,
        .proof_present = true,
        .roster_count = fields.roster_count,
        .session_id = zero_digest,
        .job_id = fields.job_id,
        .recursive_parent_vk_id = zero_digest,
        .verification_key_id = fields.verification_key_id,
        .air_program_id = fields.air_program_id,
        .manifest_id = fields.manifest_id,
        .profile_id = fields.profile_id,
        .statement_words = fields.statement_words,
        .proof_id = fields.proof_id,
        .transcript_id = fields.transcript_id,
        .capture_id = fields.capture_id,
        .verifier_receipt_id = fields.verifier_receipt_id,
        .claimed_sums_id = fields.claimed_sums_id,
        .relation_replay_id = fields.relation_replay_id,
        .auxiliary_claim_seal_id = fields.auxiliary_claim_seal_id,
        .closure_receipt_id = zero_digest,
        .lineage_id = zero_digest,
        .closure_value = fields.closure_value,
    };
    child.closure_receipt_id = try temporal.closureReceiptId(&child);
    return child.closure_receipt_id;
}

fn qm31FromCanonicalWire(value: fixed_wire.Qm31Wire) QM31 {
    return QM31.fromM31Array(.{
        M31.fromCanonical(value[0]),
        M31.fromCanonical(value[1]),
        M31.fromCanonical(value[2]),
        M31.fromCanonical(value[3]),
    });
}

fn validateWorkspace(
    destination: []const u8,
    encoding_scratch: []u8,
    verified: *const outer.VerifiedOuterProofV1,
    wire: []const u8,
    candidate: []const u8,
) !void {
    const verified_inline = std.mem.asBytes(verified);
    if (overlap(destination, encoding_scratch) or
        overlap(destination, verified_inline) or
        overlap(destination, wire) or
        overlap(destination, candidate) or
        overlap(encoding_scratch, verified_inline) or
        overlap(encoding_scratch, wire) or
        overlap(encoding_scratch, candidate) or
        captureStorageOverlaps(destination, &verified.capture) or
        captureStorageOverlaps(encoding_scratch, &verified.capture))
    {
        return error.AliasedWorkspace;
    }
}

fn validateClosureWorkspace(
    destination: []const u8,
    encoding_scratch: []u8,
    verified: *const outer.VerifiedOuterProofV1,
    wire: []const u8,
    candidate: []const u8,
    closure_receipt: *const global_closure.ClosureReceiptV2,
) !void {
    try validateWorkspace(
        destination,
        encoding_scratch,
        verified,
        wire,
        candidate,
    );
    const closure_bytes = std.mem.asBytes(closure_receipt);
    if (overlap(destination, closure_bytes) or
        overlap(encoding_scratch, closure_bytes) or
        overlap(std.mem.asBytes(verified), closure_bytes) or
        overlap(wire, closure_bytes) or
        overlap(candidate, closure_bytes) or
        captureStorageOverlaps(closure_bytes, &verified.capture))
    {
        return error.AliasedWorkspace;
    }
}

fn captureStorageOverlaps(
    target: []const u8,
    capture: *const outer.OuterProofCapture,
) bool {
    if (overlap(target, std.mem.asBytes(capture)) or
        overlap(target, std.mem.sliceAsBytes(capture.queries.raw)) or
        overlap(target, std.mem.sliceAsBytes(capture.queries.unique)) or
        overlap(target, std.mem.sliceAsBytes(capture.commitments)) or
        overlap(target, std.mem.sliceAsBytes(capture.column_log_sizes)) or
        overlap(target, std.mem.sliceAsBytes(capture.sampled_points)) or
        overlap(target, std.mem.sliceAsBytes(capture.sampled_values)) or
        overlap(target, std.mem.sliceAsBytes(capture.queried_values)) or
        overlap(target, std.mem.sliceAsBytes(capture.deep_answers)) or
        overlap(target, std.mem.sliceAsBytes(capture.trace_paths)) or
        overlap(target, std.mem.sliceAsBytes(capture.fri.layers)) or
        overlap(
            target,
            std.mem.sliceAsBytes(capture.last_layer_coefficients),
        ))
    {
        return true;
    }
    for (capture.column_log_sizes) |logs|
        if (overlap(target, std.mem.sliceAsBytes(logs))) return true;
    for (capture.sampled_points) |columns| {
        if (overlap(target, std.mem.sliceAsBytes(columns))) return true;
        for (columns) |points|
            if (overlap(target, std.mem.sliceAsBytes(points))) return true;
    }
    for (capture.trace_paths) |path| {
        if (overlap(target, std.mem.sliceAsBytes(path.positions)) or
            overlap(target, std.mem.sliceAsBytes(path.siblings))) return true;
    }
    for (capture.fri.layers) |layer| {
        if (overlap(target, std.mem.sliceAsBytes(layer.positions)) or
            overlap(target, std.mem.sliceAsBytes(layer.values)) or
            overlap(target, std.mem.sliceAsBytes(layer.siblings))) return true;
    }
    return false;
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

comptime {
    if (FORMAT_VERSION != 1 or REQUIRED_CONTEXT_FORMAT_VERSION != 2 or
        CLOSURE_PREFLIGHT_FORMAT_VERSION != 2 or
        ROSTER_COUNT != temporal.COMPLETE_ROSTER_COUNT or
        HEAP_ALLOCATIONS_PER_INSPECT != 0 or
        HEAP_ALLOCATIONS_PER_PUBLISH != 0 or
        HEAP_ALLOCATIONS_PER_CLOSURE_PREFLIGHT != 0 or
        CAPTURE_VALIDATION_PASSES_PER_INSPECT != 2 or
        !PROTOCOL_SUBSTRATE_ONLY or VERIFIED_CHILD_PUBLICATION_AVAILABLE or
        AUTHENTICATED_TEMPORAL_CONTEXT_AVAILABLE or
        !CLOSURE_RECEIPT_V2_PREFLIGHT_AVAILABLE or
        VERIFIED_COHORT_RECEIPT_AVAILABLE or
        NATIVE_TEMPORAL_DIGEST_PUBLICATION_AVAILABLE or
        !B1_STATEMENT_VERSION_TRANSCRIPT_BOUND or CURRENT_CAPABILITIES.ready())
    {
        @compileError("temporal child custody boundary drifted");
    }
    if (temporal.Digest != [NATIVE_TEMPORAL_DIGEST_WORD_COUNT]u32 or
        @TypeOf(@as(global_closure.RequiredContextV2, undefined).session_id) !=
            [GLOBAL_CLOSURE_DIGEST_BYTE_COUNT]u8 or
        @TypeOf(@as(global_closure.ClosureReceiptV2, undefined).closure_id) !=
            [GLOBAL_CLOSURE_DIGEST_BYTE_COUNT]u8)
    {
        @compileError("SHA metadata and native temporal digest types drifted");
    }
}
