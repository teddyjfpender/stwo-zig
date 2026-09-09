//! Verifier-transaction publication helpers for recursively closed nodes.
//!
//! This module owns no proof authority. Its inputs include the opaque success
//! evidence minted by the native verifier after proof capture and closure
//! replay; it only projects that authenticated transaction into the stable V3
//! temporal publication used by the next level.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const binary_driver = @import("recursive_binary_outer.zig");
const canonical_proof = @import("recursive_binary_verified_publication.zig");
const segment_publication = @import("recursive_segment_v2_verified_publication.zig");
const publication_mod = @import("recursive_temporal_parent_publication_v3.zig");
const cohort_support = @import("recursive_temporal_parent_cohort_support.zig");
const Digest = frontend.recursion.poseidon2_channel.Digest;

pub fn verifierSuccessBinding(
    cohort: anytype,
    proof: canonical_proof.CanonicalProofIdentityV1,
    capture: *const binary_driver.OuterProofCapture,
    transcript_id: Digest,
    claims: anytype,
    audited: anytype,
    recursive_admission_sha_id: [32]u8,
) !binary_driver.TemporalVerifierSuccessBindingV1 {
    try cohort.validate();
    try proof.validate();
    try claims.validate(cohort.manifest());
    if (capture.commitments.len == 0 or capture.queries.raw.len == 0)
        return error.InvalidPublication;
    const result = binary_driver.TemporalVerifierSuccessBindingV1{
        .canonical_proof_byte_count = proof.byte_count,
        .proof_id = proof.proof_id,
        .canonical_proof_sha_id = proof.canonical_proof_sha_id,
        .capture_id = segment_publication.captureIdentity(capture),
        .transcript_id = transcript_id,
        .cohort_authority_sha_id = cohort.authority_sha_id,
        .manifest_sha_id = cohort.manifest().seal,
        .claims_sha_id = claims.seal,
        .generated_interactions_sha_id = audited.suffix.generated.identity,
        .audit_sha_id = audited.identity,
        .closure_receipt_sha_id = audited.closure.closure_id,
        .recursive_admission_sha_id = recursive_admission_sha_id,
    };
    try result.validate();
    return result;
}

pub fn publishSuccessfulVerifier(
    cohort: anytype,
    evidence: *const binary_driver.TemporalVerifierSuccessEvidenceV1,
    claims: anytype,
    audited: anytype,
    relations: anytype,
    provider_relations: anytype,
) !publication_mod.VerifiedPublicationV1 {
    const Cohort = @TypeOf(cohort.*);
    const verified = try binary_driver.openTemporalVerifierSuccessEvidence(
        evidence,
    );
    try cohort.validate();
    try claims.validate(cohort.manifest());
    try relations.validate();
    try provider_relations.validateAgainst(relations);
    try audited.closure.validate();
    try audited.context.validateAgainst(cohort.inputs.pair);
    if (!std.mem.eql(
        u8,
        &verified.cohort_authority_sha_id,
        &cohort.authority_sha_id,
    ) or !std.mem.eql(
        u8,
        &verified.manifest_sha_id,
        &cohort.manifest().seal,
    ) or !std.mem.eql(u8, &verified.claims_sha_id, &claims.seal) or
        !std.mem.eql(
            u8,
            &verified.generated_interactions_sha_id,
            &audited.suffix.generated.identity,
        ) or !std.mem.eql(u8, &verified.audit_sha_id, &audited.identity) or
        !std.mem.eql(
            u8,
            &verified.closure_receipt_sha_id,
            &audited.closure.closure_id,
        ) or !std.mem.eql(
        u8,
        &audited.identity,
        &cohort_support.auditedIdentity(audited),
    )) {
        return error.InvalidPublication;
    }
    const context = try cohort.publicationContext();
    const statement_words = try cohort.recursiveStatementWords();
    var result = publication_mod.VerifiedPublicationV1{
        .canonical_proof_byte_count = verified.canonical_proof_byte_count,
        .proof_id = verified.proof_id,
        .canonical_proof_sha_id = verified.canonical_proof_sha_id,
        .capture_id = verified.capture_id,
        .transcript_id = verified.transcript_id,
        .transcript_authority = Cohort.CHILD_TRANSCRIPT_AUTHORITY,
        .transcript_context_sha_id = audited.context.identity,
        .statement_words = statement_words.*,
        .pair_authority_id = cohort.inputs.pair.authority_id,
        .context = context,
        .manifest_sha_id = cohort.manifest().seal,
        .claims_sha_id = claims.seal,
        .generated_interactions_sha_id = audited.suffix.generated.identity,
        .audit_sha_id = audited.identity,
        .cohort_authority_sha_id = cohort.authority_sha_id,
        .closure_receipt_sha_id = audited.closure.closure_id,
        .publication_sha_id = undefined,
    };
    result.publication_sha_id = publication_mod.identity(&result);
    try result.validate();
    if (comptime @import("builtin").is_test)
        try publication_mod.validateMutationFleetForTest(result);
    return result;
}
