//! Transactional publication emitted only after the binary outer verifier
//! accepts one complete 36-row proof.
//!
//! The current binary cohort is the frozen split-role V1 protocol substrate.
//! Its proof closes all 47 universal relation domains, but it is neither an
//! adjacent-span temporal V2 node nor a production `complete_parent` proof.
//! This record preserves that distinction in its type, identity preimages,
//! and validation rules: both capability bits are fixed to false.
//!
//! Native Poseidon2-M31 digests and SHA-256 byte identities are deliberately
//! different field types and use different hashing methods below. In
//! particular, no `[32]u8` closure/proof/cohort identity is reinterpreted as
//! an eight-word recursive digest.
//!
//! `ClosureReceiptV2` is pointer-free and is retained by value. Publication
//! therefore has an owned lifetime, borrows no verifier/cohort storage, uses
//! no heap allocation, and performs one fixed-size closure copy at commit.
//! The destination is written exactly once after every fallible check.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const admission = recursion.outer_parent_child_admission;
const channel = recursion.poseidon2_channel;
const global_closure = recursion.binary_global_closure_outer_source;
const pair_node = recursion.pair_node;
const protocol = recursion.protocol;

pub const NativeDigest = channel.Digest;
pub const Sha256Digest = [32]u8;
pub const PreparedPairAuthorityV1 = pair_node.PreparedRootContextV1;

pub const FORMAT_VERSION: u16 = 2;
pub const VERIFIER_EVIDENCE_FORMAT_VERSION: u16 = 1;
pub const LINEAGE_SCHEMA_VERSION: u16 = 1;
pub const CONTEXT_SCHEMA_VERSION: u16 = 1;
pub const PUBLICATION_SCHEMA_VERSION: u16 = 1;

pub const VERIFIER_EVIDENCE_ID_DOMAIN: u32 = 0x4250_4556; // "BPEV"
pub const SPLIT_ROLE_LINEAGE_ID_DOMAIN: u32 = 0x4250_4c4e; // "BPLN"
pub const SPLIT_ROLE_CONTEXT_ID_DOMAIN: u32 = 0x4250_4358; // "BPCX"
pub const PUBLICATION_ID_DOMAIN: u32 = 0x4250_5542; // "BPUB"
pub const SHA256_ENCODING_TAG: u32 = 0x5348_4132; // "SHA2"

pub const HEAP_ALLOCATIONS_PER_PAIR_PREPARATION: usize = 0;
pub const HEAP_ALLOCATIONS_PER_PUBLISH: usize = 0;
pub const HEAP_ALLOCATIONS_PER_PROOF_IDENTITY_STREAM: usize = 0;
pub const CLOSURE_RECEIPT_COPIES_PER_PUBLISH: usize = 1;
pub const BORROWED_STORAGE_AFTER_PUBLISH = false;
pub const OWNS_CLOSURE_RECEIPT_BY_VALUE = true;
pub const PAIR_SCALAR_POSEIDON_PERMUTATIONS_PER_PUBLISH =
    pair_node.AuthenticationPermutationCostV1.successful_context_prepared_root;

pub const PROTOCOL_SUBSTRATE_ONLY = true;
pub const AUTHENTICATED_TEMPORAL_V2 = false;
pub const COMPLETE_PARENT_CAPABILITY = false;
pub const SUCCESSFUL_VERIFIER_TRANSACTION_REQUIRED = true;

pub const Error = pair_node.Error || global_closure.Error || error{
    AliasedDestination,
    CapabilityEscalation,
    CohortAuthorityMismatch,
    EmptyProofEncoding,
    EmptySha256Digest,
    EvidenceIdentityMismatch,
    InvalidAuthenticatedPair,
    InvalidNativeDigest,
    LineageMismatch,
    NativeContextMismatch,
    ProofStatementMismatch,
    ProofEncodingTooLarge,
    ProofEncodingLengthMismatch,
    ProofIdentityAlreadyFinalized,
    ProofVerificationKeyMismatch,
    PublicationIdentityMismatch,
    UnsupportedCohortSemantics,
    UnsupportedFormat,
    UnsupportedProofEncoding,
    UnsupportedProofScope,
};

/// Frozen meaning of the parent being proved. It joins the two complementary
/// roles of one execution; it does not join adjacent complete executions.
pub const CohortSemanticsV1 = enum(u8) {
    split_role_v1 = 1,
};

/// Canonical byte encoding whose SHA and native proof identity were computed
/// inside the successful verifier transaction.
pub const ProofEncodingV1 = enum(u8) {
    canonical_postcard_v1 = 1,
};

/// Allocation-free dual identity of one exact canonical postcard stream.
/// The byte count is part of the value because the native Poseidon proof ID
/// absorbs it before the byte limbs. Callers with a stream whose length is not
/// known a priori must perform a count pass, then feed the exact second pass to
/// `CanonicalProofIdentityStreamV1`.
pub const CanonicalProofIdentityV1 = struct {
    byte_count: u32,
    proof_id: NativeDigest,
    canonical_proof_sha_id: Sha256Digest,

    pub fn fromBytes(bytes: []const u8) Error!CanonicalProofIdentityV1 {
        var stream = try CanonicalProofIdentityStreamV1.init(bytes.len);
        try stream.writeAll(bytes);
        return stream.finalize();
    }

    pub fn validate(self: CanonicalProofIdentityV1) Error!void {
        if (self.byte_count == 0) return error.EmptyProofEncoding;
        try requireNativeDigest(self.proof_id);
        try requireSha256Digest(self.canonical_proof_sha_id);
    }
};

/// Writer-compatible incremental identity authority. SHA-256 receives the
/// raw byte stream. The native proof ID receives the same stream through the
/// protocol's injective `[byte length, little-endian u16 limbs]` encoding.
/// Arbitrary writer chunk boundaries, including a split two-byte limb, are
/// intentionally semantics-free.
pub const CanonicalProofIdentityStreamV1 = struct {
    expected_byte_count: u32,
    observed_byte_count: u32 = 0,
    sha256: std.crypto.hash.sha2.Sha256 = std.crypto.hash.sha2.Sha256.init(.{}),
    proof_id: channel.CanonicalWordHasher,
    pending_low_byte: ?u8 = null,
    finalized: bool = false,

    pub fn init(expected_byte_count: usize) Error!CanonicalProofIdentityStreamV1 {
        if (expected_byte_count == 0) return error.EmptyProofEncoding;
        const exact_count = std.math.cast(u32, expected_byte_count) orelse
            return error.ProofEncodingTooLarge;
        if (exact_count >= m31.Modulus) return error.ProofEncodingTooLarge;
        var proof_id = channel.CanonicalWordHasher.init(protocol.PROOF_ID_DOMAIN);
        const length = [_]M31{M31.fromCanonical(exact_count)};
        proof_id.update(&length);
        return .{
            .expected_byte_count = exact_count,
            .proof_id = proof_id,
        };
    }

    pub fn write(
        self: *CanonicalProofIdentityStreamV1,
        bytes: []const u8,
    ) Error!usize {
        if (self.finalized) return error.ProofIdentityAlreadyFinalized;
        const next_count = std.math.add(
            u32,
            self.observed_byte_count,
            std.math.cast(u32, bytes.len) orelse
                return error.ProofEncodingTooLarge,
        ) catch return error.ProofEncodingTooLarge;
        if (next_count > self.expected_byte_count)
            return error.ProofEncodingLengthMismatch;

        self.sha256.update(bytes);
        var at: usize = 0;
        if (self.pending_low_byte) |low| {
            if (bytes.len != 0) {
                self.absorbByteLimb(low, bytes[0]);
                self.pending_low_byte = null;
                at = 1;
            }
        }
        while (at + 1 < bytes.len) : (at += 2)
            self.absorbByteLimb(bytes[at], bytes[at + 1]);
        if (at < bytes.len) self.pending_low_byte = bytes[at];
        self.observed_byte_count = next_count;
        return bytes.len;
    }

    pub fn writeAll(
        self: *CanonicalProofIdentityStreamV1,
        bytes: []const u8,
    ) Error!void {
        _ = try self.write(bytes);
    }

    pub fn writeByte(
        self: *CanonicalProofIdentityStreamV1,
        byte: u8,
    ) Error!void {
        const bytes = [_]u8{byte};
        _ = try self.write(&bytes);
    }

    pub fn finalize(
        self: *CanonicalProofIdentityStreamV1,
    ) Error!CanonicalProofIdentityV1 {
        if (self.finalized) return error.ProofIdentityAlreadyFinalized;
        if (self.observed_byte_count != self.expected_byte_count)
            return error.ProofEncodingLengthMismatch;
        if (self.pending_low_byte) |low| self.absorbByteLimb(low, 0);
        self.pending_low_byte = null;
        self.finalized = true;
        var canonical_proof_sha_id: Sha256Digest = undefined;
        self.sha256.final(&canonical_proof_sha_id);
        const result = CanonicalProofIdentityV1{
            .byte_count = self.expected_byte_count,
            .proof_id = self.proof_id.finalize(),
            .canonical_proof_sha_id = canonical_proof_sha_id,
        };
        try result.validate();
        return result;
    }

    fn absorbByteLimb(
        self: *CanonicalProofIdentityStreamV1,
        low: u8,
        high: u8,
    ) void {
        const limb = [_]M31{M31.fromCanonical(
            @as(u32, low) | (@as(u32, high) << 8),
        )};
        self.proof_id.update(&limb);
    }
};

/// Pointer-free proof identity staged while the successful verifier still
/// owns the canonical proof bytes and the independently reconstructed cohort.
///
/// `initFromSuccessfulVerifier` is an integration boundary, not a proof
/// verifier. The binary driver must call it only after native verification and
/// while it still owns the exact canonical proof bytes and local cohort. This
/// constructor derives both proof identity families from that one byte slice;
/// the evidence identity prevents any later field mutation from being silently
/// accepted by `publishInto`.
pub const SuccessfulVerifierEvidenceV1 = struct {
    format_version: u16 = VERIFIER_EVIDENCE_FORMAT_VERSION,
    source_scope: admission.ProofScope = .verifier_subsystem,
    proof_encoding: ProofEncodingV1 = .canonical_postcard_v1,
    canonical_proof_byte_count: u32,
    proof_id: NativeDigest,
    statement_id: NativeDigest,
    verification_key_id: NativeDigest,
    canonical_proof_sha_id: Sha256Digest,
    cohort_authority_sha_id: Sha256Digest,
    evidence_id: NativeDigest,

    pub fn initFromSuccessfulVerifier(
        canonical_proof_bytes: []const u8,
        statement_id: NativeDigest,
        verification_key_id: NativeDigest,
        cohort_authority_sha_id: Sha256Digest,
    ) Error!SuccessfulVerifierEvidenceV1 {
        return initFromSuccessfulVerifierIdentity(
            try CanonicalProofIdentityV1.fromBytes(canonical_proof_bytes),
            statement_id,
            verification_key_id,
            cohort_authority_sha_id,
        );
    }

    /// Buffer-free integration form. The driver must construct `identity`
    /// from the exact canonical stream consumed by this verifier transaction
    /// and invoke this only after native proof verification succeeds.
    pub fn initFromSuccessfulVerifierIdentity(
        identity: CanonicalProofIdentityV1,
        statement_id: NativeDigest,
        verification_key_id: NativeDigest,
        cohort_authority_sha_id: Sha256Digest,
    ) Error!SuccessfulVerifierEvidenceV1 {
        try identity.validate();
        var result = SuccessfulVerifierEvidenceV1{
            .canonical_proof_byte_count = identity.byte_count,
            .proof_id = identity.proof_id,
            .statement_id = statement_id,
            .verification_key_id = verification_key_id,
            .canonical_proof_sha_id = identity.canonical_proof_sha_id,
            .cohort_authority_sha_id = cohort_authority_sha_id,
            .evidence_id = undefined,
        };
        try validateEvidencePayload(&result);
        result.evidence_id = evidenceIdentity(&result);
        return result;
    }

    pub fn validate(self: *const SuccessfulVerifierEvidenceV1) Error!void {
        try validateEvidencePayload(self);
        try requireNativeDigest(self.evidence_id);
        if (!std.meta.eql(self.evidence_id, evidenceIdentity(self)))
            return error.EvidenceIdentityMismatch;
    }
};

/// Successful-verifier publication for the current split-role binary cohort.
/// The embedded closure receipt is the exact independently reconstructed V2
/// receipt validated before proof admission, not a caller-supplied scalar.
pub const VerifiedBinaryClosurePublicationV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    publication_schema_version: u16 = PUBLICATION_SCHEMA_VERSION,
    statement_version: u32 = protocol.LEAF_STATEMENT_VERSION,
    source_scope: admission.ProofScope = .verifier_subsystem,
    cohort_semantics: CohortSemanticsV1 = .split_role_v1,
    proof_encoding: ProofEncodingV1 = .canonical_postcard_v1,
    authenticated_temporal_v2: bool = AUTHENTICATED_TEMPORAL_V2,
    complete_parent_capability: bool = COMPLETE_PARENT_CAPABILITY,

    canonical_proof_byte_count: u32,
    proof_id: NativeDigest,
    verifier_evidence_id: NativeDigest,
    cohort_id: NativeDigest,
    statement_id: NativeDigest,
    job_id: NativeDigest,
    session_id: NativeDigest,
    recursive_parent_vk_id: NativeDigest,
    lineage_id: NativeDigest,
    authenticated_context_id: NativeDigest,

    canonical_proof_sha_id: Sha256Digest,
    cohort_authority_sha_id: Sha256Digest,
    closure_receipt_sha_id: Sha256Digest,

    verifier_context: pair_node.VerifierContextV1,
    authenticated_pair: pair_node.RootAuthenticatedPairV1,
    closure_receipt: global_closure.ClosureReceiptV2,
    publication_id: NativeDigest,

    /// This is deliberately false for every valid value of this type.
    pub fn temporalV2Ready(self: *const VerifiedBinaryClosurePublicationV2) bool {
        return AUTHENTICATED_TEMPORAL_V2 and
            self.authenticated_temporal_v2;
    }

    /// Thirty-six proved rows do not upgrade V1 split-role semantics into a
    /// complete temporal parent.
    pub fn completeParentReady(
        self: *const VerifiedBinaryClosurePublicationV2,
    ) bool {
        return COMPLETE_PARENT_CAPABILITY and
            self.complete_parent_capability and
            self.source_scope == .complete_parent;
    }

    /// Allocation-free consumer-side replay of every retained identity and
    /// capability gate. The pair was authenticated transactionally by
    /// `publishInto`; the retained verifier context is re-derived here so a
    /// later session/job/statement/VK mutation cannot survive validation.
    pub fn validate(self: *const VerifiedBinaryClosurePublicationV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.publication_schema_version != PUBLICATION_SCHEMA_VERSION or
            self.statement_version != protocol.LEAF_STATEMENT_VERSION)
        {
            return error.UnsupportedFormat;
        }
        if (self.source_scope != .verifier_subsystem)
            return error.UnsupportedProofScope;
        if (self.cohort_semantics != .split_role_v1)
            return error.UnsupportedCohortSemantics;
        if (self.proof_encoding != .canonical_postcard_v1)
            return error.UnsupportedProofEncoding;
        if (self.authenticated_temporal_v2 or
            self.complete_parent_capability or
            self.temporalV2Ready() or
            self.completeParentReady())
        {
            return error.CapabilityEscalation;
        }

        const evidence = SuccessfulVerifierEvidenceV1{
            .source_scope = self.source_scope,
            .proof_encoding = self.proof_encoding,
            .canonical_proof_byte_count = self.canonical_proof_byte_count,
            .proof_id = self.proof_id,
            .statement_id = self.statement_id,
            .verification_key_id = self.recursive_parent_vk_id,
            .canonical_proof_sha_id = self.canonical_proof_sha_id,
            .cohort_authority_sha_id = self.cohort_authority_sha_id,
            .evidence_id = self.verifier_evidence_id,
        };
        try evidence.validate();
        try self.closure_receipt.validate();
        if (!std.mem.eql(
            u8,
            &self.closure_receipt_sha_id,
            &self.closure_receipt.closure_id,
        )) return error.CohortAuthorityMismatch;

        try validateAuthenticatedPair(&self.authenticated_pair.pair);
        const verifier_context_id = try self.verifier_context.contextId();
        const pair = &self.authenticated_pair.pair;
        if (!std.meta.eql(pair.authority_context_id, verifier_context_id) or
            !std.meta.eql(pair.session_id, self.verifier_context.session_id) or
            !std.meta.eql(
                pair.aggregator_vk_id,
                self.verifier_context.aggregator_vk_id,
            ))
        {
            return error.NativeContextMismatch;
        }
        if (!std.meta.eql(self.proof_id, evidence.proof_id) or
            !std.meta.eql(self.cohort_id, pair.node_id) or
            !std.meta.eql(
                self.statement_id,
                self.verifier_context.execution_statement_id,
            ) or
            !std.meta.eql(self.job_id, self.verifier_context.job_id) or
            !std.meta.eql(self.session_id, self.verifier_context.session_id) or
            !std.meta.eql(
                self.recursive_parent_vk_id,
                self.verifier_context.aggregator_vk_id,
            ))
        {
            return error.NativeContextMismatch;
        }

        const expected_lineage = lineageIdentity(
            &evidence,
            &self.verifier_context,
            &self.authenticated_pair,
        );
        if (!std.meta.eql(self.lineage_id, expected_lineage))
            return error.LineageMismatch;
        const expected_context = authenticatedContextIdentity(
            &evidence,
            &self.verifier_context,
            &self.authenticated_pair,
            self.lineage_id,
            self.closure_receipt_sha_id,
        );
        if (!std.meta.eql(self.authenticated_context_id, expected_context))
            return error.NativeContextMismatch;
        if (!std.meta.eql(self.publication_id, publicationIdentity(self)))
            return error.PublicationIdentityMismatch;
    }
};

/// Cold authority preparation. The suite and verifier context are snapshotted
/// once; subsequent publications use the 38-permutation context-prepared
/// pair path instead of the 94-permutation convenience path.
pub fn preparePairAuthority(
    authority: *const pair_node.VerifierAuthorityV1,
    root_pin: *const pair_node.RootVkPinV1,
) Error!PreparedPairAuthorityV1 {
    const suite = try pair_node.prepareProtocolSuite();
    return pair_node.prepareRootContext(&suite, authority, root_pin);
}

/// Publishes only after the caller's independent binary verifier has
/// succeeded and issued `evidence` from its still-local proof/cohort state.
///
/// Every input is pointer-free. The destination may not alias any source and
/// remains byte-for-byte unchanged on every error. The exact closure receipt
/// is copied by value only in the final staged assignment.
pub fn publishInto(
    destination: *VerifiedBinaryClosurePublicationV2,
    evidence: *const SuccessfulVerifierEvidenceV1,
    prepared_pair: *const PreparedPairAuthorityV1,
    authority: *const pair_node.VerifierAuthorityV1,
    record: *const pair_node.PairNodeRecordV1,
    root_pin: *const pair_node.RootVkPinV1,
    verified_cohort_authority_sha_id: *const Sha256Digest,
    closure_receipt: *const global_closure.ClosureReceiptV2,
) Error!void {
    try rejectDestinationAliases(
        destination,
        evidence,
        prepared_pair,
        authority,
        record,
        root_pin,
        verified_cohort_authority_sha_id,
        closure_receipt,
    );
    try evidence.validate();
    try requireSha256Digest(verified_cohort_authority_sha_id.*);
    if (!std.mem.eql(
        u8,
        &evidence.cohort_authority_sha_id,
        verified_cohort_authority_sha_id,
    )) return error.CohortAuthorityMismatch;
    try closure_receipt.validate();

    const authenticated_pair = try pair_node.authenticateRootWithPreparedContext(
        prepared_pair,
        authority,
        record,
        root_pin,
    );
    if (!std.meta.eql(
        evidence.statement_id,
        authority.context.execution_statement_id,
    )) return error.ProofStatementMismatch;
    if (!std.meta.eql(
        evidence.verification_key_id,
        authority.context.aggregator_vk_id,
    )) return error.ProofVerificationKeyMismatch;

    const lineage_id = lineageIdentity(
        evidence,
        &authority.context,
        &authenticated_pair,
    );
    const authenticated_context_id = authenticatedContextIdentity(
        evidence,
        &authority.context,
        &authenticated_pair,
        lineage_id,
        closure_receipt.closure_id,
    );
    var staged = VerifiedBinaryClosurePublicationV2{
        .canonical_proof_byte_count = evidence.canonical_proof_byte_count,
        .proof_id = evidence.proof_id,
        .verifier_evidence_id = evidence.evidence_id,
        .cohort_id = authenticated_pair.pair.node_id,
        .statement_id = authority.context.execution_statement_id,
        .job_id = authority.context.job_id,
        .session_id = authority.context.session_id,
        .recursive_parent_vk_id = authority.context.aggregator_vk_id,
        .lineage_id = lineage_id,
        .authenticated_context_id = authenticated_context_id,
        .canonical_proof_sha_id = evidence.canonical_proof_sha_id,
        .cohort_authority_sha_id = evidence.cohort_authority_sha_id,
        .closure_receipt_sha_id = closure_receipt.closure_id,
        .verifier_context = authority.context,
        .authenticated_pair = authenticated_pair,
        .closure_receipt = closure_receipt.*,
        .publication_id = undefined,
    };
    staged.publication_id = publicationIdentity(&staged);

    // No fallible operation is permitted below this point.
    destination.* = staged;
}

fn validateEvidencePayload(
    evidence: *const SuccessfulVerifierEvidenceV1,
) Error!void {
    if (evidence.format_version != VERIFIER_EVIDENCE_FORMAT_VERSION)
        return error.UnsupportedFormat;
    if (evidence.source_scope != .verifier_subsystem)
        return error.UnsupportedProofScope;
    if (evidence.proof_encoding != .canonical_postcard_v1)
        return error.UnsupportedProofEncoding;
    if (evidence.canonical_proof_byte_count == 0)
        return error.EmptyProofEncoding;
    if (evidence.canonical_proof_byte_count >= m31.Modulus)
        return error.ProofEncodingTooLarge;
    try requireNativeDigest(evidence.proof_id);
    try requireNativeDigest(evidence.statement_id);
    try requireNativeDigest(evidence.verification_key_id);
    try requireSha256Digest(evidence.canonical_proof_sha_id);
    try requireSha256Digest(evidence.cohort_authority_sha_id);
}

fn validateAuthenticatedPair(pair: *const pair_node.AuthenticatedPairV1) Error!void {
    for ([_]NativeDigest{
        pair.format_id,
        pair.protocol_id,
        pair.session_id,
        pair.challenge_context_id,
        pair.authority_context_id,
        pair.aggregator_vk_id,
        pair.identities.statement_id,
        pair.identities.proof_id,
        pair.identities.transcript_id,
        pair.identities.summary_id,
        pair.node_id,
    }) |digest| try requireNativeDigest(digest);
    if (!std.meta.eql(pair.format_id, pair_node.FORMAT_ID_WORDS) or
        !std.meta.eql(pair.protocol_id, protocol.PROTOCOL_ID_WORDS) or
        pair.leaf_count != pair_node.CHILD_COUNT or
        pair.session_leaf_count == 0 or
        pair.session_leaf_count > pair_node.MAX_KAPPA or
        pair.pair_index > pair_node.MAX_PAIR_INDEX)
    {
        return error.InvalidAuthenticatedPair;
    }
    const expected_first = std.math.mul(
        u32,
        pair.pair_index,
        pair_node.CHILD_COUNT,
    ) catch return error.InvalidAuthenticatedPair;
    const pair_end = std.math.add(
        u32,
        expected_first,
        pair_node.CHILD_COUNT,
    ) catch return error.InvalidAuthenticatedPair;
    if (pair.first_leaf_index != expected_first or
        pair_end > pair.session_leaf_count)
    {
        return error.InvalidAuthenticatedPair;
    }
}

fn evidenceIdentity(evidence: *const SuccessfulVerifierEvidenceV1) NativeDigest {
    var hash = IdentityHasher.init(VERIFIER_EVIDENCE_ID_DOMAIN);
    hash.scalar(evidence.format_version);
    hash.scalar(@intFromEnum(evidence.source_scope));
    hash.scalar(@intFromEnum(evidence.proof_encoding));
    hash.addU32(evidence.canonical_proof_byte_count);
    hash.digest(evidence.proof_id);
    hash.digest(evidence.statement_id);
    hash.digest(evidence.verification_key_id);
    hash.sha256(evidence.canonical_proof_sha_id);
    hash.sha256(evidence.cohort_authority_sha_id);
    return hash.finalize();
}

fn lineageIdentity(
    evidence: *const SuccessfulVerifierEvidenceV1,
    context: *const pair_node.VerifierContextV1,
    root: *const pair_node.RootAuthenticatedPairV1,
) NativeDigest {
    const pair = &root.pair;
    var hash = IdentityHasher.init(SPLIT_ROLE_LINEAGE_ID_DOMAIN);
    hash.scalar(FORMAT_VERSION);
    hash.scalar(LINEAGE_SCHEMA_VERSION);
    hash.scalar(@intFromEnum(CohortSemanticsV1.split_role_v1));
    hash.scalar(@intFromEnum(admission.ProofScope.verifier_subsystem));
    hash.scalar(protocol.LEAF_STATEMENT_VERSION);
    hash.addU32(evidence.canonical_proof_byte_count);
    hash.digest(pair.format_id);
    hash.digest(pair.protocol_id);
    hash.digest(pair.session_id);
    hash.digest(pair.challenge_context_id);
    hash.digest(pair.authority_context_id);
    hash.digest(pair.aggregator_vk_id);
    hash.scalar(pair.pair_index);
    hash.scalar(pair.first_leaf_index);
    hash.scalar(pair.leaf_count);
    hash.scalar(pair.session_leaf_count);
    hash.digest(pair.identities.statement_id);
    hash.digest(pair.identities.proof_id);
    hash.digest(pair.identities.transcript_id);
    hash.digest(pair.identities.summary_id);
    hash.digest(pair.node_id);
    hash.digest(evidence.proof_id);
    hash.digest(evidence.evidence_id);
    hash.digest(context.execution_statement_id);
    hash.digest(context.job_id);
    hash.digest(context.session_id);
    hash.digest(context.aggregator_vk_id);
    hash.sha256(evidence.canonical_proof_sha_id);
    hash.sha256(evidence.cohort_authority_sha_id);
    return hash.finalize();
}

/// Native split-role context identity. Despite the retained field name used
/// by the future handoff schema, this is explicitly not temporal V2 context.
fn authenticatedContextIdentity(
    evidence: *const SuccessfulVerifierEvidenceV1,
    context: *const pair_node.VerifierContextV1,
    root: *const pair_node.RootAuthenticatedPairV1,
    lineage_id: NativeDigest,
    closure_receipt_sha_id: Sha256Digest,
) NativeDigest {
    var hash = IdentityHasher.init(SPLIT_ROLE_CONTEXT_ID_DOMAIN);
    hash.scalar(FORMAT_VERSION);
    hash.scalar(CONTEXT_SCHEMA_VERSION);
    hash.scalar(@intFromEnum(CohortSemanticsV1.split_role_v1));
    hash.scalar(@intFromEnum(admission.ProofScope.verifier_subsystem));
    hash.scalar(protocol.LEAF_STATEMENT_VERSION);
    hash.scalar(@intFromBool(AUTHENTICATED_TEMPORAL_V2));
    hash.scalar(@intFromBool(COMPLETE_PARENT_CAPABILITY));
    hash.addU32(evidence.canonical_proof_byte_count);
    hash.digest(evidence.evidence_id);
    hash.digest(evidence.proof_id);
    hash.digest(root.pair.node_id);
    hash.digest(context.execution_statement_id);
    hash.digest(context.job_id);
    hash.digest(context.session_id);
    hash.digest(context.aggregator_vk_id);
    hash.digest(lineage_id);
    hash.sha256(evidence.canonical_proof_sha_id);
    hash.sha256(evidence.cohort_authority_sha_id);
    hash.sha256(closure_receipt_sha_id);
    return hash.finalize();
}

fn publicationIdentity(
    publication: *const VerifiedBinaryClosurePublicationV2,
) NativeDigest {
    var hash = IdentityHasher.init(PUBLICATION_ID_DOMAIN);
    hash.scalar(publication.format_version);
    hash.scalar(publication.publication_schema_version);
    hash.scalar(publication.statement_version);
    hash.scalar(@intFromEnum(publication.source_scope));
    hash.scalar(@intFromEnum(publication.cohort_semantics));
    hash.scalar(@intFromEnum(publication.proof_encoding));
    hash.scalar(@intFromBool(publication.authenticated_temporal_v2));
    hash.scalar(@intFromBool(publication.complete_parent_capability));
    hash.addU32(publication.canonical_proof_byte_count);
    hash.digest(publication.proof_id);
    hash.digest(publication.verifier_evidence_id);
    hash.digest(publication.cohort_id);
    hash.digest(publication.statement_id);
    hash.digest(publication.job_id);
    hash.digest(publication.session_id);
    hash.digest(publication.recursive_parent_vk_id);
    hash.digest(publication.lineage_id);
    hash.digest(publication.authenticated_context_id);
    hash.sha256(publication.canonical_proof_sha_id);
    hash.sha256(publication.cohort_authority_sha_id);
    hash.sha256(publication.closure_receipt_sha_id);
    hash.digest(publication.authenticated_pair.pair.authority_context_id);
    hash.digest(publication.authenticated_pair.pair.node_id);
    hash.sha256(publication.closure_receipt.source_authority_id);
    hash.sha256(publication.closure_receipt.input_id);
    hash.sha256(publication.closure_receipt.context_seam.identity);
    return hash.finalize();
}

const IdentityHasher = struct {
    inner: channel.CanonicalWordHasher,

    fn init(domain: u32) IdentityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    fn scalar(self: *IdentityHasher, value: anytype) void {
        const canonical: u32 = @intCast(value);
        std.debug.assert(canonical < m31.Modulus);
        const word = [_]M31{M31.fromCanonical(canonical)};
        self.inner.update(&word);
    }

    fn digest(self: *IdentityHasher, value: NativeDigest) void {
        for (value) |word| self.scalar(word);
    }

    fn addU32(self: *IdentityHasher, value: u32) void {
        self.scalar(value & 0xffff);
        self.scalar(value >> 16);
    }

    /// Injective SHA byte encoding: an explicit type tag and byte length,
    /// followed by little-endian 16-bit limbs. No bytes become M31 digest
    /// words by reinterpretation.
    fn sha256(self: *IdentityHasher, value: Sha256Digest) void {
        self.scalar(SHA256_ENCODING_TAG);
        self.scalar(value.len);
        var at: usize = 0;
        while (at < value.len) : (at += 2) {
            self.scalar(@as(u32, value[at]) |
                (@as(u32, value[at + 1]) << 8));
        }
    }

    fn finalize(self: *IdentityHasher) NativeDigest {
        return self.inner.finalize();
    }
};

fn requireNativeDigest(value: NativeDigest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.InvalidNativeDigest;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidNativeDigest;
}

fn requireSha256Digest(value: Sha256Digest) Error!void {
    var aggregate: u8 = 0;
    for (value) |byte| aggregate |= byte;
    if (aggregate == 0) return error.EmptySha256Digest;
}

fn rejectDestinationAliases(
    destination: *VerifiedBinaryClosurePublicationV2,
    evidence: *const SuccessfulVerifierEvidenceV1,
    prepared_pair: *const PreparedPairAuthorityV1,
    authority: *const pair_node.VerifierAuthorityV1,
    record: *const pair_node.PairNodeRecordV1,
    root_pin: *const pair_node.RootVkPinV1,
    verified_cohort_authority_sha_id: *const Sha256Digest,
    closure_receipt: *const global_closure.ClosureReceiptV2,
) Error!void {
    const destination_bytes = std.mem.asBytes(destination);
    for ([_][]const u8{
        std.mem.asBytes(evidence),
        std.mem.asBytes(prepared_pair),
        std.mem.asBytes(authority),
        std.mem.asBytes(record),
        std.mem.asBytes(root_pin),
        std.mem.asBytes(verified_cohort_authority_sha_id),
        std.mem.asBytes(closure_receipt),
    }) |source| if (overlap(destination_bytes, source))
        return error.AliasedDestination;
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

fn assertPointerFree(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer, .error_union => @compileError(
            "binary verifier publication fixed storage contains dynamic state",
        ),
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
    if (FORMAT_VERSION != 2 or VERIFIER_EVIDENCE_FORMAT_VERSION != 1 or
        !PROTOCOL_SUBSTRATE_ONLY or AUTHENTICATED_TEMPORAL_V2 or
        COMPLETE_PARENT_CAPABILITY or !SUCCESSFUL_VERIFIER_TRANSACTION_REQUIRED or
        HEAP_ALLOCATIONS_PER_PAIR_PREPARATION != 0 or
        HEAP_ALLOCATIONS_PER_PUBLISH != 0 or
        HEAP_ALLOCATIONS_PER_PROOF_IDENTITY_STREAM != 0 or
        CLOSURE_RECEIPT_COPIES_PER_PUBLISH != 1 or
        BORROWED_STORAGE_AFTER_PUBLISH or !OWNS_CLOSURE_RECEIPT_BY_VALUE)
    {
        @compileError("binary verifier publication capability contract drifted");
    }
    if (NativeDigest != [channel.RATE]u32 or NativeDigest == Sha256Digest or
        @TypeOf(@as(global_closure.ClosureReceiptV2, undefined).closure_id) !=
            Sha256Digest)
    {
        @compileError("native Poseidon and SHA-256 identity types drifted");
    }
    assertPointerFree(global_closure.ClosureReceiptV2);
    assertPointerFree(CanonicalProofIdentityV1);
    assertPointerFree(SuccessfulVerifierEvidenceV1);
    assertPointerFree(VerifiedBinaryClosurePublicationV2);
}
