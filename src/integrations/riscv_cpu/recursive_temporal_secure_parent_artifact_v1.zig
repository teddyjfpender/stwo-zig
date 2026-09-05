//! Canonical custody for one secure temporal-parent proof.
//!
//! A decoded `OwnedArtifactV1` is deliberately not verifier authority.  The
//! secure native engine must reopen the exact session, decode and canonically
//! reserialize the retained postcard proof, and complete a cold q=193 STARK
//! verification before it can mint its non-serializable fresh result.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");

const h1_ingress =
    @import("recursive_temporal_ethereum_poseidon_h1_ingress_v1.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");
const secure_tail = @import("recursive_temporal_secure_tree_tail_v1.zig");
const protocol_mod =
    @import("recursive_temporal_secure_parent_protocol_v1.zig");

const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const span = recursion.span_statement;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const MAX_CANONICAL_PROOF_BYTES: usize = 512 * 1024 * 1024;
pub const STATEMENT_ENCODED_BYTE_COUNT: usize = 680;
pub const ARTIFACT_HEADER_BYTE_COUNT: usize = 8;

const ARTIFACT_MAGIC = [ARTIFACT_HEADER_BYTE_COUNT]u8{
    'S', 'T', 'W', 'S', 'P', 'A', '1', 0,
};
const SESSION_DOMAIN =
    "stwo-zig/typed-air/secure-temporal-parent-session/v1\x00";
const STATEMENT_DOMAIN =
    "stwo-zig/typed-air/secure-temporal-parent-statement/v1\x00";

pub const SourceKindV1 = enum(u8) {
    fresh_ethereum_poseidon_h1 = 1,
    fresh_temporal_parent_v3 = 2,
    canonical_empty_wrapper_v1 = 3,
    common_fold_field_v2 = 4,
    ethereum_incremental_leaf_wrapper_v4 = 5,
    canonical_empty_campaign_v2 = 6,
    testing_only = 255,
};

/// Pointer-free authority for the proof-bearing canonical-empty wrapper.
/// The wrapper cohort reconstructs this exact value from its cold source and
/// the registered circuit contract; the session constructor alone grants no
/// proof or freshness capability.
pub const CanonicalEmptySessionAuthorityV1 = struct {
    ingress_identity_sha256: [32]u8,
    parent_statement_words: span.StatementWords,
    profile_identity_sha256: [32]u8,
    child_composition_manifest_sha256: [32]u8,
    parent_outer_manifest_sha256: [32]u8,
    verification_key_id: channel.Digest,
    next_parent_vk_id: channel.Digest,
    air_program_id: channel.Digest,

    pub fn validate(self: *const CanonicalEmptySessionAuthorityV1) !void {
        inline for (.{
            self.ingress_identity_sha256,
            self.profile_identity_sha256,
            self.child_composition_manifest_sha256,
            self.parent_outer_manifest_sha256,
        }) |value| try requireSha(value);
        inline for (.{
            self.verification_key_id,
            self.next_parent_vk_id,
            self.air_program_id,
        }) |value| try requireDigest(value);
        const statement = try span.SpanStatement.fromCanonicalWords(
            &self.parent_statement_words,
        );
        if (statement.slots.height != 0 or
            statement.slots.first < 210 or statement.slots.first >= 256)
        {
            return error.InvalidSecureTemporalParentSession;
        }
        switch (statement.body) {
            .empty => {},
            .executed => return error.InvalidSecureTemporalParentSession,
        }
    }
};

/// Pointer-free session projection for a campaign-bound canonical empty.
/// Unlike the frozen V1 authority, admissible indices are derived from the
/// authenticated statement itself. The campaign cohort separately binds the
/// exact namespace and shape into its ingress and manifest identities.
pub const CampaignCanonicalEmptySessionAuthorityV2 = struct {
    ingress_identity_sha256: [32]u8,
    parent_statement_words: span.StatementWords,
    profile_identity_sha256: [32]u8,
    child_composition_manifest_sha256: [32]u8,
    parent_outer_manifest_sha256: [32]u8,
    verification_key_id: channel.Digest,
    next_parent_vk_id: channel.Digest,
    air_program_id: channel.Digest,

    pub fn validate(
        self: *const CampaignCanonicalEmptySessionAuthorityV2,
    ) !void {
        inline for (.{
            self.ingress_identity_sha256,
            self.profile_identity_sha256,
            self.child_composition_manifest_sha256,
            self.parent_outer_manifest_sha256,
        }) |value| try requireSha(value);
        inline for (.{
            self.verification_key_id,
            self.next_parent_vk_id,
            self.air_program_id,
        }) |value| try requireDigest(value);
        const statement = try span.SpanStatement.fromCanonicalWords(
            &self.parent_statement_words,
        );
        if (statement.slots.height != 0 or
            statement.slots.first < statement.job.segment_count or
            statement.slots.first >= statement.job.slotCapacity())
        {
            return error.InvalidSecureTemporalParentSession;
        }
        switch (statement.body) {
            .empty => {},
            .executed => return error.InvalidSecureTemporalParentSession,
        }
    }
};

/// Pointer-free session projection for the field-native common fold.  This
/// value is reconstructed only from the live two-child fold authority and the
/// cold-derived common-fold geometry; it is not a freshness capability.
pub const CommonFoldSessionAuthorityV2 = struct {
    ingress_identity_sha256: [32]u8,
    parent_statement_words: span.StatementWords,
    profile_identity_sha256: [32]u8,
    child_composition_manifest_sha256: [32]u8,
    parent_outer_manifest_sha256: [32]u8,
    verification_key_id: channel.Digest,
    next_parent_vk_id: channel.Digest,
    air_program_id: channel.Digest,

    pub fn validate(self: *const CommonFoldSessionAuthorityV2) !void {
        inline for (.{
            self.ingress_identity_sha256,
            self.profile_identity_sha256,
            self.child_composition_manifest_sha256,
            self.parent_outer_manifest_sha256,
        }) |value| try requireSha(value);
        inline for (.{
            self.verification_key_id,
            self.next_parent_vk_id,
            self.air_program_id,
        }) |value| try requireDigest(value);
        const statement = try span.SpanStatement.fromCanonicalWords(
            &self.parent_statement_words,
        );
        if (statement.slots.height == 0 or statement.slots.height > 8)
            return error.InvalidSecureTemporalParentSession;
    }
};

/// Pointer-free session projection for one genuine field-native Ethereum
/// incremental leaf wrapper. The exact live stage-101/campaign authority must
/// independently reconstruct this value at every cold boundary; this value
/// alone is never proof or freshness admission.
pub const EthereumIncrementalLeafWrapperSessionAuthorityV4 = struct {
    ingress_identity_sha256: [32]u8,
    parent_statement_words: span.StatementWords,
    profile_identity_sha256: [32]u8,
    child_composition_manifest_sha256: [32]u8,
    parent_outer_manifest_sha256: [32]u8,
    verification_key_id: channel.Digest,
    next_parent_vk_id: channel.Digest,
    air_program_id: channel.Digest,

    pub fn validate(
        self: *const EthereumIncrementalLeafWrapperSessionAuthorityV4,
    ) !void {
        inline for (.{
            self.ingress_identity_sha256,
            self.profile_identity_sha256,
            self.child_composition_manifest_sha256,
            self.parent_outer_manifest_sha256,
        }) |value| try requireSha(value);
        inline for (.{
            self.verification_key_id,
            self.next_parent_vk_id,
            self.air_program_id,
        }) |value| try requireDigest(value);
        const statement = try span.SpanStatement.fromCanonicalWords(
            &self.parent_statement_words,
        );
        if (statement.slots.height != 0)
            return error.InvalidSecureTemporalParentSession;
        switch (statement.body) {
            .executed => {},
            .empty => return error.InvalidSecureTemporalParentSession,
        }
    }
};

/// Fixed session projection mixed into the native transcript before the one
/// interaction PoW.  The protocol is arm-invariant; the ingress, statement,
/// and profile remain program-bound and may differ between reviewed A/B arms.
pub const SessionV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    source_kind: SourceKindV1,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: u16 = 0,
    protocol: protocol_mod.AuthorityV1,
    ingress_identity_sha256: [32]u8,
    parent_statement_words: span.StatementWords,
    parent_statement_sha256: [32]u8,
    profile_identity_sha256: [32]u8,
    child_composition_manifest_sha256: [32]u8,
    parent_outer_manifest_sha256: [32]u8,
    verification_key_id: channel.Digest,
    next_parent_vk_id: channel.Digest,
    air_program_id: channel.Digest,
    identity_sha256: [32]u8,

    pub fn initFromFreshEthereumH1(
        fresh: *const h1_ingress.FreshIngressV1,
    ) !SessionV1 {
        try fresh.custody.validate();
        const profile = fresh.custody.h1_profile;
        const protocol = protocol_mod.AuthorityV1.secureParent();
        try protocol.requireSecure();
        if (profile.parent_proof_security_kind != .recursive_parent_secure or
            !std.mem.eql(
                u8,
                &profile.parent_proof_security_sha256,
                &protocol.proof_security_sha256,
            ))
        {
            return error.InvalidSecureTemporalParentSession;
        }
        var result = SessionV1{
            .source_kind = .fresh_ethereum_poseidon_h1,
            .protocol = protocol,
            .ingress_identity_sha256 = fresh.custody.identity_sha256,
            .parent_statement_words = fresh.custody.parent_statement_words,
            .parent_statement_sha256 = fresh.custody.parent_statement_sha256,
            .profile_identity_sha256 = profile.identity_sha256,
            .child_composition_manifest_sha256 = profile.child_composition_manifest_sha256,
            .parent_outer_manifest_sha256 = profile.parent_outer_manifest_sha256,
            .verification_key_id = profile.verification_key_id,
            .next_parent_vk_id = profile.next_parent_vk_id,
            .air_program_id = profile.air_program_id,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = sessionIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn initCanonicalEmptyWrapper(
        authority: CanonicalEmptySessionAuthorityV1,
    ) !SessionV1 {
        try authority.validate();
        const protocol = protocol_mod.AuthorityV1.secureParent();
        try protocol.requireSecure();
        var result = SessionV1{
            .source_kind = .canonical_empty_wrapper_v1,
            .protocol = protocol,
            .ingress_identity_sha256 = authority.ingress_identity_sha256,
            .parent_statement_words = authority.parent_statement_words,
            .parent_statement_sha256 = statement_plan.statementSha256(
                &authority.parent_statement_words,
            ),
            .profile_identity_sha256 = authority.profile_identity_sha256,
            .child_composition_manifest_sha256 = authority.child_composition_manifest_sha256,
            .parent_outer_manifest_sha256 = authority.parent_outer_manifest_sha256,
            .verification_key_id = authority.verification_key_id,
            .next_parent_vk_id = authority.next_parent_vk_id,
            .air_program_id = authority.air_program_id,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = sessionIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn initCanonicalEmptyCampaignV2(
        authority: CampaignCanonicalEmptySessionAuthorityV2,
    ) !SessionV1 {
        try authority.validate();
        const protocol = protocol_mod.AuthorityV1.secureParent();
        try protocol.requireSecure();
        var result = SessionV1{
            .source_kind = .canonical_empty_campaign_v2,
            .protocol = protocol,
            .ingress_identity_sha256 = authority.ingress_identity_sha256,
            .parent_statement_words = authority.parent_statement_words,
            .parent_statement_sha256 = statement_plan.statementSha256(
                &authority.parent_statement_words,
            ),
            .profile_identity_sha256 = authority.profile_identity_sha256,
            .child_composition_manifest_sha256 = authority.child_composition_manifest_sha256,
            .parent_outer_manifest_sha256 = authority.parent_outer_manifest_sha256,
            .verification_key_id = authority.verification_key_id,
            .next_parent_vk_id = authority.next_parent_vk_id,
            .air_program_id = authority.air_program_id,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = sessionIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn initCommonFoldFieldV2(
        authority: CommonFoldSessionAuthorityV2,
    ) !SessionV1 {
        try authority.validate();
        const protocol = protocol_mod.AuthorityV1.secureParent();
        try protocol.requireSecure();
        var result = SessionV1{
            .source_kind = .common_fold_field_v2,
            .protocol = protocol,
            .ingress_identity_sha256 = authority.ingress_identity_sha256,
            .parent_statement_words = authority.parent_statement_words,
            .parent_statement_sha256 = statement_plan.statementSha256(
                &authority.parent_statement_words,
            ),
            .profile_identity_sha256 = authority.profile_identity_sha256,
            .child_composition_manifest_sha256 = authority.child_composition_manifest_sha256,
            .parent_outer_manifest_sha256 = authority.parent_outer_manifest_sha256,
            .verification_key_id = authority.verification_key_id,
            .next_parent_vk_id = authority.next_parent_vk_id,
            .air_program_id = authority.air_program_id,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = sessionIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn initEthereumIncrementalLeafWrapperV4(
        authority: EthereumIncrementalLeafWrapperSessionAuthorityV4,
    ) !SessionV1 {
        try authority.validate();
        const protocol = protocol_mod.AuthorityV1.secureParent();
        try protocol.requireSecure();
        var result = SessionV1{
            .source_kind = .ethereum_incremental_leaf_wrapper_v4,
            .protocol = protocol,
            .ingress_identity_sha256 = authority.ingress_identity_sha256,
            .parent_statement_words = authority.parent_statement_words,
            .parent_statement_sha256 = statement_plan.statementSha256(
                &authority.parent_statement_words,
            ),
            .profile_identity_sha256 = authority.profile_identity_sha256,
            .child_composition_manifest_sha256 = authority.child_composition_manifest_sha256,
            .parent_outer_manifest_sha256 = authority.parent_outer_manifest_sha256,
            .verification_key_id = authority.verification_key_id,
            .next_parent_vk_id = authority.next_parent_vk_id,
            .air_program_id = authority.air_program_id,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = sessionIdentity(&result);
        try result.validate();
        return result;
    }

    /// Exact secure upper-task session. `ingress_identity_sha256` must identify
    /// the separately authenticated pair of fresh child captures; a topology
    /// task or matching statement hash alone is not child-proof authority.
    pub fn initFromFreshTemporalParent(
        allocator: std.mem.Allocator,
        plan: *const secure_tail.TailPlanV1,
        source: *const statement_plan.MaterializedPlanV1,
        upper_local_ordinal: usize,
        parent_statement_words: span.StatementWords,
        ingress_identity_sha256: [32]u8,
    ) !SessionV1 {
        try plan.validateAgainst(allocator, source);
        if (upper_local_ordinal >= secure_tail.UPPER_TASK_COUNT)
            return error.InvalidSecureTemporalParentSession;
        const task = &plan.tasks[
            secure_tail.EMPTY_H1_TASK_COUNT + upper_local_ordinal
        ];
        const profile = try source.profiles.forNode(
            task.parent_height,
            task.parent_kind,
        );
        try profile.requireProductionSecurity();
        const protocol = protocol_mod.AuthorityV1.secureParent();
        try protocol.requireSecure();
        if (task.task_class != .upper or
            !task.requires_child_composition_capture or
            profile.kind != .recursive_parent or
            profile.parent_height != task.parent_height or
            !std.mem.eql(
                u8,
                &task.profile_identity_sha256,
                &profile.identity,
            ) or !std.meta.eql(
            task.verification_key_id,
            profile.verification_key_id,
        ) or !std.meta.eql(
            task.next_parent_vk_id,
            profile.next_parent_vk_id,
        ) or !std.mem.eql(
            u8,
            &task.parent_statement_sha256,
            &statement_plan.statementSha256(&parent_statement_words),
        ) or !std.mem.eql(
            u8,
            &profile.parent_proof_security.identity,
            &protocol.proof_security_sha256,
        ) or std.mem.allEqual(u8, &ingress_identity_sha256, 0)) {
            return error.InvalidSecureTemporalParentSession;
        }
        var result = SessionV1{
            .source_kind = .fresh_temporal_parent_v3,
            .protocol = protocol,
            .ingress_identity_sha256 = ingress_identity_sha256,
            .parent_statement_words = parent_statement_words,
            .parent_statement_sha256 = task.parent_statement_sha256,
            .profile_identity_sha256 = profile.identity,
            .child_composition_manifest_sha256 = profile.child_composition_manifest_sha_id,
            .parent_outer_manifest_sha256 = profile.manifest_sha_id,
            .verification_key_id = profile.verification_key_id,
            .next_parent_vk_id = profile.next_parent_vk_id,
            .air_program_id = profile.air_program_id,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = sessionIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const SessionV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or self.reserved != 0)
        {
            return error.InvalidSecureTemporalParentSession;
        }
        switch (self.source_kind) {
            .fresh_ethereum_poseidon_h1 => {},
            .fresh_temporal_parent_v3 => {},
            .canonical_empty_wrapper_v1 => {},
            .common_fold_field_v2 => {},
            .ethereum_incremental_leaf_wrapper_v4 => {},
            .canonical_empty_campaign_v2 => {},
            .testing_only => if (!builtin.is_test)
                return error.InvalidSecureTemporalParentSession,
        }
        try self.protocol.requireSecure();
        inline for (.{
            self.ingress_identity_sha256,
            self.parent_statement_sha256,
            self.profile_identity_sha256,
            self.child_composition_manifest_sha256,
            self.parent_outer_manifest_sha256,
            self.identity_sha256,
        }) |value| try requireSha(value);
        inline for (.{
            self.verification_key_id,
            self.next_parent_vk_id,
            self.air_program_id,
        }) |value| try requireDigest(value);
        _ = try span.SpanStatement.fromCanonicalWords(
            &self.parent_statement_words,
        );
        if (!std.mem.eql(
            u8,
            &self.parent_statement_sha256,
            &statement_plan.statementSha256(&self.parent_statement_words),
        ) or !std.mem.eql(
            u8,
            &self.identity_sha256,
            &sessionIdentity(self),
        )) return error.InvalidSecureTemporalParentSession;
    }

    pub fn mixInto(self: *const SessionV1, transcript: anytype) !void {
        try self.validate();
        transcript.mixU32s(&.{
            0x5350_5331, // "SPS1"
            FORMAT_VERSION,
            SCHEMA_VERSION,
            self.protocol.interaction_pow_bits,
            self.protocol.pcs_pow_bits,
            self.protocol.fri_query_count,
            self.protocol.fri_fold_step,
        });
        transcript.mixU32s(&shaWords(self.identity_sha256));
    }
};

/// Pointer-free statement sealed only after the native verifier has accepted
/// the exact retained proof bytes and independently reconstructed all claims.
pub const StatementV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    protocol: protocol_mod.AuthorityV1,
    session_identity_sha256: [32]u8,
    ingress_identity_sha256: [32]u8,
    parent_statement_sha256: [32]u8,
    profile_identity_sha256: [32]u8,
    child_composition_manifest_sha256: [32]u8,
    parent_outer_manifest_sha256: [32]u8,
    verification_key_id: channel.Digest,
    next_parent_vk_id: channel.Digest,
    air_program_id: channel.Digest,
    interaction_pow_nonce: u64,
    canonical_proof_byte_count: u32,
    canonical_proof_sha256: [32]u8,
    proof_id: channel.Digest,
    capture_id: channel.Digest,
    transcript_id: channel.Digest,
    claims_sha256: [32]u8,
    audit_sha256: [32]u8,
    closure_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn validate(self: *const StatementV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            self.canonical_proof_byte_count == 0 or
            self.canonical_proof_byte_count > MAX_CANONICAL_PROOF_BYTES)
        {
            return error.InvalidSecureTemporalParentStatement;
        }
        try self.protocol.requireSecure();
        inline for (.{
            self.session_identity_sha256,
            self.ingress_identity_sha256,
            self.parent_statement_sha256,
            self.profile_identity_sha256,
            self.child_composition_manifest_sha256,
            self.parent_outer_manifest_sha256,
            self.canonical_proof_sha256,
            self.claims_sha256,
            self.audit_sha256,
            self.closure_sha256,
            self.identity_sha256,
        }) |value| try requireSha(value);
        inline for (.{
            self.verification_key_id,
            self.next_parent_vk_id,
            self.air_program_id,
            self.proof_id,
            self.capture_id,
            self.transcript_id,
        }) |value| try requireDigest(value);
        if (!std.mem.eql(
            u8,
            &self.identity_sha256,
            &statementIdentity(self),
        )) return error.InvalidSecureTemporalParentStatement;
    }

    pub fn validateAgainstSession(
        self: *const StatementV1,
        session: *const SessionV1,
    ) !void {
        try self.validate();
        try session.validate();
        if (!std.meta.eql(self.protocol, session.protocol) or
            !std.mem.eql(
                u8,
                &self.session_identity_sha256,
                &session.identity_sha256,
            ) or !std.mem.eql(
            u8,
            &self.ingress_identity_sha256,
            &session.ingress_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.parent_statement_sha256,
            &session.parent_statement_sha256,
        ) or !std.mem.eql(
            u8,
            &self.profile_identity_sha256,
            &session.profile_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.child_composition_manifest_sha256,
            &session.child_composition_manifest_sha256,
        ) or !std.mem.eql(
            u8,
            &self.parent_outer_manifest_sha256,
            &session.parent_outer_manifest_sha256,
        ) or !std.meta.eql(
            self.verification_key_id,
            session.verification_key_id,
        ) or !std.meta.eql(
            self.next_parent_vk_id,
            session.next_parent_vk_id,
        ) or !std.meta.eql(self.air_program_id, session.air_program_id)) {
            return error.SecureTemporalParentSessionMismatch;
        }
    }
};

pub const VerifierStatementInputV1 = struct {
    interaction_pow_nonce: u64,
    canonical_proof_byte_count: u32,
    canonical_proof_sha256: [32]u8,
    proof_id: channel.Digest,
    capture_id: channel.Digest,
    transcript_id: channel.Digest,
    claims_sha256: [32]u8,
    audit_sha256: [32]u8,
    closure_sha256: [32]u8,
};

/// Builds custody metadata from values already reconstructed by the secure
/// verifier.  Calling this function is not proof admission; only the engine's
/// non-serializable fresh result carries that authority.
pub fn statementFromVerifier(
    session: *const SessionV1,
    input: VerifierStatementInputV1,
) !StatementV1 {
    try session.validate();
    var result = StatementV1{
        .protocol = session.protocol,
        .session_identity_sha256 = session.identity_sha256,
        .ingress_identity_sha256 = session.ingress_identity_sha256,
        .parent_statement_sha256 = session.parent_statement_sha256,
        .profile_identity_sha256 = session.profile_identity_sha256,
        .child_composition_manifest_sha256 = session.child_composition_manifest_sha256,
        .parent_outer_manifest_sha256 = session.parent_outer_manifest_sha256,
        .verification_key_id = session.verification_key_id,
        .next_parent_vk_id = session.next_parent_vk_id,
        .air_program_id = session.air_program_id,
        .interaction_pow_nonce = input.interaction_pow_nonce,
        .canonical_proof_byte_count = input.canonical_proof_byte_count,
        .canonical_proof_sha256 = input.canonical_proof_sha256,
        .proof_id = input.proof_id,
        .capture_id = input.capture_id,
        .transcript_id = input.transcript_id,
        .claims_sha256 = input.claims_sha256,
        .audit_sha256 = input.audit_sha256,
        .closure_sha256 = input.closure_sha256,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = statementIdentity(&result);
    try result.validateAgainstSession(session);
    return result;
}

/// Owned, durable custody.  `proof_bytes` are exact postcard bytes and remain
/// untrusted until the cold verifier decodes and canonically reserializes them.
pub const OwnedArtifactV1 = struct {
    allocator: std.mem.Allocator,
    statement: StatementV1,
    proof_bytes: []u8,

    pub fn initCopy(
        allocator: std.mem.Allocator,
        statement: StatementV1,
        proof_bytes: []const u8,
    ) !OwnedArtifactV1 {
        const owned = try allocator.dupe(u8, proof_bytes);
        errdefer allocator.free(owned);
        var result = OwnedArtifactV1{
            .allocator = allocator,
            .statement = statement,
            .proof_bytes = owned,
        };
        try result.validateCustody();
        return result;
    }

    pub fn deinit(self: *OwnedArtifactV1) void {
        self.allocator.free(self.proof_bytes);
        self.* = undefined;
    }

    pub fn validateCustody(self: *const OwnedArtifactV1) !void {
        try self.statement.validate();
        var proof_sha256: [32]u8 = undefined;
        Sha256.hash(self.proof_bytes, &proof_sha256, .{});
        if (self.proof_bytes.len !=
            @as(usize, self.statement.canonical_proof_byte_count) or
            self.proof_bytes.len == 0 or
            self.proof_bytes.len > MAX_CANONICAL_PROOF_BYTES or
            !std.mem.eql(
                u8,
                &proof_sha256,
                &self.statement.canonical_proof_sha256,
            ))
        {
            return error.InvalidSecureTemporalParentArtifact;
        }
    }

    pub fn encodeCanonicalAlloc(
        self: *const OwnedArtifactV1,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        try self.validateCustody();
        const byte_count = std.math.add(
            usize,
            ARTIFACT_HEADER_BYTE_COUNT + STATEMENT_ENCODED_BYTE_COUNT,
            self.proof_bytes.len,
        ) catch return error.InvalidSecureTemporalParentArtifact;
        const result = try allocator.alloc(u8, byte_count);
        errdefer allocator.free(result);
        @memcpy(result[0..ARTIFACT_HEADER_BYTE_COUNT], &ARTIFACT_MAGIC);
        var writer = Writer{
            .bytes = result[ARTIFACT_HEADER_BYTE_COUNT..][0..STATEMENT_ENCODED_BYTE_COUNT],
        };
        writeStatement(&writer, &self.statement);
        std.debug.assert(writer.at == STATEMENT_ENCODED_BYTE_COUNT);
        @memcpy(
            result[ARTIFACT_HEADER_BYTE_COUNT + STATEMENT_ENCODED_BYTE_COUNT ..],
            self.proof_bytes,
        );
        return result;
    }

    pub fn decodeCanonical(
        allocator: std.mem.Allocator,
        bytes: []const u8,
    ) !OwnedArtifactV1 {
        const fixed = ARTIFACT_HEADER_BYTE_COUNT + STATEMENT_ENCODED_BYTE_COUNT;
        if (bytes.len <= fixed or
            !std.mem.eql(u8, bytes[0..ARTIFACT_HEADER_BYTE_COUNT], &ARTIFACT_MAGIC))
        {
            return error.InvalidSecureTemporalParentArtifact;
        }
        var reader = Reader{
            .bytes = bytes[ARTIFACT_HEADER_BYTE_COUNT..][0..STATEMENT_ENCODED_BYTE_COUNT],
        };
        const statement = try readStatement(&reader);
        if (reader.at != reader.bytes.len)
            return error.InvalidSecureTemporalParentArtifact;
        const proof_bytes = bytes[fixed..];
        var result = try OwnedArtifactV1.initCopy(
            allocator,
            statement,
            proof_bytes,
        );
        errdefer result.deinit();
        const canonical = try result.encodeCanonicalAlloc(allocator);
        defer allocator.free(canonical);
        if (!std.mem.eql(u8, bytes, canonical))
            return error.InvalidSecureTemporalParentArtifact;
        return result;
    }
};

fn sessionIdentity(value: *const SessionV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(SESSION_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.source_kind));
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hashInt(&hash, u16, value.reserved);
    hash.update(&value.protocol.identity_sha256);
    hash.update(&value.ingress_identity_sha256);
    for (value.parent_statement_words) |word|
        hashInt(&hash, u32, word.toU32());
    hash.update(&value.parent_statement_sha256);
    hash.update(&value.profile_identity_sha256);
    hash.update(&value.child_composition_manifest_sha256);
    hash.update(&value.parent_outer_manifest_sha256);
    hashDigest(&hash, value.verification_key_id);
    hashDigest(&hash, value.next_parent_vk_id);
    hashDigest(&hash, value.air_program_id);
    return hash.finalResult();
}

fn statementIdentity(value: *const StatementV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(STATEMENT_DOMAIN);
    var encoded: [STATEMENT_ENCODED_BYTE_COUNT - 32]u8 = undefined;
    var writer = Writer{ .bytes = &encoded };
    writeStatementWithoutIdentity(&writer, value);
    std.debug.assert(writer.at == encoded.len);
    hash.update(&encoded);
    return hash.finalResult();
}

fn writeStatement(writer: *Writer, value: *const StatementV1) void {
    writeStatementWithoutIdentity(writer, value);
    writer.bytesValue(&value.identity_sha256);
}

fn writeStatementWithoutIdentity(
    writer: *Writer,
    value: *const StatementV1,
) void {
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u8Value(@intFromBool(value.production_activation));
    writer.bytesValue(&value.reserved);
    const protocol_bytes = value.protocol.encodeCanonical() catch unreachable;
    writer.bytesValue(&protocol_bytes);
    writer.bytesValue(&value.session_identity_sha256);
    writer.bytesValue(&value.ingress_identity_sha256);
    writer.bytesValue(&value.parent_statement_sha256);
    writer.bytesValue(&value.profile_identity_sha256);
    writer.bytesValue(&value.child_composition_manifest_sha256);
    writer.bytesValue(&value.parent_outer_manifest_sha256);
    writer.digest(value.verification_key_id);
    writer.digest(value.next_parent_vk_id);
    writer.digest(value.air_program_id);
    writer.u64Value(value.interaction_pow_nonce);
    writer.u32Value(value.canonical_proof_byte_count);
    writer.bytesValue(&value.canonical_proof_sha256);
    writer.digest(value.proof_id);
    writer.digest(value.capture_id);
    writer.digest(value.transcript_id);
    writer.bytesValue(&value.claims_sha256);
    writer.bytesValue(&value.audit_sha256);
    writer.bytesValue(&value.closure_sha256);
}

fn readStatement(reader: *Reader) !StatementV1 {
    const format_version = try reader.u16Value();
    const schema_version = try reader.u16Value();
    const production_activation = try reader.boolValue();
    const reserved = try reader.array(3);
    const protocol_bytes = try reader.array(protocol_mod.ENCODED_BYTE_COUNT);
    const result = StatementV1{
        .format_version = format_version,
        .schema_version = schema_version,
        .production_activation = production_activation,
        .reserved = reserved,
        .protocol = try protocol_mod.AuthorityV1.decodeCanonical(
            &protocol_bytes,
        ),
        .session_identity_sha256 = try reader.array(32),
        .ingress_identity_sha256 = try reader.array(32),
        .parent_statement_sha256 = try reader.array(32),
        .profile_identity_sha256 = try reader.array(32),
        .child_composition_manifest_sha256 = try reader.array(32),
        .parent_outer_manifest_sha256 = try reader.array(32),
        .verification_key_id = try reader.digest(),
        .next_parent_vk_id = try reader.digest(),
        .air_program_id = try reader.digest(),
        .interaction_pow_nonce = try reader.u64Value(),
        .canonical_proof_byte_count = try reader.u32Value(),
        .canonical_proof_sha256 = try reader.array(32),
        .proof_id = try reader.digest(),
        .capture_id = try reader.digest(),
        .transcript_id = try reader.digest(),
        .claims_sha256 = try reader.array(32),
        .audit_sha256 = try reader.array(32),
        .closure_sha256 = try reader.array(32),
        .identity_sha256 = try reader.array(32),
    };
    try result.validate();
    return result;
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn bytesValue(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.at..][0..value.len], value);
        self.at += value.len;
    }

    fn u8Value(self: *Writer, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }

    fn u16Value(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.at..][0..2], value, .little);
        self.at += 2;
    }

    fn u32Value(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.at..][0..4], value, .little);
        self.at += 4;
    }

    fn u64Value(self: *Writer, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.at..][0..8], value, .little);
        self.at += 8;
    }

    fn digest(self: *Writer, value: channel.Digest) void {
        for (value) |word| self.u32Value(word);
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(self: *Reader, count: usize) ![]const u8 {
        const end = std.math.add(usize, self.at, count) catch
            return error.InvalidSecureTemporalParentArtifact;
        if (end > self.bytes.len)
            return error.InvalidSecureTemporalParentArtifact;
        const result = self.bytes[self.at..end];
        self.at = end;
        return result;
    }

    fn array(self: *Reader, comptime count: usize) ![count]u8 {
        return (try self.take(count))[0..count].*;
    }

    fn u8Value(self: *Reader) !u8 {
        return (try self.take(1))[0];
    }

    fn boolValue(self: *Reader) !bool {
        return switch (try self.u8Value()) {
            0 => false,
            1 => true,
            else => error.InvalidSecureTemporalParentArtifact,
        };
    }

    fn u16Value(self: *Reader) !u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .little);
    }

    fn u32Value(self: *Reader) !u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }

    fn u64Value(self: *Reader) !u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }

    fn digest(self: *Reader) !channel.Digest {
        var result: channel.Digest = undefined;
        for (&result) |*word| word.* = try self.u32Value();
        return result;
    }
};

fn requireSha(value: [32]u8) !void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.InvalidSecureTemporalParentAuthority;
}

fn requireDigest(value: channel.Digest) !void {
    var nonzero = false;
    for (value) |word| {
        if (word >= @import("stwo_core").fields.m31.Modulus)
            return error.InvalidSecureTemporalParentAuthority;
        nonzero = nonzero or word != 0;
    }
    if (!nonzero) return error.InvalidSecureTemporalParentAuthority;
}

fn shaWords(value: [32]u8) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = std.mem.readInt(u32, value[index * 4 ..][0..4], .little);
    return result;
}

fn hashDigest(hash: *Sha256, value: channel.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

pub const testing = struct {
    pub fn session(
        parent_statement_words: span.StatementWords,
        parent_outer_manifest_sha256: [32]u8,
        seed: u8,
    ) !SessionV1 {
        if (!builtin.is_test)
            return error.SecureTemporalParentTestingUnavailable;
        const digest = seededDigest(seed);
        var result = SessionV1{
            .source_kind = .testing_only,
            .protocol = protocol_mod.AuthorityV1.secureParent(),
            .ingress_identity_sha256 = [_]u8{seed} ** 32,
            .parent_statement_words = parent_statement_words,
            .parent_statement_sha256 = statement_plan.statementSha256(
                &parent_statement_words,
            ),
            .profile_identity_sha256 = [_]u8{seed +% 1} ** 32,
            .child_composition_manifest_sha256 = [_]u8{seed +% 2} ** 32,
            .parent_outer_manifest_sha256 = parent_outer_manifest_sha256,
            .verification_key_id = digest,
            .next_parent_vk_id = seededDigest(seed +% 1),
            .air_program_id = seededDigest(seed +% 2),
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = sessionIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn resealStatement(value: *StatementV1) void {
        if (!builtin.is_test)
            @panic("secure parent testing helper used outside test build");
        value.identity_sha256 = statementIdentity(value);
    }

    fn seededDigest(seed: u8) channel.Digest {
        var result: channel.Digest = undefined;
        for (&result, 0..) |*word, index|
            word.* = @as(u32, seed) + @as(u32, @intCast(index)) + 1;
        return result;
    }
};

comptime {
    if (PRODUCTION_ACTIVATION or STATEMENT_ENCODED_BYTE_COUNT != 680 or
        ARTIFACT_HEADER_BYTE_COUNT != ARTIFACT_MAGIC.len or
        @intFromEnum(SourceKindV1.fresh_ethereum_poseidon_h1) != 1 or
        @intFromEnum(SourceKindV1.fresh_temporal_parent_v3) != 2 or
        @intFromEnum(SourceKindV1.canonical_empty_wrapper_v1) != 3 or
        @intFromEnum(SourceKindV1.common_fold_field_v2) != 4 or
        @intFromEnum(SourceKindV1.ethereum_incremental_leaf_wrapper_v4) != 5 or
        @intFromEnum(SourceKindV1.canonical_empty_campaign_v2) != 6 or
        @intFromEnum(SourceKindV1.testing_only) != 255 or
        @sizeOf(channel.Digest) != 32 or protocol_mod.ENCODED_BYTE_COUNT != 116)
    {
        @compileError("secure temporal-parent artifact ABI drifted");
    }
}
