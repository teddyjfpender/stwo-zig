//! Verifier-transaction handoff required by secure child composition.
//!
//! A secure parent fresh verification currently retains its PCS capture and a
//! pointer-free statement, but the next recursion layer also needs the exact
//! verifier-reconstructed relations, physical claims, and H1 closure.  This
//! module defines that typed handoff without pretending it is already an AIR
//! composition capture.  It can only be formed while those live values are
//! available and replays the H1 cohort audit before retaining them.
//!
//! Graph recording, evaluated-node custody, and upper-node admission remain
//! deliberately unavailable.  In particular, the SHA identity below is only
//! custody for the retained typed values; it is never a digest-only substitute
//! for the missing composition graph.

const std = @import("std");
const builtin = @import("builtin");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_mod =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const h1_manifest =
    @import("recursive_temporal_ethereum_poseidon_h1_manifest_v1.zig");
const h1_cohort =
    @import("recursive_temporal_ethereum_poseidon_h1_proof_cohort_v1.zig");
const segment_publication =
    @import("recursive_segment_v2_verified_publication.zig");

const recursion = frontend.recursion;
const universal = recursion.air.universal_challenges;
const shared_provider = recursion.air.universal_shared_provider;
const QM31 = stwo_core.fields.qm31.QM31;
const Sha256 = std.crypto.hash.sha2.Sha256;
const OuterProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
    recursion.engine.Hasher,
);

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const COMPOSITION_CAPTURE_MINT_AVAILABLE = false;
pub const UPPER_CHILD_ADMISSION_AVAILABLE = false;
pub const H1_PHYSICAL_CLAIM_COUNT: usize = h1_manifest.COMPONENT_COUNT;
pub const H1_PROVIDER_PARTIAL_COUNT: usize = 2;
pub const H1_COMPOSITION_CLAIM_INPUT_COUNT: usize =
    H1_PHYSICAL_CLAIM_COUNT + H1_PROVIDER_PARTIAL_COUNT;

const IDENTITY_DOMAIN =
    "stwo-zig/typed-air/secure-child-verifier-reconstruction/v1\x00";
const AUDIT_DOMAIN =
    "stwo-zig/typed-air/secure-temporal-parent-audit/v1\x00";
const GRAPH_MINT_PLAN_DOMAIN =
    "stwo-zig/typed-air/secure-child-h1-graph-mint-plan/v1\x00";

pub const ChildProgramKindV1 = enum(u8) {
    ethereum_poseidon_h1 = 1,
};

/// Exact non-serializable values reconstructed by the cold H1 verifier.
///
/// This is a prerequisite to recording the child composition graph, not that
/// graph and not an upper-child authority.  The future engine handoff must
/// construct it before `relations`, `claims`, and `audited` leave scope.
pub const VerifiedReconstructionV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    session: artifact_mod.SessionV1,
    statement: artifact_mod.StatementV1,
    manifest: h1_manifest.Manifest,
    relations: universal.UniversalRelations,
    provider_relations: shared_provider.SharedProviderRelations,
    claims: h1_manifest.ClaimVector,
    /// The H1 physical provider placement commits their sum. Composition
    /// evaluation additionally needs both native Poseidon partial claims.
    provider_partial_claims: [H1_PROVIDER_PARTIAL_COUNT]QM31,
    audited: h1_cohort.H1AuditedInteractionsV2,
    identity_sha256: [32]u8,

    pub fn validateRetained(self: *const VerifiedReconstructionV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0))
        {
            return error.InvalidSecureChildVerifierReconstruction;
        }
        try self.session.validate();
        if (self.session.source_kind != .fresh_ethereum_poseidon_h1)
            return error.InvalidSecureChildVerifierReconstruction;
        try self.statement.validateAgainstSession(&self.session);
        try self.manifest.validate();
        try self.relations.validate();
        try self.provider_relations.validateAgainst(&self.relations);
        try self.claims.validate(&self.manifest);
        try self.audited.validate();

        const provider_total = self.provider_partial_claims[0].add(
            self.provider_partial_claims[1],
        );
        if (!provider_total.eql(
            self.claims.values[h1_manifest.keyIndex(.poseidon2)],
        )) return error.SecureChildProviderPartialMismatch;

        const contract_identity = try h1_manifest.contractIdentity();
        if (!std.mem.eql(
            u8,
            &self.session.parent_outer_manifest_sha256,
            &contract_identity,
        ) or !std.mem.eql(
            u8,
            &self.session.ingress_identity_sha256,
            &self.manifest.ingress_authority_sha256,
        ) or !std.mem.eql(
            u8,
            &self.statement.claims_sha256,
            &self.claims.seal,
        ) or !std.mem.eql(
            u8,
            &self.statement.audit_sha256,
            &auditIdentity(&self.claims, &self.audited),
        ) or !std.mem.eql(
            u8,
            &self.statement.closure_sha256,
            &self.audited.closure.closure_id,
        ) or !std.mem.eql(
            u8,
            &self.identity_sha256,
            &reconstructionIdentity(self),
        )) return error.InvalidSecureChildVerifierReconstruction;
    }

    pub fn validateAgainstCapture(
        self: *const VerifiedReconstructionV1,
        capture: *const OuterProofCapture,
    ) !void {
        try self.validateRetained();
        if (!std.meta.eql(
            self.statement.capture_id,
            segment_publication.captureIdentity(capture),
        )) return error.SecureChildPcsCaptureMismatch;
    }

    /// Terminal until the H1-specific graph recorder retains bindings,
    /// evaluated nodes, and the source/output relation joins.
    pub fn requireCompositionCapture(
        self: *const VerifiedReconstructionV1,
    ) !void {
        try self.validateRetained();
        if (!COMPOSITION_CAPTURE_MINT_AVAILABLE)
            return error.SecureChildCompositionCaptureUnavailable;
        if (!UPPER_CHILD_ADMISSION_AVAILABLE or !PRODUCTION_ACTIVATION)
            return error.SecureUpperChildAdmissionUnavailable;
    }
};

/// Called from the cold verifier transaction while every value is still live.
/// `Cohort` remains generic over the verifier-minted leaf capture surface, so
/// baseline and projected-candidate H1 proofs share this exact handoff.
pub fn fromVerifiedH1Transaction(
    comptime Cohort: type,
    cohort: *Cohort,
    session: *const artifact_mod.SessionV1,
    statement: *const artifact_mod.StatementV1,
    capture: *const OuterProofCapture,
    relations: *const universal.UniversalRelations,
    provider_relations: *const shared_provider.SharedProviderRelations,
    generated: *const Cohort.GeneratedInteractionsV1,
    claims: *const h1_manifest.ClaimVector,
    audited: *const h1_cohort.H1AuditedInteractionsV2,
) !VerifiedReconstructionV1 {
    try cohort.validate();
    const manifest = cohort.manifest();
    try manifest.validate();
    try cohort.validateGenerated(
        generated,
        relations,
        provider_relations,
    );
    const expected_claims = try cohort.claimVector(generated);
    if (!std.meta.eql(claims.*, expected_claims))
        return error.SecureChildClaimVectorMismatch;
    try cohort.validateAuditedInteractions(
        audited,
        claims,
        relations,
        provider_relations,
    );
    var result = VerifiedReconstructionV1{
        .session = session.*,
        .statement = statement.*,
        .manifest = manifest.*,
        .relations = relations.*,
        .provider_relations = provider_relations.*,
        .claims = claims.*,
        .provider_partial_claims = generated.claims.provider,
        .audited = audited.*,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = reconstructionIdentity(&result);
    try result.validateAgainstCapture(capture);
    return result;
}

/// Exact source shape for the missing graph owner.  The current generic V3
/// recorder cannot consume this plan: it admits only three legacy program
/// kinds, fixes the binary roster at 36, and places Poseidon partials after a
/// 39-claim maximum. H1 instead has 12 physical claims, provider row 11, and
/// partial slots 12/13. Keeping those coordinates explicit prevents a future
/// patch from zero-padding H1 into the legacy binary claim policy.
pub const GraphMintPlanV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    program_kind: ChildProgramKindV1 = .ethereum_poseidon_h1,
    production_activation: bool = PRODUCTION_ACTIVATION,
    recorder_support_available: bool = COMPOSITION_CAPTURE_MINT_AVAILABLE,
    reserved: [3]u8 = .{ 0, 0, 0 },
    component_count: u8 = H1_PHYSICAL_CLAIM_COUNT,
    provider_roster_row: u8 = h1_manifest.keyIndex(.poseidon2),
    physical_claim_count: u8 = H1_PHYSICAL_CLAIM_COUNT,
    provider_partial_count: u8 = H1_PROVIDER_PARTIAL_COUNT,
    provider_partial_start: u8 = H1_PHYSICAL_CLAIM_COUNT,
    composition_claim_input_count: u8 = H1_COMPOSITION_CLAIM_INPUT_COUNT,
    sampled_value_count: u32,
    reconstruction_identity_sha256: [32]u8,
    manifest_seal: [32]u8,
    identity_sha256: [32]u8,

    pub fn init(
        reconstruction: *const VerifiedReconstructionV1,
        capture: *const OuterProofCapture,
    ) !GraphMintPlanV1 {
        try reconstruction.validateAgainstCapture(capture);
        const sample_count = std.math.cast(
            u32,
            capture.sampled_values.len,
        ) orelse return error.SecureChildSampleCountOverflow;
        if (sample_count == 0) return error.InvalidSecureChildGraphMintPlan;
        var result = GraphMintPlanV1{
            .sampled_value_count = sample_count,
            .reconstruction_identity_sha256 = reconstruction.identity_sha256,
            .manifest_seal = reconstruction.manifest.seal,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = graphMintPlanIdentity(&result);
        try result.validateAgainst(reconstruction);
        return result;
    }

    pub fn validateAgainst(
        self: *const GraphMintPlanV1,
        reconstruction: *const VerifiedReconstructionV1,
    ) !void {
        try reconstruction.validateRetained();
        try self.validateShape();
        if (!std.mem.eql(
            u8,
            &self.reconstruction_identity_sha256,
            &reconstruction.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.manifest_seal,
            &reconstruction.manifest.seal,
        )) return error.InvalidSecureChildGraphMintPlan;
    }

    pub fn validateShape(self: *const GraphMintPlanV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.program_kind != .ethereum_poseidon_h1 or
            self.production_activation or self.recorder_support_available or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            self.component_count != H1_PHYSICAL_CLAIM_COUNT or
            self.provider_roster_row != h1_manifest.keyIndex(.poseidon2) or
            self.physical_claim_count != H1_PHYSICAL_CLAIM_COUNT or
            self.provider_partial_count != H1_PROVIDER_PARTIAL_COUNT or
            self.provider_partial_start != H1_PHYSICAL_CLAIM_COUNT or
            self.composition_claim_input_count !=
                H1_COMPOSITION_CLAIM_INPUT_COUNT or
            self.sampled_value_count == 0 or
            std.mem.allEqual(u8, &self.reconstruction_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.manifest_seal, 0) or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &graphMintPlanIdentity(self),
            )) return error.InvalidSecureChildGraphMintPlan;
    }

    pub fn requireRecorderSupport(self: *const GraphMintPlanV1) !void {
        try self.validateShape();
        if (self.recorder_support_available or
            COMPOSITION_CAPTURE_MINT_AVAILABLE or PRODUCTION_ACTIVATION)
        {
            return error.InvalidSecureChildGraphMintPlan;
        }
        return error.SecureChildH1CompositionRecorderUnavailable;
    }
};

fn auditIdentity(
    claims: *const h1_manifest.ClaimVector,
    audited: *const h1_cohort.H1AuditedInteractionsV2,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUDIT_DOMAIN);
    hash.update(&claims.seal);
    hash.update(&audited.closure.closure_id);
    hashInt(&hash, u64, audited.wire_boundary.tuple_count);
    hashQm31(&hash, audited.wire_boundary.claimed_sum);
    hashInt(&hash, u64, audited.verifier_input_boundary.tuple_count);
    hashQm31(&hash, audited.verifier_input_boundary.claimed_sum);
    return hash.finalResult();
}

fn reconstructionIdentity(value: *const VerifiedReconstructionV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hash.update(&value.reserved);
    hash.update(&value.session.identity_sha256);
    hash.update(&value.statement.identity_sha256);
    hash.update(&value.manifest.seal);
    hash.update(&value.relations.registry_order_digest);
    for (value.relations.elements) |element| {
        hashInt(&hash, u8, element.arity);
        hashQm31(&hash, element.z);
        hashQm31(&hash, element.alpha);
        for (element.alpha_powers) |power| hashQm31(&hash, power);
    }
    const provider_identity = value.provider_relations.identityDigest() catch
        return [_]u8{0} ** 32;
    hash.update(&provider_identity);
    hash.update(&value.claims.seal);
    for (value.claims.values) |claim| hashQm31(&hash, claim);
    for (value.provider_partial_claims) |claim| hashQm31(&hash, claim);
    hash.update(&value.audited.closure.closure_id);
    hash.update(&value.audited.h1_boundary.identity_sha256);
    hashQm31(&hash, value.audited.wire_boundary.claimed_sum);
    hashQm31(&hash, value.audited.verifier_input_boundary.claimed_sum);
    return hash.finalResult();
}

fn graphMintPlanIdentity(value: *const GraphMintPlanV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(GRAPH_MINT_PLAN_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.program_kind));
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hashInt(&hash, u8, @intFromBool(value.recorder_support_available));
    hash.update(&value.reserved);
    hashInt(&hash, u8, value.component_count);
    hashInt(&hash, u8, value.provider_roster_row);
    hashInt(&hash, u8, value.physical_claim_count);
    hashInt(&hash, u8, value.provider_partial_count);
    hashInt(&hash, u8, value.provider_partial_start);
    hashInt(&hash, u8, value.composition_claim_input_count);
    hashInt(&hash, u32, value.sampled_value_count);
    hash.update(&value.reconstruction_identity_sha256);
    hash.update(&value.manifest_seal);
    return hash.finalResult();
}

fn hashQm31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

pub const testing = struct {
    pub fn graphMintPlan(sampled_value_count: u32) GraphMintPlanV1 {
        requireTest();
        var result = GraphMintPlanV1{
            .sampled_value_count = sampled_value_count,
            .reconstruction_identity_sha256 = [_]u8{0x31} ** 32,
            .manifest_seal = [_]u8{0x42} ** 32,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = graphMintPlanIdentity(&result);
        return result;
    }

    pub fn resealGraphMintPlan(value: *GraphMintPlanV1) void {
        requireTest();
        value.identity_sha256 = graphMintPlanIdentity(value);
    }

    fn requireTest() void {
        if (!builtin.is_test)
            @panic("secure child composition testing helper outside test");
    }
};

comptime {
    if (PRODUCTION_ACTIVATION or COMPOSITION_CAPTURE_MINT_AVAILABLE or
        UPPER_CHILD_ADMISSION_AVAILABLE or H1_PHYSICAL_CLAIM_COUNT != 12 or
        H1_PROVIDER_PARTIAL_COUNT != 2 or
        H1_COMPOSITION_CLAIM_INPUT_COUNT != 14 or
        h1_manifest.keyIndex(.poseidon2) != 11)
    {
        @compileError("secure child composition activated before graph capture");
    }
}
