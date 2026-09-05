//! Secure universal cohort for one campaign-native canonical-empty wrapper.
//!
//! NodePublicV2 is mixed word-for-word before relation challenges.  The
//! existing Poseidon2 AIR proves the exact 173 campaign permutations.  Its positive
//! atomic-I/O provider claim must cancel the cold-verifier-reconstructed
//! public request boundary.  No digest supplied by a prover grants closure.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const field_public =
    @import("recursive_common_canonical_empty_campaign_field_public_v2.zig");
const manifest_mod =
    @import("recursive_common_canonical_empty_campaign_universal_manifest_v2.zig");
const trace_mod =
    @import("recursive_common_canonical_empty_campaign_universal_trace_v2.zig");
const source_mod =
    @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const padding_target_mod =
    @import("recursive_pipeline_campaign_padding_target_v2.zig");
const identity_mod =
    @import("recursive_common_canonical_empty_campaign_cohort_identity_v2.zig");
const preprocessed_authority =
    @import("recursive_process_local_preprocessed_authority_v1.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const air = recursion.air;
const adapter = air.universal_typed_component;
const binding = air.universal_relation_binding;
const catalog = air.universal_catalog;
const provider = air.universal_shared_provider;
const range_bridge = air.range_check_8_8_bridge;
const universal = air.universal_challenges;
const global_closure = recursion.binary_global_closure_outer_source;
const RelationDomain = @TypeOf(global_closure.VERIFIER_INPUT_BOUNDARY_DOMAIN);

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 2;
pub const PRODUCTION_ACTIVATION = false;
pub const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const PUBLIC_WORD_COUNT: usize = field_public.AIR_WORD_COUNT;
pub const POSEIDON2_DOMAIN_INDEX =
    @intFromEnum(@as(RelationDomain, .poseidon2));
pub const POSEIDON2_IO_DOMAIN_INDEX =
    @intFromEnum(@as(RelationDomain, .poseidon2_io));

const AUTHORITY_TRANSCRIPT_DOMAIN: u32 = 0x4343_5032; // "CEP2"
const FIELD_BOUNDARY_TRANSCRIPT_DOMAIN: u32 = 0x4343_4232; // "CEB2"
pub const AuthorityInputs = struct {
    cold: source_mod.ColdInputV2,
    padding_target: padding_target_mod.CampaignPaddingTargetV2,
};

pub const BoundaryEvidenceV2 = struct {
    domain: RelationDomain,
    tuple_count: u64,
    claimed_sum: QM31,
    tuple_provenance_sha256: [32]u8,

    pub fn zero(domain: RelationDomain) BoundaryEvidenceV2 {
        const result = BoundaryEvidenceV2{
            .domain = domain,
            .tuple_count = 0,
            .claimed_sum = QM31.zero(),
            .tuple_provenance_sha256 = undefined,
        };
        var sealed = result;
        sealed.tuple_provenance_sha256 = identity_mod.boundaryIdentity(&sealed);
        return sealed;
    }

    pub fn validate(self: *const BoundaryEvidenceV2) !void {
        if (!std.mem.eql(
            u8,
            &self.tuple_provenance_sha256,
            &identity_mod.boundaryIdentity(self),
        )) return error.CanonicalEmptyPublicBoundaryMismatch;
    }
};

pub const ClosureReceiptV2 = struct {
    closure_id: [32]u8,
};

pub const AuditedInteractionsV2 = struct {
    wire_boundary: BoundaryEvidenceV2,
    verifier_input_boundary: BoundaryEvidenceV2,
    closure: ClosureReceiptV2,
    identity_sha256: [32]u8,

    pub fn validate(self: *const AuditedInteractionsV2) !void {
        try self.wire_boundary.validate();
        try self.verifier_input_boundary.validate();
        if (self.wire_boundary.domain != .poseidon2_io or
            self.wire_boundary.tuple_count != field_public.POSEIDON_CALL_COUNT or
            self.verifier_input_boundary.domain !=
                .recursion_verifier_input_word or
            self.verifier_input_boundary.tuple_count != 0 or
            !self.verifier_input_boundary.claimed_sum.isZero() or
            std.mem.allEqual(u8, &self.closure.closure_id, 0) or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &identity_mod.auditIdentity(self),
            ))
        {
            return error.CanonicalEmptyPublicBoundaryMismatch;
        }
    }
};

pub const GeneratedInteractionsV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    provider_closed: bool,
    manifest_seal: [32]u8,
    cohort_identity_sha256: [32]u8,
    relations_identity_sha256: [32]u8,
    provider_relations_identity_sha256: [32]u8,
    provider_claims: trace_mod.ProviderClaimsV2,
    public_request_claim: QM31,
    claims: [COMPONENT_COUNT]QM31,
    domain_totals: [universal.RELATION_COUNT]QM31,
    identity_sha256: [32]u8,

    pub fn validate(self: *const GeneratedInteractionsV1) !void {
        try self.provider_claims.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or !self.provider_closed or
            std.mem.allEqual(u8, &self.manifest_seal, 0) or
            std.mem.allEqual(u8, &self.cohort_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.relations_identity_sha256, 0) or
            std.mem.allEqual(
                u8,
                &self.provider_relations_identity_sha256,
                0,
            ) or !self.provider_claims.poseidon2_io.add(
            self.public_request_claim,
        ).isZero() or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &identity_mod.generatedIdentity(self),
            ))
        {
            return error.CanonicalEmptyGeneratedInteractionMismatch;
        }
        for (self.claims, 0..) |claim, index| {
            const expected = if (index == @intFromEnum(
                manifest_mod.ComponentKey.poseidon2,
            )) self.provider_claims.total() else QM31.zero();
            if (!claim.eql(expected))
                return error.CanonicalEmptyGeneratedInteractionMismatch;
        }
        for (self.domain_totals, 0..) |total, index| {
            const expected = if (index == POSEIDON2_DOMAIN_INDEX)
                self.provider_claims.poseidon2
            else if (index == POSEIDON2_IO_DOMAIN_INDEX)
                self.provider_claims.poseidon2_io
            else
                QM31.zero();
            if (!total.eql(expected))
                return error.CanonicalEmptyGeneratedInteractionMismatch;
        }
    }
};

fn LogicalOwner(comptime entry: catalog.Entry) type {
    const Air = entry.Air;
    const Relation = binding.Binding(Air);
    return struct {
        definition: Air.Definition,
        relation_plan: Relation.Plan,

        fn init(allocator: std.mem.Allocator) !@This() {
            var definition = if (entry.requires_location)
                try Air.build(allocator, .generated)
            else
                try Air.build(allocator);
            errdefer definition.deinit();
            return .{
                .relation_plan = try Relation.authenticate(&definition),
                .definition = definition,
            };
        }

        fn deinit(self: *@This()) void {
            self.definition.deinit();
            self.* = undefined;
        }
    };
}

fn LogicalOwnersType() type {
    var types: [catalog.LOGICAL_COUNT]type = undefined;
    inline for (catalog.LOGICAL_ROWS, 0..) |entry, index|
        types[index] = LogicalOwner(entry);
    return std.meta.Tuple(&types);
}

const LogicalOwners = LogicalOwnersType();
const CohortAuthorityInputs = AuthorityInputs;
const CohortGeneratedInteractionsV1 = GeneratedInteractionsV1;
const CohortAuditedInteractionsV2 = AuditedInteractionsV2;

pub const CohortV2 = struct {
    pub const AuthorityInputs = CohortAuthorityInputs;
    pub const GeneratedInteractionsV1 = CohortGeneratedInteractionsV1;
    pub const AuditedInteractionsV2 = CohortAuditedInteractionsV2;

    allocator: std.mem.Allocator,
    inputs: CohortAuthorityInputs,
    schedule: field_public.PoseidonScheduleV2,
    statement_words_m31: recursion.span_statement.StatementWords,
    manifest_value: manifest_mod.Manifest,
    logical: LogicalOwners,
    logical_initialized: usize,
    range_definition: range_bridge.Definition,
    range_executor: range_bridge.Executor,
    authority_sha256: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        inputs: CohortAuthorityInputs,
    ) !CohortV2 {
        const schedule = try field_public.PoseidonScheduleV2.build(
            &inputs.cold,
        );
        var statement_words_m31: recursion.span_statement.StatementWords =
            undefined;
        for (
            &statement_words_m31,
            inputs.cold.source.statement_words,
        ) |*target, word| target.* = M31.fromCanonical(word);
        const manifest_value = try manifest_mod.buildForLogSizes(
            try logSizesForInputs(&inputs),
        );
        var logical: LogicalOwners = undefined;
        var logical_initialized: usize = 0;
        errdefer deinitLogical(&logical, logical_initialized);
        inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
            logical[index] = try LogicalOwner(entry).init(allocator);
            logical_initialized += 1;
        }
        var range_definition = try range_bridge.build(allocator);
        errdefer range_definition.deinit();
        const range_binding = try range_bridge.Binding.canonical(
            &range_definition,
        );
        const range_executor = try range_bridge.Executor.init(
            &range_definition,
            &range_binding,
        );
        var result = CohortV2{
            .allocator = allocator,
            .inputs = inputs,
            .schedule = schedule,
            .statement_words_m31 = statement_words_m31,
            .manifest_value = manifest_value,
            .logical = logical,
            .logical_initialized = logical_initialized,
            .range_definition = range_definition,
            .range_executor = range_executor,
            .authority_sha256 = undefined,
        };
        result.authority_sha256 = identity_mod.cohortIdentity(
            &result,
            FORMAT_VERSION,
            SCHEMA_VERSION,
        );
        try result.validate();
        return result;
    }

    pub fn deinit(self: *CohortV2) void {
        self.range_definition.deinit();
        deinitLogical(&self.logical, self.logical_initialized);
        self.* = undefined;
    }

    pub fn validate(self: *CohortV2) !void {
        const logs = try logSizesForInputs(&self.inputs);
        try manifest_mod.validateForLogSizes(&self.manifest_value, logs);
        try self.schedule.validateAgainst(&self.inputs.cold);
        if (self.logical_initialized != catalog.LOGICAL_COUNT or
            !std.meta.eql(
                self.schedule.node_public,
                self.inputs.cold.node_public,
            ))
        {
            return error.CanonicalEmptyCohortAuthorityMismatch;
        }
        for (
            self.statement_words_m31,
            self.inputs.cold.source.statement_words,
        ) |felt, word|
            if (felt.toU32() != word)
                return error.CanonicalEmptyCohortAuthorityMismatch;
        inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
            try self.logical[index].definition.validate();
            try self.logical[index].relation_plan.validateAgainst(
                &self.logical[index].definition.arena,
                entry.Air.SEMANTIC_DIGEST,
                binding.Binding(entry.Air).events(
                    &self.logical[index].definition,
                ),
            );
        }
        try self.range_definition.validate();
        try self.range_executor.validate();
        if (!std.mem.eql(
            u8,
            &self.authority_sha256,
            &identity_mod.cohortIdentity(self, FORMAT_VERSION, SCHEMA_VERSION),
        )) return error.CanonicalEmptyCohortAuthorityMismatch;
    }

    pub fn manifest(self: *const CohortV2) *const manifest_mod.Manifest {
        return &self.manifest_value;
    }

    pub fn parentManifestIdentity(self: *const CohortV2) ![32]u8 {
        const logs = try logSizesForInputs(&self.inputs);
        return manifest_mod.contractIdentityForManifest(
            &self.manifest_value,
            logs,
        );
    }

    pub fn processLocalPreprocessedCacheKey(
        self: *CohortV2,
        pcs_identity_sha256: [32]u8,
        root: recursion.engine.Hasher.Hash,
    ) !preprocessed_authority.KeyV1 {
        try self.validate();
        const logs = try logSizesForInputs(&self.inputs);
        const layout = try manifest_mod.tableLayoutIdentityForManifest(
            &self.manifest_value,
            logs,
        );
        return preprocessed_authority.KeyV1.init(.{
            .circuit_identity_sha256 = try self.parentManifestIdentity(),
            .program_identity_sha256 = try manifest_mod.programIdentityForManifest(
                &self.manifest_value,
                logs,
            ),
            .profile_identity_sha256 = try manifest_mod.profileIdentityForManifest(
                &self.manifest_value,
                logs,
            ),
            .pcs_identity_sha256 = pcs_identity_sha256,
            .padding_identity_sha256 = try manifest_mod.paddingIdentityForManifest(
                &self.manifest_value,
                logs,
            ),
            .preprocessed_identity_sha256 = try preprocessed_authority
                .preprocessedIdentity(
                recursion.engine.Hasher.Hash,
                layout,
                self.manifest_value.seal,
                root,
            ),
            .identity_sha256 = undefined,
        });
    }

    pub fn publicationAuthority(
        self: *const CohortV2,
    ) *const field_public.PoseidonScheduleV2 {
        return &self.schedule;
    }

    pub fn recursiveStatementWords(
        self: *const CohortV2,
    ) !*const recursion.span_statement.StatementWords {
        try self.schedule.source.validateAgainst(&self.inputs.cold);
        if (!std.meta.eql(
            self.schedule.node_public.source_digest,
            self.schedule.source.source_digest,
        )) return error.CanonicalEmptyCohortAuthorityMismatch;
        return &self.statement_words_m31;
    }

    pub fn sessionAuthority(
        self: *const CohortV2,
    ) !secure_artifact.CampaignCanonicalEmptySessionAuthorityV2 {
        const logs = try logSizesForInputs(&self.inputs);
        const manifest_identity = try manifest_mod.contractIdentityForManifest(
            &self.manifest_value,
            logs,
        );
        return .{
            .ingress_identity_sha256 = self.authority_sha256,
            .parent_statement_words = self.statement_words_m31,
            .profile_identity_sha256 = try manifest_mod.profileIdentityForManifest(
                &self.manifest_value,
                logs,
            ),
            .child_composition_manifest_sha256 = manifest_identity,
            .parent_outer_manifest_sha256 = manifest_identity,
            .verification_key_id = try manifest_mod.verificationKeyIdForManifest(
                &self.manifest_value,
                logs,
            ),
            .next_parent_vk_id = try manifest_mod.nextParentVkIdForManifest(
                &self.manifest_value,
                logs,
            ),
            .air_program_id = try manifest_mod.airProgramIdForManifest(
                &self.manifest_value,
                logs,
            ),
        };
    }

    pub fn session(self: *const CohortV2) !secure_artifact.SessionV1 {
        return secure_artifact.SessionV1.initCanonicalEmptyCampaignV2(
            try self.sessionAuthority(),
        );
    }

    pub fn validateSession(
        self: *const CohortV2,
        value: *const secure_artifact.SessionV1,
    ) !void {
        if (!std.meta.eql(value.*, try self.session()))
            return error.CanonicalEmptyCohortAuthorityMismatch;
    }

    /// Exact field-native public statement mix. SHA receipts are deliberately
    /// absent from this semantic transcript boundary.
    pub fn mixAuthority(self: *CohortV2, transcript: anytype) !void {
        try self.validate();
        const public_words = try self.schedule.node_public.canonicalAirWords();
        transcript.mixU32s(&.{
            AUTHORITY_TRANSCRIPT_DOMAIN,
            FORMAT_VERSION,
            SCHEMA_VERSION,
            PUBLIC_WORD_COUNT,
            field_public.POSEIDON_CALL_COUNT,
        });
        transcript.mixU32s(&public_words);
    }

    pub fn mixBoundaryReceipt(
        transcript: anytype,
        audited: *const CohortAuditedInteractionsV2,
    ) !void {
        try audited.validate();
        transcript.mixU32s(&.{
            FIELD_BOUNDARY_TRANSCRIPT_DOMAIN,
            FORMAT_VERSION,
            SCHEMA_VERSION,
            @intFromEnum(audited.wire_boundary.domain),
            @as(u32, @intCast(audited.wire_boundary.tuple_count)),
        });
        transcript.mixFelts(&.{audited.wire_boundary.claimed_sum});
    }

    pub fn fillPreprocessedInto(
        self: *CohortV2,
        manifest_value: *const manifest_mod.Manifest,
        destination: [][]M31,
    ) !void {
        try self.validate();
        try requireManifest(manifest_value, &self.manifest_value);
        try trace_mod.fillPreprocessed(manifest_value, destination);
    }

    pub fn fillMainInto(
        self: *CohortV2,
        manifest_value: *const manifest_mod.Manifest,
        destination: [][]M31,
    ) !void {
        try self.validate();
        try requireManifest(manifest_value, &self.manifest_value);
        try trace_mod.fillMain(
            self.allocator,
            manifest_value,
            &self.schedule,
            &self.inputs.cold,
            destination,
        );
    }

    pub fn fillInteractionInto(
        self: *CohortV2,
        manifest_value: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        provider_relations: *const provider.SharedProviderRelations,
        destination: [][]M31,
    ) !CohortGeneratedInteractionsV1 {
        try self.validate();
        try requireManifest(manifest_value, &self.manifest_value);
        try provider_relations.validateAgainst(relations);
        const claims = try trace_mod.fillInteraction(
            self.allocator,
            manifest_value,
            &self.schedule,
            &self.inputs.cold,
            provider_relations,
            destination,
        );
        return self.generated(relations, provider_relations, claims);
    }

    pub fn rebuildGeneratedInteractions(
        self: *CohortV2,
        relations: *const universal.UniversalRelations,
        provider_relations: *const provider.SharedProviderRelations,
    ) !CohortGeneratedInteractionsV1 {
        try self.validate();
        try provider_relations.validateAgainst(relations);
        return self.generated(
            relations,
            provider_relations,
            try trace_mod.rebuildClaims(
                self.allocator,
                &self.manifest_value,
                &self.schedule,
                &self.inputs.cold,
                provider_relations,
            ),
        );
    }

    pub fn validateGenerated(
        self: *CohortV2,
        generated_value: *const CohortGeneratedInteractionsV1,
        relations: *const universal.UniversalRelations,
        provider_relations: *const provider.SharedProviderRelations,
    ) !void {
        try generated_value.validate();
        const expected = try self.rebuildGeneratedInteractions(
            relations,
            provider_relations,
        );
        if (!identity_mod.generatedEql(generated_value, &expected))
            return error.CanonicalEmptyGeneratedInteractionMismatch;
    }

    pub fn claimVector(
        self: *CohortV2,
        generated_value: *const CohortGeneratedInteractionsV1,
    ) !manifest_mod.ClaimVector {
        try generated_value.validate();
        var result = try manifest_mod.ClaimVector.init(&self.manifest_value);
        inline for (manifest_mod.COMPONENT_KEYS, 0..) |key, ordinal|
            try result.bind(key, generated_value.claims[ordinal]);
        try result.sealClaims(&self.manifest_value);
        return result;
    }

    pub fn auditGlobalClosureV2(
        self: *CohortV2,
        generated_value: *const CohortGeneratedInteractionsV1,
        claims: *const manifest_mod.ClaimVector,
        relations: *const universal.UniversalRelations,
        provider_relations: *const provider.SharedProviderRelations,
    ) !CohortAuditedInteractionsV2 {
        try self.validateGenerated(
            generated_value,
            relations,
            provider_relations,
        );
        if (!std.meta.eql(claims.*, try self.claimVector(generated_value)))
            return error.CanonicalEmptyGeneratedInteractionMismatch;
        var wire = BoundaryEvidenceV2{
            .domain = .poseidon2_io,
            .tuple_count = field_public.POSEIDON_CALL_COUNT,
            .claimed_sum = generated_value.public_request_claim,
            .tuple_provenance_sha256 = undefined,
        };
        wire.tuple_provenance_sha256 = identity_mod.boundaryIdentity(&wire);
        var result = CohortAuditedInteractionsV2{
            .wire_boundary = wire,
            .verifier_input_boundary = BoundaryEvidenceV2.zero(
                .recursion_verifier_input_word,
            ),
            .closure = .{ .closure_id = generated_value.identity_sha256 },
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = identity_mod.auditIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn auditGlobalClosure(
        self: *CohortV2,
        generated_value: *const CohortGeneratedInteractionsV1,
        claims: *const manifest_mod.ClaimVector,
        relations: *const universal.UniversalRelations,
        provider_relations: *const provider.SharedProviderRelations,
    ) !CohortAuditedInteractionsV2 {
        return self.auditGlobalClosureV2(
            generated_value,
            claims,
            relations,
            provider_relations,
        );
    }

    pub fn validateAuditedInteractions(
        self: *CohortV2,
        audited: *const CohortAuditedInteractionsV2,
        claims: *const manifest_mod.ClaimVector,
        relations: *const universal.UniversalRelations,
        provider_relations: *const provider.SharedProviderRelations,
    ) !void {
        try audited.validate();
        const generated_value = try self.rebuildGeneratedInteractions(
            relations,
            provider_relations,
        );
        const expected = try self.auditGlobalClosureV2(
            &generated_value,
            claims,
            relations,
            provider_relations,
        );
        if (!std.meta.eql(audited.*, expected))
            return error.CanonicalEmptyPublicBoundaryMismatch;
    }

    pub fn initComponents(
        self: *CohortV2,
        generated_value: *const CohortGeneratedInteractionsV1,
        relations: *const universal.UniversalRelations,
        provider_relations: *const provider.SharedProviderRelations,
    ) !ComponentSetV2 {
        try self.validateGenerated(
            generated_value,
            relations,
            provider_relations,
        );
        return ComponentSetV2.init(
            self,
            generated_value,
            relations,
            provider_relations,
        );
    }

    fn generated(
        self: *CohortV2,
        relations: *const universal.UniversalRelations,
        provider_relations: *const provider.SharedProviderRelations,
        provider_claims: trace_mod.ProviderClaimsV2,
    ) !CohortGeneratedInteractionsV1 {
        try provider_claims.validate();
        var claims = [_]QM31{QM31.zero()} ** COMPONENT_COUNT;
        claims[@intFromEnum(manifest_mod.ComponentKey.poseidon2)] =
            provider_claims.total();
        var domains = [_]QM31{QM31.zero()} ** universal.RELATION_COUNT;
        domains[POSEIDON2_DOMAIN_INDEX] = provider_claims.poseidon2;
        domains[POSEIDON2_IO_DOMAIN_INDEX] = provider_claims.poseidon2_io;
        var result = CohortGeneratedInteractionsV1{
            .provider_closed = true,
            .manifest_seal = self.manifest_value.seal,
            .cohort_identity_sha256 = self.authority_sha256,
            .relations_identity_sha256 = identity_mod.relationsIdentity(relations),
            .provider_relations_identity_sha256 = try provider_relations.identityDigest(),
            .provider_claims = provider_claims,
            .public_request_claim = try trace_mod.publicRequestBoundary(
                provider_claims,
            ),
            .claims = claims,
            .domain_totals = domains,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = identity_mod.generatedIdentity(&result);
        try result.validate();
        return result;
    }
};

fn LogicalComponent(comptime entry: catalog.Entry) type {
    @setEvalBranchQuota(500_000);
    const Air = entry.Air;
    const Relation = binding.Binding(Air);
    return adapter.Component(Air, Relation);
}

fn LogicalComponentsType() type {
    var types: [catalog.LOGICAL_COUNT]type = undefined;
    inline for (catalog.LOGICAL_ROWS, 0..) |entry, index|
        types[index] = LogicalComponent(entry);
    return std.meta.Tuple(&types);
}

const LogicalComponents = LogicalComponentsType();

pub const ComponentSetV2 = struct {
    logical: LogicalComponents,
    poseidon: provider.Poseidon2AdapterForManifest(manifest_mod),
    range: provider.RangeCheck8x8AdapterForManifest(manifest_mod),

    fn init(
        cohort: *CohortV2,
        generated_value: *const CohortGeneratedInteractionsV1,
        relations: *const universal.UniversalRelations,
        provider_relations: *const provider.SharedProviderRelations,
    ) !ComponentSetV2 {
        var logical: LogicalComponents = undefined;
        inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
            const Component = LogicalComponent(entry);
            logical[index] = try Component.init(
                &cohort.logical[index].definition,
                cohort.logical[index].relation_plan,
                &cohort.manifest_value,
                entry.row,
                manifest_mod.exactLogSizes()[@intFromEnum(entry.row)],
                [_]M31{M31.zero()} ** Component.PARAMETER_COLUMN_COUNT,
                relations,
                QM31.zero(),
            );
        }
        return .{
            .logical = logical,
            .poseidon = try provider.Poseidon2AdapterForManifest(
                manifest_mod,
            ).init(
                &cohort.manifest_value,
                manifest_mod.POSEIDON_LOG_SIZE,
                manifest_mod.PROVIDER_ACTIVE_ROW_COUNT,
                provider_relations,
                relations,
                .{
                    generated_value.provider_claims.poseidon2,
                    generated_value.provider_claims.poseidon2_io,
                },
            ),
            .range = try provider.RangeCheck8x8AdapterForManifest(
                manifest_mod,
            ).init(
                &cohort.range_definition,
                &cohort.range_executor,
                &cohort.manifest_value,
                provider_relations,
                relations,
                QM31.zero(),
            ),
        };
    }

    pub fn appendToGate(
        self: *const ComponentSetV2,
        manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        if (gate.count != 0 or gate.sealed)
            return error.CanonicalEmptyCohortAuthorityMismatch;
        inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
            _ = entry;
            try gate.append(
                manifest,
                try self.logical[index].binding(manifest),
            );
        }
        try gate.append(manifest, try self.poseidon.binding(manifest));
        try gate.append(manifest, try self.range.binding(manifest));
    }

    pub fn deinit(self: *ComponentSetV2) void {
        self.* = undefined;
    }
};

fn deinitLogical(owners: *LogicalOwners, initialized: usize) void {
    inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
        _ = entry;
        if (index < initialized) owners[index].deinit();
    }
}

fn requireManifest(
    actual: *const manifest_mod.Manifest,
    expected: *const manifest_mod.Manifest,
) !void {
    _ = try manifest_mod.logSizesFromManifest(actual);
    if (!std.meta.eql(actual.*, expected.*))
        return error.CanonicalEmptyCohortAuthorityMismatch;
}

fn logSizesForInputs(
    inputs: *const AuthorityInputs,
) !manifest_mod.LogSizes {
    try inputs.padding_target.validateSelf();
    if (!std.mem.eql(
        u8,
        &inputs.padding_target.shape.identity_sha256,
        &inputs.cold.shape.identity_sha256,
    )) return error.CanonicalEmptyCohortAuthorityMismatch;
    const active_logs = try inputs.padding_target.activeLogsForRole(
        .canonical_empty_field_v2,
    );
    const padded_logs = try inputs.padding_target.paddedLogs();
    var result: manifest_mod.LogSizes = undefined;
    const semantic_logs = manifest_mod.exactLogSizes();
    for (&result, semantic_logs, 0..) |*destination, minimum, index| {
        if (active_logs[index] != minimum or padded_logs[index] < minimum) {
            return error.CanonicalEmptyCohortAuthorityMismatch;
        }
        destination.* = padded_logs[index];
    }
    return result;
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 2 or
        COMPONENT_COUNT != 36 or PUBLIC_WORD_COUNT != 450 or
        field_public.POSEIDON_CALL_COUNT != 173 or PRODUCTION_ACTIVATION)
    {
        @compileError("campaign canonical-empty universal cohort V2 drifted");
    }
}
