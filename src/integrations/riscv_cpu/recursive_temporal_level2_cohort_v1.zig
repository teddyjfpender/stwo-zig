//! Complete 36-row height-2 temporal root cohort.
//!
//! Rows 0--17 come from two verified temporal-parent publications, rows
//! 18--34 reuse the shared binary FRI bundle, and row 35 reuses the statement
//! range provider. This module owns only the joins and global closure.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const level2 = @import("recursive_temporal_parent_pair_authority_v1.zig");
const level2_prefix = @import("recursive_temporal_level2_prefix_v1.zig");
const level2_suffix = @import("recursive_temporal_level2_suffix_v1.zig");
const binary_driver = @import("recursive_binary_outer.zig");
const canonical_proof = @import("recursive_binary_verified_publication.zig");
const segment_publication = @import("recursive_segment_v2_verified_publication.zig");
const publication_mod = @import("recursive_temporal_parent_publication_v3.zig");
const artifact_mod = @import("recursive_temporal_parent_verified_artifact_v1.zig");
const publication_context = @import("recursive_temporal_parent_context_v3.zig");
const node_publication = @import("recursive_temporal_node_publication_v1.zig");
const diagnostics = @import("recursive_temporal_level2_diagnostics.zig");
const child_transcript = @import("recursive_temporal_child_transcript_authority_v1.zig");
const verifier_input_mod =
    @import("recursive_temporal_level2_verifier_input_v1.zig");
const prefix_runtime = @import("recursive_temporal_parent_prefix_runtime.zig");
const temporal_nonfri = @import("recursive_temporal_nonfri_source_v2.zig");
const manifest_mod = @import("recursive_temporal_parent_manifest_v3.zig");
const row35_mod = @import("recursive_temporal_parent_row35_owner_v1.zig");
const support = @import("recursive_temporal_parent_cohort_support.zig");

const M31 = stwo_core.fields.m31.M31;
const recursion = frontend.recursion;
const universal = recursion.air.universal_challenges;
const shared_provider = recursion.air.universal_shared_provider;
const global_closure = recursion.binary_global_closure_outer_source;
const range_bridge = recursion.air.range_check_8_8_bridge;
const lookup_interaction = frontend.air.lookups.tables.interaction;
const channel = recursion.poseidon2_channel;

const PrefixComponents = temporal_nonfri.TemporalPrefixComponentsForManifest(
    manifest_mod,
);
const SuffixComponents = recursion.binary_fri_outer_bundle.ComponentsForManifest(
    manifest_mod,
);

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const GENERATED_FORMAT_VERSION: u16 = 1;
pub const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const PREFIX_ROW_COUNT: usize = manifest_mod.PREFIX_ROW_COUNT;
pub const SUFFIX_ROW_COUNT: usize = level2_suffix.ROW_COUNT;
pub const PROVIDER_ROW: usize = row35_mod.ROW;
const COHORT_CHILD_TRANSCRIPT_AUTHORITY = child_transcript.DescriptorV1.recursiveNodeV1();
pub const AUTHORITY_TRANSCRIPT_DOMAIN = COHORT_CHILD_TRANSCRIPT_AUTHORITY.domain;

pub const AuthorityInputs = struct {
    pair: *const level2.PreparedLevel2PairV1,
    children: [2]level2_suffix.ChildInputV1,
};

pub const GeneratedInteractionsV1 = struct {
    format_version: u16 = GENERATED_FORMAT_VERSION,
    padding: [6]u8 = [_]u8{0} ** 6,
    cohort_id: [32]u8,
    manifest_seal: [32]u8,
    prefix: temporal_nonfri.TemporalPrefixInteractionsV3,
    suffix: recursion.binary_fri_outer_bundle.GeneratedInteractionsV1,
    row35: row35_mod.GeneratedV1,
    identity: [32]u8,
};

pub const AuditedInteractionsV2 = struct {
    prefix: temporal_nonfri.TemporalPrefixDomainAuditsV3,
    suffix: recursion.binary_fri_outer_bundle.AuditedInteractionsV1,
    row35: row35_mod.GeneratedV1,
    rows: [global_closure.PREFIX_ROW_COUNT]global_closure.RowClaimsV1,
    provider_claim: global_closure.ProviderClaimV1,
    wire_boundary: global_closure.BoundaryEvidenceV2,
    verifier_input_boundary: global_closure.BoundaryEvidenceV2,
    closure: global_closure.ClosureReceiptV2,
    context: verifier_input_mod.ContextReceiptV1,
    identity: [32]u8,
};

pub const Components = struct {
    prefix: PrefixComponents,
    suffix: SuffixComponents,
    row35: row35_mod.Adapter,

    pub fn deinit(self: *Components) void {
        self.* = undefined;
    }

    pub fn appendToGate(
        self: *const Components,
        manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        if (gate.count != 0) return error.RosterOrderMismatch;
        try self.prefix.appendToGate(manifest, gate);
        if (gate.count != PREFIX_ROW_COUNT) return error.RosterOrderMismatch;
        try self.suffix.appendToGate(manifest, gate);
        if (gate.count != PROVIDER_ROW) return error.RosterOrderMismatch;
        try gate.append(manifest, try self.row35.binding(manifest));
        if (gate.count != COMPONENT_COUNT) return error.RosterOrderMismatch;
    }
};

const CohortAuthorityInputs = AuthorityInputs;
const CohortGeneratedInteractions = GeneratedInteractionsV1;
const CohortAuditedInteractions = AuditedInteractionsV2;
const CohortComponents = Components;

pub const Cohort = struct {
    const Self = @This();
    pub const CHILD_TRANSCRIPT_AUTHORITY = COHORT_CHILD_TRANSCRIPT_AUTHORITY;

    pub const AuthorityInputs = CohortAuthorityInputs;
    pub const GeneratedInteractionsV1 = CohortGeneratedInteractions;
    pub const AuditedInteractionsV2 = CohortAuditedInteractions;
    pub const Components = CohortComponents;
    pub const VerifiedPublicationV1 = publication_mod.VerifiedPublicationV1;
    pub const VerifiedArtifactV1 = artifact_mod.VerifiedTemporalParentArtifactV1;
    pub const PAIR_AUTHENTICATION_POSEIDON_PERMUTATIONS: usize = 0;

    allocator: std.mem.Allocator,
    inputs: CohortAuthorityInputs,
    prefix: *prefix_runtime.OwnerV1,
    suffix: *level2_suffix.OwnerV1,
    fri: level2_suffix.BundleV1,
    verifier_input_source: verifier_input_mod.AuthorityV1,
    row35: row35_mod.OwnerV1,
    manifest_value: manifest_mod.Manifest,
    closure_authority: global_closure.PreparedAuthorityV1,
    closure_workspace: global_closure.Workspace,
    authority_sha_id: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        inputs: CohortAuthorityInputs,
    ) !Self {
        try inputs.pair.validate();
        for (inputs.children) |child| try child.validate();
        const prefix = try allocator.create(prefix_runtime.OwnerV1);
        errdefer allocator.destroy(prefix);
        prefix.* = level2_prefix.init(
            allocator,
            inputs.pair,
            .{
                .{
                    .publication = inputs.children[0].publication,
                    .artifact = inputs.children[0].artifact,
                    .capture = inputs.children[0].capture,
                },
                .{
                    .publication = inputs.children[1].publication,
                    .artifact = inputs.children[1].artifact,
                    .capture = inputs.children[1].capture,
                },
            },
        ) catch |err| return initStageFailure("prefix", err);
        errdefer prefix.deinit();
        const suffix = level2_suffix.OwnerV1.init(
            allocator,
            inputs.pair,
            prefix,
            inputs.children,
        ) catch |err| return initStageFailure("suffix", err);
        errdefer suffix.deinit();
        const boundary_layout = suffix.boundaryScheduleReceipt();
        var fri = level2_suffix.BundleV1.initWithBoundarySchedule(
            allocator,
            suffix.source(),
            &boundary_layout,
            suffix.boundaryPoseidonCalls(),
        ) catch |err| return initStageFailure("fri", err);
        errdefer fri.deinit();
        const verifier_input_source = verifier_input_mod.AuthorityV1.init(
            inputs.pair,
            suffix.source(),
        ) catch |err| return initStageFailure("verifier_input", err);
        var row35 = row35_mod.OwnerV1.init(allocator, prefix) catch |err|
            return initStageFailure("row35", err);
        errdefer row35.deinit();

        const fri_logs = try fri.componentLogSizes();
        var suffix_logs: manifest_mod.SuffixLogSizes = undefined;
        @memcpy(suffix_logs[0..SUFFIX_ROW_COUNT], &fri_logs);
        suffix_logs[SUFFIX_ROW_COUNT] = row35_mod.LOG_SIZE;
        const manifest_value = try manifest_mod.build(
            try prefix.commitmentLayout(),
            suffix_logs,
            suffix.authorityIdentity(),
        );
        var result = Self{
            .allocator = allocator,
            .inputs = inputs,
            .prefix = prefix,
            .suffix = suffix,
            .fri = fri,
            .verifier_input_source = verifier_input_source,
            .row35 = row35,
            .manifest_value = manifest_value,
            .closure_authority = try global_closure.prepareAuthority(),
            .closure_workspace = global_closure.Workspace.init(),
            .authority_sha_id = undefined,
        };
        result.authority_sha_id = cohortIdentity(&result);
        result.validate() catch |err| return initStageFailure("validate", err);
        return result;
    }

    pub fn deinit(self: *Self) void {
        const prefix = self.prefix;
        self.row35.deinit();
        self.fri.deinit();
        self.suffix.deinit();
        prefix.deinit();
        self.allocator.destroy(prefix);
        self.* = undefined;
    }

    pub fn validate(self: *Self) !void {
        try self.manifest_value.validateAgainstPrefix(
            try self.prefix.commitmentLayout(),
        );
        try self.suffix.validate();
        try self.fri.validate();
        try self.verifier_input_source.validateAgainst(
            self.inputs.pair,
            self.suffix.source(),
        );
        try self.row35.validate();
        try self.closure_workspace.validate();
        if (!std.mem.eql(u8, &self.authority_sha_id, &cohortIdentity(self)))
            return error.AuthorityIdentityMismatch;
    }

    pub fn manifest(self: *const Self) *const manifest_mod.Manifest {
        return &self.manifest_value;
    }

    pub fn publicationContext(
        self: *const Self,
    ) !publication_context.ContextReceiptV3 {
        return publication_context.ContextReceiptV3.initFromVerifiedNodePair(
            self.inputs.pair,
        );
    }

    pub fn recursiveStatementWords(
        self: *const Self,
    ) !*const recursion.span_statement.StatementWords {
        return &self.prefix.statement_rows.parent_words;
    }

    pub fn mixAuthority(self: *Self, transcript: anytype) !void {
        try self.validate();
        transcript.mixU32s(&.{
            AUTHORITY_TRANSCRIPT_DOMAIN,
            FORMAT_VERSION,
            SCHEMA_VERSION,
            COMPONENT_COUNT,
        });
        transcript.mixU32s(&support.digestWords(self.authority_sha_id));
        transcript.mixU32s(&self.inputs.pair.authority_id);
        transcript.mixU32s(&support.digestWords(
            self.verifier_input_source.context.identity,
        ));
    }

    pub fn fillPreprocessedInto(
        self: *Self,
        active_manifest: *const manifest_mod.Manifest,
        destination: [][]M31,
    ) !void {
        try support.requireManifest(self, active_manifest);
        try support.preflightTree(
            active_manifest,
            manifest_mod.PREPROCESSED_TREE_INDEX,
            destination,
        );
        errdefer support.clearTree(destination);
        try support.ensurePrefixBaseTrees(self);
        try support.copyPrefixTree(self.prefix, 0, destination);
        self.fri.fillPreprocessedInto(active_manifest, destination) catch |err|
            return runtimeStageFailure("fill_preprocessed_suffix", err);
        var provider = try support.row35Columns(
            range_bridge.FRAMEWORK_PREPROCESSED_COLUMN_COUNT,
            active_manifest,
            manifest_mod.PREPROCESSED_TREE_INDEX,
            destination,
        );
        try self.row35.fillPreprocessedInto(&provider);
    }

    pub fn fillMainInto(
        self: *Self,
        active_manifest: *const manifest_mod.Manifest,
        destination: [][]M31,
    ) !void {
        try support.requireManifest(self, active_manifest);
        try support.preflightTree(
            active_manifest,
            manifest_mod.MAIN_TREE_INDEX,
            destination,
        );
        errdefer support.clearTree(destination);
        try support.ensurePrefixBaseTrees(self);
        try support.copyPrefixTree(self.prefix, 1, destination);
        self.fri.fillMainInto(active_manifest, destination) catch |err|
            return runtimeStageFailure("fill_main_suffix", err);
        var provider = try support.row35Columns(
            range_bridge.PHYSICAL_MAIN_COLUMN_COUNT,
            active_manifest,
            manifest_mod.MAIN_TREE_INDEX,
            destination,
        );
        try self.row35.fillMainInto(&provider);
    }

    pub fn fillInteractionInto(
        self: *Self,
        active_manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
        destination: [][]M31,
    ) !CohortGeneratedInteractions {
        try support.requireManifest(self, active_manifest);
        try support.preflightTree(
            active_manifest,
            manifest_mod.INTERACTION_TREE_INDEX,
            destination,
        );
        errdefer support.clearTree(destination);
        try support.ensurePrefixBaseTrees(self);
        const prefix = switch (self.prefix.phase) {
            .base_trees_filled => try self.prefix.fillInteractionTree(relations),
            .prefix_trees_filled => self.prefix.interactions.?,
            .cold => unreachable,
        };
        try support.copyPrefixTree(self.prefix, 2, destination);
        const suffix = self.fri.fillInteractionInto(
            active_manifest,
            relations,
            provider_relations,
            destination,
        ) catch |err| return runtimeStageFailure("fill_interaction_suffix", err);
        var provider = try support.row35Columns(
            lookup_interaction.N_COLUMNS,
            active_manifest,
            manifest_mod.INTERACTION_TREE_INDEX,
            destination,
        );
        const row35 = try self.row35.fillInteractionInto(
            relations,
            provider_relations,
            &provider,
        );
        var result = CohortGeneratedInteractions{
            .cohort_id = self.authority_sha_id,
            .manifest_seal = active_manifest.seal,
            .prefix = prefix,
            .suffix = suffix,
            .row35 = row35,
            .identity = undefined,
        };
        result.identity = support.generatedIdentity(&result);
        try self.validateGenerated(&result, relations, provider_relations);
        return result;
    }

    pub fn validateGenerated(
        self: *Self,
        generated: *const CohortGeneratedInteractions,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        try self.validate();
        if (generated.format_version != GENERATED_FORMAT_VERSION or
            !std.mem.allEqual(u8, &generated.padding, 0) or
            !std.mem.eql(u8, &generated.cohort_id, &self.authority_sha_id) or
            !std.mem.eql(u8, &generated.manifest_seal, &self.manifest_value.seal) or
            !std.mem.eql(u8, &generated.identity, &support.generatedIdentity(generated)))
        {
            return error.GeneratedIdentityMismatch;
        }
        const retained = self.prefix.interactions orelse
            return error.GeneratedIdentityMismatch;
        try generated.prefix.validate(&self.prefix.custody);
        try generated.prefix.validateAgainstRelations(&self.prefix.custody, relations);
        if (!std.meta.eql(generated.prefix, retained))
            return error.GeneratedIdentityMismatch;
        try self.fri.validateGeneratedInteractions(
            &generated.suffix,
            relations,
            provider_relations,
        );
        try generated.row35.validateAgainst(
            &self.row35,
            relations,
            provider_relations,
        );
    }

    pub fn claimVector(
        self: *Self,
        generated: *const CohortGeneratedInteractions,
    ) !manifest_mod.ClaimVector {
        var claims = try manifest_mod.ClaimVector.init(&self.manifest_value);
        for (generated.prefix.claims, 0..) |claim, row|
            try claims.bind(@enumFromInt(row), claim);
        for (generated.suffix.claims.asRows18Through34(), PREFIX_ROW_COUNT..) |
            claim,
            row,
        | try claims.bind(@enumFromInt(row), claim);
        try claims.bind(.range_check_8_8, generated.row35.claim);
        try claims.sealClaims(&self.manifest_value);
        return claims;
    }

    pub fn auditGlobalClosureV2(
        self: *Self,
        generated: *const CohortGeneratedInteractions,
        claims: *const manifest_mod.ClaimVector,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !CohortAuditedInteractions {
        try claims.validate(&self.manifest_value);
        try self.validateGenerated(generated, relations, provider_relations);
        const prefix = try self.prefix.auditInteractionDomains(relations, null);
        const suffix = try self.fri.auditGeneratedInteractions(
            self.allocator,
            relations,
            provider_relations,
            &generated.suffix,
        );
        var rows: [global_closure.PREFIX_ROW_COUNT]global_closure.RowClaimsV1 =
            undefined;
        const prefix_rows = prefix.rowClaims();
        @memcpy(rows[0..PREFIX_ROW_COUNT], &prefix_rows);
        for (suffix.audits.typed_rows, 0..) |audit, index|
            rows[PREFIX_ROW_COUNT + index] = support.rowClaim(
                @enumFromInt(PREFIX_ROW_COUNT + index),
                audit.values,
                audit.total,
            );
        rows[PROVIDER_ROW - 1] = support.poseidonRowClaim(suffix.audits.poseidon2);
        const provider_claim = try global_closure.ProviderClaimV1.init(
            &self.closure_authority,
            generated.row35.provider_snapshot_sha_id,
            generated.row35.claim,
        );
        const wire_boundary = support.globalBoundaryEvidence(
            try self.suffix.source().wireBoundaryEvidence(relations),
        );
        const verifier_input_boundary = support.globalBoundaryEvidence(
            try self.verifier_input_source.boundaryEvidence(
                self.inputs.pair,
                self.suffix.source(),
                relations,
            ),
        );
        const boundary_authorities = try global_closure.BoundaryAuthoritiesV2.init(
            try global_closure.BoundarySourceV2.init(.wire, wire_boundary),
            try global_closure.BoundarySourceV2.init(
                .verifier_input,
                verifier_input_boundary,
            ),
        );
        const closure_authority = try global_closure.prepareAuthorityV2(
            boundary_authorities,
        );
        const public_boundaries = try global_closure.PublicBoundariesV2.init(
            &closure_authority,
            wire_boundary,
            verifier_input_boundary,
        );
        const closure_input = try global_closure.ClosureInputV2.init(
            &closure_authority,
            &rows,
            &provider_claim,
            public_boundaries,
        );
        var closure = global_closure.ClosureReceiptV2.fresh();
        global_closure.fillIntoV2(
            &self.closure_workspace,
            &closure_authority,
            &closure_input,
            &closure,
        ) catch |err| {
            if (err == error.RelationNotClosed) {
                diagnostics.reportVerifierInputResidual(
                    self,
                    &rows,
                    verifier_input_boundary,
                    relations,
                );
                support.reportClosureResidual(
                    &rows,
                    &provider_claim,
                    wire_boundary,
                    verifier_input_boundary,
                );
                diagnostics.reportTupleClosure(
                    self,
                    generated,
                    relations,
                    provider_relations,
                );
            }
            return err;
        };
        try closure.validate();
        for (rows, 0..) |row, index|
            if (!row.claimed_sum.eql(claims.values[index]))
                return error.ClaimAuditMismatch;
        if (!provider_claim.claimed_sum.eql(claims.values[PROVIDER_ROW]))
            return error.ClaimAuditMismatch;
        var result = CohortAuditedInteractions{
            .prefix = prefix,
            .suffix = suffix,
            .row35 = generated.row35,
            .rows = rows,
            .provider_claim = provider_claim,
            .wire_boundary = wire_boundary,
            .verifier_input_boundary = verifier_input_boundary,
            .closure = closure,
            .context = self.verifier_input_source.context,
            .identity = undefined,
        };
        result.identity = support.auditedIdentity(&result);
        return result;
    }

    pub fn auditGlobalClosure(
        self: *Self,
        generated: *const CohortGeneratedInteractions,
        claims: *const manifest_mod.ClaimVector,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        _ = try self.auditGlobalClosureV2(
            generated,
            claims,
            relations,
            provider_relations,
        );
    }

    pub fn rebuildGeneratedInteractions(
        self: *Self,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !CohortGeneratedInteractions {
        {
            var main = try support.TreeScratch.init(
                self.allocator,
                &self.manifest_value,
                manifest_mod.MAIN_TREE_INDEX,
            );
            defer main.deinit();
            try self.fillMainInto(&self.manifest_value, main.columns);
        }
        var interaction = try support.TreeScratch.init(
            self.allocator,
            &self.manifest_value,
            manifest_mod.INTERACTION_TREE_INDEX,
        );
        defer interaction.deinit();
        return self.fillInteractionInto(
            &self.manifest_value,
            relations,
            provider_relations,
            interaction.columns,
        );
    }

    pub fn initComponents(
        self: *Self,
        generated: *const CohortGeneratedInteractions,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !CohortComponents {
        try self.validateGenerated(generated, relations, provider_relations);
        return .{
            .prefix = try self.prefix.initComponentsForManifest(
                manifest_mod,
                &self.manifest_value,
                relations,
            ),
            .suffix = try self.fri.initComponents(
                &self.manifest_value,
                relations,
                provider_relations,
                &generated.suffix,
            ),
            .row35 = try self.row35.initComponent(
                &self.manifest_value,
                relations,
                provider_relations,
                &generated.row35,
            ),
        };
    }

    pub fn verifierSuccessBinding(
        self: *Self,
        proof: canonical_proof.CanonicalProofIdentityV1,
        capture: *const binary_driver.OuterProofCapture,
        transcript_id: channel.Digest,
        claims: *const manifest_mod.ClaimVector,
        audited: *const CohortAuditedInteractions,
        recursive_admission_sha_id: [32]u8,
    ) !binary_driver.TemporalVerifierSuccessBindingV1 {
        return node_publication.verifierSuccessBinding(
            self,
            proof,
            capture,
            transcript_id,
            claims,
            audited,
            recursive_admission_sha_id,
        );
    }

    pub fn publishSuccessfulVerifier(
        self: *Self,
        evidence: *const binary_driver.TemporalVerifierSuccessEvidenceV1,
        claims: *const manifest_mod.ClaimVector,
        audited: *const CohortAuditedInteractions,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !VerifiedPublicationV1 {
        return node_publication.publishSuccessfulVerifier(
            self,
            evidence,
            claims,
            audited,
            relations,
            provider_relations,
        );
    }

    pub fn validateAuditedInteractions(
        self: *Self,
        audited: *const CohortAuditedInteractions,
        claims: *const manifest_mod.ClaimVector,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        try self.validate();
        try claims.validate(&self.manifest_value);
        try relations.validate();
        try provider_relations.validateAgainst(relations);
        const retained_prefix = self.prefix.interactions orelse
            return error.ClaimAuditMismatch;
        try audited.prefix.validateAgainst(
            &self.prefix.custody,
            &retained_prefix,
        );
        try audited.suffix.validateAgainst(
            &self.fri,
            relations,
            provider_relations,
        );
        try audited.row35.validateAgainst(
            &self.row35,
            relations,
            provider_relations,
        );
        try audited.context.validateAgainst(self.inputs.pair);
        if (!std.meta.eql(audited.context, self.verifier_input_source.context))
            return error.ClaimAuditMismatch;

        var expected_rows: [global_closure.PREFIX_ROW_COUNT]global_closure.RowClaimsV1 = undefined;
        const prefix_rows = audited.prefix.rowClaims();
        @memcpy(expected_rows[0..PREFIX_ROW_COUNT], &prefix_rows);
        for (audited.suffix.audits.typed_rows, 0..) |audit, index|
            expected_rows[PREFIX_ROW_COUNT + index] = support.rowClaim(
                @enumFromInt(PREFIX_ROW_COUNT + index),
                audit.values,
                audit.total,
            );
        expected_rows[PROVIDER_ROW - 1] =
            support.poseidonRowClaim(audited.suffix.audits.poseidon2);
        if (!std.meta.eql(expected_rows, audited.rows))
            return error.ClaimAuditMismatch;

        const expected_provider = try global_closure.ProviderClaimV1.init(
            &self.closure_authority,
            audited.row35.provider_snapshot_sha_id,
            audited.row35.claim,
        );
        if (!std.meta.eql(expected_provider, audited.provider_claim))
            return error.ClaimAuditMismatch;

        const expected_wire = support.globalBoundaryEvidence(
            try self.suffix.source().wireBoundaryEvidence(relations),
        );
        const expected_verifier_input = support.globalBoundaryEvidence(
            try self.verifier_input_source.boundaryEvidence(
                self.inputs.pair,
                self.suffix.source(),
                relations,
            ),
        );
        if (!std.meta.eql(expected_wire, audited.wire_boundary) or
            !std.meta.eql(
                expected_verifier_input,
                audited.verifier_input_boundary,
            ))
        {
            return error.ClaimAuditMismatch;
        }

        const boundary_authorities = try global_closure.BoundaryAuthoritiesV2.init(
            try global_closure.BoundarySourceV2.init(.wire, expected_wire),
            try global_closure.BoundarySourceV2.init(
                .verifier_input,
                expected_verifier_input,
            ),
        );
        const closure_authority = try global_closure.prepareAuthorityV2(
            boundary_authorities,
        );
        const public_boundaries = try global_closure.PublicBoundariesV2.init(
            &closure_authority,
            expected_wire,
            expected_verifier_input,
        );
        const closure_input = try global_closure.ClosureInputV2.init(
            &closure_authority,
            &expected_rows,
            &expected_provider,
            public_boundaries,
        );
        var closure_workspace = global_closure.Workspace.init();
        var expected_closure = global_closure.ClosureReceiptV2.fresh();
        try global_closure.fillIntoV2(
            &closure_workspace,
            &closure_authority,
            &closure_input,
            &expected_closure,
        );
        if (!std.meta.eql(expected_closure, audited.closure))
            return error.ClaimAuditMismatch;

        for (expected_rows, 0..) |row, index|
            if (!row.claimed_sum.eql(claims.values[index]))
                return error.ClaimAuditMismatch;
        if (!expected_provider.claimed_sum.eql(claims.values[PROVIDER_ROW]))
            return error.ClaimAuditMismatch;
        if (!std.mem.eql(
            u8,
            &audited.identity,
            &support.auditedIdentity(audited),
        )) {
            return error.ClaimAuditMismatch;
        }
    }
};

fn initStageFailure(stage: []const u8, err: anyerror) anyerror {
    std.debug.print(
        "\nTEMPORAL_LEVEL2_COHORT_INIT_FAIL stage={s} error={s}\n",
        .{ stage, @errorName(err) },
    );
    return err;
}

fn runtimeStageFailure(stage: []const u8, err: anyerror) anyerror {
    std.debug.print(
        "\nTEMPORAL_LEVEL2_COHORT_RUNTIME_FAIL stage={s} error={s}\n",
        .{ stage, @errorName(err) },
    );
    return err;
}

fn cohortIdentity(value: *const Cohort) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursive-temporal-level2-cohort/v1\x00");
    hashInt(&hash, u16, FORMAT_VERSION);
    hash.update(&value.manifest_value.seal);
    hash.update(&value.prefix.authority_sha_id);
    const suffix_id = value.suffix.authorityIdentity();
    hash.update(&suffix_id);
    hash.update(&value.verifier_input_source.identity);
    hash.update(&value.row35.identity);
    hash.update(&value.closure_authority.source_authority_id);
    hash.update(&value.closure_authority.provider_source_authority_id);
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (COMPONENT_COUNT != 36 or PREFIX_ROW_COUNT != 18 or
        SUFFIX_ROW_COUNT != 17 or PROVIDER_ROW != 35)
    {
        @compileError("level-2 cohort roster drifted");
    }
}
