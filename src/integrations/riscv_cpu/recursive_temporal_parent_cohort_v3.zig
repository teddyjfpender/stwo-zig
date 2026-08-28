//! Concrete authenticated temporal-parent rows-0--35 cohort.
//!
//! The cohort owns no AIR equations. Rows 0--17 come from the adjacent-span
//! temporal prefix owner, rows 18--34 from the authenticated fixed-wire suffix,
//! and row 35 from the statement-owned range provider.  The only shared
//! Poseidon provider is finalized in-place during the single Tree-1 fill.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const binary_driver = @import("recursive_binary_outer.zig");
const canonical_proof = @import("recursive_binary_verified_publication.zig");
const segment_publication = @import("recursive_segment_v2_verified_publication.zig");
const pair_authority = @import("recursive_temporal_pair_authority_v2.zig");
const temporal_nonfri = @import("recursive_temporal_nonfri_source_v2.zig");
const prefix_runtime = @import("recursive_temporal_parent_prefix_runtime.zig");
const row18_source = @import("recursive_temporal_parent_row18_source_v3.zig");
const suffix_mod = @import("recursive_temporal_parent_suffix_v3.zig");
const verifier_input_publication =
    @import("recursive_temporal_parent_verifier_input_publication_v3.zig");
const row35_mod = @import("recursive_temporal_parent_row35_owner_v1.zig");
const manifest_mod = @import("recursive_temporal_parent_manifest_v3.zig");
const cohort_contract = @import("recursive_temporal_parent_cohort_contract.zig");
const cohort_support = @import("recursive_temporal_parent_cohort_support.zig");
const publication_mod = @import("recursive_temporal_parent_publication_v3.zig");
const verified_artifact_mod = @import("recursive_temporal_parent_verified_artifact_v1.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const roster = recursion.air.universal_roster;
const universal = recursion.air.universal_challenges;
const relation_interaction = recursion.air.relation_interaction;
const shared_provider = recursion.air.universal_shared_provider;
const global_closure = recursion.binary_global_closure_outer_source;
const range_bridge = recursion.air.range_check_8_8_bridge;
const lookup_interaction = frontend.air.lookups.tables.interaction;
const channel = recursion.poseidon2_channel;

const Suffix = suffix_mod.SegmentV2;
const PrefixComponents = temporal_nonfri.TemporalPrefixComponentsForManifest(
    manifest_mod,
);
const SuffixComponents = recursion.binary_fri_outer_bundle.ComponentsForManifest(
    manifest_mod,
);
pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 1;
pub const GENERATED_FORMAT_VERSION: u16 = 1;
pub const PUBLICATION_SCHEMA_VERSION: u16 = 1;
pub const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const PREFIX_ROW_COUNT: usize = manifest_mod.PREFIX_ROW_COUNT;
pub const SUFFIX_ROW_COUNT: usize = suffix_mod.ROW_COUNT;
pub const PROVIDER_ROW: usize = row35_mod.ROW;
pub const AUTHORITY_TRANSCRIPT_DOMAIN: u32 = 0x5450_4333; // "TPC3"
pub const PAIR_AUTHENTICATION_POSEIDON_PERMUTATIONS: usize =
    pair_authority.HOT_AUTHENTICATION_SCALAR_POSEIDON_PERMUTATIONS;

pub const PROTOCOL_SUBSTRATE_ONLY = false;
pub const AUTHENTICATED_TEMPORAL_V2 = true;
pub const COMPLETE_PARENT_PROOF_AVAILABLE = true;
pub const TEMPORAL_PARENT_VERIFIED = true;
pub const PRODUCTION_ACTIVATION = false;

pub const HOT_COHORT_TREE_HEAP_ALLOCATIONS = [_]usize{0} ** manifest_mod.TREE_COUNT;
pub const PREFIX_COMMITTED_COLUMN_COPY_PASSES_PER_TREE: usize = 1;

pub const Error = error{
    AdversarialMutationAccepted,
    ArithmeticOverflow,
    AuthorityIdentityMismatch,
    ClaimAuditMismatch,
    DestinationAlias,
    DestinationNotFresh,
    DestinationShapeMismatch,
    GeneratedIdentityMismatch,
    InvalidPublication,
    ManifestGeometryMismatch,
    RosterOrderMismatch,
};

pub const Cohort = struct {
    const Self = @This();

    pub const PAIR_AUTHENTICATION_POSEIDON_PERMUTATIONS =
        pair_authority.HOT_AUTHENTICATION_SCALAR_POSEIDON_PERMUTATIONS;

    pub const AuthorityInputs = cohort_contract.AuthorityInputs;
    pub const GeneratedInteractionsV1 = cohort_contract.GeneratedInteractionsV1;
    pub const AuditedInteractionsV2 = cohort_contract.AuditedInteractionsV2;
    pub const VerifiedPublicationV1 = publication_mod.VerifiedPublicationV1;
    pub const VerifiedArtifactV1 = verified_artifact_mod.VerifiedTemporalParentArtifactV1;
    pub const Components = cohort_contract.Components;

    allocator: std.mem.Allocator,
    inputs: AuthorityInputs,
    prefix: *prefix_runtime.OwnerV1,
    suffix: *Suffix.OwnerV3,
    fri: Suffix.BundleV3,
    verifier_input_source: verifier_input_publication.AuthorityV3,
    row35: row35_mod.OwnerV1,
    manifest_value: manifest_mod.Manifest,
    closure_authority: global_closure.PreparedAuthorityV1,
    closure_workspace: global_closure.Workspace,
    authority_sha_id: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        inputs: AuthorityInputs,
    ) !Self {
        _ = try inputs.runtime.validate();
        try inputs.row18.validateAgainst(inputs.runtime);

        const prefix = try allocator.create(prefix_runtime.OwnerV1);
        errdefer allocator.destroy(prefix);
        prefix.* = try prefix_runtime.OwnerV1.init(allocator, inputs.runtime);
        var prefix_live = true;
        errdefer if (prefix_live) prefix.deinit();

        const suffix = try Suffix.OwnerV3.init(
            allocator,
            inputs.runtime,
            inputs.row18,
            try prefix.transcriptRows(),
            try prefix.sharedArithmeticInput(),
        );
        errdefer suffix.deinit();
        const boundary_layout = suffix.boundaryScheduleReceipt();
        var fri = try Suffix.BundleV3.initWithBoundarySchedule(
            allocator,
            suffix.source(),
            &boundary_layout,
            suffix.boundaryPoseidonCalls(),
        );
        errdefer fri.deinit();
        const verifier_input_source = try verifier_input_publication.AuthorityV3.init(
            inputs.runtime,
            suffix.source(),
        );
        var row35 = try row35_mod.OwnerV1.init(allocator, prefix);
        errdefer row35.deinit();

        const fri_logs = try fri.componentLogSizes();
        var suffix_logs: manifest_mod.SuffixLogSizes = undefined;
        @memcpy(suffix_logs[0..SUFFIX_ROW_COUNT], fri_logs[0..]);
        suffix_logs[SUFFIX_ROW_COUNT] = row35_mod.LOG_SIZE;
        const manifest_value = try manifest_mod.build(
            try prefix.commitmentLayout(),
            suffix_logs,
            suffix.authorityIdentity(),
        );
        const closure_authority = try global_closure.prepareAuthority();

        var result = Self{
            .allocator = allocator,
            .inputs = inputs,
            .prefix = prefix,
            .suffix = suffix,
            .fri = fri,
            .verifier_input_source = verifier_input_source,
            .row35 = row35,
            .manifest_value = manifest_value,
            .closure_authority = closure_authority,
            .closure_workspace = global_closure.Workspace.init(),
            .authority_sha_id = undefined,
        };
        result.authority_sha_id = cohort_support.cohortIdentity(
            &result,
            FORMAT_VERSION,
        );
        try result.validate();
        prefix_live = false;
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
            self.inputs.runtime,
            self.suffix.source(),
        );
        try self.row35.validate();
        try self.closure_workspace.validate();
        if (!std.mem.eql(
            u8,
            &self.authority_sha_id,
            &cohort_support.cohortIdentity(self, FORMAT_VERSION),
        )) return error.AuthorityIdentityMismatch;
    }

    pub fn manifest(self: *const Self) *const manifest_mod.Manifest {
        return &self.manifest_value;
    }

    pub fn mixAuthority(self: *Self, transcript: anytype) !void {
        try self.validate();
        transcript.mixU32s(&.{
            AUTHORITY_TRANSCRIPT_DOMAIN,
            FORMAT_VERSION,
            SCHEMA_VERSION,
            COMPONENT_COUNT,
        });
        transcript.mixU32s(&cohort_support.digestWords(self.authority_sha_id));
        transcript.mixU32s(&self.inputs.runtime.artifacts.pair.authority_id);
        transcript.mixU32s(&cohort_support.digestWords(self.suffix.contextReceipt().identity));
    }

    pub fn fillPreprocessedInto(
        self: *Self,
        active_manifest: *const manifest_mod.Manifest,
        destination: [][]M31,
    ) !void {
        try cohort_support.requireManifest(self, active_manifest);
        try cohort_support.preflightTree(
            active_manifest,
            manifest_mod.PREPROCESSED_TREE_INDEX,
            destination,
        );
        errdefer cohort_support.clearTree(destination);
        try cohort_support.ensurePrefixBaseTrees(self);
        try cohort_support.copyPrefixTree(self.prefix, 0, destination);
        try self.fri.fillPreprocessedInto(active_manifest, destination);
        var provider = try cohort_support.row35Columns(
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
        try cohort_support.requireManifest(self, active_manifest);
        try cohort_support.preflightTree(active_manifest, manifest_mod.MAIN_TREE_INDEX, destination);
        errdefer cohort_support.clearTree(destination);
        try cohort_support.ensurePrefixBaseTrees(self);
        try cohort_support.copyPrefixTree(self.prefix, 1, destination);
        try self.fri.fillMainInto(active_manifest, destination);
        var provider = try cohort_support.row35Columns(
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
    ) !GeneratedInteractionsV1 {
        try cohort_support.requireManifest(self, active_manifest);
        try cohort_support.preflightTree(
            active_manifest,
            manifest_mod.INTERACTION_TREE_INDEX,
            destination,
        );
        errdefer cohort_support.clearTree(destination);
        try cohort_support.ensurePrefixBaseTrees(self);
        const prefix = switch (self.prefix.phase) {
            .base_trees_filled => try self.prefix.fillInteractionTree(relations),
            .prefix_trees_filled => self.prefix.interactions.?,
            .cold => unreachable,
        };
        try cohort_support.copyPrefixTree(self.prefix, 2, destination);
        const suffix = try self.fri.fillInteractionInto(
            active_manifest,
            relations,
            provider_relations,
            destination,
        );
        var provider = try cohort_support.row35Columns(
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
        var result = GeneratedInteractionsV1{
            .cohort_id = self.authority_sha_id,
            .manifest_seal = active_manifest.seal,
            .prefix = prefix,
            .suffix = suffix,
            .row35 = row35,
            .identity = undefined,
        };
        result.identity = cohort_support.generatedIdentity(&result);
        try self.validateGenerated(&result, relations, provider_relations);
        return result;
    }

    pub fn validateGenerated(
        self: *Self,
        generated: *const GeneratedInteractionsV1,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        try self.validate();
        if (generated.format_version != GENERATED_FORMAT_VERSION or
            !std.mem.allEqual(u8, &generated.padding, 0) or
            !std.mem.eql(u8, &generated.cohort_id, &self.authority_sha_id) or
            !std.mem.eql(u8, &generated.manifest_seal, &self.manifest_value.seal) or
            !std.mem.eql(u8, &generated.identity, &cohort_support.generatedIdentity(generated)))
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
        generated: *const GeneratedInteractionsV1,
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
        generated: *const GeneratedInteractionsV1,
        claims: *const manifest_mod.ClaimVector,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !AuditedInteractionsV2 {
        try claims.validate(&self.manifest_value);
        try self.validateGenerated(generated, relations, provider_relations);
        const prefix = try self.prefix.auditInteractionDomains(
            relations,
            null,
        );
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
            rows[PREFIX_ROW_COUNT + index] = cohort_support.rowClaim(
                @enumFromInt(PREFIX_ROW_COUNT + index),
                audit.values,
                audit.total,
            );
        rows[PROVIDER_ROW - 1] = cohort_support.poseidonRowClaim(suffix.audits.poseidon2);

        const provider_claim = try global_closure.ProviderClaimV1.init(
            &self.closure_authority,
            generated.row35.provider_snapshot_sha_id,
            generated.row35.claim,
        );
        const wire_boundary = cohort_support.globalBoundaryEvidence(
            try self.suffix.source().wireBoundaryEvidence(relations),
        );
        const verifier_input_boundary = cohort_support.globalBoundaryEvidence(
            try self.verifier_input_source.boundaryEvidence(
                self.inputs.runtime,
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
                cohort_support.reportClosureResidual(
                    &rows,
                    &provider_claim,
                    wire_boundary,
                    verifier_input_boundary,
                );
                self.reportTupleClosure(
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

        var result = AuditedInteractionsV2{
            .prefix = prefix,
            .suffix = suffix,
            .row35 = generated.row35,
            .rows = rows,
            .provider_claim = provider_claim,
            .wire_boundary = wire_boundary,
            .verifier_input_boundary = verifier_input_boundary,
            .closure = closure,
            .context = self.suffix.contextReceipt(),
            .identity = undefined,
        };
        result.identity = cohort_support.auditedIdentity(&result);
        return result;
    }

    /// Failure-only exact tuple decomposition.  The ordinary proving path
    /// reaches this routine only after the cheaper algebraic closure receipt
    /// has rejected the cohort, so successful parents retain zero tuple-ledger
    /// allocations and hashes.
    fn reportTupleClosure(
        self: *Self,
        generated: *const GeneratedInteractionsV1,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) void {
        var ledger = relation_interaction.TupleLedger.init(self.allocator);
        defer ledger.deinit();
        _ = self.prefix.auditInteractionDomains(
            relations,
            &ledger,
        ) catch |err| {
            std.debug.print(
                "TEMPORAL_TUPLE_AUDIT prefix_error={s}\n",
                .{@errorName(err)},
            );
            return;
        };
        _ = self.fri.auditGeneratedInteractionsWithTupleLedger(
            self.allocator,
            relations,
            provider_relations,
            &generated.suffix,
            &ledger,
        ) catch |err| {
            std.debug.print(
                "TEMPORAL_TUPLE_AUDIT suffix_error={s}\n",
                .{@errorName(err)},
            );
            return;
        };
        cohort_support.reportTupleLedger(&ledger);
    }

    pub fn auditGlobalClosure(
        self: *Self,
        generated: *const GeneratedInteractionsV1,
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
    ) !GeneratedInteractionsV1 {
        {
            var main = try cohort_support.TreeScratch.init(
                self.allocator,
                &self.manifest_value,
                manifest_mod.MAIN_TREE_INDEX,
            );
            defer main.deinit();
            try self.fillMainInto(&self.manifest_value, main.columns);
        }
        var interaction = try cohort_support.TreeScratch.init(
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
        generated: *const GeneratedInteractionsV1,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !Components {
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

    /// Derives the exact value statement which the native verifier seals only
    /// after successful proof verification. This function does not mint the
    /// opaque capability and therefore cannot promote proof-shaped data.
    pub fn verifierSuccessBinding(
        self: *Self,
        proof: canonical_proof.CanonicalProofIdentityV1,
        capture: *const binary_driver.OuterProofCapture,
        transcript_id: channel.Digest,
        claims: *const manifest_mod.ClaimVector,
        audited: *const AuditedInteractionsV2,
        recursive_admission_sha_id: [32]u8,
    ) !binary_driver.TemporalVerifierSuccessBindingV1 {
        try self.validate();
        try proof.validate();
        try claims.validate(&self.manifest_value);
        if (capture.commitments.len == 0 or capture.queries.raw.len == 0)
            return error.InvalidPublication;
        const result = binary_driver.TemporalVerifierSuccessBindingV1{
            .canonical_proof_byte_count = proof.byte_count,
            .proof_id = proof.proof_id,
            .canonical_proof_sha_id = proof.canonical_proof_sha_id,
            .capture_id = segment_publication.captureIdentity(capture),
            .transcript_id = transcript_id,
            .cohort_authority_sha_id = self.authority_sha_id,
            .manifest_sha_id = self.manifest_value.seal,
            .claims_sha_id = claims.seal,
            .generated_interactions_sha_id = audited.suffix.generated.identity,
            .audit_sha_id = audited.identity,
            .closure_receipt_sha_id = audited.closure.closure_id,
            .recursive_admission_sha_id = recursive_admission_sha_id,
        };
        try result.validate();
        return result;
    }

    /// Replays every duplicated audit field against this cohort and rebuilds
    /// the complete V2 closure receipt. A self-consistent hash is insufficient:
    /// rows, provider, both public boundaries, claims, and context must all be
    /// the exact values independently derived by the verifier.
    pub fn validateAuditedInteractions(
        self: *Self,
        audited: *const AuditedInteractionsV2,
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
        try audited.context.validateAgainst(self.inputs.runtime.artifacts);
        if (!std.meta.eql(audited.context, self.suffix.contextReceipt()))
            return error.ClaimAuditMismatch;

        var expected_rows: [global_closure.PREFIX_ROW_COUNT]global_closure.RowClaimsV1 =
            undefined;
        const prefix_rows = audited.prefix.rowClaims();
        @memcpy(expected_rows[0..PREFIX_ROW_COUNT], &prefix_rows);
        for (audited.suffix.audits.typed_rows, 0..) |audit, index|
            expected_rows[PREFIX_ROW_COUNT + index] = cohort_support.rowClaim(
                @enumFromInt(PREFIX_ROW_COUNT + index),
                audit.values,
                audit.total,
            );
        expected_rows[PROVIDER_ROW - 1] =
            cohort_support.poseidonRowClaim(audited.suffix.audits.poseidon2);
        if (!std.meta.eql(expected_rows, audited.rows))
            return error.ClaimAuditMismatch;

        const expected_provider = try global_closure.ProviderClaimV1.init(
            &self.closure_authority,
            audited.row35.provider_snapshot_sha_id,
            audited.row35.claim,
        );
        if (!std.meta.eql(expected_provider, audited.provider_claim))
            return error.ClaimAuditMismatch;

        const expected_wire = cohort_support.globalBoundaryEvidence(
            try self.suffix.source().wireBoundaryEvidence(relations),
        );
        const expected_verifier_input = cohort_support.globalBoundaryEvidence(
            try self.verifier_input_source.boundaryEvidence(
                self.inputs.runtime,
                self.suffix.source(),
                relations,
            ),
        );
        if (!std.meta.eql(expected_wire, audited.wire_boundary) or
            !std.meta.eql(expected_verifier_input, audited.verifier_input_boundary))
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
        if (!std.mem.eql(u8, &audited.identity, &cohort_support.auditedIdentity(audited)))
            return error.ClaimAuditMismatch;
    }
    pub fn runPublicationMutationFleetForTest(
        self: *Self,
        audited: *const AuditedInteractionsV2,
        claims: *const manifest_mod.ClaimVector,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        return cohort_support.runAuditMutationFleetForTest(
            self,
            audited,
            claims,
            relations,
            provider_relations,
        );
    }

    pub fn publishSuccessfulVerifier(
        self: *Self,
        evidence: *const binary_driver.TemporalVerifierSuccessEvidenceV1,
        claims: *const manifest_mod.ClaimVector,
        audited: *const AuditedInteractionsV2,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !VerifiedPublicationV1 {
        const verified = try binary_driver.openTemporalVerifierSuccessEvidence(
            evidence,
        );
        try self.validate();
        try claims.validate(&self.manifest_value);
        try relations.validate();
        try provider_relations.validateAgainst(relations);
        try audited.closure.validate();
        try audited.context.validateAgainst(self.inputs.runtime.artifacts);
        if (!std.mem.eql(
            u8,
            &verified.cohort_authority_sha_id,
            &self.authority_sha_id,
        ) or !std.mem.eql(
            u8,
            &verified.manifest_sha_id,
            &self.manifest_value.seal,
        ) or !std.mem.eql(
            u8,
            &verified.claims_sha_id,
            &claims.seal,
        ) or !std.mem.eql(
            u8,
            &verified.generated_interactions_sha_id,
            &audited.suffix.generated.identity,
        ) or !std.mem.eql(
            u8,
            &verified.audit_sha_id,
            &audited.identity,
        ) or !std.mem.eql(
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
        var result = VerifiedPublicationV1{
            .canonical_proof_byte_count = verified.canonical_proof_byte_count,
            .proof_id = verified.proof_id,
            .canonical_proof_sha_id = verified.canonical_proof_sha_id,
            .capture_id = verified.capture_id,
            .transcript_id = verified.transcript_id,
            .statement_words = self.prefix.statement_rows.parent_words,
            .pair_authority_id = self.inputs.runtime.artifacts.pair.authority_id,
            .context = audited.context,
            .manifest_sha_id = self.manifest_value.seal,
            .claims_sha_id = claims.seal,
            .generated_interactions_sha_id = audited.suffix.generated.identity,
            .audit_sha_id = audited.identity,
            .cohort_authority_sha_id = self.authority_sha_id,
            .closure_receipt_sha_id = audited.closure.closure_id,
            .publication_sha_id = undefined,
        };
        result.publication_sha_id = publication_mod.identity(&result);
        try result.validate();
        if (comptime @import("builtin").is_test)
            try publication_mod.validateMutationFleetForTest(result);
        return result;
    }
};

comptime {
    if (COMPONENT_COUNT != 36 or PREFIX_ROW_COUNT != 18 or
        SUFFIX_ROW_COUNT != 17 or PROVIDER_ROW != 35 or
        PAIR_AUTHENTICATION_POSEIDON_PERMUTATIONS != 0 or
        PROTOCOL_SUBSTRATE_ONLY or !COMPLETE_PARENT_PROOF_AVAILABLE or
        !TEMPORAL_PARENT_VERIFIED or PRODUCTION_ACTIVATION)
    {
        @compileError("temporal parent cohort roster or hot pair contract drifted");
    }
}
