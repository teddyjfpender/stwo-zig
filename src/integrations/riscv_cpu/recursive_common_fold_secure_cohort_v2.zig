//! Complete universal-36 cohort for the field-native common fold.
//!
//! Rows 0--17 are the inactive universal prefix, rows 18--34 come from the
//! two verifier-owned fixed child captures and their authenticated composition
//! graphs, and row 35 is the canonical range provider.  Both external
//! verifier-input boundaries participate in the global closure transaction.

const std = @import("std");
const builtin = @import("builtin");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const fixed_source = @import("recursive_common_fold_fixed_wire_v2.zig");
const field_public = @import("recursive_common_fold_field_public_v2.zig");
const field_closure =
    @import("recursive_common_fold_field_public_closure_v2.zig");
const suffix_boundary =
    @import("recursive_common_fold_suffix_input_boundary_v2.zig");
const suffix_closure =
    @import("recursive_common_fold_suffix_closure_v2.zig");
const live_mod = @import("recursive_common_fold_universal_cohort_v2.zig");
const manifest_mod = @import("recursive_common_fold_universal_manifest_v2.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const preprocessed_authority =
    @import("recursive_process_local_preprocessed_authority_v1.zig");
const support = @import("recursive_binary_outer_cohort_support.zig");

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
const lookup_interaction = frontend.air.lookups.tables.interaction;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PREFIX_ROW_COUNT: usize = 18;
pub const SUFFIX_ROW_COUNT: usize = 17;
pub const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const PROVIDER_ROW: usize = 35;
pub const PRODUCTION_ACTIVATION = false;
pub const COMPLETE_COMMON_FOLD_PROOF_COHORT =
    live_mod.ALL_SCHEMA4_ROLE_BRANCHES_AVAILABLE and
    live_mod.FIXED_WIRE_SOURCE_AVAILABLE;
pub const GLOBAL_RELATION_CLOSURE_AVAILABLE =
    live_mod.GLOBAL_RELATION_CLOSURE_AVAILABLE;

const AUTHORITY_TRANSCRIPT_DOMAIN: u32 = 0x4346_4132; // "CFA2"
const BOUNDARY_TRANSCRIPT_DOMAIN: u32 = 0x4346_4232; // "CFB2"
const GENERATED_DOMAIN =
    "stwo-zig/recursive-common-fold-interactions/v2\x00";
const AUDITED_DOMAIN =
    "stwo-zig/recursive-common-fold-global-audit/v2\x00";

pub const Error = fixed_source.Error || live_mod.Error ||
    manifest_mod.Error || suffix_boundary.Error || suffix_closure.Error || error{
    CommonFoldAuditMismatch,
    CommonFoldCohortMismatch,
    CommonFoldDestinationNotFresh,
    CommonFoldManifestMismatch,
    CommonFoldRosterMismatch,
};

pub fn CohortV2(comptime dimensions: recursion.fixed_wire.Dimensions) type {
    const Fixed = fixed_source.Types(dimensions);
    return CohortForLiveV2(
        dimensions,
        live_mod.CohortV2,
        Fixed,
        ProductionManifestPolicyV2,
    );
}

/// Shared secure-cohort engine.  The production alias above retains the
/// three-role geometry/parity policy; the isolated bootstrap supplies a
/// separate nonserializable manifest policy and cannot enter that alias.
pub fn CohortForLiveV2(
    comptime dimensions: recursion.fixed_wire.Dimensions,
    comptime Live: type,
    comptime Fixed: type,
    comptime ManifestPolicy: type,
) type {
    dimensions.validate();
    const SuffixComponents = recursion.binary_fri_outer_bundle
        .ComponentsForManifest(manifest_mod);
    const LogicalOwners = LogicalOwnersType();
    const LogicalComponents = LogicalComponentsType();

    return struct {
        const Self = @This();

        pub const AuthorityInputs = struct {
            live: *const Live,
        };

        pub const GeneratedInteractionsV1 = struct {
            format_version: u16 = FORMAT_VERSION,
            schema_version: u16 = SCHEMA_VERSION,
            cohort_identity_sha256: [32]u8,
            manifest_seal: [32]u8,
            suffix: recursion.binary_fri_outer_bundle.GeneratedInteractionsV1,
            row35_claim: QM31,
            identity_sha256: [32]u8,

            pub fn validate(self: *const GeneratedInteractionsV1) !void {
                if (self.format_version != FORMAT_VERSION or
                    self.schema_version != SCHEMA_VERSION or
                    self.row35_claim.isZero() == false or
                    std.mem.allEqual(u8, &self.cohort_identity_sha256, 0) or
                    std.mem.allEqual(u8, &self.manifest_seal, 0) or
                    !std.mem.eql(
                        u8,
                        &self.identity_sha256,
                        &generatedIdentity(self),
                    )) return error.CommonFoldCohortMismatch;
            }
        };

        pub const AuditedInteractionsV2 = struct {
            suffix: recursion.binary_fri_outer_bundle.AuditedInteractionsV1,
            rows: [global_closure.PREFIX_ROW_COUNT]global_closure.RowClaimsV1,
            provider_claim: global_closure.ProviderClaimV1,
            wire_boundary: global_closure.BoundaryEvidenceV2,
            verifier_input_boundary: global_closure.BoundaryEvidenceV2,
            field_public_boundary: field_closure.BoundaryEvidenceV2,
            suffix_input_boundary: suffix_boundary.BoundaryEvidenceV2,
            closure: suffix_closure.ClosureReceiptV2,
            identity_sha256: [32]u8,

            pub fn validate(self: *const AuditedInteractionsV2) !void {
                try self.provider_claim.validate();
                try self.field_public_boundary.validate();
                try self.suffix_input_boundary.validate();
                const expected_verifier_input =
                    try self.suffix_input_boundary.verifierInputEvidence();
                if (!std.meta.eql(
                    self.verifier_input_boundary,
                    expected_verifier_input,
                )) return error.CommonFoldAuditMismatch;
                const authorities = try global_closure.BoundaryAuthoritiesV2.init(
                    try global_closure.BoundarySourceV2.init(
                        .wire,
                        self.wire_boundary,
                    ),
                    try global_closure.BoundarySourceV2.init(
                        .verifier_input,
                        self.verifier_input_boundary,
                    ),
                );
                const closure_authority =
                    try global_closure.prepareAuthorityV2(authorities);
                const boundaries = try global_closure.PublicBoundariesV2.init(
                    &closure_authority,
                    self.wire_boundary,
                    self.verifier_input_boundary,
                );
                const input = try global_closure.ClosureInputV2.init(
                    &closure_authority,
                    &self.rows,
                    &self.provider_claim,
                    boundaries,
                );
                try self.closure.validateAgainst(
                    &input,
                    &self.field_public_boundary,
                    &self.suffix_input_boundary,
                );
                if (!std.mem.eql(
                    u8,
                    &self.identity_sha256,
                    &auditedIdentity(self),
                )) return error.CommonFoldAuditMismatch;
            }
        };

        pub const Components = struct {
            logical: LogicalComponents,
            suffix: SuffixComponents,
            range: provider.RangeCheck8x8AdapterForManifest(manifest_mod),

            pub fn deinit(self: *Components) void {
                self.* = undefined;
            }

            pub fn appendToGate(
                self: *const Components,
                manifest_value: *const manifest_mod.Manifest,
                gate: *manifest_mod.ProofGate,
            ) !void {
                if (gate.count != 0) return error.CommonFoldRosterMismatch;
                inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
                    if (index >= PREFIX_ROW_COUNT) continue;
                    _ = entry;
                    try gate.append(
                        manifest_value,
                        try self.logical[index].binding(manifest_value),
                    );
                }
                try self.suffix.appendToGate(manifest_value, gate);
                try gate.append(
                    manifest_value,
                    try self.range.binding(manifest_value),
                );
                if (gate.count != COMPONENT_COUNT)
                    return error.CommonFoldRosterMismatch;
            }
        };

        allocator: std.mem.Allocator,
        inputs: AuthorityInputs,
        source_owner: *Fixed.OwnerV2,
        suffix: Fixed.BundleV2,
        manifest_value: manifest_mod.Manifest,
        logical: LogicalOwners,
        logical_initialized: usize,
        range_definition: range_bridge.Definition,
        range_executor: range_bridge.Executor,
        closure_authority: global_closure.PreparedAuthorityV1,
        closure_workspace: global_closure.Workspace,
        statement_words: recursion.span_statement.StatementWords,
        manifest_authority_identity_sha256: [32]u8,
        authority_sha256: [32]u8,

        pub fn init(
            allocator: std.mem.Allocator,
            inputs: AuthorityInputs,
        ) !Self {
            try inputs.live.validate();
            const source_owner = try Fixed.OwnerV2.init(allocator, inputs.live);
            errdefer source_owner.deinit();
            const boundary = source_owner.boundaryLayout();
            var suffix = try Fixed.BundleV2.initWithBoundarySchedule(
                allocator,
                source_owner.source(),
                &boundary,
                source_owner.boundaryCalls(),
            );
            errdefer suffix.deinit();
            var logical: LogicalOwners = undefined;
            var logical_initialized: usize = 0;
            errdefer deinitLogical(&logical, logical_initialized);
            inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
                if (index >= PREFIX_ROW_COUNT) continue;
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
            var statement_words: recursion.span_statement.StatementWords =
                undefined;
            for (
                &statement_words,
                inputs.live.input.outputNodePublic().statement_words,
            ) |*destination, word| destination.* = M31.fromCanonical(word);
            const manifest_value = try ManifestPolicy.initManifest(
                inputs.live,
                source_owner,
            );
            var result = Self{
                .allocator = allocator,
                .inputs = inputs,
                .source_owner = source_owner,
                .suffix = suffix,
                .manifest_value = manifest_value,
                .logical = logical,
                .logical_initialized = logical_initialized,
                .range_definition = range_definition,
                .range_executor = range_executor,
                .closure_authority = try global_closure.prepareAuthority(),
                .closure_workspace = global_closure.Workspace.init(),
                .statement_words = statement_words,
                .manifest_authority_identity_sha256 = ManifestPolicy.authorityIdentity(
                    inputs.live,
                    &manifest_value,
                ),
                .authority_sha256 = undefined,
            };
            result.authority_sha256 = cohortIdentity(&result);
            try result.validate();
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.range_definition.deinit();
            deinitLogical(&self.logical, self.logical_initialized);
            self.suffix.deinit();
            self.source_owner.deinit();
            self.* = undefined;
        }

        pub fn validate(self: *Self) !void {
            try self.inputs.live.validate();
            try self.source_owner.validate();
            try self.suffix.validate();
            try ManifestPolicy.validateManifest(
                &self.manifest_value,
                self.inputs.live,
                self.source_owner,
            );
            try self.closure_workspace.validate();
            if (self.logical_initialized != PREFIX_ROW_COUNT or
                !std.mem.eql(
                    u8,
                    &self.manifest_authority_identity_sha256,
                    &ManifestPolicy.authorityIdentity(
                        self.inputs.live,
                        &self.manifest_value,
                    ),
                ) or
                !std.mem.eql(
                    u8,
                    &self.authority_sha256,
                    &cohortIdentity(self),
                )) return error.CommonFoldCohortMismatch;
        }

        pub fn manifest(self: *const Self) *const manifest_mod.Manifest {
            return &self.manifest_value;
        }

        /// Exact field-public schedule authenticated by the two typed child
        /// capabilities and the fold input. No canonical-empty nominal
        /// publication authority is reused at this boundary.
        pub fn publicationAuthority(
            self: *const Self,
        ) !*const field_public.PoseidonScheduleV2 {
            try self.inputs.live.validate();
            if (!std.meta.eql(
                self.inputs.live.public_schedule.parent,
                self.inputs.live.input.outputNodePublic().*,
            )) return error.CommonFoldCohortMismatch;
            return &self.inputs.live.public_schedule;
        }

        pub fn recursiveStatementWords(
            self: *const Self,
        ) !*const recursion.span_statement.StatementWords {
            const publication = try self.publicationAuthority();
            var expected: recursion.span_statement.StatementWords = undefined;
            for (
                &expected,
                publication.parent.statement_words,
            ) |*destination, word| destination.* = M31.fromCanonical(word);
            if (!std.meta.eql(self.statement_words, expected))
                return error.CommonFoldCohortMismatch;
            return &self.statement_words;
        }

        pub fn parentManifestIdentity(self: *Self) ![32]u8 {
            return ManifestPolicy.contractIdentity(
                self.inputs.live,
                &self.manifest_value,
            );
        }

        /// Dynamic-manifest cache key for immutable preprocessed circuit data.
        /// The manifest is first re-admitted against the live authority; its
        /// exact log sizes feed every role-independent identity. The root is
        /// part of the preprocessed identity, so a changed circuit, layout,
        /// padding target, PCS policy, manifest, or root cannot hit.
        pub fn processLocalPreprocessedCacheKey(
            self: *Self,
            pcs_identity_sha256: [32]u8,
            root: recursion.engine.Hasher.Hash,
        ) !preprocessed_authority.KeyV1 {
            try self.validate();
            const authenticated_manifest = &self.manifest_value;
            const table_layout_identity_sha256 =
                try ManifestPolicy.tableLayoutIdentity(
                    self.inputs.live,
                    authenticated_manifest,
                );
            return preprocessed_authority.KeyV1.init(.{
                .circuit_identity_sha256 = try ManifestPolicy.contractIdentity(
                    self.inputs.live,
                    authenticated_manifest,
                ),
                .program_identity_sha256 = try ManifestPolicy.programIdentity(
                    self.inputs.live,
                    authenticated_manifest,
                ),
                .profile_identity_sha256 = try ManifestPolicy.profileIdentity(
                    self.inputs.live,
                    authenticated_manifest,
                ),
                .pcs_identity_sha256 = pcs_identity_sha256,
                .padding_identity_sha256 = try ManifestPolicy.paddingLayoutIdentity(
                    self.inputs.live,
                    authenticated_manifest,
                ),
                .preprocessed_identity_sha256 = try preprocessed_authority.preprocessedIdentity(
                    recursion.engine.Hasher.Hash,
                    table_layout_identity_sha256,
                    authenticated_manifest.seal,
                    root,
                ),
                .identity_sha256 = undefined,
            });
        }

        pub fn sessionAuthority(
            self: *Self,
        ) !secure_artifact.CommonFoldSessionAuthorityV2 {
            try self.validate();
            const manifest_identity = try self.parentManifestIdentity();
            return .{
                .ingress_identity_sha256 = self.inputs.live.identity_sha256,
                .parent_statement_words = self.statement_words,
                .profile_identity_sha256 = try ManifestPolicy.profileIdentity(
                    self.inputs.live,
                    &self.manifest_value,
                ),
                .child_composition_manifest_sha256 = self.inputs.live.identity_sha256,
                .parent_outer_manifest_sha256 = manifest_identity,
                .verification_key_id = try ManifestPolicy.verificationKeyId(
                    self.inputs.live,
                    &self.manifest_value,
                ),
                .next_parent_vk_id = try ManifestPolicy.nextParentVkId(
                    self.inputs.live,
                    &self.manifest_value,
                ),
                .air_program_id = try ManifestPolicy.airProgramId(
                    self.inputs.live,
                    &self.manifest_value,
                ),
            };
        }

        pub fn session(self: *Self) !secure_artifact.SessionV1 {
            return secure_artifact.SessionV1.initCommonFoldFieldV2(
                try self.sessionAuthority(),
            );
        }

        pub fn validateSession(
            self: *Self,
            value: *const secure_artifact.SessionV1,
        ) !void {
            if (!std.meta.eql(value.*, try self.session()))
                return error.CommonFoldCohortMismatch;
        }

        pub fn mixAuthority(self: *Self, transcript: anytype) !void {
            try self.validate();
            const words = try self.inputs.live.input.outputNodePublic()
                .canonicalAirWords();
            transcript.mixU32s(&.{
                AUTHORITY_TRANSCRIPT_DOMAIN,
                FORMAT_VERSION,
                SCHEMA_VERSION,
                @as(u32, @intCast(words.len)),
            });
            transcript.mixU32s(&words);
        }

        pub fn mixBoundaryReceipt(
            transcript: anytype,
            audited: *const AuditedInteractionsV2,
        ) !void {
            try audited.validate();
            transcript.mixU32s(&.{
                BOUNDARY_TRANSCRIPT_DOMAIN,
                FORMAT_VERSION,
                SCHEMA_VERSION,
                @as(u32, @intCast(audited.wire_boundary.tuple_count)),
                @as(u32, @intCast(
                    audited.verifier_input_boundary.tuple_count,
                )),
                @intFromEnum(audited.field_public_boundary.domain),
                audited.field_public_boundary.tuple_count,
                suffix_boundary.DOMAIN_COUNT,
            });
            transcript.mixFelts(&.{
                audited.wire_boundary.claimed_sum,
                audited.verifier_input_boundary.claimed_sum,
                audited.field_public_boundary.claimed_sum,
            });
            for (audited.suffix_input_boundary.domains) |boundary| {
                transcript.mixU32s(&.{
                    @intFromEnum(boundary.domain),
                    boundary.tuple_count,
                });
                transcript.mixFelts(&.{boundary.claimed_sum});
            }
        }

        pub fn fillPreprocessedInto(
            self: *Self,
            manifest_value: *const manifest_mod.Manifest,
            destination: [][]M31,
        ) !void {
            try self.requireDynamicManifest(manifest_value);
            try support.preflightTree(
                manifest_value,
                manifest_mod.PREPROCESSED_TREE_INDEX,
                destination,
            );
            errdefer support.clearTree(destination);
            try self.suffix.fillPreprocessedInto(manifest_value, destination);
            const placement = try manifest_value.placement(.range_check_8_8);
            destination[placement.preprocessed_offset][
                range_bridge.committedRow(0)
            ] = M31.one();
            const low = destination[placement.preprocessed_offset + 1];
            const high = destination[placement.preprocessed_offset + 2];
            for (0..range_bridge.TABLE_SIZE) |logical_row| {
                const row = range_bridge.committedRow(logical_row);
                low[row] = M31.fromCanonical(@intCast(logical_row & 0xff));
                high[row] = M31.fromCanonical(@intCast(logical_row >> 8));
            }
        }

        pub fn fillMainInto(
            self: *Self,
            manifest_value: *const manifest_mod.Manifest,
            destination: [][]M31,
        ) !void {
            try self.requireDynamicManifest(manifest_value);
            try support.preflightTree(
                manifest_value,
                manifest_mod.MAIN_TREE_INDEX,
                destination,
            );
            errdefer support.clearTree(destination);
            try self.suffix.fillMainInto(manifest_value, destination);
        }

        pub fn fillInteractionInto(
            self: *Self,
            manifest_value: *const manifest_mod.Manifest,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
            destination: [][]M31,
        ) !GeneratedInteractionsV1 {
            try self.requireDynamicManifest(manifest_value);
            try support.preflightTree(
                manifest_value,
                manifest_mod.INTERACTION_TREE_INDEX,
                destination,
            );
            errdefer support.clearTree(destination);
            const suffix = try self.suffix.fillInteractionInto(
                manifest_value,
                relations,
                provider_relations,
                destination,
            );
            var result = GeneratedInteractionsV1{
                .cohort_identity_sha256 = self.authority_sha256,
                .manifest_seal = manifest_value.seal,
                .suffix = suffix,
                .row35_claim = QM31.zero(),
                .identity_sha256 = undefined,
            };
            result.identity_sha256 = generatedIdentity(&result);
            try self.validateGenerated(&result, relations, provider_relations);
            return result;
        }

        pub fn rebuildGeneratedInteractions(
            self: *Self,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !GeneratedInteractionsV1 {
            var main = try support.TreeScratch.init(
                self.allocator,
                &self.manifest_value,
                manifest_mod.MAIN_TREE_INDEX,
            );
            defer main.deinit();
            try self.fillMainInto(&self.manifest_value, main.columns);
            var scratch = try support.TreeScratch.init(
                self.allocator,
                &self.manifest_value,
                manifest_mod.INTERACTION_TREE_INDEX,
            );
            defer scratch.deinit();
            return self.fillInteractionInto(
                &self.manifest_value,
                relations,
                provider_relations,
                scratch.columns,
            );
        }

        pub fn validateGenerated(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !void {
            try generated.validate();
            try self.suffix.validateGeneratedInteractions(
                &generated.suffix,
                relations,
                provider_relations,
            );
            if (!std.mem.eql(
                u8,
                &generated.cohort_identity_sha256,
                &self.authority_sha256,
            ) or !std.mem.eql(
                u8,
                &generated.manifest_seal,
                &self.manifest_value.seal,
            )) return error.CommonFoldCohortMismatch;
        }

        pub fn claimVector(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
        ) !manifest_mod.ClaimVector {
            try generated.validate();
            var result = try manifest_mod.ClaimVector.init(&self.manifest_value);
            inline for (0..PREFIX_ROW_COUNT) |row|
                try result.bind(@enumFromInt(row), QM31.zero());
            for (
                generated.suffix.claims.asRows18Through34(),
                PREFIX_ROW_COUNT..,
            ) |claim, row| try result.bind(@enumFromInt(row), claim);
            try result.bind(.range_check_8_8, generated.row35_claim);
            try result.sealClaims(&self.manifest_value);
            return result;
        }

        pub fn auditGlobalClosureV2(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            claims: *const manifest_mod.ClaimVector,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !AuditedInteractionsV2 {
            try self.validateGenerated(generated, relations, provider_relations);
            if (!std.meta.eql(claims.*, try self.claimVector(generated)))
                return error.CommonFoldAuditMismatch;
            const suffix = try self.suffix.auditGeneratedInteractions(
                self.allocator,
                relations,
                provider_relations,
                &generated.suffix,
            );
            var rows: [global_closure.PREFIX_ROW_COUNT]global_closure.RowClaimsV1 =
                undefined;
            const zero_domains = [_]QM31{QM31.zero()} **
                global_closure.DOMAIN_COUNT;
            for (0..PREFIX_ROW_COUNT) |row| rows[row] = support.rowClaim(
                @enumFromInt(row),
                zero_domains,
                QM31.zero(),
            );
            for (suffix.audits.typed_rows, 0..) |audit, index|
                rows[PREFIX_ROW_COUNT + index] = support.rowClaim(
                    @enumFromInt(PREFIX_ROW_COUNT + index),
                    audit.values,
                    audit.total,
                );
            rows[PROVIDER_ROW - 1] = support.poseidonRowClaim(
                suffix.audits.poseidon2,
            );
            const provider_claim = try global_closure.ProviderClaimV1.init(
                &self.closure_authority,
                rangeSnapshotIdentity(self),
                generated.row35_claim,
            );
            const wire_boundary = support.globalBoundaryEvidence(
                try self.source_owner.source().wireBoundaryEvidence(relations),
            );
            const suffix_input_boundary = try suffix_boundary.derive(
                self.source_owner.source(),
                &self.suffix.relation_rows,
                relations,
            );
            const verifier_input_boundary =
                try suffix_input_boundary.verifierInputEvidence();
            const authorities = try global_closure.BoundaryAuthoritiesV2.init(
                try global_closure.BoundarySourceV2.init(
                    .wire,
                    wire_boundary,
                ),
                try global_closure.BoundarySourceV2.init(
                    .verifier_input,
                    verifier_input_boundary,
                ),
            );
            const closure_authority = try global_closure.prepareAuthorityV2(
                authorities,
            );
            const boundaries = try global_closure.PublicBoundariesV2.init(
                &closure_authority,
                wire_boundary,
                verifier_input_boundary,
            );
            const input = try global_closure.ClosureInputV2.init(
                &closure_authority,
                &rows,
                &provider_claim,
                boundaries,
            );
            const boundary_layout = self.source_owner.boundaryLayout();
            const field_public_boundary = try field_closure.derive(
                self.source_owner.boundaryCalls(),
                &boundary_layout,
                self.source_owner.authorityIdentity(),
                self.suffix.provider_log_size,
                provider_relations,
            );
            const closure = suffix_closure.close(
                &closure_authority,
                &input,
                &field_public_boundary,
                &suffix_input_boundary,
            ) catch |err| {
                if (builtin.is_test and err == error.RelationNotClosed)
                    suffix_closure.reportResidual(
                        &input,
                        &field_public_boundary,
                        &suffix_input_boundary,
                    );
                return err;
            };
            for (rows, 0..) |row, index|
                if (!row.claimed_sum.eql(claims.values[index]))
                    return error.CommonFoldAuditMismatch;
            if (!provider_claim.claimed_sum.eql(claims.values[PROVIDER_ROW]))
                return error.CommonFoldAuditMismatch;
            var result = AuditedInteractionsV2{
                .suffix = suffix,
                .rows = rows,
                .provider_claim = provider_claim,
                .wire_boundary = wire_boundary,
                .verifier_input_boundary = verifier_input_boundary,
                .field_public_boundary = field_public_boundary,
                .suffix_input_boundary = suffix_input_boundary,
                .closure = closure,
                .identity_sha256 = undefined,
            };
            result.identity_sha256 = auditedIdentity(&result);
            try result.validate();
            return result;
        }

        pub fn auditGlobalClosure(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            claims: *const manifest_mod.ClaimVector,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !void {
            _ = try self.auditGlobalClosureV2(
                generated,
                claims,
                relations,
                provider_relations,
            );
        }

        pub fn validateAuditedInteractions(
            self: *Self,
            audited: *const AuditedInteractionsV2,
            claims: *const manifest_mod.ClaimVector,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !void {
            try audited.validate();
            const generated = try self.rebuildGeneratedInteractions(
                relations,
                provider_relations,
            );
            const expected = try self.auditGlobalClosureV2(
                &generated,
                claims,
                relations,
                provider_relations,
            );
            if (!std.meta.eql(audited.*, expected))
                return error.CommonFoldAuditMismatch;
        }

        pub fn initComponents(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !Components {
            try self.validateGenerated(generated, relations, provider_relations);
            var logical: LogicalComponents = undefined;
            inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
                if (index >= PREFIX_ROW_COUNT) continue;
                const Component = LogicalComponent(entry);
                logical[index] = try Component.init(
                    &self.logical[index].definition,
                    self.logical[index].relation_plan,
                    &self.manifest_value,
                    entry.row,
                    (try self.manifest_value.placement(entry.row))
                        .geometry.log_size,
                    [_]M31{M31.zero()} ** Component.PARAMETER_COLUMN_COUNT,
                    relations,
                    QM31.zero(),
                );
            }
            return .{
                .logical = logical,
                .suffix = try self.suffix.initComponents(
                    &self.manifest_value,
                    relations,
                    provider_relations,
                    &generated.suffix,
                ),
                .range = try provider.RangeCheck8x8AdapterForManifest(
                    manifest_mod,
                ).init(
                    &self.range_definition,
                    &self.range_executor,
                    &self.manifest_value,
                    provider_relations,
                    relations,
                    generated.row35_claim,
                ),
            };
        }

        fn requireDynamicManifest(
            self: *Self,
            candidate: *const manifest_mod.Manifest,
        ) !void {
            try ManifestPolicy.validateManifest(
                candidate,
                self.inputs.live,
                self.source_owner,
            );
            if (!std.meta.eql(candidate.*, self.manifest_value))
                return error.CommonFoldManifestMismatch;
        }
    };
}

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
    var types: [PREFIX_ROW_COUNT]type = undefined;
    inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
        if (index >= PREFIX_ROW_COUNT) continue;
        types[index] = LogicalOwner(entry);
    }
    return std.meta.Tuple(&types);
}

fn LogicalComponent(comptime entry: catalog.Entry) type {
    @setEvalBranchQuota(500_000);
    return adapter.Component(entry.Air, binding.Binding(entry.Air));
}

fn LogicalComponentsType() type {
    var types: [PREFIX_ROW_COUNT]type = undefined;
    inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
        if (index >= PREFIX_ROW_COUNT) continue;
        types[index] = LogicalComponent(entry);
    }
    return std.meta.Tuple(&types);
}

fn deinitLogical(owners: anytype, initialized: usize) void {
    inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
        if (index >= PREFIX_ROW_COUNT) continue;
        _ = entry;
        if (index < initialized) owners[index].deinit();
    }
}

fn requireManifest(cohort: anytype, manifest: *const manifest_mod.Manifest) !void {
    return cohort.requireManifest(manifest);
}

fn cohortIdentity(value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/recursive-common-fold-secure-cohort/v2\x00");
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&value.inputs.live.identity_sha256);
    const source_identity = value.source_owner.authorityIdentity();
    hash.update(&source_identity);
    hash.update(&value.manifest_value.seal);
    hash.update(&rangeSnapshotIdentity(value));
    return hash.finalResult();
}

fn rangeSnapshotIdentity(value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/recursive-common-fold-range-provider/v2\x00");
    hash.update(&value.manifest_authority_identity_sha256);
    hash.update(&value.range_executor.binding_digest);
    return hash.finalResult();
}

const ProductionManifestPolicyV2 = struct {
    pub fn initManifest(
        live: *const live_mod.CohortV2,
        _: anytype,
    ) !manifest_mod.Manifest {
        try live.geometry.validate();
        return live.geometry.manifest_value;
    }

    pub fn validateManifest(
        value: *const manifest_mod.Manifest,
        live: *const live_mod.CohortV2,
        _: anytype,
    ) !void {
        return manifest_mod.validateExact(value, live.geometry);
    }

    pub fn contractIdentity(
        live: *const live_mod.CohortV2,
        _: *const manifest_mod.Manifest,
    ) ![32]u8 {
        return live.geometry.contractIdentity();
    }

    pub fn profileIdentity(
        live: *const live_mod.CohortV2,
        _: *const manifest_mod.Manifest,
    ) ![32]u8 {
        return live.geometry.profileIdentity();
    }

    pub fn programIdentity(
        live: *const live_mod.CohortV2,
        _: *const manifest_mod.Manifest,
    ) ![32]u8 {
        return live.geometry.programIdentity();
    }

    pub fn paddingLayoutIdentity(
        live: *const live_mod.CohortV2,
        _: *const manifest_mod.Manifest,
    ) ![32]u8 {
        return live.geometry.paddingLayoutIdentity();
    }

    pub fn tableLayoutIdentity(
        live: *const live_mod.CohortV2,
        _: *const manifest_mod.Manifest,
    ) ![32]u8 {
        return live.geometry.tableLayoutIdentity();
    }

    pub fn verificationKeyId(
        live: *const live_mod.CohortV2,
        _: *const manifest_mod.Manifest,
    ) !recursion.poseidon2_channel.Digest {
        return live.geometry.verificationKeyId();
    }

    pub fn nextParentVkId(
        live: *const live_mod.CohortV2,
        _: *const manifest_mod.Manifest,
    ) !recursion.poseidon2_channel.Digest {
        return live.geometry.nextParentVkId();
    }

    pub fn airProgramId(
        live: *const live_mod.CohortV2,
        _: *const manifest_mod.Manifest,
    ) !recursion.poseidon2_channel.Digest {
        return live.geometry.airProgramId();
    }

    pub fn authorityIdentity(
        live: *const live_mod.CohortV2,
        _: *const manifest_mod.Manifest,
    ) [32]u8 {
        return live.geometry.identity_sha256;
    }
};

fn generatedIdentity(value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(GENERATED_DOMAIN);
    hash.update(&value.cohort_identity_sha256);
    hash.update(&value.manifest_seal);
    hash.update(&value.suffix.identity);
    hashQm31(&hash, value.row35_claim);
    return hash.finalResult();
}

fn auditedIdentity(value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUDITED_DOMAIN);
    hash.update(&value.suffix.identity);
    hash.update(&value.provider_claim.identity);
    hash.update(&value.field_public_boundary.identity_sha256);
    hash.update(&value.suffix_input_boundary.identity_sha256);
    hash.update(&value.closure.closure_id);
    hashInt(&hash, u32, value.wire_boundary.tuple_count);
    hashQm31(&hash, value.wire_boundary.claimed_sum);
    hashInt(&hash, u32, value.verifier_input_boundary.tuple_count);
    hashQm31(&hash, value.verifier_input_boundary.claimed_sum);
    return hash.finalResult();
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PREFIX_ROW_COUNT != 18 or SUFFIX_ROW_COUNT != 17 or
        COMPONENT_COUNT != 36 or PROVIDER_ROW != 35 or
        PRODUCTION_ACTIVATION or
        COMPLETE_COMMON_FOLD_PROOF_COHORT !=
            (live_mod.ALL_SCHEMA4_ROLE_BRANCHES_AVAILABLE and
                live_mod.FIXED_WIRE_SOURCE_AVAILABLE) or
        GLOBAL_RELATION_CLOSURE_AVAILABLE !=
            live_mod.GLOBAL_RELATION_CLOSURE_AVAILABLE)
    {
        @compileError("common-fold secure cohort contract drifted");
    }
}
