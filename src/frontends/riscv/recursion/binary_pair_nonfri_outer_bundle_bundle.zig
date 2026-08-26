//! Internal binary pair nonfri outer bundle authority shard; use binary_pair_nonfri_outer_bundle.zig publicly.

const dependency_0 = @import("binary_pair_nonfri_outer_bundle_contract.zig");
const dependency_1 = @import("binary_pair_nonfri_outer_bundle_owned_tree_ranges.zig");

const AUDITED_HANDOFF_HEAP_ALLOCATIONS = dependency_0.AUDITED_HANDOFF_HEAP_ALLOCATIONS;
const AuditedInteractionsV1 = dependency_0.AuditedInteractionsV1;
const COMPLETE_PARENT_STARK_VERIFIED = dependency_0.COMPLETE_PARENT_STARK_VERIFIED;
const Claims = dependency_0.Claims;
const Components = dependency_0.Components;
const DomainAudits = dependency_0.DomainAudits;
const FIRST_PREFIX_ROW = dependency_0.FIRST_PREFIX_ROW;
const GENERATED_RECEIPT_HEAP_ALLOCATIONS = dependency_0.GENERATED_RECEIPT_HEAP_ALLOCATIONS;
const GeneratedInteractionsV1 = dependency_0.GeneratedInteractionsV1;
const HOT_ALIAS_LOOP_PLACEMENT_READS_PER_TREE = dependency_0.HOT_ALIAS_LOOP_PLACEMENT_READS_PER_TREE;
const HOT_ALL_TREES_HEAP_ALLOCATIONS = dependency_0.HOT_ALL_TREES_HEAP_ALLOCATIONS;
const HOT_ALL_TREES_PAIR_AUTHENTICATIONS = dependency_0.HOT_ALL_TREES_PAIR_AUTHENTICATIONS;
const HOT_BUNDLE_OVERHEAD_HEAP_ALLOCATIONS = dependency_0.HOT_BUNDLE_OVERHEAD_HEAP_ALLOCATIONS;
const HOT_PREFLIGHT_DIRECT_PLACEMENT_READS_PER_TREE = dependency_0.HOT_PREFLIGHT_DIRECT_PLACEMENT_READS_PER_TREE;
const HOT_PREFLIGHT_MANIFEST_VALIDATIONS_PER_TREE = dependency_0.HOT_PREFLIGHT_MANIFEST_VALIDATIONS_PER_TREE;
const HOT_PREFLIGHT_OWNERSHIP_RANGES_PER_TREE = dependency_0.HOT_PREFLIGHT_OWNERSHIP_RANGES_PER_TREE;
const HOT_ROLLBACK_DIRECT_PLACEMENT_READS_PER_TREE = dependency_0.HOT_ROLLBACK_DIRECT_PLACEMENT_READS_PER_TREE;
const LAST_PREFIX_ROW = dependency_0.LAST_PREFIX_ROW;
const M31 = dependency_0.M31;
const OWNED_ROW_COUNT = dependency_0.OWNED_ROW_COUNT;
const PREFIX_ROW_COUNT = dependency_0.PREFIX_ROW_COUNT;
const PRODUCTION_ACTIVATION = dependency_0.PRODUCTION_ACTIVATION;
const SHARED_PROVIDER_ROW = dependency_0.SHARED_PROVIDER_ROW;
const VERIFIER_DOMAIN_AUDIT_CUSTODY_EXPOSED = dependency_0.VERIFIER_DOMAIN_AUDIT_CUSTODY_EXPOSED;
const WHOLE_FRONTEND_VERIFIED = dependency_0.WHOLE_FRONTEND_VERIFIED;
const auditedIdentity = dependency_0.auditedIdentity;
const bundleIdentity = dependency_1.bundleIdentity;
const clearOwnedTree = dependency_1.clearOwnedTree;
const fixed_wire = dependency_0.fixed_wire;
const generatedIdentity = dependency_0.generatedIdentity;
const global_closure = dependency_0.global_closure;
const inactive_source_mod = dependency_0.inactive_source_mod;
const leaf_authority = dependency_0.leaf_authority;
const lowering = dependency_0.lowering;
const manifest_mod = dependency_0.manifest_mod;
const pair_authority = dependency_0.pair_authority;
const pair_node = dependency_0.pair_node;
const preflightFreshOwnedTree = dependency_1.preflightFreshOwnedTree;
const providerSnapshotId = dependency_0.providerSnapshotId;
const providerSourceAuthorityId = dependency_0.providerSourceAuthorityId;
const public_authority_mod = dependency_0.public_authority_mod;
const relation_interaction = dependency_0.relation_interaction;
const roster = dependency_0.roster;
const schedule = dependency_0.schedule;
const shared_provider = dependency_0.shared_provider;
const statement_authority_mod = dependency_0.statement_authority_mod;
const statement_parent_source = dependency_0.statement_parent_source;
const statement_source = dependency_0.statement_source;
const std = dependency_0.std;
const transcript_source_mod = dependency_0.transcript_source_mod;
const universal = dependency_0.universal;
const universal_manifest = dependency_0.universal_manifest;
const validateCrossCustody = dependency_0.validateCrossCustody;
const validateProviderFromInputs = dependency_0.validateProviderFromInputs;

/// Source-custody bundle. Transcript and statement proof profiles may differ;
/// their shared parent context and exact statement preimages are cross-bound.
pub fn Bundle(
    comptime transcript_dimensions: fixed_wire.Dimensions,
    comptime statement_dimensions: fixed_wire.Dimensions,
) type {
    transcript_dimensions.validate();
    statement_dimensions.validate();
    const TranscriptSource = transcript_source_mod.Source(transcript_dimensions);
    const TranscriptPrepared = pair_authority.Prepared(transcript_dimensions);
    const StatementPrepared = statement_source.Prepared(statement_dimensions);
    const StatementParent = statement_parent_source.Prepared(statement_dimensions);

    return struct {
        const Self = @This();

        pub const Inputs = struct {
            vm_plan: *const schedule.Plan,
            recursion_plans: [2]*const schedule.Plan,
            transcript_preprocessing: *const pair_authority.TranscriptPreprocessing,
            transcript_prepared: *const TranscriptPrepared,
            transcript_source: *const TranscriptSource,
            transcript_workspace: *TranscriptSource.InteractionWorkspace,
            pair_validation_workspace: *pair_authority.ValidationWorkspace,
            root_pin: pair_node.RootVkPinV1,

            statement_authority: *const statement_authority_mod.Authority,
            statement_workspace: *statement_source.Workspace,
            statement_parent: *const StatementParent,
            statement_suite: *const pair_node.PreparedProtocolSuiteV1,
            statement_publications: *const [statement_source.CHILD_COUNT]statement_source.VerifiedStatementPublicationV1,
            statement_prepared: *const StatementPrepared,

            leaf_preprocessing: *const leaf_authority.Preprocessing,
            public_authority: *const public_authority_mod.Source,
            inactive_source: *const inactive_source_mod.Source,
            inactive_prepared: *const inactive_source_mod.Prepared,
        };

        inputs: Inputs,
        authority_seal: [32]u8,

        pub fn init(inputs: Inputs) !Self {
            var result = Self{
                .inputs = inputs,
                .authority_seal = undefined,
            };
            try result.validateColdInputs();
            result.authority_seal = bundleIdentity(&result);
            try result.validate();
            return result;
        }

        /// Allocation-free hot revalidation. Expensive pair-root admission is
        /// cold and is not repeated by tree fills.
        pub fn validate(self: *const Self) !void {
            const input = self.inputs;
            try input.transcript_source.validateAgainst(
                input.vm_plan,
                input.recursion_plans,
                input.transcript_preprocessing,
                input.transcript_prepared,
            );
            try input.statement_prepared.validateHot(
                input.statement_authority,
                input.statement_workspace,
            );
            try input.inactive_source.validateAgainst(
                input.public_authority,
                input.vm_plan,
                input.recursion_plans[0],
                input.leaf_preprocessing,
            );
            try input.inactive_prepared.validateAgainst(
                input.inactive_source,
                input.public_authority,
                input.vm_plan,
                input.recursion_plans[0],
                input.leaf_preprocessing,
            );
            try validateCrossCustody(input);
            try validateProviderFromInputs(input);
            if (!std.mem.eql(u8, &self.authority_seal, &bundleIdentity(self)))
                return error.BundleIdentityMismatch;
        }

        fn validateColdInputs(self: *const Self) !void {
            const input = self.inputs;
            try input.transcript_prepared.validateAgainst(
                input.vm_plan,
                input.recursion_plans,
                input.transcript_preprocessing,
                &input.statement_authority.statement_input_preprocessing,
                &input.statement_authority.circuit,
                input.pair_validation_workspace,
                input.root_pin,
            );
            try input.statement_prepared.validateAgainst(
                input.statement_authority,
                input.statement_workspace,
                input.statement_parent,
                input.statement_suite,
                input.statement_publications,
            );
            try input.transcript_source.validateAgainst(
                input.vm_plan,
                input.recursion_plans,
                input.transcript_preprocessing,
                input.transcript_prepared,
            );
            try input.inactive_prepared.validateAgainst(
                input.inactive_source,
                input.public_authority,
                input.vm_plan,
                input.recursion_plans[0],
                input.leaf_preprocessing,
            );
            try validateCrossCustody(input);
            try validateProviderFromInputs(input);
        }

        pub fn installLogSizes(
            self: *const Self,
            destination: *universal_manifest.LogSizes,
        ) void {
            self.inputs.transcript_source.installLogSizes(destination);
            statement_source.installLogSizes(
                self.inputs.statement_authority,
                destination,
            );
            self.inputs.inactive_source.installLogSizes(destination);
        }

        pub fn loweringLanes(self: *const Self) [1]lowering.Lane {
            return .{statement_source.loweringLane(
                self.inputs.statement_authority,
            )};
        }

        /// Exact row-11 graph evaluation paired with `loweringLanes`. The
        /// all-36 cohort must lower this lane together with rows 24/29 so one
        /// arithmetic provider owns every `recursion_wire` edge.
        pub fn loweringEvaluations(self: *const Self) [1]lowering.Evaluation {
            return .{self.inputs.statement_prepared.loweringEvaluation()};
        }

        pub fn fillPreprocessedInto(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
            destination: [][]M31,
        ) !void {
            try self.validate();
            try preflightFreshOwnedTree(
                manifest,
                manifest_mod.PREPROCESSED_TREE_INDEX,
                destination,
            );
            errdefer clearOwnedTree(
                manifest,
                manifest_mod.PREPROCESSED_TREE_INDEX,
                destination,
            );

            const input = self.inputs;
            try input.transcript_source.fillPreprocessedInto(
                input.vm_plan,
                input.recursion_plans,
                input.transcript_preprocessing,
                input.transcript_prepared,
                manifest,
                destination,
            );
            var statement_columns = try statement_source.bindPreprocessedCommitted(
                input.statement_authority,
                manifest,
                destination,
            );
            try statement_source.fillPreprocessedCommitted(
                input.statement_authority,
                input.statement_workspace,
                &statement_columns,
            );
            try input.inactive_source.fillPreprocessedInto(
                input.public_authority,
                input.vm_plan,
                input.recursion_plans[0],
                input.leaf_preprocessing,
                manifest,
                destination,
            );
        }

        pub fn fillMainInto(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
            destination: [][]M31,
        ) !void {
            try self.validate();
            try preflightFreshOwnedTree(
                manifest,
                manifest_mod.MAIN_TREE_INDEX,
                destination,
            );
            errdefer clearOwnedTree(
                manifest,
                manifest_mod.MAIN_TREE_INDEX,
                destination,
            );

            const input = self.inputs;
            try input.transcript_source.fillMainInto(
                input.vm_plan,
                input.recursion_plans,
                input.transcript_preprocessing,
                input.transcript_prepared,
                manifest,
                destination,
            );
            var statement_columns = try statement_source.bindMainCommitted(
                input.statement_authority,
                manifest,
                destination,
            );
            try statement_source.fillMainCommitted(
                statement_dimensions,
                input.statement_authority,
                input.statement_workspace,
                input.statement_prepared,
                &statement_columns,
            );
            try input.inactive_source.fillMainInto(
                input.public_authority,
                input.vm_plan,
                input.recursion_plans[0],
                input.leaf_preprocessing,
                input.inactive_prepared,
                manifest,
                destination,
            );
        }

        /// Generates and seals all owned interaction claims. The returned
        /// receipt cannot be initialized from detached caller values.
        pub fn fillInteractionInto(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            destination: [][]M31,
        ) !GeneratedInteractionsV1 {
            try self.validate();
            try relations.validate();
            try provider_relations.validateAgainst(relations);
            try preflightFreshOwnedTree(
                manifest,
                manifest_mod.INTERACTION_TREE_INDEX,
                destination,
            );
            errdefer clearOwnedTree(
                manifest,
                manifest_mod.INTERACTION_TREE_INDEX,
                destination,
            );

            const input = self.inputs;
            const transcript_claims = try input.transcript_source
                .fillInteractionIntoWithWorkspace(
                input.transcript_workspace,
                input.vm_plan,
                input.recursion_plans,
                input.transcript_preprocessing,
                input.transcript_prepared,
                manifest,
                relations,
                destination,
            );
            var statement_columns = try statement_source.bindInteractionsCommitted(
                input.statement_authority,
                manifest,
                destination,
            );
            const statement_claims = try statement_source.fillInteractionsCommitted(
                statement_dimensions,
                input.statement_authority,
                input.statement_workspace,
                input.statement_prepared,
                relations,
                provider_relations,
                &statement_columns,
            );
            const inactive_claims = try input.inactive_source.fillInteractionInto(
                input.public_authority,
                input.vm_plan,
                input.recursion_plans[0],
                input.leaf_preprocessing,
                input.inactive_prepared,
                manifest,
                relations,
                destination,
            );
            const claims = Claims{
                .transcript = transcript_claims,
                .statement = statement_claims,
                .inactive = inactive_claims,
            };
            try claims.validate();
            var result = GeneratedInteractionsV1{
                .bundle_id = self.authority_seal,
                .provider_source_authority_id = providerSourceAuthorityId(input),
                .provider_snapshot_id = providerSnapshotId(input),
                .claims = claims,
                .identity = undefined,
            };
            result.identity = generatedIdentity(&result);
            try result.validateAgainst(self);
            return result;
        }

        /// Cold provenance pass. It consumes only the sealed generator result,
        /// rebuilds every per-domain audit from the real row sources, and
        /// emits the only production-authorized row-35/global handoff.
        pub fn auditGeneratedInteractions(
            self: *const Self,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            generated: *const GeneratedInteractionsV1,
            tuple_ledger: ?*relation_interaction.TupleLedger,
        ) !AuditedInteractionsV1 {
            try generated.validateAgainst(self);
            try relations.validate();
            try provider_relations.validateAgainst(relations);
            const input = self.inputs;
            const audits = DomainAudits{
                .transcript = try input.transcript_source.auditInteractionDomains(
                    input.vm_plan,
                    input.recursion_plans,
                    input.transcript_preprocessing,
                    input.transcript_prepared,
                    relations,
                    generated.claims.transcript,
                    tuple_ledger,
                ),
                .statement = try statement_source.auditInteractionDomains(
                    statement_dimensions,
                    input.statement_authority,
                    input.statement_workspace,
                    input.statement_prepared,
                    relations,
                    provider_relations,
                    generated.claims.statement,
                    tuple_ledger,
                ),
                .inactive = try input.inactive_source.auditInteractionDomains(
                    input.public_authority,
                    input.vm_plan,
                    input.recursion_plans[0],
                    input.leaf_preprocessing,
                    input.inactive_prepared,
                    relations,
                    generated.claims.inactive,
                    tuple_ledger,
                ),
            };
            try audits.validateAgainst(generated.claims);
            const global_authority = try global_closure.prepareAuthority();
            const provider_claim = try global_closure.ProviderClaimV1.init(
                &global_authority,
                generated.provider_snapshot_id,
                generated.claims.statement.range_check,
            );
            var result = AuditedInteractionsV1{
                .generated = generated.*,
                .audits = audits,
                .prefix_rows = audits.prefixRowClaims(),
                .provider_claim = provider_claim,
                .identity = undefined,
            };
            result.identity = auditedIdentity(&result);
            try result.validateAgainst(self);
            return result;
        }

        pub fn initComponents(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            generated: *const GeneratedInteractionsV1,
        ) !Components {
            try generated.validateAgainst(self);
            return .{
                .transcript = try self.inputs.transcript_source.initComponents(
                    manifest,
                    relations,
                    generated.claims.transcript,
                ),
                .statement = try statement_source.components(
                    self.inputs.statement_authority,
                    manifest,
                    relations,
                    provider_relations,
                    generated.claims.statement.rosterClaims(),
                ),
                .inactive = try self.inputs.inactive_source.initComponents(
                    self.inputs.public_authority,
                    manifest,
                    relations,
                    generated.claims.inactive,
                ),
            };
        }

        pub fn validateProviderIdentity(
            self: *const Self,
            source_id: [32]u8,
            snapshot_id: [32]u8,
        ) !void {
            try validateProviderFromInputs(self.inputs);
            if (!std.mem.eql(u8, &source_id, &providerSourceAuthorityId(self.inputs)))
                return error.ProviderAuthorityMismatch;
            if (!std.mem.eql(u8, &snapshot_id, &providerSnapshotId(self.inputs)))
                return error.ProviderSnapshotMismatch;
        }
    };
}

comptime {
    @setEvalBranchQuota(20_000);
    if (FIRST_PREFIX_ROW != 0 or PREFIX_ROW_COUNT != 18 or
        LAST_PREFIX_ROW + 1 != PREFIX_ROW_COUNT or SHARED_PROVIDER_ROW != 35 or
        OWNED_ROW_COUNT != 19)
    {
        @compileError("binary non-FRI bundle roster ownership drifted");
    }
    if (transcript_source_mod.FIRST_ROW != 0 or
        transcript_source_mod.ROW_COUNT != 10 or
        inactive_source_mod.FIRST_ROW != 12 or
        inactive_source_mod.ROW_COUNT != 6)
    {
        @compileError("binary non-FRI source cohort drifted");
    }
    if (HOT_ALL_TREES_HEAP_ALLOCATIONS != 15 or
        HOT_BUNDLE_OVERHEAD_HEAP_ALLOCATIONS != 0 or
        GENERATED_RECEIPT_HEAP_ALLOCATIONS != 0 or
        AUDITED_HANDOFF_HEAP_ALLOCATIONS != 0 or
        HOT_ALL_TREES_PAIR_AUTHENTICATIONS != 0 or
        HOT_PREFLIGHT_MANIFEST_VALIDATIONS_PER_TREE != 1 or
        HOT_PREFLIGHT_DIRECT_PLACEMENT_READS_PER_TREE != 22 or
        HOT_PREFLIGHT_OWNERSHIP_RANGES_PER_TREE != 2 or
        HOT_ALIAS_LOOP_PLACEMENT_READS_PER_TREE != 0 or
        HOT_ROLLBACK_DIRECT_PLACEMENT_READS_PER_TREE != 19)
    {
        @compileError("binary non-FRI hot-path accounting drifted");
    }
    if (VERIFIER_DOMAIN_AUDIT_CUSTODY_EXPOSED or WHOLE_FRONTEND_VERIFIED or
        COMPLETE_PARENT_STARK_VERIFIED or PRODUCTION_ACTIVATION)
    {
        @compileError("binary non-FRI production boundary changed");
    }
    assertPointerFree(Claims);
    assertPointerFree(DomainAudits);
    assertPointerFree(GeneratedInteractionsV1);
    assertPointerFree(AuditedInteractionsV1);
}

pub fn assertPointerFree(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer, .optional, .error_union, .@"union" => @compileError("binary non-FRI fixed receipt contains dynamic state"),
        .array => |array| assertPointerFree(array.child),
        .@"struct" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        else => {},
    }
}
