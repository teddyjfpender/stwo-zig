//! Concrete 39-row cohort for one authenticated SegmentV2 leaf.
//! Its non-core and native verifier-core owners share one row-34 Poseidon
//! schedule and publish all three trees allocation-free and failure-atomically.
const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const leaf_outer = @import("recursive_segment_v2_leaf_outer.zig");
const noncore_mod = @import("recursive_segment_v2_noncore_owner.zig");
const core_mod = @import("recursive_fri_outer.zig");
const tuple_diagnostic = @import("recursive_segment_v2_tuple_closure_diagnostic.zig");
const contract = @import("recursive_segment_v2_outer_cohort_contract.zig");
const support = @import("recursive_segment_v2_outer_cohort_support.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;

const recursion = frontend.recursion;
const air = recursion.air;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const manifest_mod = air.segment_outer_adapter_manifest_v2;
const universal = air.universal_challenges;
const shared_provider = air.universal_shared_provider;
const relation_interaction = air.relation_interaction;
const cohort_protocol = recursion.segment_outer_cohort_v2;
const public_native_sum = recursion.segment_public_native_sum_authority_v2;

const DomainAudit = relation_interaction.DomainAudit;
const NonCoreOwner = noncore_mod.Owner;
const NativeCoreOwner = core_mod.NativeSegmentCoreV2;
pub const FORMAT_VERSION = contract.FORMAT_VERSION;
pub const GENERATED_FORMAT_VERSION = contract.GENERATED_FORMAT_VERSION;
pub const AUTHORITY_TRANSCRIPT_DOMAIN = contract.AUTHORITY_TRANSCRIPT_DOMAIN;
pub const COMPONENT_COUNT = contract.COMPONENT_COUNT;
pub const UNIVERSAL_COMPONENT_COUNT = contract.UNIVERSAL_COMPONENT_COUNT;
pub const CORE_FIRST_ROW = contract.CORE_FIRST_ROW;
pub const CORE_LAST_ROW = contract.CORE_LAST_ROW;
pub const CORE_ROW_COUNT = contract.CORE_ROW_COUNT;
pub const CORE_ROW_MASK = contract.CORE_ROW_MASK;
pub const ALL_COMPONENT_MASK = contract.ALL_COMPONENT_MASK;
pub const HOT_COHORT_TREE_OVERHEAD_HEAP_ALLOCATIONS = contract.HOT_COHORT_TREE_OVERHEAD_HEAP_ALLOCATIONS;
pub const HOT_TREE_HEAP_ALLOCATIONS = contract.HOT_TREE_HEAP_ALLOCATIONS;
pub const INTERACTION_GENERATION_IS_COLD = contract.INTERACTION_GENERATION_IS_COLD;
pub const FAILS_AT_WHOLE_TREE_BOUNDARY = contract.FAILS_AT_WHOLE_TREE_BOUNDARY;
pub const SHARED_ROW34_PROVIDER_INSTANCE_COUNT = contract.SHARED_ROW34_PROVIDER_INSTANCE_COUNT;
pub const RED_TUPLE_DOMAIN_MASK = contract.RED_TUPLE_DOMAIN_MASK;
pub const PUBLIC_WIRE_BOUNDARY_TRANSCRIPT_DOMAIN = contract.PUBLIC_WIRE_BOUNDARY_TRANSCRIPT_DOMAIN;
pub const AuthorityInputs = contract.AuthorityInputs;
pub const GeneratedInteractionsV2 = contract.GeneratedInteractionsV2;
pub const RecursiveTranscriptPrefixSourceV1 = contract.RecursiveTranscriptPrefixSourceV1;
pub const OuterAdmissionBoundariesV2 = contract.OuterAdmissionBoundariesV2;
pub const Components = contract.Components;
const coreInputs = support.coreInputs;
const generatedIdentity = support.generatedIdentity;
const preflightTree = support.preflightTree;
const clearTree = support.clearTree;
const digestWords = support.digestWords;
const componentBit = support.componentBit;
const rangeMask = support.rangeMask;
const allZero = support.allZero;
const CLOSURE_DIAGNOSTIC_ENV = "STWO_RECURSION_OUTER_CLOSURE_DIAGNOSTIC";
pub const Error = contract.Error;

/// The complete cohort accepts one authority and nothing else. In particular,
/// detached source manifests, log sizes, claims, audits, or provider calls can
/// never be supplied by the prover.
const CohortGeneratedInteractionsV2 = GeneratedInteractionsV2;
const CohortComponents = Components;

pub const Cohort = struct {
    const Self = @This();

    pub const AuthorityInputs =
        *const leaf_outer.PreparedNativeV2LeafOuter;
    pub const AuthorityInput = *const leaf_outer.PreparedNativeV2LeafOuter;
    pub const GeneratedInteractionsV2 = CohortGeneratedInteractionsV2;
    pub const Components = CohortComponents;

    /// Verifier-owned, pointer-free authority for the successful outer proof.
    pub const PublicationAuthorityV1 = contract.PublicationAuthorityV1;

    allocator: std.mem.Allocator,
    prepared: *const leaf_outer.PreparedNativeV2LeafOuter,
    prepared_identity: [32]u8,
    /// Heap ownership gives source owners a stable manifest address even when
    /// this aggregate is returned or moved in ReleaseFast builds.
    complete_manifest: *manifest_mod.Manifest,
    public_native_sum_source: *public_native_sum.SourceV2,
    public_native_sum_evaluation: *public_native_sum.OwnedEvaluationV2,
    noncore: *NonCoreOwner,
    core: *NativeCoreOwner,
    plan: cohort_protocol.CohortPlanV2,
    noncore_authority_id: [32]u8,
    core_authority_id: [32]u8,
    authority_id: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        prepared: AuthorityInput,
    ) !Self {
        // `PreflightV2.init` is the single whole-leaf admission at this
        // layer. Both source owners subsequently validate the exact borrowed
        // subsets they retain; replaying `prepared.validate()` here would add
        // no independent evidence.
        const preflight = try noncore_mod.PreflightV2.init(prepared);

        var native_relations = noncore_mod.nativeRelations(prepared);
        const native_sum_inputs = noncore_mod.publicInputs(
            prepared,
            &native_relations,
        );
        const public_native_sum_source = try allocator.create(
            public_native_sum.SourceV2,
        );
        errdefer allocator.destroy(public_native_sum_source);
        public_native_sum_source.* = try public_native_sum.SourceV2.init(
            allocator,
            &preflight.public_prepared,
            native_sum_inputs,
        );
        errdefer public_native_sum_source.deinit();
        const public_native_sum_evaluation = try allocator.create(
            public_native_sum.OwnedEvaluationV2,
        );
        errdefer allocator.destroy(public_native_sum_evaluation);
        public_native_sum_evaluation.* = try public_native_sum.OwnedEvaluationV2.init(
            allocator,
            public_native_sum_source,
            &preflight.public_prepared,
            native_sum_inputs,
        );
        errdefer public_native_sum_evaluation.deinit();

        const core = try allocator.create(NativeCoreOwner);
        errdefer allocator.destroy(core);
        try core.initInPlace(
            allocator,
            coreInputs(
                prepared,
                &preflight.transcript_prepared,
                public_native_sum_source,
                public_native_sum_evaluation,
            ),
        );
        errdefer core.deinit();

        var log_sizes = [_]u32{0} ** UNIVERSAL_COMPONENT_COUNT;
        try preflight.installLogSizes(&log_sizes);
        const core_logs = try core.componentLogSizes();
        for (core_logs, CORE_FIRST_ROW..) |log_size, row| {
            if (log_sizes[row] != 0) return error.CrossCustodyMismatch;
            log_sizes[row] = log_size;
        }

        const manifest_value = try manifest_mod.build(
            log_sizes,
            &preflight.transcript_manifest,
            &preflight.statement_manifest,
            &preflight.public_manifest,
            &preflight.boundary_manifest,
        );
        const complete_manifest = try allocator.create(manifest_mod.Manifest);
        errdefer allocator.destroy(complete_manifest);
        complete_manifest.* = manifest_value;
        try core.validateAgainstManifest(complete_manifest);

        const noncore = try allocator.create(NonCoreOwner);
        errdefer allocator.destroy(noncore);
        try noncore.initInPlace(
            allocator,
            prepared,
            complete_manifest,
            public_native_sum_source,
        );
        errdefer noncore.deinit();

        // The provider is finalized exactly once, after both halves have been
        // bound to the same complete manifest and before any external write.
        try core.finalizeSharedProviderMain();
        const complete_layout = try core.completeScheduleReceipt();
        const complete_calls = try core.completePoseidonCalls();
        const plan = try cohort_protocol.CohortPlanV2.measuredCanonical(
            complete_manifest,
            &complete_layout,
            complete_calls,
        );
        const noncore_authority_id = try noncore.authorityIdentity();
        const core_authority_id = try core.authorityIdentity();

        var result = Self{
            .allocator = allocator,
            .prepared = prepared,
            .prepared_identity = prepared.identity,
            .complete_manifest = complete_manifest,
            .public_native_sum_source = public_native_sum_source,
            .public_native_sum_evaluation = public_native_sum_evaluation,
            .noncore = noncore,
            .core = core,
            .plan = plan,
            .noncore_authority_id = noncore_authority_id,
            .core_authority_id = core_authority_id,
            .authority_id = undefined,
        };
        result.authority_id = support.cohortIdentity(
            &result,
            FORMAT_VERSION,
            SHARED_ROW34_PROVIDER_INSTANCE_COUNT,
        );
        // Source constructors, exact manifest assembly, and the measured
        // provider plan have already performed the cold checks. Keep the
        // explicit rebuilding diagnostic in `validateCold` without imposing
        // a second source-manifest derivation on every prover/verifier init.
        try result.validateEnvelope();
        return result;
    }

    pub fn deinit(self: *Self) void {
        self.noncore.deinit();
        self.allocator.destroy(self.noncore);
        self.core.deinit();
        self.allocator.destroy(self.core);
        self.public_native_sum_evaluation.deinit();
        self.allocator.destroy(self.public_native_sum_evaluation);
        self.public_native_sum_source.deinit();
        self.allocator.destroy(self.public_native_sum_source);
        self.allocator.destroy(self.complete_manifest);
        self.* = undefined;
    }

    /// Constant-storage validation used between proof-engine stages.
    pub fn validate(self: *const Self) !void {
        try self.validateEnvelope();
    }

    /// Full hostile-input audit. Construction performs this once before the
    /// cohort becomes observable; mutation suites may invoke it explicitly.
    pub fn validateCold(self: *const Self) !void {
        try self.prepared.validate();
        try self.validateEnvelope();
        const preflight = try noncore_mod.PreflightV2.init(self.prepared);
        var logs = [_]u32{0} ** UNIVERSAL_COMPONENT_COUNT;
        try preflight.installLogSizes(&logs);
        const core_logs = try self.core.componentLogSizes();
        for (core_logs, CORE_FIRST_ROW..) |log_size, row| logs[row] = log_size;
        const rebuilt = try manifest_mod.build(
            logs,
            &preflight.transcript_manifest,
            &preflight.statement_manifest,
            &preflight.public_manifest,
            &preflight.boundary_manifest,
        );
        if (!std.meta.eql(rebuilt, self.complete_manifest.*))
            return error.ManifestGeometryMismatch;
    }

    fn validateEnvelope(self: *const Self) !void {
        try self.complete_manifest.validate();
        try self.noncore.validate();
        try self.public_native_sum_evaluation.validateAgainst(
            self.public_native_sum_source,
        );
        try self.core.validateComplete();
        try self.core.validateAgainstManifest(self.complete_manifest);
        try self.plan.validateAgainst(self.complete_manifest);
        const calls = try self.core.completePoseidonCalls();
        try self.plan.provider.validateAuthenticated(
            self.complete_manifest,
            calls,
        );
        if (self.complete_manifest.roster_count != COMPONENT_COUNT or
            calls.len != cohort_protocol.MEASURED_TOTAL_POSEIDON_CALLS or
            self.plan.provider.provider_instance_count !=
                SHARED_ROW34_PROVIDER_INSTANCE_COUNT or
            !std.mem.eql(u8, &self.prepared_identity, &self.prepared.identity) or
            !std.mem.eql(
                u8,
                &self.noncore_authority_id,
                &(try self.noncore.authorityIdentity()),
            ) or
            !std.mem.eql(
                u8,
                &self.core_authority_id,
                &(try self.core.authorityIdentity()),
            ) or
            !std.mem.eql(
                u8,
                &self.authority_id,
                &support.cohortIdentity(
                    self,
                    FORMAT_VERSION,
                    SHARED_ROW34_PROVIDER_INSTANCE_COUNT,
                ),
            ))
        {
            return error.AuthorityIdentityMismatch;
        }
    }

    pub fn manifest(self: *const Self) *const manifest_mod.Manifest {
        return self.complete_manifest;
    }

    /// Re-authenticates the exact retained SegmentV2 wire and snapshots the
    /// authority needed by the verifier's private publication mint.  This
    /// method is called on the verifier cohort only; no prover-side generated
    /// claim, audit, or receipt crosses the proof-admission boundary.
    pub fn publicationAuthority(
        self: *const Self,
    ) !PublicationAuthorityV1 {
        try self.validateEnvelope();
        const data = &self.prepared.capture.public_data.data;
        const view = try recursion.segment_statement_v2
            .authenticateCanonicalWire(data.words());
        const context = self.prepared.authority_prepared.source.context;
        if (!std.meta.eql(view.wire_id, data.wireId()) or
            !std.meta.eql(view.wire_id, context.segment_wire_id) or
            !std.meta.eql(
                view.statement.base_statement_id,
                context.statement_id,
            ))
        {
            return error.CrossCustodyMismatch;
        }
        return .{
            .context = context,
            .statement_words = view.statement.base_statement_words,
            .prepared_leaf_sha_id = self.prepared_identity,
            .cohort_authority_sha_id = self.authority_id,
            .manifest_sha_id = self.complete_manifest.seal,
            .catalog_sha_id = self.plan.catalog_identity,
            .relation_registry_sha_id = self.plan.relation_registry_identity,
            .plan_sha_id = self.plan.identity,
        };
    }

    /// Deterministic pre-challenge binding of the aggregate envelope and both
    /// source-specific authority transcripts.
    pub fn mixAuthority(self: *const Self, channel: anytype) !void {
        try self.validateEnvelope();
        channel.mixU32s(&.{
            AUTHORITY_TRANSCRIPT_DOMAIN,
            FORMAT_VERSION,
            COMPONENT_COUNT,
            CORE_FIRST_ROW,
            CORE_LAST_ROW,
            cohort_protocol.MEASURED_TOTAL_POSEIDON_CALLS,
        });
        channel.mixU32s(&digestWords(self.complete_manifest.seal));
        channel.mixU32s(&digestWords(self.plan.identity));
        channel.mixU32s(&digestWords(self.authority_id));
        try self.noncore.mixAuthority(channel);
        try self.core.mixAuthority(channel);
    }

    /// Relation-dependent but prover-independent public boundary for the core
    /// arithmetic graphs. The concrete core derives both geometry and scalar
    /// from its pre-challenge-sealed lowering plan; this aggregate accepts no
    /// detached term list or caller-selected claimed sum.
    pub fn publicWireBoundary(
        self: *const Self,
        relations: *const universal.UniversalRelations,
    ) !cohort_protocol.PublicWireBoundaryV2 {
        try self.validateEnvelope();
        return cohort_protocol.PublicWireBoundaryV2.init(
            self.core_authority_id,
            try self.core.publicWireBoundaryTermCount(),
            try self.core.publicWireBoundaryClaim(relations),
        );
    }

    /// Rebuilds the three SegmentV2 outer-admission terms from the exact
    /// verifier claim vector and the prepared authorities that own the public
    /// wire and verifier-input boundaries. No detached scalar is accepted.
    pub fn outerAdmissionBoundaries(
        self: *const Self,
        relations: *const universal.UniversalRelations,
        claims: *const manifest_mod.ClaimVector,
    ) !OuterAdmissionBoundariesV2 {
        try self.validateEnvelope();
        try claims.validate(self.complete_manifest);
        const provider_prepared = if (self.noncore.input_provider_active_prepared) |*value|
            value
        else
            return error.InteractionsNotPrepared;
        try provider_prepared.validate();
        const public_wire = try self.publicWireBoundary(relations);
        var claim_aggregate = QM31.zero();
        for (claims.values) |claim| claim_aggregate = claim_aggregate.add(claim);
        const result = OuterAdmissionBoundariesV2{
            .input_wire = claim_aggregate,
            .public_wire = public_wire.claimed_sum,
            .verifier_input = provider_prepared.detailed_publisher_claim,
        };
        try result.validate();
        return result;
    }

    /// Rebuilds the complete source-specific transcript prefix in one native
    /// core validation pass. The returned value remains local to the verifier
    /// until successful proof admission seals it into the recursive witness.
    pub fn recursiveTranscriptPrefixSource(
        self: *const Self,
        relations: *const universal.UniversalRelations,
    ) !RecursiveTranscriptPrefixSourceV1 {
        try self.validateEnvelope();
        const core_prefix = try self.core.transcriptPrefixAuthority(relations);
        if (!std.mem.eql(
            u8,
            &core_prefix.authority_sha_id,
            &self.core_authority_id,
        )) return error.AuthorityIdentityMismatch;
        const public_wire_boundary =
            try cohort_protocol.PublicWireBoundaryV2.init(
                core_prefix.authority_sha_id,
                core_prefix.public_wire_boundary_term_count,
                core_prefix.public_wire_boundary_claimed_sum,
            );
        return .{
            .noncore_authority_sha_id = self.noncore_authority_id,
            .core_authority_sha_id = core_prefix.authority_sha_id,
            .core_layout_sha_id = core_prefix.layout_sha_id,
            .core_call_buffer_sha_id = core_prefix.call_buffer_sha_id,
            .core_total_call_count = core_prefix.total_call_count,
            .public_wire_boundary = public_wire_boundary,
        };
    }

    /// Fixed prover/verifier transcript frame for the boundary above. The
    /// frame is injected after the 39 committed interaction claims and before
    /// Tree 2, so neither omission nor a sign/count substitution can reuse the
    /// same outer-proof transcript.
    pub fn mixPublicWireBoundary(
        self: *const Self,
        channel: anytype,
        relations: *const universal.UniversalRelations,
    ) !void {
        const boundary = try self.publicWireBoundary(relations);
        channel.mixU32s(&.{
            PUBLIC_WIRE_BOUNDARY_TRANSCRIPT_DOMAIN,
            boundary.format_version,
            @intFromEnum(boundary.domain),
            boundary.term_count,
        });
        channel.mixU32s(&digestWords(boundary.source_authority_id));
        channel.mixFelts(&.{boundary.claimed_sum});
        channel.mixU32s(&digestWords(boundary.identity));
    }

    pub fn fillPreprocessedInto(
        self: *Self,
        manifest_value: *const manifest_mod.Manifest,
        destination: [][]M31,
    ) !void {
        try self.requireManifest(manifest_value);
        try preflightTree(
            manifest_value,
            manifest_mod.PREPROCESSED_TREE_INDEX,
            destination,
        );
        errdefer clearTree(destination);
        try self.noncore.fillPreprocessedInto(manifest_value, destination);
        try self.core.fillPreprocessedInto(manifest_value, destination);
    }

    pub fn fillMainInto(
        self: *Self,
        manifest_value: *const manifest_mod.Manifest,
        destination: [][]M31,
    ) !void {
        try self.requireManifest(manifest_value);
        try preflightTree(
            manifest_value,
            manifest_mod.MAIN_TREE_INDEX,
            destination,
        );
        errdefer clearTree(destination);
        try self.noncore.fillMainInto(manifest_value, destination);
        try self.core.fillMainInto(manifest_value, destination);
    }

    pub fn fillInteractionInto(
        self: *Self,
        manifest_value: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
        destination: [][]M31,
    ) !CohortGeneratedInteractionsV2 {
        try self.requireManifest(manifest_value);
        try preflightTree(
            manifest_value,
            manifest_mod.INTERACTION_TREE_INDEX,
            destination,
        );
        errdefer clearTree(destination);

        // All fallible/allocation-bearing generation precedes the first copy
        // into caller-owned memory. Publication below is cached and hot.
        const noncore_generated = try self.noncore.prepareInteractions(
            self.allocator,
            relations,
            provider_relations,
        );
        const core_generated = try self.core.prepareInteractions(
            self.allocator,
            relations,
            provider_relations,
        );
        const published_noncore = try self.noncore.fillInteractionInto(
            manifest_value,
            destination,
        );
        const published_core = try self.core.fillInteractionInto(
            manifest_value,
            destination,
        );
        if (!std.meta.eql(noncore_generated, published_noncore) or
            !std.meta.eql(core_generated, published_core))
        {
            return error.CrossCustodyMismatch;
        }
        const generated = support.generatedEnvelope(
            CohortGeneratedInteractionsV2,
            self,
            noncore_generated,
            core_generated,
        );
        try self.validateGenerated(
            &generated,
            relations,
            provider_relations,
        );
        return generated;
    }

    pub fn validateGenerated(
        self: *const Self,
        generated: *const CohortGeneratedInteractionsV2,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        try self.validateGeneratedHeader(generated);
        try generated.noncore.validateCachedAgainst(
            self.noncore,
            relations,
            provider_relations,
        );
        try generated.core.validateAgainst(
            self.core,
            relations,
            provider_relations,
        );
        _ = try self.collectClosure(generated, relations);
    }

    /// Explicit cold diagnostic. The proof path uses exact equality to the
    /// owner's internally generated receipt; this entry point additionally
    /// reconstructs all 21 non-core domain audits from authenticated inputs.
    pub fn validateGeneratedCold(
        self: *const Self,
        generated: *const CohortGeneratedInteractionsV2,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        try self.validateGeneratedHeader(generated);
        try generated.noncore.validateAgainstInputs(
            self.allocator,
            self.noncore,
            relations,
            provider_relations,
        );
        try generated.core.validateAgainst(
            self.core,
            relations,
            provider_relations,
        );
        _ = try self.collectClosure(generated, relations);
    }

    pub fn claimVector(
        self: *const Self,
        generated: *const CohortGeneratedInteractionsV2,
    ) !manifest_mod.ClaimVector {
        try self.validateGeneratedHeader(generated);
        var result = try manifest_mod.ClaimVector.init(self.complete_manifest);
        try generated.noncore.bindClaimsInto(&result);
        try generated.core.bindClaimsInto(&result);
        if (result.bound_mask != ALL_COMPONENT_MASK)
            return error.ComponentCoverageMismatch;
        try result.sealClaims(self.complete_manifest);
        return result;
    }

    pub fn auditGlobalClosure(
        self: *const Self,
        generated: *const CohortGeneratedInteractionsV2,
        claims: *const manifest_mod.ClaimVector,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !cohort_protocol.ClosureSummaryV2 {
        try self.validateGenerated(
            generated,
            relations,
            provider_relations,
        );
        try claims.validate(self.complete_manifest);
        const collected = try self.collectClosure(generated, relations);
        for (claims.values, collected.claims) |actual, expected|
            if (!actual.eql(expected)) return error.ComponentCoverageMismatch;
        return collected.closure;
    }

    /// Exact, challenge-independent classifier for the six domains identified
    /// by the algebraic V2 closure gate. It includes every committed row, the
    /// one row-34 provider, and the core lowering plan's authenticated public
    /// constant/output anchors. It admits no detached verifier-input helper.
    pub fn diagnoseRedTupleClosure(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) !tuple_diagnostic.Report {
        try self.validateEnvelope();
        var ledger = relation_interaction.TupleLedger.init(allocator);
        defer ledger.deinit();
        try self.noncore.appendTupleContributions(
            &ledger,
            RED_TUPLE_DOMAIN_MASK,
        );
        try self.core.appendTupleContributions(
            allocator,
            &ledger,
            RED_TUPLE_DOMAIN_MASK,
        );
        return tuple_diagnostic.classify(
            allocator,
            &ledger,
            RED_TUPLE_DOMAIN_MASK,
        );
    }

    /// Prepares only the retained interaction authorities needed by the exact
    /// tuple classifier, without committing trees or entering the outer STARK.
    /// The relation context is already authenticated by the prepared leaf and
    /// cannot alter any base tuple; it only supplies the LogUp coefficients
    /// required to rebuild rows 0--37 in their ordinary production owners.
    pub fn prepareAndDiagnoseRedTupleClosure(
        self: *Self,
        allocator: std.mem.Allocator,
    ) !tuple_diagnostic.Report {
        const relations = &self.prepared.outer_relations;
        const provider_relations = try shared_provider.SharedProviderRelations.init(
            relations,
        );
        _ = try self.noncore.prepareInteractions(
            self.allocator,
            relations,
            &provider_relations,
        );
        _ = try self.core.prepareInteractions(
            self.allocator,
            relations,
            &provider_relations,
        );
        return self.diagnoseRedTupleClosure(allocator);
    }

    /// Verifier-side regeneration from this cohort's authenticated owners.
    /// The outer engine constructs a fresh cohort before invoking this method,
    /// so no prover-generated receipt, claim, audit, or Tree 2 column crosses
    /// the verifier boundary.
    pub fn rebuildGeneratedInteractions(
        self: *Self,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !CohortGeneratedInteractionsV2 {
        const noncore_generated = try self.noncore.rebuildGeneratedInteractions(
            self.allocator,
            relations,
            provider_relations,
        );
        const core_generated = try self.core.rebuildGeneratedInteractions(
            self.allocator,
            relations,
            provider_relations,
        );
        const generated = support.generatedEnvelope(
            CohortGeneratedInteractionsV2,
            self,
            noncore_generated,
            core_generated,
        );
        try self.validateGenerated(
            &generated,
            relations,
            provider_relations,
        );
        return generated;
    }

    pub fn initComponents(
        self: *Self,
        generated: *const CohortGeneratedInteractionsV2,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !CohortComponents {
        try self.validateGenerated(
            generated,
            relations,
            provider_relations,
        );
        return .{
            .noncore = try self.noncore.initComponents(
                self.complete_manifest,
                relations,
                provider_relations,
                &generated.noncore,
            ),
            .core = try self.core.initComponents(
                self.complete_manifest,
                relations,
                provider_relations,
                &generated.core,
            ),
        };
    }

    fn validateGeneratedHeader(
        self: *const Self,
        generated: *const CohortGeneratedInteractionsV2,
    ) !void {
        try self.validateEnvelope();
        if (generated.format_version != GENERATED_FORMAT_VERSION or
            !allZero(&generated.padding) or
            !std.mem.eql(u8, &generated.cohort_id, &self.authority_id) or
            !std.mem.eql(
                u8,
                &generated.manifest_seal,
                &self.complete_manifest.seal,
            ) or
            !std.mem.eql(
                u8,
                &generated.identity,
                &generatedIdentity(generated),
            ))
        {
            return error.GeneratedIdentityMismatch;
        }
    }

    const CollectedClosure = struct {
        claims: [COMPONENT_COUNT]QM31,
        audits: [COMPONENT_COUNT]DomainAudit,
        closure: cohort_protocol.ClosureSummaryV2,
    };

    fn collectClosure(
        self: *const Self,
        generated: *const CohortGeneratedInteractionsV2,
        relations: *const universal.UniversalRelations,
    ) !CollectedClosure {
        var claims = [_]QM31{QM31.zero()} ** COMPONENT_COUNT;
        var audits: [COMPONENT_COUNT]DomainAudit = undefined;
        var mask: u64 = 0;
        try generated.noncore.installClaimsAndAudits(
            &claims,
            &audits,
            &mask,
        );
        if (mask != noncore_mod.OWNED_ROW_MASK or mask & CORE_ROW_MASK != 0)
            return error.ComponentCoverageMismatch;
        for (generated.core.claims, generated.core.audits, CORE_FIRST_ROW..) |
            claim,
            audit,
            row,
        | {
            const bit = componentBit(row);
            if (mask & bit != 0) return error.ComponentCoverageMismatch;
            claims[row] = claim;
            audits[row] = audit;
            mask |= bit;
        }
        if (mask != ALL_COMPONENT_MASK)
            return error.ComponentCoverageMismatch;
        const public_wire_boundary = try self.publicWireBoundary(relations);
        const closure = cohort_protocol.verifyInteractionClosureV2(
            self.complete_manifest,
            &claims,
            &audits,
            &public_wire_boundary,
        ) catch |err| {
            if (err == error.RelationNotClosed and
                std.process.hasEnvVarConstant(CLOSURE_DIAGNOSTIC_ENV))
            {
                var diagnostic = self.diagnoseRedTupleClosure(
                    self.allocator,
                ) catch |diagnostic_error| {
                    std.debug.print(
                        "SegmentV2 tuple diagnostic failed: {s}\n",
                        .{@errorName(diagnostic_error)},
                    );
                    return err;
                };
                defer diagnostic.deinit();
                diagnostic.print();
            }
            return err;
        };
        return .{
            .claims = claims,
            .audits = audits,
            .closure = closure,
        };
    }

    fn requireManifest(
        self: *const Self,
        manifest_value: *const manifest_mod.Manifest,
    ) !void {
        try self.validateEnvelope();
        if (manifest_value != self.complete_manifest) {
            try manifest_value.validate();
            if (!std.meta.eql(manifest_value.*, self.complete_manifest.*))
                return error.ManifestGeometryMismatch;
        }
        if (!std.mem.eql(
            u8,
            &manifest_value.seal,
            &self.complete_manifest.seal,
        )) return error.ManifestGeometryMismatch;
    }
};

/// Rebuilds fresh verifier-owned subreceipts from authenticated ingress.
pub fn independentlyRebuild(
    allocator: std.mem.Allocator,
    prepared: AuthorityInputs,
    relations: *const universal.UniversalRelations,
    provider_relations: *const shared_provider.SharedProviderRelations,
) !GeneratedInteractionsV2 {
    var cohort = try Cohort.init(allocator, prepared);
    defer cohort.deinit();
    return cohort.rebuildGeneratedInteractions(relations, provider_relations);
}

test "SegmentV2 concrete cohort pins complete ownership and hot publication" {
    std.testing.refAllDeclsRecursive(Cohort);
    try std.testing.expectEqual(@as(usize, 39), COMPONENT_COUNT);
    try std.testing.expectEqual(ALL_COMPONENT_MASK, noncore_mod.OWNED_ROW_MASK | CORE_ROW_MASK);
    try std.testing.expectEqual([_]usize{ 0, 0, 0 }, HOT_TREE_HEAP_ALLOCATIONS);
    try std.testing.expect(INTERACTION_GENERATION_IS_COLD);
}
