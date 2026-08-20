//! Native-capture-owned SegmentV2 outer rows 0--17 and 35--38.
//!
//! The owner is deliberately narrower than a complete outer cohort. It owns
//! no verifier-core row, does not assemble the 39-row manifest, and never
//! edits the proof engine. Its job is the exact chain of custody from one
//! admitted `PreparedNativeV2LeafOuter` to the non-core committed columns,
//! claims, typed components, and 47-domain audits.
//!
//! Boundary Tree 0/1 columns are copied from the admitted leaf. On every
//! outer relation draw the two boundary rows are independently rebuilt in
//! owner storage, their Tree 0/1 bytes are compared with those admitted
//! columns, and only the newly rebuilt Tree 2 is made publishable.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;

const leaf_outer = @import("recursive_segment_v2_leaf_outer.zig");
const manifest_mod = recursion.air.segment_outer_adapter_manifest_v2;
const transcript_source = recursion.segment_transcript_outer_source_v2;
const transcript_components = recursion.segment_transcript_outer_components_v2;
const statement_source = recursion.segment_statement_outer_source_v2;
const statement_components = recursion.segment_statement_outer_components_v2;
const public_source = recursion.segment_public_outer_source_v2;
const public_components = recursion.segment_public_outer_components_v2;
const public_native_sum = recursion.segment_public_native_sum_authority_v2;
const range_authority = recursion.segment_range_authority_v2;
const boundary_authority = recursion.segment_leaf_outer_authority_v2;
const boundary_components = recursion.air.segment_boundary_components_v2;
const input_provider_authority =
    recursion.segment_publication_input_provider_authority_v2;
const input_provider_component =
    recursion.air.segment_publication_input_provider_component_v2;
const input_provider_air = recursion.air.segment_publication_input_provider_v2;
const shared_provider = recursion.air.universal_shared_provider;
const universal = recursion.air.universal_challenges;
const universal_manifest = recursion.air.universal_manifest;
const universal_roster = recursion.air.universal_roster;
const relation_interaction = recursion.air.relation_interaction;
const native_relations_mod = frontend.air.relation_challenges;
const noncore_audits = recursion.segment_outer_noncore_audits_v2;
const range_bridge = recursion.air.range_check_8_8_bridge;
const contract = @import("recursive_segment_v2_noncore_contract.zig");
const support = @import("recursive_segment_v2_noncore_support.zig");
const runtime = @import("recursive_segment_v2_noncore_runtime.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const UNIVERSAL_COMPONENT_COUNT: usize = universal_roster.COMPONENT_COUNT;
pub const OWNED_ROW_COUNT: usize = noncore_audits.NONCORE_ROW_COUNT;
pub const UNIVERSAL_OWNED_ROW_MASK: u64 = rangeMask(0, 18) | componentBit(35);
pub const BOUNDARY_ROW_MASK: u64 = componentBit(36) | componentBit(37);
pub const VERIFIER_INPUT_PROVIDER_ROW_MASK: u64 = componentBit(38);
pub const OWNED_ROW_MASK: u64 = UNIVERSAL_OWNED_ROW_MASK | BOUNDARY_ROW_MASK |
    VERIFIER_INPUT_PROVIDER_ROW_MASK;
pub const OWNED_ROW_INDICES = noncore_audits.NONCORE_ROW_INDICES;

/// Every retained slice points to an allocation, never to another field in
/// the owner. Moving an initialized owner is therefore ReleaseFast-safe.
pub const RETAINS_SELF_POINTERS = false;
pub const TREE_0_1_REBUILT_FROM_ADMITTED_CAPTURE = true;
pub const BOUNDARY_REBUILT_PER_RELATION_DRAW = true;
pub const BOUNDARY_TREE_0_1_BYTE_EQUALITY_REQUIRED = true;
pub const TREE_PUBLICATION_FAILS_BEFORE_FIRST_EXTERNAL_WRITE = true;
pub const HOT_TREE_0_1_HEAP_ALLOCATIONS: usize = 0;
pub const HOT_CACHED_TREE_2_HEAP_ALLOCATIONS: usize = 0;
pub const HOT_TREE_HEAP_ALLOCATIONS = [_]usize{ 0, 0, 0 };
pub const INTERACTION_GENERATION_IS_COLD = true;
pub const HOT_GENERATED_VALIDATION_HEAP_ALLOCATIONS: usize = 0;
pub const COLD_INDEPENDENT_AUDIT_REPLAYS_PER_GENERATION: usize = 1;

pub const AUTHORITY_ID_DOMAIN = contract.OWNER_ID_DOMAIN;
pub const GENERATED_ID_DOMAIN = contract.GENERATED_ID_DOMAIN;
pub const AUTHORITY_TRANSCRIPT_DOMAIN: u32 = 0x4e43_5632; // "NCV2"

pub const Error = error{
    AliasedDestination,
    ArithmeticOverflow,
    BoundaryCommittedTraceMismatch,
    DestinationColumnCountMismatch,
    DestinationLogSizeMismatch,
    DestinationNotFresh,
    GeneratedIdentityMismatch,
    InteractionGenerationMismatch,
    InteractionsNotPrepared,
    InvalidOwner,
    ManifestMismatch,
    OccupiedRowOverlap,
    SourceManifestMismatch,
};

pub const PreparedNativeV2LeafOuter = leaf_outer.PreparedNativeV2LeafOuter;
pub const Manifest = manifest_mod.Manifest;
pub const DomainAudit = relation_interaction.DomainAudit;

pub const AuthorityInputs = struct {
    prepared: *const PreparedNativeV2LeafOuter,
};

/// Allocation-free source geometry needed by the complete cohort to assemble
/// its one manifest. Rows 18--34 remain unset and are filled by the core owner.
pub const PreflightV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    transcript_prepared: transcript_source.PreparedV2,
    public_prepared: public_source.PreparedV2,
    transcript_manifest: transcript_source.ManifestV2,
    statement_manifest: statement_source.ManifestV2,
    public_manifest: public_source.ManifestV2,
    boundary_manifest: boundary_authority.OuterManifestV2,
    leaf_identity: leaf_outer.Sha256Digest,

    pub fn init(prepared: *const PreparedNativeV2LeafOuter) !PreflightV2 {
        try prepared.validate();
        const transcript_prepared = try deriveTranscriptPrepared(prepared);
        const statement_manifest = try statement_source.preflight(
            &prepared.capture.public_data.data,
            &prepared.authority_prepared.source,
            &transcript_prepared,
            prepared.transcript_program.statement_authority_id,
        );
        var native_relations = nativeRelations(prepared);
        const public_prepared = try public_source.preflight(publicInputs(
            prepared,
            &native_relations,
        ));
        const result = PreflightV2{
            .transcript_prepared = transcript_prepared,
            .public_prepared = public_prepared,
            .transcript_manifest = transcript_prepared.manifest,
            .statement_manifest = statement_manifest,
            .public_manifest = public_prepared.manifest,
            .boundary_manifest = prepared.authority_prepared.manifest,
            .leaf_identity = prepared.identity,
        };
        try result.validateAgainst(prepared);
        return result;
    }

    pub fn validateAgainst(
        self: *const PreflightV2,
        prepared: *const PreparedNativeV2LeafOuter,
    ) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.meta.eql(self.leaf_identity, prepared.identity))
        {
            return error.SourceManifestMismatch;
        }
        try self.transcript_manifest.validate();
        try self.statement_manifest.validate();
        try self.public_manifest.validate();
        try self.boundary_manifest.validate();
        try self.transcript_prepared.validateAgainst(
            &prepared.transcript_program,
            &prepared.transcript_execution,
            &prepared.transcript_evidence,
            &prepared.vm_plan,
            prepared.pcs_config,
            &prepared.capture.public_data.data,
            prepared.capture.vm_air.component_descs,
            prepared.capture.vm_air.infra_descs,
        );
        var relations = nativeRelations(prepared);
        try self.public_prepared.validateAgainst(publicInputs(
            prepared,
            &relations,
        ));
        if (!std.meta.eql(
            self.transcript_manifest,
            self.transcript_prepared.manifest,
        ) or !std.meta.eql(
            self.public_manifest,
            self.public_prepared.manifest,
        )) return error.SourceManifestMismatch;
        if (!std.meta.eql(
            self.boundary_manifest,
            prepared.authority_prepared.manifest,
        )) return error.SourceManifestMismatch;
    }

    pub fn sourceManifests(self: *const PreflightV2) SourceManifestsV2 {
        return .{
            .transcript = &self.transcript_manifest,
            .statement = &self.statement_manifest,
            .public = &self.public_manifest,
            .boundary = &self.boundary_manifest,
        };
    }

    /// Installs exactly universal rows 0--17 and 35. The caller/core retains
    /// sole authority over 18--34; rows 36/37 live in `boundary_manifest`.
    pub fn installLogSizes(
        self: *const PreflightV2,
        destination: *universal_manifest.LogSizes,
    ) !void {
        try self.transcript_manifest.validate();
        try self.statement_manifest.validate();
        try self.public_manifest.validate();
        for (self.transcript_manifest.log_sizes, 0..) |value, row|
            destination[row] = value;
        destination[10] = statement_components.ROW10_LOG_SIZE;
        destination[11] = self.statement_manifest.trace_log_size;
        for (self.public_manifest.log_sizes, 0..) |value, index|
            destination[12 + index] = value;
        destination[35] = range_bridge.LOG_SIZE;
    }

    pub fn componentLogSizes(self: *const PreflightV2) ![19]u32 {
        var result: [19]u32 = undefined;
        for (self.transcript_manifest.log_sizes, 0..) |value, row|
            result[row] = value;
        result[10] = statement_components.ROW10_LOG_SIZE;
        result[11] = self.statement_manifest.trace_log_size;
        for (self.public_manifest.log_sizes, 0..) |value, index|
            result[12 + index] = value;
        result[18] = range_bridge.LOG_SIZE;
        return result;
    }
};

pub const SourceManifestsV2 = struct {
    transcript: *const transcript_source.ManifestV2,
    statement: *const statement_source.ManifestV2,
    public: *const public_source.ManifestV2,
    boundary: *const boundary_authority.OuterManifestV2,
};

pub fn preflight(inputs: AuthorityInputs) !PreflightV2 {
    return PreflightV2.init(inputs.prepared);
}

pub const GeneratedInteractionsV2 = contract.GeneratedInteractionsV2;
pub const Components = contract.Components;
const OwnedStatementDestinations = support.OwnedStatementDestinations;
const OwnedInputProviderTraces = support.OwnedInputProviderTraces;
const SparseTree = support.SparseTree;
const deriveTranscriptPrepared = support.deriveTranscriptPrepared;
const transcriptNativeInputs = support.transcriptNativeInputs;
pub const nativeRelations = support.nativeRelations;
pub const publicInputs = support.publicInputs;
const admittedBoundaryTraces = support.admittedBoundaryTraces;
const fillRangePreprocessed = support.fillRangePreprocessed;
const fillRangeMain = support.fillRangeMain;
const copyRangeInteraction = support.copyRangeInteraction;
const copyBoundaryInteraction = support.copyBoundaryInteraction;
const compareBoundaryCommittedColumns = support.compareBoundaryCommittedColumns;
const compareInputProviderCommittedColumns = support.compareInputProviderCommittedColumns;
const initStageFailure = support.initStageFailure;
const publishSparseTree = support.publishSparseTree;
const ownerIdentity = support.ownerIdentity;
const generatedIdentity = support.generatedIdentity;
const shaWords = support.shaWords;
const traceSize = support.traceSize;
const overlap = support.overlap;
const hashInt = support.hashInt;
const componentBit = support.componentBit;
const rangeMask = support.rangeMask;

pub const Owner = struct {
    allocator: std.mem.Allocator,
    prepared_leaf: *const PreparedNativeV2LeafOuter,
    manifest: Manifest,
    native_relations: native_relations_mod.Relations,
    public_native_sum_source: *const public_native_sum.SourceV2,
    transcript_prepared: transcript_source.PreparedV2,
    statement_prepared: statement_source.PreparedV2,
    public_prepared: public_source.PreparedV2,
    statement_destinations: OwnedStatementDestinations,
    transcript_owner: transcript_components.Source,
    transcript_workspace: transcript_components.Workspace,
    statement_owner: statement_components.AuthorityV2,
    statement_workspace: statement_components.WorkspaceV2,
    public_owner: public_components.Source,
    public_workspace: public_components.Workspace,
    range_owner: range_authority.ProviderAuthorityV2,
    range_workspace: range_authority.WorkspaceV2,
    range_prepared: range_authority.PreparedV2,
    boundary_owner: boundary_authority.AuthorityV2,
    boundary_workspace: boundary_authority.WorkspaceV2,
    boundary_active_traces: leaf_outer.OwnedAuthorityTracesV2,
    boundary_staging_traces: leaf_outer.OwnedAuthorityTracesV2,
    boundary_active_prepared: ?boundary_authority.PreparedNativeVerifierOuterAuthorityV2,
    input_provider_owner: input_provider_authority.AuthorityV2,
    input_provider_workspace: input_provider_authority.WorkspaceV2,
    input_provider_active_traces: OwnedInputProviderTraces,
    input_provider_staging_traces: OwnedInputProviderTraces,
    input_provider_active_prepared: ?input_provider_authority.PreparedAuthorityV2,
    range_interaction: ?range_authority.ProviderInteractionV2,
    tree0: SparseTree,
    tree1: SparseTree,
    tree2: SparseTree,
    generation: u64 = 0,
    active_generated: ?GeneratedInteractionsV2 = null,
    identity: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        prepared: *const PreparedNativeV2LeafOuter,
        manifest: *const Manifest,
        public_native_sum_source: *const public_native_sum.SourceV2,
    ) !Owner {
        const source_preflight = PreflightV2.init(prepared) catch |err|
            return initStageFailure("preflight", err);
        return runtime.initOwner(
            Owner,
            allocator,
            source_preflight,
            prepared,
            manifest,
            public_native_sum_source,
        );
    }

    pub fn initInPlace(
        self: *Owner,
        allocator: std.mem.Allocator,
        prepared: *const PreparedNativeV2LeafOuter,
        manifest: *const Manifest,
        public_native_sum_source: *const public_native_sum.SourceV2,
    ) !void {
        if (overlap(std.mem.asBytes(self), std.mem.asBytes(prepared)) or
            overlap(std.mem.asBytes(self), std.mem.asBytes(manifest)) or
            overlap(std.mem.asBytes(self), std.mem.asBytes(public_native_sum_source)))
        {
            return error.AliasedDestination;
        }
        self.* = try Owner.init(
            allocator,
            prepared,
            manifest,
            public_native_sum_source,
        );
    }

    pub fn deinit(self: *Owner) void {
        if (self.range_interaction) |*interaction| interaction.deinit();
        self.tree2.deinit();
        self.tree1.deinit();
        self.tree0.deinit();
        self.input_provider_staging_traces.deinit();
        self.input_provider_active_traces.deinit();
        self.input_provider_workspace.deinit();
        self.input_provider_owner.deinit();
        self.boundary_staging_traces.deinit();
        self.boundary_active_traces.deinit();
        self.boundary_workspace.deinit();
        self.boundary_owner.deinit();
        self.range_owner.deinit();
        self.range_prepared.deinit();
        self.range_workspace.deinit(self.allocator);
        self.public_workspace.deinit();
        self.public_owner.deinit();
        self.statement_workspace.deinit();
        self.transcript_workspace.deinit();
        self.transcript_owner.deinit();
        self.statement_destinations.deinit();
        self.statement_owner.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Owner) !void {
        try self.prepared_leaf.validate();
        try self.manifest.validateAgainstSources(
            &self.transcript_prepared.manifest,
            &self.statement_prepared.manifest,
            &self.public_prepared.manifest,
            &self.prepared_leaf.authority_prepared.manifest,
        );
        try self.transcript_prepared.validateAgainst(
            &self.prepared_leaf.transcript_program,
            &self.prepared_leaf.transcript_execution,
            &self.prepared_leaf.transcript_evidence,
            &self.prepared_leaf.vm_plan,
            self.prepared_leaf.pcs_config,
            &self.prepared_leaf.capture.public_data.data,
            self.prepared_leaf.capture.vm_air.component_descs,
            self.prepared_leaf.capture.vm_air.infra_descs,
        );
        try self.statement_prepared.validate();
        try self.public_prepared.validateAgainst(publicInputs(
            self.prepared_leaf,
            &self.native_relations,
        ));
        try self.transcript_owner.validateAgainst(
            &self.transcript_prepared,
            &self.manifest,
        );
        try self.transcript_workspace.validateAgainst(&self.transcript_prepared);
        try self.statement_owner.validateAgainst(
            &self.statement_prepared,
            &self.manifest,
        );
        try self.statement_workspace.validateAgainst(&self.statement_prepared);
        try self.public_owner.validateAgainst(&self.public_prepared, &self.manifest);
        try self.public_workspace.validateBoundAgainst(
            &self.public_prepared,
            self.public_native_sum_source,
        );
        try self.range_owner.validate();
        _ = try self.range_prepared.publication();
        const request_count = try self.rangeSources().validate();
        if (request_count != self.range_prepared.request_count)
            return error.InvalidOwner;
        try self.boundary_owner.validate();
        try self.input_provider_owner.validate();
        try self.input_provider_workspace.validate();
        try self.tree0.validate(&self.manifest);
        try self.tree1.validate(&self.manifest);
        try self.tree2.validate(&self.manifest);
        if (!std.mem.eql(u8, &self.identity, &ownerIdentity(self)))
            return error.InvalidOwner;
        if ((self.generation == 0) != (self.active_generated == null) or
            (self.generation == 0) != (self.range_interaction == null) or
            (self.generation == 0) != (self.boundary_active_prepared == null) or
            (self.generation == 0) !=
                (self.input_provider_active_prepared == null))
        {
            return error.InvalidOwner;
        }
        if (self.active_generated) |generated| try generated.validate();
    }

    pub fn sourceManifests(self: *const Owner) SourceManifestsV2 {
        return .{
            .transcript = &self.transcript_prepared.manifest,
            .statement = &self.statement_prepared.manifest,
            .public = &self.public_prepared.manifest,
            .boundary = &self.prepared_leaf.authority_prepared.manifest,
        };
    }

    pub fn authorityIdentity(self: *const Owner) ![32]u8 {
        try self.validate();
        return self.identity;
    }

    pub fn mixAuthority(self: *const Owner, channel: anytype) !void {
        try self.validate();
        channel.mixU32s(&.{
            AUTHORITY_TRANSCRIPT_DOMAIN,
            FORMAT_VERSION,
            @as(u32, @intCast(OWNED_ROW_COUNT)),
        });
        channel.mixU32s(&shaWords(self.identity));
    }

    pub fn fillPreprocessedInto(
        self: *Owner,
        manifest: *const Manifest,
        destination: []const []M31,
    ) !void {
        try self.validateManifest(manifest);
        try publishSparseTree(&self.tree0, manifest, destination);
    }

    pub fn fillMainInto(
        self: *Owner,
        manifest: *const Manifest,
        destination: []const []M31,
    ) !void {
        try self.validateManifest(manifest);
        try publishSparseTree(&self.tree1, manifest, destination);
    }

    /// Generates all 21 non-core interaction rows in private storage. The
    /// prior active generation remains valid on every failure.
    pub fn prepareInteractions(
        self: *Owner,
        audit_allocator: std.mem.Allocator,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !GeneratedInteractionsV2 {
        return runtime.prepareInteractions(
            self,
            audit_allocator,
            relations,
            provider_relations,
        );
    }

    pub fn rebuildGeneratedInteractions(
        self: *Owner,
        audit_allocator: std.mem.Allocator,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !GeneratedInteractionsV2 {
        return self.prepareInteractions(
            audit_allocator,
            relations,
            provider_relations,
        );
    }

    /// Allocation-free publication of the most recently rebuilt Tree 2.
    pub fn fillInteractionInto(
        self: *Owner,
        manifest: *const Manifest,
        destination: []const []M31,
    ) !GeneratedInteractionsV2 {
        try self.validateManifest(manifest);
        const generated = self.active_generated orelse
            return error.InteractionsNotPrepared;
        try generated.validate();
        try publishSparseTree(&self.tree2, manifest, destination);
        return generated;
    }

    pub fn validateGenerated(
        self: *const Owner,
        generated: *const GeneratedInteractionsV2,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        return generated.validateCachedAgainst(self, relations, provider_relations);
    }

    /// Cold, challenge-independent projection of every exact red-domain tuple
    /// owned by rows 0--17 and 36--37. Row 35 is intentionally absent because
    /// its authenticated range provider cannot contribute to `domain_mask`.
    /// The boundary rows are taken from the most recently successful rebuild;
    /// no detached public-boundary tuple is accepted here.
    pub fn appendTupleContributions(
        self: *const Owner,
        ledger: *relation_interaction.TupleLedger,
        domain_mask: u64,
    ) !void {
        return runtime.appendTupleContributions(self, ledger, domain_mask);
    }

    pub fn initComponents(
        self: *const Owner,
        manifest: *const Manifest,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
        generated: *const GeneratedInteractionsV2,
    ) !Components {
        try self.validateManifest(manifest);
        try generated.validateCachedAgainst(self, relations, provider_relations);
        const range_interaction = if (self.range_interaction) |*value| value else return error.InteractionsNotPrepared;
        const boundary_prepared = if (self.boundary_active_prepared) |*value| value else return error.InteractionsNotPrepared;
        const input_provider_prepared = if (self.input_provider_active_prepared) |*value| value else return error.InteractionsNotPrepared;
        return .{
            .transcript = try self.transcript_owner.initComponents(
                &self.transcript_prepared,
                manifest,
                relations,
                generated.transcript,
            ),
            .statement = try self.statement_owner.initComponents(
                &self.statement_prepared,
                manifest,
                relations,
                generated.statement,
            ),
            .public = try self.public_owner.initComponents(
                &self.public_prepared,
                manifest,
                relations,
                generated.public,
            ),
            .range = try range_interaction.component(
                &self.range_owner,
                manifest,
                provider_relations,
                relations,
            ),
            .boundary = try boundary_components.Components.init(
                &self.boundary_owner,
                boundary_prepared,
                relations,
                manifest,
            ),
            .verifier_input_provider = try input_provider_component.initForManifest(
                manifest_mod,
                .segment_publication_input_provider_v2,
                &self.input_provider_owner,
                input_provider_prepared,
                relations,
                manifest,
            ),
        };
    }

    pub fn materializeCommittedTrees(self: *Owner) !void {
        transcript_components.fillPreprocessedInto(
            &self.transcript_owner,
            &self.transcript_workspace,
            &self.transcript_prepared,
            &self.manifest,
            self.tree0.columns,
        ) catch |err| return initStageFailure("tree0_transcript", err);
        statement_components.fillPreprocessedInto(
            &self.statement_owner,
            &self.statement_prepared,
            self.statement_destinations.logical_rows,
            &self.manifest,
            self.tree0.columns,
        ) catch |err| return initStageFailure("tree0_statement", err);
        public_components.fillPreprocessedInto(
            &self.public_owner,
            &self.public_workspace,
            &self.public_prepared,
            &self.manifest,
            self.tree0.columns,
        ) catch |err| return initStageFailure("tree0_public", err);
        fillRangePreprocessed(self) catch |err|
            return initStageFailure("tree0_range", err);
        boundary_components.fillTreeInto(
            &self.manifest,
            admittedBoundaryTraces(self.prepared_leaf),
            manifest_mod.PREPROCESSED_TREE_INDEX,
            self.tree0.columns,
        ) catch |err| return initStageFailure("tree0_boundary", err);
        input_provider_component.fillTreeInto(
            manifest_mod,
            .segment_publication_input_provider_v2,
            &self.manifest,
            self.input_provider_active_traces.view(),
            manifest_mod.PREPROCESSED_TREE_INDEX,
            self.tree0.columns,
        ) catch |err| return initStageFailure("tree0_input_provider", err);

        transcript_components.fillMainInto(
            &self.transcript_owner,
            &self.transcript_workspace,
            &self.transcript_prepared,
            &self.manifest,
            self.tree1.columns,
        ) catch |err| return initStageFailure("tree1_transcript", err);
        statement_components.fillMainInto(
            &self.statement_owner,
            &self.statement_prepared,
            self.statement_destinations.logical_rows,
            &self.manifest,
            self.tree1.columns,
        ) catch |err| return initStageFailure("tree1_statement", err);
        public_components.fillMainInto(
            &self.public_owner,
            &self.public_workspace,
            &self.public_prepared,
            &self.manifest,
            self.tree1.columns,
        ) catch |err| return initStageFailure("tree1_public", err);
        fillRangeMain(self) catch |err|
            return initStageFailure("tree1_range", err);
        boundary_components.fillTreeInto(
            &self.manifest,
            admittedBoundaryTraces(self.prepared_leaf),
            manifest_mod.MAIN_TREE_INDEX,
            self.tree1.columns,
        ) catch |err| return initStageFailure("tree1_boundary", err);
        input_provider_component.fillTreeInto(
            manifest_mod,
            .segment_publication_input_provider_v2,
            &self.manifest,
            self.input_provider_active_traces.view(),
            manifest_mod.MAIN_TREE_INDEX,
            self.tree1.columns,
        ) catch |err| return initStageFailure("tree1_input_provider", err);
    }

    fn validateManifest(self: *const Owner, manifest: *const Manifest) !void {
        try manifest.validate();
        if (!std.meta.eql(self.manifest, manifest.*))
            return error.ManifestMismatch;
    }

    fn rangeSources(self: *const Owner) range_authority.SourcesV2 {
        return .{
            .statement = &self.statement_prepared,
            .logical_rows = self.statement_destinations.logical_rows,
        };
    }

    pub fn auditInputs(
        self: *const Owner,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
        transcript_claims: transcript_components.Claims,
        statement_claims: statement_components.ClaimsV2,
        public_claims: public_components.Claims,
        range_interaction_value: *const range_authority.ProviderInteractionV2,
        boundary_prepared: *const boundary_authority.PreparedNativeVerifierOuterAuthorityV2,
        input_provider_prepared: *const input_provider_authority.PreparedAuthorityV2,
    ) noncore_audits.InputsV2 {
        return .{
            .manifest = &self.manifest,
            .relations = relations,
            .transcript = .{
                .owner = &self.transcript_owner,
                .workspace = &self.transcript_workspace,
                .prepared = &self.transcript_prepared,
                .claims = transcript_claims,
            },
            .statement = .{
                .authority = &self.statement_owner,
                .prepared = &self.statement_prepared,
                .logical_rows = self.statement_destinations.logical_rows,
                .claims = statement_claims,
            },
            .public = .{
                .owner = &self.public_owner,
                .workspace = &self.public_workspace,
                .prepared = &self.public_prepared,
                .claims = public_claims,
            },
            .range = .{
                .authority = &self.range_owner,
                .prepared = &self.range_prepared,
                .sources = self.rangeSources(),
                .provider_relations = provider_relations,
                .interaction = range_interaction_value,
            },
            .boundary = .{
                .authority = &self.boundary_owner,
                .prepared = boundary_prepared,
            },
            .verifier_input_provider = .{
                .authority = &self.input_provider_owner,
                .prepared = input_provider_prepared,
                .vm_context = &self.prepared_leaf.capture.vm_air,
            },
        };
    }

    pub fn activeAuditInputs(
        self: *const Owner,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
        generated: *const GeneratedInteractionsV2,
    ) !noncore_audits.InputsV2 {
        const range_interaction_value = if (self.range_interaction) |*value| value else return error.InteractionsNotPrepared;
        const boundary_prepared = if (self.boundary_active_prepared) |*value| value else return error.InteractionsNotPrepared;
        const input_provider_prepared = if (self.input_provider_active_prepared) |*value| value else return error.InteractionsNotPrepared;
        return self.auditInputs(
            relations,
            provider_relations,
            generated.transcript,
            generated.statement,
            generated.public,
            range_interaction_value,
            boundary_prepared,
            input_provider_prepared,
        );
    }

    /// Diagnostic-only fingerprint of the cached interaction columns. It is
    /// not mixed into the protocol and performs no allocation.
    pub fn interactionTreeIdentity(self: *const Owner) ![32]u8 {
        const generated = self.active_generated orelse
            return error.InteractionsNotPrepared;
        try generated.validate();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/typed-air/segment-v2-noncore-tree2/v1\x00");
        hashInt(&hash, u64, self.generation);
        for (self.tree2.storage) |word| hashInt(&hash, u32, word.toU32());
        return hash.finalResult();
    }
};

comptime {
    if (COMPONENT_COUNT != 39 or UNIVERSAL_COMPONENT_COUNT != 36 or
        OWNED_ROW_COUNT != 22 or OWNED_ROW_MASK != noncore_audits.NONCORE_ROW_MASK or
        RETAINS_SELF_POINTERS or !BOUNDARY_REBUILT_PER_RELATION_DRAW or
        !BOUNDARY_TREE_0_1_BYTE_EQUALITY_REQUIRED or
        transcript_components.FIRST_ROW != 0 or
        statement_components.FIRST_ROW != 10 or
        public_components.FIRST_ROW != 12 or
        range_bridge.LOG_SIZE != 16)
    {
        @compileError("SegmentV2 non-core owner contract drifted");
    }
}
