const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const leaf_outer = @import("recursive_segment_v2_leaf_outer.zig");
const contract = @import("recursive_segment_v2_noncore_contract.zig");
const support = @import("recursive_segment_v2_noncore_support.zig");

const M31 = stwo_core.fields.m31.M31;
const recursion = frontend.recursion;
const manifest_mod = recursion.air.segment_outer_adapter_manifest_v2;
const transcript_components = recursion.segment_transcript_outer_components_v2;
const statement_components = recursion.segment_statement_outer_components_v2;
const statement_source = recursion.segment_statement_outer_source_v2;
const public_source = recursion.segment_public_outer_source_v2;
const public_components = recursion.segment_public_outer_components_v2;
const public_native_sum = recursion.segment_public_native_sum_authority_v2;
const range_authority = recursion.segment_range_authority_v2;
const boundary_authority = recursion.segment_leaf_outer_authority_v2;
const input_provider_authority = recursion.segment_publication_input_provider_authority_v2;
const input_provider_component = recursion.air.segment_publication_input_provider_component_v2;
const shared_provider = recursion.air.universal_shared_provider;
const universal = recursion.air.universal_challenges;
const relation_interaction = recursion.air.relation_interaction;
const noncore_audits = recursion.segment_outer_noncore_audits_v2;
const PreparedNativeV2LeafOuter = leaf_outer.PreparedNativeV2LeafOuter;
const Manifest = manifest_mod.Manifest;
const GeneratedInteractionsV2 = contract.GeneratedInteractionsV2;
const OwnedStatementDestinations = support.OwnedStatementDestinations;
const OwnedInputProviderTraces = support.OwnedInputProviderTraces;
const SparseTree = support.SparseTree;
const initStageFailure = support.initStageFailure;
const deriveTranscriptPrepared = support.deriveTranscriptPrepared;
const nativeRelations = support.nativeRelations;
const publicInputs = support.publicInputs;
const transcriptNativeInputs = support.transcriptNativeInputs;
const ownerIdentity = support.ownerIdentity;
const copyRangeInteraction = support.copyRangeInteraction;
const compareBoundaryCommittedColumns = support.compareBoundaryCommittedColumns;
const copyBoundaryInteraction = support.copyBoundaryInteraction;
const compareInputProviderCommittedColumns = support.compareInputProviderCommittedColumns;
const generatedIdentity = support.generatedIdentity;

pub fn initOwner(
    comptime OwnerType: type,
    allocator: std.mem.Allocator,
    source_preflight: anytype,
    prepared: *const PreparedNativeV2LeafOuter,
    manifest: *const Manifest,
    public_native_sum_source: *const public_native_sum.SourceV2,
) !OwnerType {
    prepared.validate() catch |err|
        return initStageFailure("prepared_validate", err);
    manifest.validateAgainstSources(
        &source_preflight.transcript_manifest,
        &source_preflight.statement_manifest,
        &source_preflight.public_manifest,
        &source_preflight.boundary_manifest,
    ) catch |err| return initStageFailure("manifest_sources", err);
    const transcript_prepared = deriveTranscriptPrepared(prepared) catch |err|
        return initStageFailure("transcript_preflight", err);
    var native_relations = nativeRelations(prepared);
    const public_prepared = public_source.preflight(publicInputs(
        prepared,
        &native_relations,
    )) catch |err| return initStageFailure("public_preflight", err);

    var statement_owner = statement_components.AuthorityV2.init(allocator) catch |err|
        return initStageFailure("statement_owner", err);
    errdefer statement_owner.deinit();
    var statement_destinations = OwnedStatementDestinations.init(
        allocator,
        source_preflight.statement_manifest,
    ) catch |err| return initStageFailure("statement_destinations", err);
    errdefer statement_destinations.deinit();
    var statement_prepared: statement_source.PreparedV2 = undefined;
    var statement_source_workspace = statement_source.WorkspaceV2{};
    statement_source.prepareInto(
        &statement_prepared,
        &statement_source_workspace,
        statement_owner.statementAuthority(),
        statement_destinations.destinations(),
        &prepared.capture.public_data.data,
        &prepared.authority_prepared.source,
        &transcript_prepared,
        prepared.transcript_program.statement_authority_id,
    ) catch |err| return initStageFailure("statement_prepare", err);
    if (!std.meta.eql(
        statement_prepared.manifest,
        source_preflight.statement_manifest,
    )) return error.SourceManifestMismatch;

    var transcript_owner = transcript_components.Source.init(
        allocator,
        &transcript_prepared,
        manifest,
    ) catch |err| return initStageFailure("transcript_owner", err);
    errdefer transcript_owner.deinit();
    var transcript_workspace = transcript_components.Workspace.init(
        allocator,
        &transcript_prepared,
    ) catch |err| return initStageFailure("transcript_workspace_init", err);
    errdefer transcript_workspace.deinit();
    transcript_workspace.prepare(
        &transcript_owner,
        &transcript_prepared,
        manifest,
        transcriptNativeInputs(prepared),
    ) catch |err| return initStageFailure("transcript_workspace", err);

    var statement_workspace = statement_components.WorkspaceV2.init(
        allocator,
        &statement_prepared,
    ) catch |err| return initStageFailure("statement_workspace", err);
    errdefer statement_workspace.deinit();
    var public_owner = public_components.Source.init(
        allocator,
        &public_prepared,
        manifest,
    ) catch |err| return initStageFailure("public_owner", err);
    errdefer public_owner.deinit();
    var public_workspace = public_components.Workspace.initBound(
        allocator,
        &public_prepared,
        public_native_sum_source,
    ) catch |err| return initStageFailure("public_workspace_init", err);
    errdefer public_workspace.deinit();
    public_workspace.prepareBound(
        &public_owner,
        &public_prepared,
        manifest,
        publicInputs(prepared, &native_relations),
        public_native_sum_source,
    ) catch |err| return initStageFailure("public_workspace", err);

    var range_workspace = range_authority.WorkspaceV2.init(allocator) catch |err|
        return initStageFailure("range_workspace", err);
    errdefer range_workspace.deinit(allocator);
    const sources = range_authority.SourcesV2{
        .statement = &statement_prepared,
        .logical_rows = statement_destinations.logical_rows,
    };
    var range_prepared = range_authority.PreparedV2.init(
        allocator,
        &range_workspace,
        sources,
    ) catch |err| return initStageFailure("range_prepare", err);
    errdefer range_prepared.deinit();
    var range_owner = range_authority.ProviderAuthorityV2.init(allocator) catch |err|
        return initStageFailure("range_owner", err);
    errdefer range_owner.deinit();

    var boundary_owner = boundary_authority.AuthorityV2.init(allocator) catch |err|
        return initStageFailure("boundary_owner", err);
    errdefer boundary_owner.deinit();
    var boundary_workspace = boundary_authority.WorkspaceV2.init(
        allocator,
        &source_preflight.boundary_manifest,
    ) catch |err| return initStageFailure("boundary_workspace", err);
    errdefer boundary_workspace.deinit();
    var boundary_active_traces = leaf_outer.OwnedAuthorityTracesV2.init(
        allocator,
        &source_preflight.boundary_manifest,
    ) catch |err| return initStageFailure("boundary_active_traces", err);
    errdefer boundary_active_traces.deinit();
    var boundary_staging_traces = leaf_outer.OwnedAuthorityTracesV2.init(
        allocator,
        &source_preflight.boundary_manifest,
    ) catch |err| return initStageFailure("boundary_staging_traces", err);
    errdefer boundary_staging_traces.deinit();

    var input_provider_owner =
        input_provider_authority.AuthorityV2.init(allocator) catch |err|
            return initStageFailure("input_provider_owner", err);
    errdefer input_provider_owner.deinit();
    var input_provider_workspace =
        input_provider_authority.WorkspaceV2.init(allocator) catch |err|
            return initStageFailure("input_provider_workspace", err);
    errdefer input_provider_workspace.deinit();
    var input_provider_active_traces =
        OwnedInputProviderTraces.init(allocator) catch |err|
            return initStageFailure("input_provider_active_traces", err);
    errdefer input_provider_active_traces.deinit();
    var input_provider_staging_traces =
        OwnedInputProviderTraces.init(allocator) catch |err|
            return initStageFailure("input_provider_staging_traces", err);
    errdefer input_provider_staging_traces.deinit();
    var initial_provider_prepared: input_provider_authority.PreparedAuthorityV2 = undefined;
    input_provider_authority.prepareInto(
        &initial_provider_prepared,
        &input_provider_workspace,
        &input_provider_owner,
        input_provider_active_traces.view(),
        .{
            .capture = &prepared.authority_prepared,
            .vm_context = &prepared.capture.vm_air,
        },
        &prepared.outer_relations,
    ) catch |err| return initStageFailure("input_provider_prepare", err);

    var tree0 = SparseTree.init(
        allocator,
        manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
    ) catch |err| return initStageFailure("tree0_init", err);
    errdefer tree0.deinit();
    var tree1 = SparseTree.init(
        allocator,
        manifest,
        manifest_mod.MAIN_TREE_INDEX,
    ) catch |err| return initStageFailure("tree1_init", err);
    errdefer tree1.deinit();
    var tree2 = SparseTree.init(
        allocator,
        manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
    ) catch |err| return initStageFailure("tree2_init", err);
    errdefer tree2.deinit();

    var result = OwnerType{
        .allocator = allocator,
        .prepared_leaf = prepared,
        .manifest = manifest.*,
        .native_relations = native_relations,
        .public_native_sum_source = public_native_sum_source,
        .transcript_prepared = transcript_prepared,
        .statement_prepared = statement_prepared,
        .public_prepared = public_prepared,
        .statement_destinations = statement_destinations,
        .transcript_owner = transcript_owner,
        .transcript_workspace = transcript_workspace,
        .statement_owner = statement_owner,
        .statement_workspace = statement_workspace,
        .public_owner = public_owner,
        .public_workspace = public_workspace,
        .range_owner = range_owner,
        .range_workspace = range_workspace,
        .range_prepared = range_prepared,
        .boundary_owner = boundary_owner,
        .boundary_workspace = boundary_workspace,
        .boundary_active_traces = boundary_active_traces,
        .boundary_staging_traces = boundary_staging_traces,
        .boundary_active_prepared = null,
        .input_provider_owner = input_provider_owner,
        .input_provider_workspace = input_provider_workspace,
        .input_provider_active_traces = input_provider_active_traces,
        .input_provider_staging_traces = input_provider_staging_traces,
        .input_provider_active_prepared = null,
        .range_interaction = null,
        .tree0 = tree0,
        .tree1 = tree1,
        .tree2 = tree2,
        .identity = undefined,
    };
    result.identity = ownerIdentity(&result);
    result.materializeCommittedTrees() catch |err|
        return initStageFailure("committed_trees", err);
    result.validate() catch |err|
        return initStageFailure("result_validate", err);
    return result;
}

pub fn prepareInteractions(
    self: anytype,
    audit_allocator: std.mem.Allocator,
    relations: *const universal.UniversalRelations,
    provider_relations: *const shared_provider.SharedProviderRelations,
) !GeneratedInteractionsV2 {
    // A proof transaction draws one immutable challenge context. Prover
    // and verifier each own a fresh cohort, so a repeated call is either
    // an idempotent request for that same context or a protocol error.
    // This check occurs before touching Tree 2 or any interaction scratch,
    // preserving the prior cache on a mismatched second call.
    if (self.active_generated) |*active| {
        try active.validateAgainst(self, relations, provider_relations);
        return active.*;
    }
    try self.validate();
    try provider_relations.validateAgainst(relations);
    const next_generation = std.math.add(u64, self.generation, 1) catch
        return error.ArithmeticOverflow;
    self.tree2.clear();

    const transcript_claims = try transcript_components.fillInteractionInto(
        &self.transcript_owner,
        &self.transcript_workspace,
        &self.transcript_prepared,
        &self.manifest,
        relations,
        self.tree2.columns,
    );
    const statement_claims = try statement_components.fillInteractionInto(
        &self.statement_owner,
        &self.statement_workspace,
        &self.statement_prepared,
        self.statement_destinations.logical_rows,
        &self.manifest,
        relations,
        self.tree2.columns,
    );
    const public_claims = try public_components.fillInteractionInto(
        &self.public_owner,
        &self.public_workspace,
        &self.public_prepared,
        &self.manifest,
        relations,
        self.tree2.columns,
    );

    var new_range = try self.range_prepared.generateProviderInteraction(
        self.allocator,
        provider_relations,
    );
    errdefer new_range.deinit();
    copyRangeInteraction(&self.tree2, &self.manifest, &new_range);

    @memset(self.boundary_staging_traces.storage, M31.zero());
    var rebuilt_boundary: boundary_authority.PreparedNativeVerifierOuterAuthorityV2 =
        undefined;
    try boundary_authority.prepareNativeVerifierInto(
        &rebuilt_boundary,
        &self.boundary_workspace,
        &self.boundary_owner,
        self.boundary_staging_traces.view(),
        &self.prepared_leaf.capture.public_data.data,
        &self.prepared_leaf.verifier_keys,
        &self.native_relations,
        &self.prepared_leaf.capture.native_public_sums,
        &self.prepared_leaf.capture.receipt,
        self.prepared_leaf.capture.vm_air.component_descs,
        self.prepared_leaf.capture.vm_air.infra_descs,
        relations,
    );
    try compareBoundaryCommittedColumns(
        &self.boundary_staging_traces,
        &self.prepared_leaf.authority_traces,
    );
    // `committed_trace_sha_id` intentionally covers Tree 2 as well as the
    // committed Tree 0/1 columns, so it is relation-bound and must change
    // under this fresh outer challenge context. Exact byte equality of
    // every Tree 0/1 boundary column above is the stable custody check;
    // `prepareNativeVerifierInto` separately authenticates the rebuilt
    // full-trace digest against its new relation-bound receipt.
    copyBoundaryInteraction(
        &self.tree2,
        &self.manifest,
        &self.boundary_staging_traces,
    );

    @memset(self.input_provider_staging_traces.storage, M31.zero());
    var rebuilt_input_provider: input_provider_authority.PreparedAuthorityV2 = undefined;
    try input_provider_authority.prepareInto(
        &rebuilt_input_provider,
        &self.input_provider_workspace,
        &self.input_provider_owner,
        self.input_provider_staging_traces.view(),
        .{
            .capture = &rebuilt_boundary,
            .vm_context = &self.prepared_leaf.capture.vm_air,
        },
        relations,
    );
    try compareInputProviderCommittedColumns(
        &self.input_provider_staging_traces,
        &self.input_provider_active_traces,
    );
    try input_provider_component.fillTreeInto(
        manifest_mod,
        .segment_publication_input_provider_v2,
        &self.manifest,
        self.input_provider_staging_traces.view(),
        manifest_mod.INTERACTION_TREE_INDEX,
        self.tree2.columns,
    );

    const audit_inputs = self.auditInputs(
        relations,
        provider_relations,
        transcript_claims,
        statement_claims,
        public_claims,
        &new_range,
        &rebuilt_boundary,
        &rebuilt_input_provider,
    );
    const audits = try noncore_audits.rebuild(audit_allocator, audit_inputs);
    var generated = GeneratedInteractionsV2{
        .generation = next_generation,
        .owner_identity = self.identity,
        .transcript = transcript_claims,
        .statement = statement_claims,
        .public = public_claims,
        .range = new_range.claim(),
        .boundary = .{
            rebuilt_boundary.statement_claim,
            rebuilt_boundary.public_logup_claim,
        },
        .verifier_input_provider = rebuilt_input_provider.claimed_sum,
        .audits = audits,
        .identity = undefined,
    };
    generated.identity = generatedIdentity(&generated);
    try generated.validate();

    if (self.range_interaction) |*old| old.deinit();
    self.range_interaction = new_range;
    std.mem.swap(
        leaf_outer.OwnedAuthorityTracesV2,
        &self.boundary_active_traces,
        &self.boundary_staging_traces,
    );
    std.mem.swap(
        OwnedInputProviderTraces,
        &self.input_provider_active_traces,
        &self.input_provider_staging_traces,
    );
    self.boundary_active_prepared = rebuilt_boundary;
    self.input_provider_active_prepared = rebuilt_input_provider;
    self.generation = next_generation;
    self.active_generated = generated;
    return generated;
}

pub fn appendTupleContributions(
    self: anytype,
    ledger: *relation_interaction.TupleLedger,
    domain_mask: u64,
) !void {
    try self.validate();
    const boundary_prepared = if (self.boundary_active_prepared) |*value|
        value
    else
        return error.InteractionsNotPrepared;
    try boundary_prepared.validate();

    try self.transcript_owner.owners.control.relation
        .appendPreparedTupleContributions(
        ledger,
        0,
        self.transcript_workspace.control_rows,
        domain_mask,
    );
    try self.transcript_owner.owners.transcript_air.relation
        .appendPreparedTupleContributions(
        ledger,
        1,
        self.transcript_workspace.transcript_air_rows,
        domain_mask,
    );
    try self.transcript_owner.owners.transcript_binding.relation
        .appendPreparedTupleContributions(
        ledger,
        2,
        self.transcript_workspace.transcript_binding_rows,
        domain_mask,
    );
    try self.transcript_owner.owners.transcript_state.relation
        .appendPreparedTupleContributions(
        ledger,
        3,
        self.transcript_workspace.transcript_state_rows,
        domain_mask,
    );
    try self.transcript_owner.owners.transcript_word.relation
        .appendPreparedTupleContributions(
        ledger,
        4,
        self.transcript_workspace.transcript_word_rows,
        domain_mask,
    );
    try self.transcript_owner.owners.transcript_payload.relation
        .appendPreparedTupleContributions(
        ledger,
        5,
        self.transcript_workspace.transcript_payload_rows,
        domain_mask,
    );
    try self.transcript_owner.owners.pow_check.relation
        .appendPreparedTupleContributions(
        ledger,
        6,
        self.transcript_workspace.pow_check_rows,
        domain_mask,
    );
    try self.transcript_owner.owners.pow_frame.relation
        .appendPreparedTupleContributions(
        ledger,
        7,
        self.transcript_workspace.pow_frame_rows,
        domain_mask,
    );
    try self.transcript_owner.owners.relation_challenge.relation
        .appendPreparedTupleContributions(
        ledger,
        8,
        self.transcript_workspace.relation_challenge_rows,
        domain_mask,
    );
    try self.transcript_owner.owners.verifier_randomness.relation
        .appendPreparedTupleContributions(
        ledger,
        9,
        self.transcript_workspace.verifier_randomness_rows,
        domain_mask,
    );
    try statement_components.appendTupleContributions(
        &self.statement_owner,
        &self.statement_prepared,
        self.statement_destinations.logical_rows,
        &self.manifest,
        ledger,
        domain_mask,
    );
    try self.public_owner.owners.publication_header.relation
        .appendPreparedTupleContributions(
        ledger,
        12,
        self.public_workspace.logical_rows[0],
        domain_mask,
    );
    try self.public_owner.owners.native_public_sums.relation
        .appendPreparedTupleContributions(
        ledger,
        13,
        self.public_workspace.claim_hash_logical_rows,
        domain_mask,
    );
    try self.public_owner.owners.publication_seal.relation
        .appendPreparedTupleContributions(
        ledger,
        14,
        self.public_workspace.logical_rows[2],
        domain_mask,
    );
    try self.public_owner.owners.boundary_bridge.relation
        .appendPreparedTupleContributions(
        ledger,
        15,
        self.public_workspace.logical_rows[3],
        domain_mask,
    );
    try self.public_owner.owners.native_challenges.relation
        .appendPreparedTupleContributions(
        ledger,
        16,
        self.public_workspace.logical_rows[4],
        domain_mask,
    );
    try self.public_owner.owners.control_relay.relation
        .appendPreparedTupleContributions(
        ledger,
        17,
        self.public_workspace.controlActiveRows(),
        domain_mask,
    );
    try self.boundary_owner.statement_plan.appendPreparedTupleContributions(
        ledger,
        36,
        self.boundary_workspace.statement_rows,
        domain_mask,
    );
    try self.boundary_owner.public_logup_plan
        .appendPreparedTupleContributions(
        ledger,
        37,
        &self.boundary_workspace.public_logup_rows,
        domain_mask,
    );
    try self.input_provider_owner.relation_plan
        .appendPreparedTupleContributions(
        ledger,
        38,
        &self.input_provider_workspace.logical_rows,
        domain_mask,
    );
}
