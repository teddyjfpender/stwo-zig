//! Owned rows-0--17 prefix for a genuine height-2 temporal root.
//!
//! The generic typed writers are reused unchanged.  This module only adapts
//! two verifier-minted temporal-parent children into their exact transcript,
//! folded statement, inactive-row, range, and commitment-layout authorities.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const stwo_core = @import("stwo_core");

const level2 = @import("recursive_temporal_parent_pair_authority_v1.zig");
const temporal_manifest = @import("recursive_temporal_parent_manifest_v3.zig");
const prefix_runtime = @import("recursive_temporal_parent_prefix_runtime.zig");
const prefix_support = @import("recursive_temporal_parent_prefix_support.zig");
const nonfri = @import("recursive_temporal_nonfri_source_v2.zig");
const transcript_v1 = @import("recursive_temporal_level2_transcript_v1.zig");
const recursion = frontend.recursion;
const inactive = recursion.binary_inactive_outer_source;
const leaf_authority = recursion.segment_leaf_authority;
const public_source_mod = recursion.segment_public_outer_source;
const range_owner = recursion.outer_parent_range_authority;
const schedule = recursion.air.verifier_schedule;
const statement_air = recursion.outer_parent_statement_air_source;
const statement_source = recursion.segment_statement_outer_source;
const span_statement = recursion.span_statement;
const vm_claim = recursion.vm_public_claim;

pub const ChildV1 = transcript_v1.ChildV1;

pub fn init(
    allocator: std.mem.Allocator,
    pair: *const level2.PreparedLevel2PairV1,
    children: [2]ChildV1,
) !prefix_runtime.OwnerV1 {
    try pair.validate();
    for (children, pair.child_publication_ids) |child, publication_id| {
        try child.validate();
        if (!std.meta.eql(child.artifact.publication_id, publication_id))
            return error.PairSnapshotMismatch;
    }

    const shape = try vm_claim.Shape.init(0, 0);
    const left_schedule_shape = nonfri.outerScheduleShapeForClaimCount(
        children[0].capture,
        temporal_manifest.COMPONENT_COUNT,
    ) catch |err| return initStageFailure("left_schedule", err);
    const right_schedule_shape = nonfri.outerScheduleShapeForClaimCount(
        children[1].capture,
        temporal_manifest.COMPONENT_COUNT,
    ) catch |err| return initStageFailure("right_schedule", err);
    if (!std.meta.eql(left_schedule_shape, right_schedule_shape))
        return error.RuntimeProfileMismatch;
    var vm_plan = try schedule.Plan.initShape(
        allocator,
        try schedule.vmProgramSpec(0, 0),
        left_schedule_shape,
    );
    errdefer vm_plan.deinit();
    var recursion_plan = try schedule.Plan.initShape(
        allocator,
        schedule.RECURSION_PROGRAM_SPEC_V1,
        left_schedule_shape,
    );
    errdefer recursion_plan.deinit();
    var preprocessing = try leaf_authority.Preprocessing.init(allocator, shape);
    errdefer preprocessing.deinit();
    var statement_authority = try statement_source.Authority.init(
        allocator,
        &preprocessing,
    );
    errdefer statement_authority.deinit();
    var statement_workspace = try statement_air.Workspace.init(allocator);
    errdefer statement_workspace.deinit();
    var statement_rows = try initStatementRows(
        allocator,
        &statement_authority,
        &statement_workspace,
        pair,
    );
    errdefer statement_rows.deinit();
    var public_source = try public_source_mod.Source.init(
        allocator,
        &vm_plan,
        &recursion_plan,
        &preprocessing,
        36,
    );
    errdefer public_source.deinit();
    var inactive_source = try inactive.Source.init(
        allocator,
        &public_source,
        &vm_plan,
        &recursion_plan,
        &preprocessing,
    );
    errdefer inactive_source.deinit();
    var inactive_prepared = try inactive.Prepared.init(
        allocator,
        &inactive_source,
        &public_source,
        &vm_plan,
        &recursion_plan,
        &preprocessing,
    );
    errdefer inactive_prepared.deinit();
    var transcript_rows = transcript_v1.prepare(
        allocator,
        pair.authority_id,
        children,
    ) catch |err| return initStageFailure("transcript", err);
    errdefer transcript_rows.deinit();
    const rows_10_through_17 = try initRowAuthority(
        &statement_rows,
        &statement_authority,
        &statement_workspace,
        pair.authority_id,
        &inactive_source,
        &inactive_prepared,
        &public_source,
        &vm_plan,
        &recursion_plan,
        &preprocessing,
    );
    const custody = try initCustody(
        pair,
        &transcript_rows,
        &statement_rows,
        &statement_authority,
        &statement_workspace,
        &rows_10_through_17,
        &inactive_source,
        &vm_plan,
        &recursion_plan,
    );
    const sources = nonfri.TemporalPrefixTreeSourcesV3{
        .custody = &custody,
        .transcript = &transcript_rows,
        .statement = &statement_rows,
        .statement_authority = &statement_authority,
        .statement_workspace = &statement_workspace,
        .inactive_source = &inactive_source,
        .inactive_prepared = &inactive_prepared,
        .typed_public = &public_source,
        .vm_plan = &vm_plan,
        .recursion_plan = &recursion_plan,
        .preprocessing = &preprocessing,
    };
    var writer = try nonfri.TemporalPrefixTreeWriterV3.init(allocator, sources);
    errdefer writer.deinit();
    var trees = try prefix_runtime.OwnedPrefixTreesV3.init(
        allocator,
        &custody.commitment_layout,
    );
    errdefer trees.deinit();

    var result = prefix_runtime.OwnerV1{
        .allocator = allocator,
        .child_prepared_leaf_sha_ids = .{
            children[0].artifact.recursive_admission.identity,
            children[1].artifact.recursive_admission.identity,
        },
        .child_publication_ids = pair.child_publication_ids,
        .segment_manifest_sha_ids = .{
            children[0].publication.manifest_sha_id,
            children[1].publication.manifest_sha_id,
        },
        .shape = shape,
        .vm_plan = vm_plan,
        .recursion_plan = recursion_plan,
        .leaf_preprocessing = preprocessing,
        .statement_authority = statement_authority,
        .statement_workspace = statement_workspace,
        .statement_rows = statement_rows,
        .public_source = public_source,
        .inactive_source = inactive_source,
        .inactive_prepared = inactive_prepared,
        .transcript_rows = transcript_rows,
        .rows_10_through_17 = rows_10_through_17,
        .custody = custody,
        .writer = writer,
        .trees = trees,
        .authority_sha_id = undefined,
    };
    result.authority_sha_id = prefix_support.ownerIdentity(
        prefix_runtime.AUTHORITY_DOMAIN,
        &result,
    );
    try result.validateCold();
    return result;
}

fn initStageFailure(stage: []const u8, err: anyerror) anyerror {
    std.debug.print(
        "\nTEMPORAL_LEVEL2_PREFIX_INIT_FAIL stage={s} error={s}\n",
        .{ stage, @errorName(err) },
    );
    return err;
}

fn initStatementRows(
    allocator: std.mem.Allocator,
    authority: *const statement_source.Authority,
    workspace: *statement_air.Workspace,
    pair: *const level2.PreparedLevel2PairV1,
) !nonfri.PreparedRows10Through11V2 {
    try pair.validate();
    try authority.validateSeals();
    try workspace.validate();
    const root = pair.prepared_root.result.pair;
    const children = pair.prepared_root.authority_snapshot.children;
    const left_statement = try children[0].statement();
    const right_statement = try children[1].statement();
    const parent_statement = try span_statement.SpanStatement.fold(
        left_statement,
        right_statement,
    );
    const left_words = try left_statement.canonicalWords();
    const right_words = try right_statement.canonicalWords();
    const parent_words = try parent_statement.canonicalWords();
    if (!std.meta.eql(parent_statement, root.parent_statement) or
        !std.meta.eql(parent_words, root.parent_statement_words))
    {
        return error.PairSnapshotMismatch;
    }
    var evaluation = try authority.circuit.evaluate(
        allocator,
        recursion.statement_semantics_circuit.Witness.forBinary(
            &left_words,
            &right_words,
            &parent_words,
        ),
    );
    errdefer evaluation.deinit();
    const values = try allocator.alloc(
        stwo_core.fields.m31.M31,
        recursion.statement_semantics_circuit.INPUT_COUNT,
    );
    errdefer allocator.free(values);
    try nonfri.baseInputs(evaluation.inputs(), values);
    var range = try range_owner.Prepared.init(
        allocator,
        &workspace.range,
        .{
            .preprocessing = &authority.statement_semantics_preprocessing,
            .values = values,
            .left = &left_words,
            .right = &right_words,
            .parent = &parent_words,
        },
    );
    errdefer range.deinit();
    var result = nonfri.PreparedRows10Through11V2{
        .allocator = allocator,
        .public = try parentPublic(pair),
        .left_statement = left_statement,
        .right_statement = right_statement,
        .parent_statement = parent_statement,
        .left_words = left_words,
        .right_words = right_words,
        .parent_words = parent_words,
        .circuit_evaluation = evaluation,
        .statement_values = values,
        .range = range,
        .source_id = undefined,
    };
    result.source_id = nonfri.statementSourceIdentity(&result);
    try result.validateHot(authority, workspace);
    return result;
}

fn parentPublic(
    pair: *const level2.PreparedLevel2PairV1,
) !nonfri.TemporalParentPublicV2 {
    const authority = pair.prepared_root.authority_snapshot;
    const root = pair.prepared_root.result.pair;
    var child_kinds: [2]recursion.statement_semantics_circuit.ProofKind = undefined;
    var statement_ids: [2]nonfri.Digest = undefined;
    for (&child_kinds, &statement_ids, &authority.children) |
        *kind,
        *statement_id,
        *child,
    | {
        kind.* = child.kind;
        statement_id.* = try child.statementId();
    }
    var result = nonfri.TemporalParentPublicV2{
        .parent_height = root.parent_height,
        .parent_node_index = root.parent_node_index,
        .pair_authority_id = pair.authority_id,
        .adjacency_id = pair.adjacency_id,
        .context_id = root.context_id,
        .node_id = root.node_id,
        .record_id = root.record_id,
        .session_id = root.session_id,
        .job_id = root.job_id,
        .aggregator_vk_id = root.aggregator_vk_id,
        .child_kinds = child_kinds,
        .child_ids = root.child_ids,
        .child_publication_ids = pair.child_publication_ids,
        .child_statement_ids = statement_ids,
        .parent_statement_id = root.parent_statement_id,
        .identity = undefined,
    };
    result.identity = nonfri.publicIdentity(&result);
    try result.validate();
    return result;
}

fn initRowAuthority(
    statement: *const nonfri.PreparedRows10Through11V2,
    statement_authority: *const statement_source.Authority,
    statement_workspace: *statement_air.Workspace,
    pair_authority_id: nonfri.Digest,
    inactive_source: *const inactive.Source,
    inactive_prepared: *const inactive.Prepared,
    typed_public: *const public_source_mod.Source,
    vm_plan: *const schedule.Plan,
    recursion_plan: *const schedule.Plan,
    preprocessing: *const leaf_authority.Preprocessing,
) !nonfri.Rows10Through17AuthorityV2 {
    try statement.validateHot(statement_authority, statement_workspace);
    try inactive_source.validateAgainst(
        typed_public,
        vm_plan,
        recursion_plan,
        preprocessing,
    );
    try inactive_prepared.validateAgainst(
        inactive_source,
        typed_public,
        vm_plan,
        recursion_plan,
        preprocessing,
    );
    var result = nonfri.Rows10Through17AuthorityV2{
        .statement_source_id = statement.source_id,
        .pair_authority_id = pair_authority_id,
        .inactive_source_sha_id = inactive_source.authority_seal,
        .inactive_prepared_sha_id = inactive_prepared.authority_seal,
        .authority_id = undefined,
    };
    result.authority_id = nonfri.rowAuthorityIdentity(&result);
    try result.validate();
    return result;
}

fn initCustody(
    pair: *const level2.PreparedLevel2PairV1,
    transcript_rows: *const nonfri.PreparedTranscriptRowsV2,
    statement_rows: *const nonfri.PreparedRows10Through11V2,
    statement_authority: *const statement_source.Authority,
    statement_workspace: *statement_air.Workspace,
    rows: *const nonfri.Rows10Through17AuthorityV2,
    inactive_source: *const inactive.Source,
    vm_plan: *const schedule.Plan,
    recursion_plan: *const schedule.Plan,
) !nonfri.TemporalRows0Through17CustodyV3 {
    try pair.validate();
    try transcript_rows.validate();
    try statement_rows.validateHot(statement_authority, statement_workspace);
    try rows.validate();
    if (!std.meta.eql(transcript_rows.pair_authority_id, pair.authority_id) or
        !std.meta.eql(rows.pair_authority_id, pair.authority_id) or
        !std.meta.eql(rows.statement_source_id, statement_rows.source_id) or
        !std.mem.eql(u8, &rows.inactive_source_sha_id, &inactive_source.authority_seal))
    {
        return error.SourceIdentityMismatch;
    }
    const transcript_manifest = try transcript_rows.manifestForPlans(
        vm_plan,
        recursion_plan,
    );
    const relation_ids = try transcript_rows.relationDomainShaIds();
    const log_sizes = try nonfri.temporalPrefixLogSizes(
        &transcript_manifest,
        inactive_source,
    );
    const layout = try nonfri.buildTemporalPrefixCommitmentLayout(
        log_sizes,
        pair.authority_id,
        statement_rows.public.identity,
        transcript_manifest.identity,
        rows.authority_id,
        transcript_rows.child_replays,
        relation_ids,
    );
    var result = nonfri.TemporalRows0Through17CustodyV3{
        .parent_public = statement_rows.public,
        .transcript_manifest = transcript_manifest,
        .rows_10_through_17 = rows.*,
        .child_replays = transcript_rows.child_replays,
        .child_relation_domain_sha_ids = relation_ids,
        .commitment_layout = layout,
        .custody_id = undefined,
    };
    result.custody_id = nonfri.prefixCustodyIdentity(&result);
    try result.validate();
    return result;
}
