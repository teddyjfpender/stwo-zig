//! Concrete, diagnostic 50-row direct cohort assembly. Its output is only
//! a field witness and exact relation accounting, never an admitted proof.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const plan_mod = @import("air/segment_leaf_wrapper_roster_direct_v5.zig");
const views_mod = @import("segment_leaf_wrapper_cohort_views_v3.zig");
const provider_mod = @import("segment_leaf_wrapper_cohort_provider_v3.zig");
const calls_mod = @import("segment_leaf_wrapper_cohort_calls_v3.zig");
const rows_mod = @import("segment_leaf_wrapper_cohort_rows_v5.zig");
const range_provider = @import("segment_leaf_wrapper_range_provider_direct_v4.zig");
const frame_provider = @import("segment_leaf_wrapper_frame_provider_direct_v4.zig");
const closure = @import("segment_leaf_wrapper_cohort_closure_v5.zig");
const universal = @import("air/universal_challenges.zig");
const shared_mod = @import("air/universal_provider_relations.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;

pub fn fillPreprocessed(
    allocator: std.mem.Allocator,
    base: anytype,
    plan: *const plan_mod.Plan,
    writer: *const provider_mod.Writer,
    rows: *const rows_mod.Rows,
    destination: [][]M31,
) !void {
    try validateSources(base, plan, writer, rows);
    var views = try views_mod.Views.initForPlan(allocator, base.manifest(), plan, destination, plan_mod.PREPROCESSED_TREE_INDEX);
    defer views.deinit();
    try views.fillPreprocessedFromV2(base);
    var frame = try frameProvider(allocator, base, rows);
    defer frame.deinit();
    try frame.fillPreprocessed(&plan.base_plan, destination);
    const placement = plan.placements[34].?;
    if (placement.geometry.preprocessed_columns != 1 or placement.preprocessed_offset >= destination.len)
        return error.DirectV5ProviderTreeShapeMismatch;
    try writer.fillPreprocessedInto(destination[placement.preprocessed_offset]);
    try rows.fillPreprocessed(plan, destination);
}

pub fn fillMain(
    allocator: std.mem.Allocator,
    base: anytype,
    plan: *const plan_mod.Plan,
    writer: *const provider_mod.Writer,
    rows: *const rows_mod.Rows,
    destination: [][]M31,
) !void {
    try validateSources(base, plan, writer, rows);
    var views = try views_mod.Views.initForPlan(allocator, base.manifest(), plan, destination, plan_mod.MAIN_TREE_INDEX);
    defer views.deinit();
    try views.fillMainFromV2(base);
    var provider_columns = try mainProviderColumns(plan, destination);
    try writer.fillMainInto(&provider_columns);
    var range = try range_provider.Provider.init(allocator, &base.noncore.range_prepared.range_check, rows.base.arithmetic);
    defer range.deinit();
    try range.fillMain(&plan.base_plan, destination);
    try rows.fillMain(plan, destination);
}

pub fn fillInteraction(
    allocator: std.mem.Allocator,
    base: anytype,
    plan: *const plan_mod.Plan,
    writer: *const provider_mod.Writer,
    rows: *const rows_mod.Rows,
    relations: *const universal.UniversalRelations,
    shared: *const shared_mod.SharedProviderRelations,
    main_tree: [][]M31,
    destination: [][]M31,
) !closure.Claims50 {
    try validateSources(base, plan, writer, rows);
    try shared.validateAgainst(relations);
    var views = try views_mod.Views.initForPlan(allocator, base.manifest(), plan, destination, plan_mod.INTERACTION_TREE_INDEX);
    defer views.deinit();
    const base_generated = try views.fillInteractionFromV2(base, relations, shared);
    const reused = try views_mod.collectReusedClaimsV5(base_generated);
    var provider_columns = try mainProviderColumns(plan, main_tree);
    var row34 = try writer.generateInteractionFromMain(&provider_columns, shared);
    defer row34.deinit(allocator);
    try copyProviderInteraction(plan, &row34, destination);
    var range = try range_provider.Provider.init(allocator, &base.noncore.range_prepared.range_check, rows.base.arithmetic);
    defer range.deinit();
    const row35 = try range.fillInteraction(&plan.base_plan, shared, destination);
    var frame = try frameProvider(allocator, base, rows);
    defer frame.deinit();
    const row4 = try frame.fillInteraction(&plan.base_plan, relations, destination);
    const appended = try rows.fillInteraction(plan, relations, destination);
    return closure.Claims50.fromGenerated(plan, &reused, writer, &row34, &row35, &row4, &appended, relations, shared);
}

fn frameProvider(allocator: std.mem.Allocator, base: anytype, rows: *const rows_mod.Rows) !frame_provider.Provider {
    return frame_provider.Provider.init(
        allocator,
        base.noncore.transcript_workspace.transcript_word_source,
        rows.base.native.tree0_link.transcript_hash_id,
        rows.base.native.tree0_link.transcript_root,
    );
}

fn validateSources(base: anytype, plan: *const plan_mod.Plan, writer: *const provider_mod.Writer, rows: *const rows_mod.Rows) !void {
    try base.validate();
    try plan.validate();
    const base_calls = try base.core.completePoseidonCalls();
    const parts = [_][]const calls_mod.Call{
        base_calls,
        rows.base.metadata_hash.calls,
        rows.base.link_hash.calls,
        rows.base.native.program_hash.calls,
        rows.local.witness.authority_hash.poseidon_calls,
        rows.local.witness.receipt_hash.poseidon_calls,
    };
    if (rows.base.native.program.words.len != plan.base_plan.shape.program_words or
        !std.meta.eql(rows.local.schedule_id, plan.local_schedule_id) or
        parts.len != plan.poseidon_calls.ordered().len)
        return error.DirectV5CohortSourceShapeMismatch;
    try writer.buffer.validateAgainst(&parts);
    for (writer.buffer.ranges, plan.poseidon_calls.ordered()) |actual, expected|
        if (actual.start != expected.start or actual.len != expected.count)
            return error.DirectV5CohortSourceShapeMismatch;
    if (try writer.logSize() != plan.placements[34].?.geometry.log_size)
        return error.DirectV5CohortSourceShapeMismatch;
}

fn mainProviderColumns(plan: *const plan_mod.Plan, destination: [][]M31) ![provider_mod.MAIN_COLUMNS][]M31 {
    const placement = plan.placements[34].?;
    if (placement.geometry.main_columns != provider_mod.MAIN_COLUMNS or
        placement.main_offset > destination.len or
        provider_mod.MAIN_COLUMNS > destination.len - placement.main_offset)
        return error.DirectV5ProviderTreeShapeMismatch;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    var result: [provider_mod.MAIN_COLUMNS][]M31 = undefined;
    for (&result, destination[placement.main_offset..][0..provider_mod.MAIN_COLUMNS]) |*slot, column| {
        if (column.len != size) return error.DirectV5ProviderTreeShapeMismatch;
        slot.* = column;
    }
    return result;
}

fn copyProviderInteraction(plan: *const plan_mod.Plan, generated: *const provider_mod.Interaction, destination: [][]M31) !void {
    const placement = plan.placements[34].?;
    if (placement.geometry.interaction_columns != provider_mod.INTERACTION_COLUMNS or
        placement.interaction_offset > destination.len or
        provider_mod.INTERACTION_COLUMNS > destination.len - placement.interaction_offset)
        return error.DirectV5ProviderTreeShapeMismatch;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    for (generated.columns, destination[placement.interaction_offset..][0..provider_mod.INTERACTION_COLUMNS]) |from, to| {
        if (from.len != size or to.len != size) return error.DirectV5ProviderTreeShapeMismatch;
        for (to) |value| if (!value.isZero()) return error.DirectV5ProviderTreeNotFresh;
    }
    for (generated.columns, destination[placement.interaction_offset..][0..provider_mod.INTERACTION_COLUMNS]) |from, to|
        @memcpy(to, from);
}
