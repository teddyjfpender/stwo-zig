//! Concrete direct 47-row tree assembly from the native SegmentV2 cohort.
//!
//! The V2 owner regenerates rows 0–33 and 35–38 through zero-copy views.
//! Its obsolete row 34 is redirected to scratch, then the enlarged ordered
//! Poseidon row and eight direct typed rows are written into the final trees.
//! This is a candidate witness, not a proof gate or production publication.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const plan_mod = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
const views_mod = @import("segment_leaf_wrapper_cohort_views_v3.zig");
const provider_mod = @import("segment_leaf_wrapper_cohort_provider_v3.zig");
const calls_mod = @import("segment_leaf_wrapper_cohort_calls_v3.zig");
const rows_mod = @import("segment_leaf_wrapper_cohort_direct_rows_v4.zig");
const range_provider = @import("segment_leaf_wrapper_range_provider_direct_v4.zig");
const closure = @import("segment_leaf_wrapper_cohort_closure_v4.zig");
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
    const placement = plan.placements[34].?;
    if (placement.geometry.preprocessed_columns != 1 or
        placement.preprocessed_offset >= destination.len)
        return error.DirectProviderTreeShapeMismatch;
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
    var range = try range_provider.Provider.init(allocator, &base.noncore.range_prepared.range_check, rows.arithmetic);
    defer range.deinit();
    try range.fillMain(plan, destination);
    try rows.fillMain(plan, destination);
}

/// Generates all row claims and per-domain audits under exactly one relation
/// draw. The caller must use `Claims47.verifyAllDomains` with the V2 cohort's
/// independently derived `publicWireBoundary` before attempting a proof.
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
) !closure.Claims47 {
    try validateSources(base, plan, writer, rows);
    try shared.validateAgainst(relations);
    var views = try views_mod.Views.initForPlan(allocator, base.manifest(), plan, destination, plan_mod.INTERACTION_TREE_INDEX);
    defer views.deinit();
    const base_generated = try views.fillInteractionFromV2(base, relations, shared);
    const reused = try views_mod.collectReusedClaims(base_generated);
    var provider_columns = try mainProviderColumns(plan, main_tree);
    var row34 = try writer.generateInteractionFromMain(&provider_columns, shared);
    defer row34.deinit(allocator);
    try copyProviderInteraction(plan, &row34, destination);
    var range = try range_provider.Provider.init(allocator, &base.noncore.range_prepared.range_check, rows.arithmetic);
    defer range.deinit();
    const row35 = try range.fillInteraction(plan, shared, destination);
    const appended = try rows.fillInteraction(plan, relations, destination);
    return closure.Claims47.fromGenerated(plan, &reused, writer, &row34, &row35, &appended, relations, shared);
}

fn validateSources(
    base: anytype,
    plan: *const plan_mod.Plan,
    writer: *const provider_mod.Writer,
    rows: *const rows_mod.Rows,
) !void {
    try base.validate();
    try plan.validate();
    if (plan.shape.program_words != rows.native.program_words.word_count or
        plan.shape.base_poseidon_calls != (try base.core.completePoseidonCalls()).len or
        rows.metadata_hash.calls.len != plan.poseidon_calls.metadata or
        rows.link_hash.calls.len != plan.poseidon_calls.link or
        rows.native.program_hash.calls.len != plan.poseidon_calls.program)
        return error.DirectCohortSourceShapeMismatch;
    const actual_parts = [_][]const calls_mod.Call{
        try base.core.completePoseidonCalls(),
        rows.metadata_hash.calls,
        rows.link_hash.calls,
        rows.native.program_hash.calls,
    };
    try writer.buffer.validateAgainst(&actual_parts);
    if (try writer.logSize() != plan.placements[34].?.geometry.log_size)
        return error.DirectCohortSourceShapeMismatch;
}

fn mainProviderColumns(
    plan: *const plan_mod.Plan,
    destination: [][]M31,
) ![provider_mod.MAIN_COLUMNS][]M31 {
    const placement = plan.placements[34].?;
    if (placement.geometry.main_columns != provider_mod.MAIN_COLUMNS or
        placement.main_offset > destination.len or
        provider_mod.MAIN_COLUMNS > destination.len - placement.main_offset)
        return error.DirectProviderTreeShapeMismatch;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    var result: [provider_mod.MAIN_COLUMNS][]M31 = undefined;
    for (&result, destination[placement.main_offset..][0..provider_mod.MAIN_COLUMNS]) |*slot, column| {
        if (column.len != size) return error.DirectProviderTreeShapeMismatch;
        slot.* = column;
    }
    return result;
}

fn copyProviderInteraction(
    plan: *const plan_mod.Plan,
    generated: *const provider_mod.Interaction,
    destination: [][]M31,
) !void {
    const placement = plan.placements[34].?;
    if (placement.geometry.interaction_columns != provider_mod.INTERACTION_COLUMNS or
        placement.interaction_offset > destination.len or
        provider_mod.INTERACTION_COLUMNS > destination.len - placement.interaction_offset)
        return error.DirectProviderTreeShapeMismatch;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    for (generated.columns, destination[placement.interaction_offset..][0..provider_mod.INTERACTION_COLUMNS]) |source, target| {
        if (source.len != size or target.len != size)
            return error.DirectProviderTreeShapeMismatch;
        for (target) |value| if (!value.isZero())
            return error.DirectProviderTreeNotFresh;
    }
    for (generated.columns, destination[placement.interaction_offset..][0..provider_mod.INTERACTION_COLUMNS]) |source, target|
        @memcpy(target, source);
}
