//! Source-identical lowering from the authenticated A-014 selected plan into
//! the append-only variable-partition lookup-polynomial V2 authority.
//!
//! This module deliberately does not install a backend capability or change a
//! proof layout. It creates the exact artifact that a later versioned physical
//! manifest can pin, while V1 remains the only production consumer.

const std = @import("std");
const prover_component = @import("stwo_prover_engine").air.component_prover;
const runtime_program = @import("../extract/runtime_program.zig");
const selected_batching = @import("lookup_batch_execution.zig");

/// Cold, failure-atomic lowering. Polynomial nodes and relation roots come
/// from the existing production exporter; only their authenticated batch
/// layout changes. The returned owner contains no pointer into `plan`.
pub fn lowerSelected(
    allocator: std.mem.Allocator,
    plan: *const selected_batching.FamilyPlan,
) !prover_component.OwnedLookupPolynomialProgramV2 {
    try plan.validate();

    var legacy = try runtime_program.buildLookups(allocator, plan.family);
    var legacy_owned = true;
    defer if (legacy_owned) legacy.deinit();

    const event_count: usize = plan.selection.event_count;
    if (legacy.entries.len != event_count)
        return error.InvalidSelectedPlanProjection;

    const event_degrees = try allocator.alloc(
        prover_component.LookupPolynomialEventDegreeV2,
        event_count,
    );
    var event_degrees_owned = true;
    defer if (event_degrees_owned) allocator.free(event_degrees);
    for (plan.events[0..event_count], event_degrees) |source, *destination| {
        destination.* = .{
            .ordinal = source.ordinal,
            .numerator_degree = source.numerator_degree,
            .denominator_degree = source.denominator_degree,
        };
    }

    const batches = try allocator.alloc(
        prover_component.LookupPolynomialBatchV2,
        plan.selection.batches.len,
    );
    var batches_owned = true;
    defer if (batches_owned) allocator.free(batches);
    for (plan.selection.batches, batches) |source, *destination| {
        destination.* = .{
            .first_entry = source.first_event,
            .entry_count = source.event_count,
            .interaction_degree = source.terms.final,
        };
    }

    const layout = try prover_component.LookupPolynomialLayoutV2.init(
        plan.selection.program_digest,
        plan.selection.plan_digest,
        legacy.column_count,
        plan.selection.policy.maximum_interaction_degree,
        event_degrees,
        batches,
    );
    if (layout.entry_count != plan.selection.event_count or
        layout.batch_count != plan.selection.score.batch_count or
        layout.interaction_column_count !=
            plan.selection.score.interaction_columns or
        layout.maximum_interaction_degree !=
            plan.selection.score.maximum_interaction_degree)
    {
        return error.InvalidSelectedPlanProjection;
    }

    var result = prover_component.OwnedLookupPolynomialProgramV2{
        .allocator = allocator,
        .layout = layout,
        .nodes = legacy.nodes,
        .entries = legacy.entries,
        .event_degrees = event_degrees,
        .batches = batches,
        .program_identity = .{0} ** 32,
    };
    legacy_owned = false;
    event_degrees_owned = false;
    batches_owned = false;
    var result_owned = true;
    errdefer if (result_owned) result.deinit();

    try result.seal();
    const authority = try result.authority();
    if (!std.mem.eql(
        u8,
        &authority.component_identity,
        &plan.selection.program_digest,
    ) or !std.mem.eql(
        u8,
        &authority.partition_identity,
        &plan.selection.plan_digest,
    )) return error.InvalidSelectedPlanProjection;
    try result.validateAgainst(&authority);
    result_owned = false;
    return result;
}
