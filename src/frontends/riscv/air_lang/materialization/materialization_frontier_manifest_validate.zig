//! Cross-field validation for canonical materialization-frontier receipts.

const std = @import("std");
const wire = @import("materialization_frontier_manifest_wire.zig");

pub const Error = error{
    CostOverflow,
    InconsistentCost,
    InvalidProposal,
    InvalidRunAccounting,
};

pub fn validateProvenance(
    proposal: anytype,
    baseline: bool,
    passes_completed: u16,
) Error!void {
    const zero = [_]u8{0} ** 32;
    if (baseline) {
        if (proposal.provenance.kind != .seed or proposal.provenance.pass != 0 or
            !std.mem.eql(u8, &proposal.provenance.parent_cut_digest, &zero) or
            proposal.provenance.removed != null or proposal.provenance.added != null)
            return error.InvalidProposal;
        return;
    }
    if (proposal.provenance.kind == .seed or proposal.provenance.pass == 0 or
        proposal.provenance.pass > passes_completed or
        std.mem.eql(u8, &proposal.provenance.parent_cut_digest, &zero) or
        std.mem.eql(u8, &proposal.provenance.parent_cut_digest, &proposal.cut_digest))
        return error.InvalidProposal;
    switch (proposal.provenance.kind) {
        .seed => unreachable,
        .remove => if (proposal.provenance.removed == null or
            proposal.provenance.added != null or wire.contains(
            proposal.selected_values,
            proposal.provenance.removed.?,
        )) return error.InvalidProposal,
        .add => if (proposal.provenance.removed != null or
            proposal.provenance.added == null or !wire.contains(
            proposal.selected_values,
            proposal.provenance.added.?,
        )) return error.InvalidProposal,
        .swap => if (proposal.provenance.removed == null or
            proposal.provenance.added == null or
            proposal.provenance.removed.? == proposal.provenance.added.? or
            wire.contains(proposal.selected_values, proposal.provenance.removed.?) or
            !wire.contains(proposal.selected_values, proposal.provenance.added.?))
            return error.InvalidProposal,
    }
}

pub fn validateRun(search: anytype, run: anytype, frontier_count: usize) Error!void {
    const classified = std.math.add(
        u32,
        run.feasible_unique_proposals,
        run.duplicate_proposals,
    ) catch return error.InvalidRunAccounting;
    const total = std.math.add(u32, classified, run.rejected_infeasible) catch
        return error.InvalidRunAccounting;
    if (run.attempted_evaluations > search.max_candidate_evaluations or
        total != run.attempted_evaluations or run.passes_completed == 0 or
        run.passes_completed > search.max_passes or
        frontier_count > run.feasible_unique_proposals or
        (run.budget_exhausted and run.attempted_evaluations != search.max_candidate_evaluations) or
        (run.frontier_truncated and frontier_count != search.frontier_limit))
        return error.InvalidRunAccounting;
}

pub fn validateCost(geometry: anytype, scenarios: anytype, proposal: anytype) Error!void {
    const cost = proposal.cost;
    const selected: u64 = @intCast(proposal.selected_values.len);
    if (cost.materialization_count != selected or
        cost.base_main_columns != geometry.base_main_columns or
        cost.candidate_main_columns != try add(geometry.base_main_columns, selected) or
        cost.direct_roots != try add(geometry.fixed_direct_roots, selected) or
        cost.interaction_columns != geometry.interaction_columns or
        cost.semantic_witness_nodes < selected or
        cost.unique_committed_column_reads > cost.canonical_direct_nodes or
        cost.canonical_streaming_peak_live_nodes > cost.canonical_direct_nodes)
        return error.InconsistentCost;
    var operations: u64 = 0;
    inline for (.{
        cost.canonical_direct_additions,
        cost.canonical_direct_subtractions,
        cost.canonical_direct_negations,
        cost.canonical_direct_multiplications,
    }) |value| operations = try add(operations, value);
    if (operations > cost.canonical_direct_nodes) return error.InconsistentCost;
    for (scenarios, proposal.scenario_costs) |scenario, actual| {
        const main_cells = try mul(cost.candidate_main_columns, scenario.rows);
        const interaction_cells = try mul(cost.interaction_columns, scenario.rows);
        const committed_cells = try add(main_cells, interaction_cells);
        if (actual.main_cells != main_cells or
            actual.interaction_cells != interaction_cells or
            actual.committed_cells != committed_cells or
            actual.main_bytes != try mul(main_cells, geometry.field_element_bytes) or
            actual.interaction_bytes != try mul(interaction_cells, geometry.field_element_bytes) or
            actual.committed_bytes != try mul(committed_cells, geometry.field_element_bytes))
            return error.InconsistentCost;
    }
}

pub fn dominates(lhs: anytype, rhs: @TypeOf(lhs)) bool {
    var strict = false;
    inline for (std.meta.fields(@TypeOf(lhs.cost))) |field| {
        const a = @field(lhs.cost, field.name);
        const b = @field(rhs.cost, field.name);
        if (a > b) return false;
        strict = strict or a < b;
    }
    for (lhs.scenario_costs, rhs.scenario_costs) |a, b| {
        inline for (std.meta.fields(@TypeOf(a))) |field| {
            const av = @field(a, field.name);
            const bv = @field(b, field.name);
            if (av > bv) return false;
            strict = strict or av < bv;
        }
    }
    return strict;
}

fn add(a: u64, b: u64) Error!u64 {
    return std.math.add(u64, a, b) catch error.CostOverflow;
}

fn mul(a: u64, b: u64) Error!u64 {
    return std.math.mul(u64, a, b) catch error.CostOverflow;
}
