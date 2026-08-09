//! Independent legacy traversal used by prepared hash-domain differential tests.

const std = @import("std");
const core_constraints = @import("stwo_core").constraints;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const core_utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const hash_component = @import("hash_component.zig");
const merkle_node = @import("merkle_node.zig");
const poseidon2_air = @import("poseidon2_air.zig");

const HashComponent = hash_component.HashComponent;

fn sourceCount(kind: hash_component.Kind) usize {
    return 2 + hash_component.nMainColumns(kind) + hash_component.nInteractionColumns(kind);
}

fn values(poly: prover_component.Poly, eval_log_size: u32) ![]const M31 {
    try poly.validate();
    if (poly.log_size != eval_log_size) return error.InvalidProofShape;
    return poly.values;
}

fn secure(evaluations: []const []const M31, offset: usize, row: usize) QM31 {
    return QM31.fromM31(
        evaluations[offset][row],
        evaluations[offset + 1][row],
        evaluations[offset + 2][row],
        evaluations[offset + 3][row],
    );
}

fn mainValues(
    comptime count: usize,
    evaluations: []const []const M31,
    offset: usize,
    row: usize,
) [count]QM31 {
    var result: [count]QM31 = undefined;
    for (&result, evaluations[offset..][0..count]) |*value, column| {
        value.* = QM31.fromBase(column[row]);
    }
    return result;
}

fn interactions(
    comptime count: usize,
    evaluations: []const []const M31,
    offset: usize,
    row: usize,
    previous_row: usize,
    sums: *[count]QM31,
    previous: *[count]QM31,
) void {
    for (0..count) |index| {
        sums[index] = secure(evaluations, offset + 4 * index, row);
        previous[index] = secure(evaluations, offset + 4 * index, previous_row);
    }
}

fn fold(powers: []const QM31, constraints: []const QM31) QM31 {
    var result = QM31.zero();
    for (constraints, 0..) |constraint, index| {
        result = result.add(powers[powers.len - 1 - index].mul(constraint));
    }
    return result;
}

/// Reconstructs the traversal that predates prepared domain evaluators.
pub fn evaluate(
    allocator: std.mem.Allocator,
    component_value: *const HashComponent,
    trace_data: *const prover_component.Trace,
    accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
) !void {
    if (trace_data.polys.items.len < 3) return error.InvalidProofShape;
    const eval_log_size = component_value.log_size + 1;
    const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
    const eval_size = eval_domain.size();
    const n_main = hash_component.nMainColumns(component_value.kind);
    const n_interaction = hash_component.nInteractionColumns(component_value.kind);
    const evaluations = try allocator.alloc([]const M31, sourceCount(component_value.kind));
    defer allocator.free(evaluations);
    const preprocessed = trace_data.polys.items[0];
    const main = trace_data.polys.items[1];
    const interaction = trace_data.polys.items[2];
    if (preprocessed.len <= @max(
        component_value.is_first_col_idx,
        component_value.is_active_col_idx,
    ) or
        main.len < component_value.main_col_offset + n_main or
        interaction.len < component_value.interaction_col_offset + n_interaction)
    {
        return error.InvalidProofShape;
    }
    evaluations[0] = try values(
        preprocessed[component_value.is_first_col_idx],
        eval_log_size,
    );
    evaluations[1] = try values(
        preprocessed[component_value.is_active_col_idx],
        eval_log_size,
    );
    for (main[component_value.main_col_offset..][0..n_main], evaluations[2..][0..n_main]) |poly, *destination| {
        destination.* = try values(poly, eval_log_size);
    }
    const interaction_start = 2 + n_main;
    for (interaction[component_value.interaction_col_offset..][0..n_interaction], evaluations[interaction_start..]) |poly, *destination| {
        destination.* = try values(poly, eval_log_size);
    }

    var denominator_inv: [2]M31 = undefined;
    const trace_coset = canonic.CanonicCoset.new(component_value.log_size).coset();
    for (&denominator_inv, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            trace_coset,
            eval_domain.at(core_utils.bitReverseIndex(index, 1)),
        ).inv();
    }
    const accumulators = try accumulator.columns(
        allocator,
        &.{.{ .log_size = eval_log_size, .n_cols = component_value.nConstraints() }},
    );
    defer allocator.free(accumulators);
    const column_accumulator = &accumulators[0];
    for (0..eval_size) |row| {
        const previous_row = core_utils.previousBitReversedCircleDomainIndex(
            row,
            component_value.log_size,
            eval_log_size,
        );
        const is_first = QM31.fromBase(evaluations[0][row]);
        const is_active = QM31.fromBase(evaluations[1][row]);
        const folded = switch (component_value.kind) {
            .merkle => merkle: {
                const row_main = mainValues(
                    merkle_node.N_MAIN_COLUMNS,
                    evaluations,
                    2,
                    row,
                );
                var sums: [merkle_node.N_SUMS]QM31 = undefined;
                var previous: [merkle_node.N_SUMS]QM31 = undefined;
                interactions(
                    merkle_node.N_SUMS,
                    evaluations,
                    interaction_start,
                    row,
                    previous_row,
                    &sums,
                    &previous,
                );
                const constraints = merkle_node.evaluate(
                    row_main,
                    is_active,
                    is_first,
                    sums,
                    previous,
                    component_value.merkle_claims,
                    component_value.relations,
                );
                break :merkle fold(column_accumulator.random_coeff_powers, &constraints);
            },
            .poseidon2 => poseidon: {
                const row_main = mainValues(
                    poseidon2_air.N_MAIN_COLUMNS,
                    evaluations,
                    2,
                    row,
                );
                var sums: [poseidon2_air.N_SUMS]QM31 = undefined;
                var previous: [poseidon2_air.N_SUMS]QM31 = undefined;
                interactions(
                    poseidon2_air.N_SUMS,
                    evaluations,
                    interaction_start,
                    row,
                    previous_row,
                    &sums,
                    &previous,
                );
                const constraints = hash_component.poseidonConstraints(
                    row_main,
                    is_active,
                    is_first,
                    sums,
                    previous,
                    component_value.poseidon_claims,
                    component_value.relations,
                );
                break :poseidon fold(column_accumulator.random_coeff_powers, &constraints);
            },
        };
        column_accumulator.accumulate(
            row,
            folded.mulM31(denominator_inv[row >> @intCast(component_value.log_size)]),
        );
    }
}
