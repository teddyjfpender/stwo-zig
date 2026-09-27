//! Allocation and quotient-domain support for the ordered provider component.

const std = @import("std");
const core_constraints = @import("stwo_core").constraints;
const M31 = @import("stwo_core").fields.m31.M31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const prepared_evaluation = @import("../../air/prepared_evaluation_owner.zig");

pub fn resources(
    eval_size: usize,
    owned_count: usize,
    denominator_count: usize,
    state_bytes: usize,
) !prover_task_graph.ResourceReservation {
    const secure_bytes = try std.math.mul(usize, eval_size, 4 * @sizeOf(M31));
    var resident = try prepared_evaluation.residentBytes(owned_count, eval_size);
    resident = try std.math.add(usize, resident, state_bytes);
    resident = try std.math.add(
        usize,
        resident,
        try std.math.mul(usize, denominator_count, @sizeOf(M31)),
    );
    return .{
        .final_output_bytes = secure_bytes,
        .shared_resident_bytes = resident,
        .worker_stack_bytes = prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    };
}

pub fn quotientDenominators(
    allocator: std.mem.Allocator,
    log_size: u32,
    eval_log_size: u32,
    composition_log_split: u32,
    eval_domain: anytype,
) ![]M31 {
    const expected_log_size = std.math.add(
        u32,
        log_size,
        composition_log_split,
    ) catch return error.InvalidProofShape;
    if (composition_log_split == 0 or eval_log_size != expected_log_size or
        composition_log_split >= @bitSizeOf(usize))
    {
        return error.InvalidProofShape;
    }
    const count = @as(usize, 1) << @intCast(composition_log_split);
    const result = try allocator.alloc(M31, count);
    errdefer allocator.free(result);
    const coset = canonic.CanonicCoset.new(log_size).coset();
    for (result, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            coset,
            eval_domain.at(utils.bitReverseIndex(index, composition_log_split)),
        ).inv();
    }
    return result;
}
