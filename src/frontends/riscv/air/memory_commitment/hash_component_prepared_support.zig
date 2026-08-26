//! Preparation-time geometry and source ownership for hash AIR domains.

const std = @import("std");
const core_constraints = @import("stwo_core").constraints;
const M31 = @import("stwo_core").fields.m31.M31;
const qm31 = @import("stwo_core").fields.qm31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
const prover_task_graph = @import("stwo_prover_engine").task_graph;

pub fn resources(
    eval_size: usize,
    source_count: usize,
    owned_count: usize,
    state_bytes: usize,
) !prover_task_graph.ResourceReservation {
    return resourcesWithStack(
        eval_size,
        source_count,
        owned_count,
        state_bytes,
        prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    );
}

/// Build the same checked reservation for a row kernel with an independently
/// reviewed stack certificate. Wide evaluators must carry their larger bound
/// explicitly rather than reducing concurrency for every prepared component.
pub fn resourcesWithStack(
    eval_size: usize,
    source_count: usize,
    owned_count: usize,
    state_bytes: usize,
    worker_stack_bytes: usize,
) !prover_task_graph.ResourceReservation {
    if (worker_stack_bytes == 0) return error.InvalidPreparedDomainResources;
    const secure_element_bytes = std.math.mul(
        usize,
        qm31.SECURE_EXTENSION_DEGREE,
        @sizeOf(M31),
    ) catch return error.ResourceReservationOverflow;
    const final_output_bytes = std.math.mul(
        usize,
        eval_size,
        secure_element_bytes,
    ) catch return error.ResourceReservationOverflow;
    const source_bytes = std.math.mul(
        usize,
        source_count,
        @sizeOf([]const M31),
    ) catch return error.ResourceReservationOverflow;
    const owned_view_bytes = std.math.mul(
        usize,
        owned_count,
        @sizeOf([]M31),
    ) catch return error.ResourceReservationOverflow;
    const owned_value_count = std.math.mul(usize, owned_count, eval_size) catch
        return error.ResourceReservationOverflow;
    const owned_value_bytes = std.math.mul(
        usize,
        owned_value_count,
        @sizeOf(M31),
    ) catch return error.ResourceReservationOverflow;
    var resident_bytes = std.math.add(usize, state_bytes, source_bytes) catch
        return error.ResourceReservationOverflow;
    resident_bytes = std.math.add(usize, resident_bytes, owned_view_bytes) catch
        return error.ResourceReservationOverflow;
    resident_bytes = std.math.add(usize, resident_bytes, owned_value_bytes) catch
        return error.ResourceReservationOverflow;
    return .{
        .final_output_bytes = final_output_bytes,
        .shared_resident_bytes = resident_bytes,
        .worker_stack_bytes = worker_stack_bytes,
    };
}

pub fn sourceNeedsExtension(
    poly: prover_component.Poly,
    trace_log_size: u32,
    eval_log_size: u32,
) !bool {
    try poly.validate();
    if (poly.log_size == eval_log_size) return false;
    const coefficients = poly.coefficients orelse return error.InvalidProofShape;
    if (coefficients.logSize() != trace_log_size) return error.InvalidProofShape;
    return true;
}

pub fn evaluationValues(
    allocator: std.mem.Allocator,
    poly: prover_component.Poly,
    eval_log_size: u32,
    eval_size: usize,
    owned_buffers: [][]M31,
    owned_initialized: *usize,
) ![]const M31 {
    if (poly.log_size == eval_log_size) return poly.values;
    if (owned_initialized.* >= owned_buffers.len) return error.InvalidProofShape;
    const source = poly.coefficients.?.coefficients();
    if (source.len > eval_size) return error.InvalidProofShape;
    const values = try allocator.alloc(M31, eval_size);
    errdefer allocator.free(values);
    @memcpy(values[0..source.len], source);
    @memset(values[source.len..], M31.zero());
    owned_buffers[owned_initialized.*] = values;
    owned_initialized.* += 1;
    return values;
}

pub fn quotientDenominators(
    comptime denominator_count: usize,
    log_size: u32,
    eval_log_size: u32,
    eval_domain: anytype,
) ![denominator_count]M31 {
    const expected_log_size = std.math.add(u32, log_size, 1) catch
        return error.InvalidProofShape;
    if (eval_log_size != expected_log_size) return error.InvalidProofShape;
    const extension_bits: u5 = 1;
    var result: [denominator_count]M31 = undefined;
    const coset = canonic.CanonicCoset.new(log_size).coset();
    for (&result, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            coset,
            eval_domain.at(utils.bitReverseIndex(index, extension_bits)),
        ).inv();
    }
    return result;
}
