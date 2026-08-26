//! Internal universal typed component authority shard; use universal_typed_component.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const core_air_accumulation = stwo_core.air.accumulation;
pub const core_air_components = stwo_core.air.components;
pub const core_air_derive = stwo_core.air.derive;
pub const core_constraints = stwo_core.constraints;
pub const circle = stwo_core.circle;
pub const M31 = stwo_core.fields.m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const canonic = stwo_core.poly.circle.canonic;
pub const utils = stwo_core.utils;
pub const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
pub const prover_component = @import("stwo_prover_engine").air.component_prover;
pub const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
pub const prover_circle = @import("stwo_prover_engine").poly.circle;
pub const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
pub const prover_task_graph = @import("stwo_prover_engine").task_graph;
pub const prover_work_pool = @import("stwo_prover_engine").work_pool;
pub const direct_program = @import("direct_constraint_program.zig");
pub const logup = @import("../../air/logup.zig");
pub const types = @import("../../air/lang/types.zig");
pub const default_manifest = @import("universal_adapter_manifest.zig");
pub const universal = @import("universal_challenges.zig");

pub const CirclePointQM31 = circle.CirclePointQM31;

/// Equation-free manifest projection shared by every versioned outer
/// protocol.  Geometry is derived only from the authenticated typed AIR; a
/// manifest may select a different AIR for a versioned row, but it cannot
/// transcribe that AIR's widths, degrees, or semantic identity by hand.
pub fn manifestGeometryForAir(
    comptime Air: type,
    comptime manifest_mod: type,
    comptime roster_row: manifest_mod.ComponentKey,
    log_size: u32,
) manifest_mod.Geometry {
    return .{
        .roster_row = manifest_mod.keyIndex(roster_row),
        .log_size = log_size,
        .preprocessed_columns = Air.PREPROCESSED_COLUMN_COUNT,
        .main_columns = Air.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = Air.INTERACTION_COLUMN_COUNT,
        .direct_constraints = Air.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = Air.INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = @intCast(
            protocolMaximumConstraintDegree(Air),
        ),
        .profiled_constraint_degree = Air.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = Air.SEMANTIC_DIGEST,
    };
}

pub fn protocolMaximumConstraintDegree(comptime Air: type) u32 {
    const compatibility: u32 = if (@hasDecl(
        Air,
        "REFERENCE_MAXIMUM_CONSTRAINT_DEGREE",
    )) Air.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE else @max(
        Air.MAXIMUM_CONSTRAINT_DEGREE,
        if (Air.INTERACTION_BATCH_COUNT == 0) @as(u32, 0) else 3,
    );
    return if (@hasDecl(
        Air,
        "LOWERED_MAXIMUM_CONSTRAINT_DEGREE",
    )) @max(
        compatibility,
        Air.LOWERED_MAXIMUM_CONSTRAINT_DEGREE,
    ) else compatibility;
}

pub fn sampledSecure(columns: [][]QM31, base: usize, point_index: usize) !QM31 {
    if (columns.len < base + 4) return error.InvalidProofShape;
    var coordinates: [4]QM31 = undefined;
    for (&coordinates, columns[base .. base + 4]) |*coordinate, column| {
        if (column.len <= point_index) return error.InvalidProofShape;
        coordinate.* = column[point_index];
    }
    return QM31.fromPartialEvals(coordinates);
}

pub inline fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}

pub fn emptyOrFilledLogs(
    allocator: std.mem.Allocator,
    count: usize,
    log_size: u32,
) ![]u32 {
    const result = try allocator.alloc(u32, count);
    @memset(result, log_size);
    return result;
}

pub fn currentPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    point: CirclePointQM31,
) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(column);
        allocator.free(result);
    }
    for (result) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{point});
        initialized += 1;
    }
    return result;
}

pub fn freePointColumns(
    allocator: std.mem.Allocator,
    columns: [][]CirclePointQM31,
) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

pub fn checkedEnd(offset: anytype, count: usize) !usize {
    return std.math.add(usize, @intCast(offset), count) catch
        error.InvalidProofShape;
}

pub fn sourceNeedsExtension(
    poly: prover_component.Poly,
    trace_log_size: u32,
    eval_log_size: u32,
) !bool {
    try poly.validate();
    if (poly.log_size == eval_log_size) return false;
    const coefficients = poly.coefficients orelse return error.InvalidProofShape;
    if (coefficients.logSize() != trace_log_size)
        return error.InvalidProofShape;
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
    if (owned_initialized.* >= owned_buffers.len)
        return error.InvalidProofShape;
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
    comptime count: usize,
    log_size: u32,
    eval_log_size: u32,
    eval_domain: anytype,
) ![count]M31 {
    if (eval_log_size <= log_size or
        eval_log_size - log_size >= @bitSizeOf(usize))
    {
        return error.InvalidProofShape;
    }
    if (count != @as(usize, 1) << @intCast(eval_log_size - log_size))
        return error.InvalidProofShape;
    var result: [count]M31 = undefined;
    const coset = canonic.CanonicCoset.new(log_size).coset();
    for (&result, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            coset,
            eval_domain.at(utils.bitReverseIndex(
                index,
                @intCast(eval_log_size - log_size),
            )),
        ).inv();
    }
    return result;
}

pub fn preparedResources(
    eval_size: usize,
    owned_count: usize,
    state_bytes: usize,
) !prover_task_graph.ResourceReservation {
    const final_output_bytes = std.math.mul(usize, eval_size, @sizeOf(QM31)) catch
        return error.ResourceReservationOverflow;
    const owned_views = std.math.mul(usize, owned_count, @sizeOf([]M31)) catch
        return error.ResourceReservationOverflow;
    const owned_values = std.math.mul(usize, owned_count, eval_size) catch
        return error.ResourceReservationOverflow;
    const owned_bytes = std.math.mul(usize, owned_values, @sizeOf(M31)) catch
        return error.ResourceReservationOverflow;
    var resident = std.math.add(usize, state_bytes, owned_views) catch
        return error.ResourceReservationOverflow;
    resident = std.math.add(usize, resident, owned_bytes) catch
        return error.ResourceReservationOverflow;
    return .{
        .final_output_bytes = final_output_bytes,
        .shared_resident_bytes = resident,
        .worker_stack_bytes = prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    };
}

pub fn serialTaskContext(
    context: *anyopaque,
    cancellation: *const prover_task_graph.CancellationToken,
) prover_task_graph.TaskContext {
    return .{
        .user_context = context,
        .cancellation = cancellation,
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 0,
            .shard_or_chunk_index = 0,
        },
        .worker_budget = prover_work_pool.WorkerBudget.serial(),
        .task_class = .leaf,
        .exclusive_lease = null,
        .child_wait_group = null,
    };
}
