//! Resident quotient construction into FRI layer zero.
//!
//! The quotient's coordinate result aliases the first FRI layer by contract.
//! Terms and partial numerators remain device-resident throughout this stage.

const std = @import("std");
const field = @import("../../../../backends/cuda/abi/field.zig");
const quotient_abi = @import("../../../../backends/cuda/abi/stages/quotient.zig");
const column = @import("../../../../backends/cuda/runtime/column.zig");
const common = @import("../../../../backends/cuda/runtime/stages/common.zig");
const quotient_stage = @import("../../../../backends/cuda/runtime/stages/quotient.zig");
const canonical_ingress = @import("../canonical_ingress.zig");
const plan_mod = @import("../plan.zig");
const request = @import("../request.zig");
const types = @import("../resident_bindings/types.zig");
const shared_executor = @import("../../common/quotient_executor.zig");

const NativeQuotient = quotient_stage.Native;

const Dispatch = struct {
    circle: canonical_ingress.CircleConstants,
    sample_points: common.SecureCirclePoints,
    sampled_values: common.SecureFields,
    quotient: types.Quotient,
};

/// Enqueues quotient preparation, accumulation, and combination without a
/// host transfer, allocation, fallback, or synchronization.
pub fn execute(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    ingress: *const canonical_ingress.Pack,
    views: *const types.Views,
) !void {
    return shared_executor.run(transaction, prepared, ingress, views);
}

/// Naming alias for stage executors that expose `run`.
pub const run = execute;

fn executeWithOps(
    comptime Ops: type,
    session: anytype,
    dispatch: Dispatch,
) !void {
    const quotient = dispatch.quotient;
    try Ops.prepareTerms(
        session,
        quotient.prepared_groups,
        dispatch.sample_points,
        dispatch.sampled_values,
        quotient.challenge,
        quotient.term_points,
        quotient.line_coefficients,
    );
    try Ops.finalizeGroups(
        session,
        quotient.prepared_groups,
        quotient.term_points,
        quotient.line_coefficients,
        quotient.group_points,
        quotient.first_linear_terms,
    );
    try Ops.zeroOutputs(
        session,
        quotient.numerator_topology,
        quotient.partial_coordinates,
    );
    try Ops.accumulate(
        session,
        quotient.numerator_topology,
        quotient.source_evaluations,
        quotient.line_coefficients,
        quotient.partial_coordinates,
    );
    try Ops.combine(
        session,
        dispatch.circle.half_coset_initial_index,
        dispatch.circle.half_coset_step_size,
        quotient.combine_topology,
        quotient.group_points,
        quotient.first_linear_terms,
        quotient.partial_coordinates,
        quotient.result_coordinates,
    );
}

fn validate(
    prepared: *const plan_mod.PreparedPlan,
    ingress: *const canonical_ingress.Pack,
    views: *const types.Views,
) !void {
    const geometry = prepared.logical.geometry;
    const topology = prepared.quotient;
    const quotient = views.quotient;
    const sample_count = try add(
        geometry.main_columns,
        request.composition_column_count,
    );
    const output_rows = geometry.commitment_rows;
    const sample_count_u32 = try u32Count(sample_count);
    const output_rows_u32 = try u32Count(output_rows);
    if (sample_count != geometry.sampled_value_count or
        ingress.circle.domain_log_size != geometry.queryLogSize() or
        ingress.circle.half_coset_step_size == 0 or
        topology.source_count != sample_count_u32 or
        topology.source_stride_words != output_rows or
        topology.output_rows != output_rows_u32 or
        topology.prepared_terms.len != sample_count or
        topology.batch_terms.len != sample_count or
        topology.group_offsets.len != 2 or
        topology.group_term_indices.len != sample_count or
        topology.group_log_sizes.len != 1 or
        topology.partial_log_sizes.len != 1 or
        views.oods.sample_points.len != sample_count or
        views.oods.sampled_values.len != sample_count or
        quotient.challenge.len != 1 or
        quotient.term_points.len != sample_count or
        quotient.line_coefficients.len != try mul(sample_count, 3) or
        quotient.group_points.len != 1 or
        quotient.first_linear_terms.len != 1)
    {
        return error.InvalidKernelDescriptor;
    }

    if (quotient.prepared_groups.descriptors.len != sample_count or
        quotient.prepared_groups.sample_count != sample_count_u32 or
        quotient.prepared_groups.offsets.len != 2 or
        quotient.prepared_groups.term_indices.len != sample_count or
        quotient.prepared_groups.group_count != 1 or
        quotient.numerator_topology.terms.len != sample_count or
        quotient.numerator_topology.offsets.len != 2 or
        quotient.numerator_topology.group_log_sizes.len != 1 or
        quotient.numerator_topology.group_count != 1 or
        quotient.numerator_topology.max_output_size != output_rows_u32 or
        quotient.numerator_topology.source_count != sample_count_u32 or
        quotient.numerator_topology.source_stride_words != output_rows or
        quotient.numerator_topology.line_term_count != sample_count_u32 or
        quotient.combine_topology.partial_log_sizes.len != 1 or
        quotient.combine_topology.sample_count != 1 or
        quotient.combine_topology.domain_log_size !=
            geometry.queryLogSize() or
        quotient.combine_topology.partial_stride_words != output_rows)
    {
        return error.InvalidKernelDescriptor;
    }

    try validateMatrix(
        quotient.source_evaluations,
        sample_count,
        output_rows,
    );
    inline for (.{
        quotient.partial_coordinates.c0,
        quotient.partial_coordinates.c1,
        quotient.partial_coordinates.c2,
        quotient.partial_coordinates.c3,
    }) |partial| {
        try validateMatrix(partial, 1, output_rows);
    }
    inline for (.{
        quotient.result_coordinates.c0,
        quotient.result_coordinates.c1,
        quotient.result_coordinates.c2,
        quotient.result_coordinates.c3,
    }) |result| {
        if (result.len != output_rows)
            return error.InvalidKernelDescriptor;
    }
    try validateFriAlias(views, output_rows);
}

fn validateFriAlias(views: *const types.Views, rows: usize) !void {
    if (views.fri.layer_count == 0) return error.InvalidKernelDescriptor;
    const first = views.fri.layers[0].coordinates;
    try validateMatrix(first, 4, rows);
    const expected = [_]common.Words{
        try first.storage.sub(0, rows),
        try first.storage.sub(rows, rows),
        try first.storage.sub(try mul(2, rows), rows),
        try first.storage.sub(try mul(3, rows), rows),
    };
    const actual = [_]common.Words{
        views.quotient.result_coordinates.c0,
        views.quotient.result_coordinates.c1,
        views.quotient.result_coordinates.c2,
        views.quotient.result_coordinates.c3,
    };
    for (actual, expected) |result, layer| {
        if (!sameSlice(result, layer)) return error.InvalidKernelDescriptor;
    }
}

fn sameSlice(left: common.Words, right: common.Words) bool {
    return left.address == right.address and
        left.len == right.len and
        left.owner == right.owner and
        left.generation == right.generation;
}

fn validateMatrix(
    matrix: common.WordMatrix,
    columns: usize,
    stride: usize,
) !void {
    if (matrix.column_stride_words != stride or
        matrix.storage.len != try mul(columns, stride))
    {
        return error.InvalidKernelDescriptor;
    }
}

fn add(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.SizeOverflow;
}

fn u32Count(value: usize) !u32 {
    return std.math.cast(u32, value) orelse error.SizeOverflow;
}

fn mul(left: anytype, right: anytype) !usize {
    const left_usize = std.math.cast(usize, left) orelse
        return error.SizeOverflow;
    const right_usize = std.math.cast(usize, right) orelse
        return error.SizeOverflow;
    return std.math.mul(usize, left_usize, right_usize) catch
        error.SizeOverflow;
}

fn deviceSlice(
    comptime T: type,
    address: usize,
    len: usize,
) column.DeviceSlice(T) {
    return .{
        .address = address,
        .len = len,
        .owner = 7,
        .generation = 11,
    };
}

test "quotient contract preserves the five resident launch boundaries" {
    const FakeOps = struct {
        const Call = enum {
            prepare,
            finalize,
            zero,
            accumulate,
            combine,
        };
        var calls: [5]Call = undefined;
        var count: usize = 0;

        fn record(call: Call) void {
            calls[count] = call;
            count += 1;
        }

        pub fn prepareTerms(
            _: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
        ) !void {
            record(.prepare);
        }
        pub fn finalizeGroups(
            _: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
        ) !void {
            record(.finalize);
        }
        pub fn zeroOutputs(
            _: anytype,
            _: anytype,
            _: anytype,
        ) !void {
            record(.zero);
        }
        pub fn accumulate(
            _: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
        ) !void {
            record(.accumulate);
        }
        pub fn combine(
            _: anytype,
            _: u32,
            _: u32,
            _: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
        ) !void {
            record(.combine);
        }
    };

    const rows: usize = 16;
    const words = struct {
        fn at(address: usize, len: usize) common.Words {
            return deviceSlice(u32, address, len);
        }
        fn matrix(address: usize, columns: usize) common.WordMatrix {
            return .{
                .storage = at(address, columns * rows),
                .column_stride_words = rows,
            };
        }
    };
    const terms = deviceSlice(
        quotient_abi.PreparedTermDescriptor,
        0x1000,
        2,
    );
    const batch = deviceSlice(
        quotient_abi.BatchTermDescriptor,
        0x2000,
        2,
    );
    const group_offsets = words.at(0x3000, 2);
    const term_indices = words.at(0x3100, 2);
    const group_logs = words.at(0x3200, 1);
    const partial_logs = words.at(0x3300, 1);
    const partials = quotient_stage.CoordinateSlabs{
        .c0 = words.matrix(0x4000, 1),
        .c1 = words.matrix(0x5000, 1),
        .c2 = words.matrix(0x6000, 1),
        .c3 = words.matrix(0x7000, 1),
    };
    const quotient = types.Quotient{
        .challenge = deviceSlice(field.SecureField, 0x8000, 1),
        .prepared_terms = terms,
        .group_offsets = group_offsets,
        .group_term_indices = term_indices,
        .batch_terms = batch,
        .group_log_sizes = group_logs,
        .partial_log_sizes = partial_logs,
        .term_points = deviceSlice(field.SecureCirclePoint, 0x9000, 2),
        .line_coefficients = deviceSlice(field.SecureField, 0xa000, 6),
        .group_points = deviceSlice(field.SecureCirclePoint, 0xb000, 1),
        .first_linear_terms = deviceSlice(field.SecureField, 0xc000, 1),
        .partial_coordinates = partials,
        .result_coordinates = .{
            .c0 = words.at(0xd000, rows),
            .c1 = words.at(0xe000, rows),
            .c2 = words.at(0xf000, rows),
            .c3 = words.at(0x10000, rows),
        },
        .source_evaluations = words.matrix(0x11000, 2),
        .prepared_groups = .{
            .descriptors = terms,
            .sample_count = 2,
            .offsets = group_offsets,
            .term_indices = term_indices,
            .group_count = 1,
        },
        .numerator_topology = .{
            .offsets = group_offsets,
            .terms = batch,
            .group_log_sizes = group_logs,
            .group_count = 1,
            .max_output_size = @intCast(rows),
            .source_count = 2,
            .source_stride_words = rows,
            .line_term_count = 2,
        },
        .combine_topology = .{
            .partial_log_sizes = partial_logs,
            .sample_count = 1,
            .domain_log_size = 4,
            .partial_stride_words = rows,
        },
    };

    FakeOps.count = 0;
    var fake_session: u8 = 0;
    try executeWithOps(FakeOps, &fake_session, .{
        .circle = .{
            .domain_log_size = 4,
            .half_coset_initial_index = 1,
            .half_coset_step_size = 2,
            .barycentric_si0 = .{ .a = 0, .b = 0, .c = 0, .d = 0 },
            .vanishing_rotation = .{ .x = 1, .y = 0 },
            .composition_denominator_inverses = .{ 1, 1 },
        },
        .sample_points = deviceSlice(field.SecureCirclePoint, 0x12000, 2),
        .sampled_values = deviceSlice(field.SecureField, 0x13000, 2),
        .quotient = quotient,
    });
    try std.testing.expectEqualSlices(
        FakeOps.Call,
        &.{ .prepare, .finalize, .zero, .accumulate, .combine },
        FakeOps.calls[0..FakeOps.count],
    );
}
