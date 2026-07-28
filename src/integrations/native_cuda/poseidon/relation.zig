//! Exact Poseidon policy for the generic resident relation graph.

const std = @import("std");
const relation_abi = @import("stwo_cuda_backend").abi.stages.relation;
const relation_stage = @import("stwo_cuda_backend").runtime.stages.relation;
const input = @import("../../../examples/poseidon/input.zig");

pub const source_pointer_count: u32 =
    input.N_INSTANCES_PER_ROW * input.N_STATE * 2;
pub const interaction_column_count: u32 =
    input.N_INSTANCES_PER_ROW;
pub const output_coordinate_count: u32 =
    interaction_column_count * 4;
pub const max_alpha_powers: u32 = input.N_STATE;

/// Sources are compacted as `[initial 16, final 16]` for each packed
/// permutation. Each fraction is `(final - initial) / (initial * final)`,
/// exactly matching the CPU LogUp interaction.
pub const descriptors = descriptorsForTrace();

pub const Plan = struct {
    geometry: [1]relation_abi.Geometry,

    pub fn init(log_rows: u32) !Plan {
        if (log_rows >= 31) return error.InvalidLogSize;
        const rows = @as(u32, 1) << @intCast(log_rows);
        const row_blocks = ceilDiv(rows, relation_abi.launch_block);
        const pair_blocks = try checkedMul(
            row_blocks,
            interaction_column_count,
        );
        const inverse_blocks = ceilDiv(
            try checkedMul(rows, interaction_column_count),
            relation_abi.inverse_block_values,
        );
        var result = Plan{ .geometry = .{.{
            .pair_first = 0,
            .pair_blocks = pair_blocks,
            .inverse_first = 0,
            .inverse_blocks = inverse_blocks,
            .row_first = 0,
            .row_blocks = row_blocks,
            .rows = rows,
            .columns = interaction_column_count,
            .real_rows = rows,
            .source_offset_rows = 0,
            .inverse_rows = inverseRows(log_rows),
        }} };
        try result.validate();
        return result;
    }

    pub fn topology(self: *const Plan) relation_stage.Topology {
        const geometry = self.geometry[0];
        return .{
            .geometry = self.geometry[0..],
            .max_alpha_powers = max_alpha_powers,
            .total_pair_blocks = geometry.pair_blocks,
            .total_inverse_blocks = geometry.inverse_blocks,
            .total_chain_blocks = geometry.row_blocks,
            .total_row_blocks = geometry.row_blocks,
        };
    }

    pub fn validate(self: *const Plan) !void {
        const bounds = relation_abi.SourceBounds{
            .source_pointer_count = source_pointer_count,
            .max_alpha_powers = max_alpha_powers,
        };
        for (descriptors) |descriptor| try descriptor.validate(bounds);
        try self.topology().validate();
    }
};

fn descriptorsForTrace() [interaction_column_count]relation_abi.ColumnDescriptor {
    var result: [interaction_column_count]relation_abi.ColumnDescriptor =
        undefined;
    for (&result, 0..) |*descriptor, rep| {
        const first = @as(u32, @intCast(rep * input.N_STATE * 2));
        descriptor.* = relation_abi.ColumnDescriptor.pair(
            tuple(first, false),
            tuple(first + input.N_STATE, true),
        );
    }
    return result;
}

fn tuple(first: u32, negative: bool) relation_abi.UseDescriptor {
    return relation_abi.UseDescriptor.init(
        .projected_columns_no_id,
        first,
        input.N_STATE,
        0,
        .one,
        0,
        negative,
    );
}

fn inverseRows(log_rows: u32) u32 {
    return if (log_rows == 0)
        1
    else
        @as(u32, 1) << @intCast(31 - log_rows);
}

fn ceilDiv(value: u32, divisor: u32) u32 {
    return (value + divisor - 1) / divisor;
}

fn checkedMul(left: u32, right: u32) !u32 {
    return std.math.mul(u32, left, right) catch error.GeometryOverflow;
}

test "exact Poseidon relation topology is immutable and host validated" {
    const plan = try Plan.init(10);
    const topology = plan.topology();
    try std.testing.expectEqual(@as(usize, 1), topology.geometry.len);
    try std.testing.expectEqual(@as(u32, 16), topology.max_alpha_powers);
    try std.testing.expectEqual(@as(u32, 8), topology.geometry[0].columns);
    try std.testing.expectEqual(@as(u32, 2), descriptors[0].arity);
    try std.testing.expectEqual(@as(u32, 0), descriptors[0].first.negative);
    try std.testing.expectEqual(@as(u32, 1), descriptors[0].second.negative);
    try std.testing.expectEqual(
        @as(u32, input.N_STATE),
        descriptors[0].second.tuple_argument,
    );
}

test "generic descriptor rows equal exact CPU Poseidon fractions" {
    const M31 = @import("stwo_core").fields.m31.M31;
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    const interaction = @import(
        "../../../examples/poseidon/interaction.zig",
    );
    const allocator = std.testing.allocator;

    const trace = try input.genTrace(
        allocator,
        .{ .log_n_instances = 7 },
    );
    defer input.deinitTrace(allocator, trace);
    const lookup = interaction.LookupElements.fromZAlpha(
        QM31.fromU32Unchecked(37, 41, 43, 47),
        QM31.fromU32Unchecked(3, 5, 7, 11),
    );

    var sources: [source_pointer_count][]const M31 = undefined;
    for (0..input.N_INSTANCES_PER_ROW) |rep| {
        const source_base = rep * input.N_STATE * 2;
        const trace_base = rep * input.N_COLUMNS_PER_REP;
        const final_base =
            trace_base + input.N_COLUMNS_PER_REP - input.N_STATE;
        for (0..input.N_STATE) |lane| {
            sources[source_base + lane] = trace[trace_base + lane];
            sources[source_base + input.N_STATE + lane] =
                trace[final_base + lane];
        }
    }

    for (0..trace[0].len) |row| {
        for (0..input.N_INSTANCES_PER_ROW) |rep| {
            const actual = try evaluateColumn(
                descriptors[rep],
                &sources,
                row,
                lookup,
            );
            var initial: [input.N_STATE]M31 = undefined;
            var final: [input.N_STATE]M31 = undefined;
            const base = rep * input.N_STATE * 2;
            for (0..input.N_STATE) |lane| {
                initial[lane] = sources[base + lane][row];
                final[lane] = sources[base + input.N_STATE + lane][row];
            }
            const d0 = lookup.combineBase(initial);
            const d1 = lookup.combineBase(final);
            const expected = try d1.sub(d0).div(d0.mul(d1));
            try std.testing.expect(actual.eql(expected));
        }
    }
}

fn evaluateColumn(
    descriptor: relation_abi.ColumnDescriptor,
    sources: []const []const @import("stwo_core").fields.m31.M31,
    row: usize,
    lookup: @import(
        "../../../examples/poseidon/interaction.zig",
    ).LookupElements,
) !@import("stwo_core").fields.qm31.QM31 {
    const first = evaluateUse(descriptor.first, sources, row, lookup);
    const second = evaluateUse(descriptor.second, sources, row, lookup);
    return try first.multiplicity.mul(second.denominator)
        .add(second.multiplicity.mul(first.denominator))
        .div(first.denominator.mul(second.denominator));
}

fn evaluateUse(
    use: relation_abi.UseDescriptor,
    sources: []const []const @import("stwo_core").fields.m31.M31,
    row: usize,
    lookup: @import(
        "../../../examples/poseidon/interaction.zig",
    ).LookupElements,
) struct {
    multiplicity: @import("stwo_core").fields.qm31.QM31,
    denominator: @import("stwo_core").fields.qm31.QM31,
} {
    const M31 = @import("stwo_core").fields.m31.M31;
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    const first = @as(usize, @intCast(use.tuple_argument));
    var denominator = lookup.z.neg();
    for (0..use.tuple_words) |word| {
        denominator = denominator.add(
            lookup.alpha_powers[word].mulM31(
                sources[first + word][row],
            ),
        );
    }
    const base = if (use.negative == 0) M31.one() else M31.one().neg();
    return .{
        .multiplicity = QM31.fromBase(base),
        .denominator = denominator,
    };
}
