//! Exact Plonk/LogUp policy for the generic resident relation graph.

const std = @import("std");
const relation_abi = @import("stwo_cuda_backend").abi.stages.relation;
const relation_stage = @import("stwo_cuda_backend").runtime.stages.relation;

pub const source_pointer_count: u32 = 7;
pub const output_coordinate_count: u32 = 8;
pub const interaction_column_count: u32 = 2;
pub const max_alpha_powers: u32 = 2;

/// Pointer-table order is policy data. Pairing each wire with its value makes
/// all three exact Plonk tuples contiguous under the generic descriptor ABI.
pub const Source = enum(u32) {
    a_wire = 0,
    a_value = 1,
    b_wire = 2,
    b_value = 3,
    c_wire = 4,
    c_value = 5,
    multiplicity = 6,
};

pub const descriptors = [interaction_column_count]relation_abi.ColumnDescriptor{
    relation_abi.ColumnDescriptor.pair(
        directTuple(.a_wire, .one, .a_wire, false),
        directTuple(.b_wire, .one, .a_wire, false),
    ),
    relation_abi.ColumnDescriptor.single(
        directTuple(
            .c_wire,
            .source_column,
            .multiplicity,
            true,
        ),
    ),
};

pub const Plan = struct {
    geometry: [1]relation_abi.Geometry,

    pub fn init(log_rows: u32) !Plan {
        if (log_rows < 4 or log_rows >= 31)
            return error.InvalidLogSize;
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

fn directTuple(
    first: Source,
    multiplicity_kind: relation_abi.MultiplicityKind,
    multiplicity_source: Source,
    negative: bool,
) relation_abi.UseDescriptor {
    return relation_abi.UseDescriptor.init(
        .projected_columns_no_id,
        @intFromEnum(first),
        2,
        0,
        multiplicity_kind,
        @intFromEnum(multiplicity_source),
        negative,
    );
}

fn inverseRows(log_rows: u32) u32 {
    return if (log_rows == 0) 1 else @as(u32, 1) << @intCast(31 - log_rows);
}

fn ceilDiv(value: u32, divisor: u32) u32 {
    return (value + divisor - 1) / divisor;
}

fn checkedMul(left: u32, right: u32) !u32 {
    return std.math.mul(u32, left, right) catch error.GeometryOverflow;
}

test "exact Plonk relation topology is immutable and host validated" {
    const plan = try Plan.init(14);
    const topology = plan.topology();
    try std.testing.expectEqual(@as(usize, 1), topology.geometry.len);
    try std.testing.expectEqual(@as(u32, 2), topology.max_alpha_powers);
    try std.testing.expectEqual(@as(u32, 2), descriptors[0].arity);
    try std.testing.expectEqual(@as(u32, 1), descriptors[1].arity);
    try std.testing.expectEqual(
        @as(u32, 1),
        descriptors[1].first.negative,
    );
    try std.testing.expectEqual(
        @as(u32, @intFromEnum(Source.multiplicity)),
        descriptors[1].first.multiplicity_argument,
    );
}

test "generic descriptor rows equal exact CPU Plonk relation fractions" {
    const M31 = @import("stwo_core").fields.m31.M31;
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    const cpu_input = @import("../../../examples/plonk_logup/input.zig");
    const cpu_interaction = @import(
        "../../../examples/plonk_logup/interaction.zig",
    );

    var trace = try cpu_input.genTrace(
        std.testing.allocator,
        .{ .log_n_rows = 4 },
    );
    defer cpu_input.deinitTrace(std.testing.allocator, &trace);
    const lookup = cpu_interaction.LookupElements{
        .z = QM31.fromU32Unchecked(37, 41, 43, 47).toM31Array(),
        .alpha = QM31.fromU32Unchecked(3, 5, 7, 11).toM31Array(),
    };
    const sources = [_][]const M31{
        trace.preprocessed[0],
        trace.main[1],
        trace.preprocessed[1],
        trace.main[2],
        trace.preprocessed[2],
        trace.main[3],
        trace.main[0],
    };

    var claimed_sum = QM31.zero();
    for (0..trace.main[0].len) |row| {
        const first = try evaluateColumn(
            descriptors[0],
            &sources,
            row,
            &lookup,
        );
        const second = try evaluateColumn(
            descriptors[1],
            &sources,
            row,
            &lookup,
        );
        const q0 = lookup.combineBase(
            trace.preprocessed[0][row],
            trace.main[1][row],
        );
        const q1 = lookup.combineBase(
            trace.preprocessed[1][row],
            trace.main[2][row],
        );
        const q2 = lookup.combineBase(
            trace.preprocessed[2][row],
            trace.main[3][row],
        );
        const expected_first = try q0.add(q1).div(q0.mul(q1));
        const expected_second = try QM31.fromBase(trace.main[0][row])
            .neg()
            .div(q2);
        try std.testing.expect(first.eql(expected_first));
        try std.testing.expect(second.eql(expected_second));
        claimed_sum = claimed_sum.add(first.add(second));
    }
    try std.testing.expect(!claimed_sum.isZero());
}

fn evaluateColumn(
    descriptor: relation_abi.ColumnDescriptor,
    sources: []const []const @import("stwo_core").fields.m31.M31,
    row: usize,
    lookup: *const @import(
        "../../../examples/plonk_logup/interaction.zig",
    ).LookupElements,
) !@import("stwo_core").fields.qm31.QM31 {
    const first = try evaluateUse(descriptor.first, sources, row, lookup);
    if (descriptor.arity == 1) return first.fraction;
    const second = try evaluateUse(descriptor.second, sources, row, lookup);
    return first.multiplicity.mul(second.denominator)
        .add(second.multiplicity.mul(first.denominator))
        .div(first.denominator.mul(second.denominator));
}

fn evaluateUse(
    use: relation_abi.UseDescriptor,
    sources: []const []const @import("stwo_core").fields.m31.M31,
    row: usize,
    lookup: *const @import(
        "../../../examples/plonk_logup/interaction.zig",
    ).LookupElements,
) !struct {
    fraction: @import("stwo_core").fields.qm31.QM31,
    multiplicity: @import("stwo_core").fields.qm31.QM31,
    denominator: @import("stwo_core").fields.qm31.QM31,
} {
    const M31 = @import("stwo_core").fields.m31.M31;
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    const first = @as(usize, @intCast(use.tuple_argument));
    const alpha = QM31.fromM31Array(lookup.alpha);
    var power = QM31.one();
    var denominator = QM31.fromM31Array(lookup.z).neg();
    for (0..use.tuple_words) |word| {
        denominator = denominator.add(
            power.mulM31(sources[first + word][row]),
        );
        power = power.mul(alpha);
    }
    var multiplicity = switch (std.meta.intToEnum(
        relation_abi.MultiplicityKind,
        use.multiplicity_kind,
    ) catch return error.InvalidKernelDescriptor) {
        .one => M31.one(),
        .source_column => sources[use.multiplicity_argument][row],
        else => return error.InvalidKernelDescriptor,
    };
    if (use.negative != 0) multiplicity = M31.zero().sub(multiplicity);
    const secure_multiplicity = QM31.fromBase(multiplicity);
    return .{
        .fraction = try secure_multiplicity.div(denominator),
        .multiplicity = secure_multiplicity,
        .denominator = denominator,
    };
}
