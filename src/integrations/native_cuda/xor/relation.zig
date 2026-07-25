//! Exact XOR truth-table policy for the generic resident relation graph.

const std = @import("std");
const relation_abi = @import(
    "../../../backends/cuda/abi/stages/relation.zig",
);
const relation_stage = @import(
    "../../../backends/cuda/runtime/stages/relation.zig",
);

pub const source_pointer_count: u32 = 7;
pub const output_coordinate_count: u32 = 4;
pub const interaction_column_count: u32 = 1;
pub const max_alpha_powers: u32 = 3;

/// Pointer-table order keeps each three-word lookup tuple contiguous.
pub const Source = enum(u32) {
    table_a = 0,
    table_b = 1,
    table_c = 2,
    multiplicity = 3,
    a = 4,
    b = 5,
    c = 6,
};

pub const descriptors = [interaction_column_count]relation_abi.ColumnDescriptor{
    relation_abi.ColumnDescriptor.pair(
        projectedTuple(.table_a, .source_column, .multiplicity, false),
        projectedTuple(.a, .one, .a, true),
    ),
};

pub const Plan = struct {
    geometry: [1]relation_abi.Geometry,

    pub fn init(log_rows: u32) !Plan {
        if (log_rows < 2 or log_rows >= 31)
            return error.InvalidLogSize;
        const rows = @as(u32, 1) << @intCast(log_rows);
        const row_blocks = ceilDiv(rows, relation_abi.launch_block);
        const inverse_blocks = ceilDiv(
            rows,
            relation_abi.inverse_block_values,
        );
        var result = Plan{ .geometry = .{.{
            .pair_first = 0,
            .pair_blocks = row_blocks,
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

fn projectedTuple(
    first: Source,
    multiplicity_kind: relation_abi.MultiplicityKind,
    multiplicity_source: Source,
    negative: bool,
) relation_abi.UseDescriptor {
    return relation_abi.UseDescriptor.init(
        .projected_columns_no_id,
        @intFromEnum(first),
        3,
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

test "exact XOR relation topology is immutable and host validated" {
    const plan = try Plan.init(14);
    const topology = plan.topology();
    try std.testing.expectEqual(@as(usize, 1), topology.geometry.len);
    try std.testing.expectEqual(@as(u32, 3), topology.max_alpha_powers);
    try std.testing.expectEqual(@as(u32, 2), descriptors[0].arity);
    try std.testing.expectEqual(
        @as(u32, 3),
        descriptors[0].first.tuple_words,
    );
    try std.testing.expectEqual(
        @as(u32, 1),
        descriptors[0].second.negative,
    );
    try std.testing.expectEqual(
        @as(u32, @intFromEnum(Source.multiplicity)),
        descriptors[0].first.multiplicity_argument,
    );
}

test "generic descriptor rows equal exact CPU XOR relation fractions" {
    const M31 = @import("stwo_core").fields.m31.M31;
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    const cpu_input = @import("../../../examples/xor/input.zig");
    const cpu_interaction = @import("../../../examples/xor/interaction.zig");

    var prepared = try cpu_input.prepare(std.testing.allocator, .{
        .log_size = 5,
        .log_step = 2,
        .offset = 3,
    });
    defer prepared.deinit(std.testing.allocator);
    const preprocessed = prepared.trace.preprocessed.columns.?;
    const main = prepared.trace.main.columns.?;
    const lookup = cpu_interaction.LookupElements{
        .z = QM31.fromU32Unchecked(37, 41, 43, 47),
        .alpha = QM31.fromU32Unchecked(3, 5, 7, 11),
    };
    const sources = [_][]const M31{
        preprocessed[@intFromEnum(cpu_input.Preprocessed.table_a)].values,
        preprocessed[@intFromEnum(cpu_input.Preprocessed.table_b)].values,
        preprocessed[@intFromEnum(cpu_input.Preprocessed.table_c)].values,
        main[@intFromEnum(cpu_input.Main.multiplicity)].values,
        main[@intFromEnum(cpu_input.Main.a)].values,
        main[@intFromEnum(cpu_input.Main.b)].values,
        main[@intFromEnum(cpu_input.Main.c)].values,
    };

    var claimed_sum = QM31.zero();
    for (0..main[0].values.len) |row| {
        const actual = try evaluateColumn(
            descriptors[0],
            &sources,
            row,
            lookup,
        );
        const table = lookup.combineBase(
            sources[@intFromEnum(Source.table_a)][row],
            sources[@intFromEnum(Source.table_b)][row],
            sources[@intFromEnum(Source.table_c)][row],
        );
        const execution = lookup.combineBase(
            sources[@intFromEnum(Source.a)][row],
            sources[@intFromEnum(Source.b)][row],
            sources[@intFromEnum(Source.c)][row],
        );
        const expected = try QM31.fromBase(
            sources[@intFromEnum(Source.multiplicity)][row],
        ).div(table);
        const negative_execution = (try QM31.one().div(execution)).neg();
        try std.testing.expect(actual.eql(expected.add(negative_execution)));
        claimed_sum = claimed_sum.add(actual);
    }
    try std.testing.expect(claimed_sum.isZero());
}

fn evaluateColumn(
    descriptor: relation_abi.ColumnDescriptor,
    sources: []const []const @import("stwo_core").fields.m31.M31,
    row: usize,
    lookup: @import(
        "../../../examples/xor/interaction.zig",
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
    lookup: @import(
        "../../../examples/xor/interaction.zig",
    ).LookupElements,
) !struct {
    fraction: @import("stwo_core").fields.qm31.QM31,
    multiplicity: @import("stwo_core").fields.qm31.QM31,
    denominator: @import("stwo_core").fields.qm31.QM31,
} {
    const M31 = @import("stwo_core").fields.m31.M31;
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    const first = @as(usize, @intCast(use.tuple_argument));
    var power = QM31.one();
    var denominator = lookup.z.neg();
    for (0..use.tuple_words) |word| {
        denominator = denominator.add(
            power.mulM31(sources[first + word][row]),
        );
        power = power.mul(lookup.alpha);
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
