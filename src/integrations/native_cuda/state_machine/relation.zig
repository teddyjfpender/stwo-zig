//! Exact two-component State Machine v2 policy for the generic relation stage.

const std = @import("std");
const relation_abi = @import(
    "../../../backends/cuda/abi/stages/relation.zig",
);
const relation_stage = @import(
    "../../../backends/cuda/runtime/stages/relation.zig",
);

pub const instance_count: u32 = 2;
pub const source_pointer_count: u32 = 2;
pub const output_coordinates_per_instance: u32 = 4;
pub const interaction_columns_per_instance: u32 = 1;
pub const max_alpha_powers: u32 = 2;

pub const x_descriptors = [_]relation_abi.ColumnDescriptor{
    transitionDescriptor(0),
};
pub const y_descriptors = [_]relation_abi.ColumnDescriptor{
    transitionDescriptor(1),
};

pub const Plan = struct {
    geometry: [instance_count]relation_abi.Geometry,

    pub fn init(log_n_rows: u32) !Plan {
        if (log_n_rows < 5 or log_n_rows >= 31)
            return error.InvalidLogSize;
        var geometry: [instance_count]relation_abi.Geometry = undefined;
        var pair_cursor: u32 = 0;
        var inverse_cursor: u32 = 0;
        var row_cursor: u32 = 0;
        inline for (0..instance_count) |index| {
            const log_rows = log_n_rows - @as(u32, @intCast(index));
            const rows = @as(u32, 1) << @intCast(log_rows);
            const row_blocks = ceilDiv(rows, relation_abi.launch_block);
            const pair_blocks = row_blocks;
            const inverse_blocks = ceilDiv(
                rows,
                relation_abi.inverse_block_values,
            );
            geometry[index] = .{
                .pair_first = pair_cursor,
                .pair_blocks = pair_blocks,
                .inverse_first = inverse_cursor,
                .inverse_blocks = inverse_blocks,
                .row_first = row_cursor,
                .row_blocks = row_blocks,
                .rows = rows,
                .columns = interaction_columns_per_instance,
                .real_rows = rows,
                .source_offset_rows = 0,
                .inverse_rows = inverseRows(log_rows),
            };
            pair_cursor = try checkedAdd(pair_cursor, pair_blocks);
            inverse_cursor = try checkedAdd(
                inverse_cursor,
                inverse_blocks,
            );
            row_cursor = try checkedAdd(row_cursor, row_blocks);
        }
        var result = Plan{ .geometry = geometry };
        try result.validate();
        return result;
    }

    pub fn topology(self: *const Plan) relation_stage.Topology {
        const last = self.geometry[instance_count - 1];
        return .{
            .geometry = self.geometry[0..],
            .max_alpha_powers = max_alpha_powers,
            .total_pair_blocks = last.pair_first + last.pair_blocks,
            .total_inverse_blocks = last.inverse_first + last.inverse_blocks,
            .total_chain_blocks = last.row_first + last.row_blocks,
            .total_row_blocks = last.row_first + last.row_blocks,
        };
    }

    pub fn validate(self: *const Plan) !void {
        const bounds = relation_abi.SourceBounds{
            .source_pointer_count = source_pointer_count,
            .max_alpha_powers = max_alpha_powers,
        };
        for (x_descriptors) |descriptor| try descriptor.validate(bounds);
        for (y_descriptors) |descriptor| try descriptor.validate(bounds);
        try self.topology().validate();
    }
};

fn transitionDescriptor(
    increment_coordinate: u32,
) relation_abi.ColumnDescriptor {
    return relation_abi.ColumnDescriptor.pair(
        relation_abi.UseDescriptor.init(
            .projected_columns_no_id,
            0,
            2,
            0,
            .one,
            0,
            false,
        ),
        relation_abi.UseDescriptor.init(
            .affine_projected_columns_no_id,
            0,
            2,
            increment_coordinate,
            .one,
            0,
            true,
        ),
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

fn checkedAdd(left: u32, right: u32) !u32 {
    return std.math.add(u32, left, right) catch
        error.GeometryOverflow;
}

test "State v2 relation topology retains both mixed-height components" {
    const plan = try Plan.init(16);
    try std.testing.expectEqual(@as(usize, 2), plan.topology().geometry.len);
    try std.testing.expectEqual(@as(u32, 1 << 16), plan.geometry[0].rows);
    try std.testing.expectEqual(@as(u32, 1 << 15), plan.geometry[1].rows);
    try std.testing.expectEqual(
        @as(u32, @intFromEnum(
            relation_abi.TupleKind.affine_projected_columns_no_id,
        )),
        x_descriptors[0].second.tuple_kind,
    );
    try std.testing.expectEqual(@as(u32, 0), x_descriptors[0].second.relation_id);
    try std.testing.expectEqual(@as(u32, 1), y_descriptors[0].second.relation_id);
}

test "generic State descriptors equal exact CPU transition fractions" {
    const M31 = @import("stwo_core").fields.m31.M31;
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    const cpu_statement = @import(
        "../../../examples/state_machine/statement.zig",
    );
    const elements = cpu_statement.Elements{
        .z = QM31.fromU32Unchecked(37, 41, 43, 47),
        .alpha = QM31.fromU32Unchecked(3, 5, 7, 11),
    };
    const state = [2]M31{
        M31.fromU64(29),
        M31.fromU64(31),
    };
    inline for (.{ x_descriptors[0], y_descriptors[0] }, 0..) |
        descriptor,
        coordinate,
    | {
        const actual = try evaluateDescriptor(
            descriptor,
            state,
            elements,
        );
        var output = state;
        output[coordinate] = output[coordinate].add(M31.one());
        const input_denominator = elements.combine(state);
        const output_denominator = elements.combine(output);
        const expected = try output_denominator
            .sub(input_denominator)
            .div(input_denominator.mul(output_denominator));
        try std.testing.expect(actual.eql(expected));
    }
}

fn evaluateDescriptor(
    descriptor: relation_abi.ColumnDescriptor,
    state: [2]@import("stwo_core").fields.m31.M31,
    elements: @import(
        "../../../examples/state_machine/statement.zig",
    ).Elements,
) !@import("stwo_core").fields.qm31.QM31 {
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    const first = combineUse(descriptor.first, state, elements);
    const second = combineUse(descriptor.second, state, elements);
    const first_multiplicity = QM31.one();
    const second_multiplicity = QM31.one().neg();
    return first_multiplicity.mul(second)
        .add(second_multiplicity.mul(first))
        .div(first.mul(second));
}

fn combineUse(
    use: relation_abi.UseDescriptor,
    state: [2]@import("stwo_core").fields.m31.M31,
    elements: @import(
        "../../../examples/state_machine/statement.zig",
    ).Elements,
) @import("stwo_core").fields.qm31.QM31 {
    const M31 = @import("stwo_core").fields.m31.M31;
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    var tuple = state;
    if (use.tuple_kind == @intFromEnum(
        relation_abi.TupleKind.affine_projected_columns_no_id,
    )) {
        const coordinate: usize = @intCast(use.relation_id);
        tuple[coordinate] = tuple[coordinate].add(M31.one());
    }
    return QM31.fromBase(tuple[0])
        .add(elements.alpha.mulM31(tuple[1]))
        .sub(elements.z);
}
