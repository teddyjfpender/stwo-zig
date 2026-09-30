//! Circuit base witness admission from the sorted preprocessed layout.
//! The CUDA kernels write all five gate component blocks and the 22 fixed
//! table multiplicity columns directly into the base commitment input.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const cuda = @import("stwo_cuda_backend");
const base = cuda.runtime.stages.circuit_base;
const common = cuda.runtime.stages.common;

const preprocessed = circuit.common.preprocessed;
pub const base_column_count: usize = 114;

const ids = .{
    .{preprocessed.EQ_COLUMN_IDS[0]},
    .{
        preprocessed.QM31_OPS_COLUMN_IDS[0], preprocessed.QM31_OPS_COLUMN_IDS[1],
        preprocessed.QM31_OPS_COLUMN_IDS[2], preprocessed.QM31_OPS_COLUMN_IDS[3],
        preprocessed.QM31_OPS_COLUMN_IDS[4], preprocessed.QM31_OPS_COLUMN_IDS[5],
        preprocessed.QM31_OPS_COLUMN_IDS[6],
    },
    .{
        preprocessed.TRIPLE_XOR_COLUMN_IDS[0], preprocessed.TRIPLE_XOR_COLUMN_IDS[1],
        preprocessed.TRIPLE_XOR_COLUMN_IDS[2], preprocessed.TRIPLE_XOR_COLUMN_IDS[3],
    },
    .{preprocessed.M31_TO_U32_COLUMN_IDS[0]},
    .{
        preprocessed.BLAKE_G_GATE_COLUMN_IDS[0], preprocessed.BLAKE_G_GATE_COLUMN_IDS[1],
        preprocessed.BLAKE_G_GATE_COLUMN_IDS[2], preprocessed.BLAKE_G_GATE_COLUMN_IDS[3],
        preprocessed.BLAKE_G_GATE_COLUMN_IDS[4], preprocessed.BLAKE_G_GATE_COLUMN_IDS[5],
        preprocessed.BLAKE_G_GATE_COLUMN_IDS[6], preprocessed.BLAKE_G_GATE_COLUMN_IDS[7],
        preprocessed.BLAKE_G_GATE_COLUMN_IDS[8], preprocessed.BLAKE_G_GATE_COLUMN_IDS[9],
    },
};

pub const Plan = struct {
    pp_indices: [base.gate_count][11]u8,
    row_counts: [base.gate_count]u32,
    first_permutation_row: u32,

    pub fn init(layout: *const preprocessed.ColumnLayout, first_permutation_row: usize) !Plan {
        var plan = Plan{
            .pp_indices = @splat(@splat(0)),
            .row_counts = undefined,
            .first_permutation_row = std.math.cast(u32, first_permutation_row) orelse return error.InvalidCircuitWitnessGeometry,
        };
        inline for (ids, 0..) |group, component| {
            const log = layout.logSize(group[0]) orelse return error.InvalidCircuitWitnessGeometry;
            if (log < 4 or log >= 31) return error.InvalidCircuitWitnessGeometry;
            plan.row_counts[component] = @as(u32, 1) << @intCast(log);
            inline for (group, 0..) |id, local| {
                var found: ?usize = null;
                for (layout.entries, 0..) |entry, index| {
                    if (std.mem.eql(u8, entry.id, id)) {
                        if (entry.log_size != log) return error.InvalidCircuitWitnessGeometry;
                        found = index;
                        break;
                    }
                }
                plan.pp_indices[component][local] = std.math.cast(u8, found orelse return error.InvalidCircuitWitnessGeometry) orelse return error.InvalidCircuitWitnessGeometry;
            }
        }
        try (base.Geometry{
            .gate = .qm31_ops,
            .row_count = plan.row_counts[1],
            .value_count = 1,
            .first_permutation_row = plan.first_permutation_row,
        }).validate();
        return plan;
    }

    pub fn execute(
        self: *const Plan,
        session: anytype,
        values: common.Words,
        preprocessed_columns: []const common.Words,
        base_columns: []const common.Words,
        error_flag: common.Words,
    ) !void {
        if (preprocessed_columns.len != preprocessed.N_PREPROCESSED_COLUMNS or
            base_columns.len != base_column_count or values.len == 0 or
            values.len % 4 != 0)
            return error.InvalidCircuitWitnessBuffers;
        const value_count = std.math.cast(u32, values.len / 4) orelse return error.InvalidCircuitWitnessBuffers;
        const Gate = base.Gate;
        const gates = [_]Gate{ .eq, .qm31_ops, .triple_xor, .m31_to_u32, .blake_g_gate };
        const counts = base_columns[base_column_count - base.count_lengths.len ..];
        try base.Native.clear(session, counts, error_flag);
        var offset: usize = 0;
        for (gates, 0..) |gate, component| {
            var pp: [11]common.Words = undefined;
            for (pp[0..base.pp_widths[component]], self.pp_indices[component][0..base.pp_widths[component]]) |*out, index|
                out.* = preprocessed_columns[index];
            try base.Native.gate(session, .{
                .gate = gate,
                .row_count = self.row_counts[component],
                .value_count = value_count,
                .first_permutation_row = self.first_permutation_row,
            }, .{
                .values = values,
                .preprocessed = pp[0..base.pp_widths[component]],
                .outputs = base_columns[offset..][0..base.output_widths[component]],
                .counts = counts,
                .error_flag = error_flag,
            });
            offset += base.output_widths[component];
        }
        std.debug.assert(offset + counts.len == base_columns.len);
    }
};

test "circuit base witness maps stable sorted preprocessed columns to CUDA gate inputs" {
    const sizes = @import("stwo_circuit_cpu_integration").air.recorded_sizes;
    const layout = try preprocessed.ColumnLayout.fromComponentSizes(sizes);
    const plan = try Plan.init(&layout, 0);
    const widths = circuit.witness.trace.traceWidths();
    var total: usize = 0;
    for (widths) |width| total += width;
    try std.testing.expectEqual(base_column_count, total);
    for (base.output_widths, widths[0..base.gate_count]) |actual, expected|
        try std.testing.expectEqual(expected, actual);
    const table_widths = [_]usize{ 2, 16, 1, 1, 1, 1 };
    for (table_widths, widths[base.gate_count..]) |actual, expected|
        try std.testing.expectEqual(expected, actual);
    const sizes_by_group = [_]usize{ 1 << 16, 1 << 20, 1 << 8, 1 << 14, 1 << 18, 1 << 16 };
    var table_index: usize = 0;
    for (table_widths, sizes_by_group) |width, size| {
        for (base.count_lengths[table_index..][0..width]) |actual|
            try std.testing.expectEqual(size, actual);
        table_index += width;
    }
    inline for (ids, 0..) |group, component| {
        inline for (group, 0..) |id, local| {
            try std.testing.expectEqualStrings(id, layout.entries[plan.pp_indices[component][local]].id);
            try std.testing.expectEqual(plan.row_counts[component], @as(u32, 1) << @intCast(layout.entries[plan.pp_indices[component][local]].log_size));
        }
    }
}

test "resident circuit witness native dispatch binds to a CUDA session" {
    const Dispatch = struct {
        fn run(plan: *const Plan, session: *cuda.runtime.NativeSession, values: common.Words, pp: []const common.Words, columns: []const common.Words, error_flag: common.Words) !void {
            try plan.execute(session, values, pp, columns, error_flag);
        }
    };
    const entry: *const fn (*const Plan, *cuda.runtime.NativeSession, common.Words, []const common.Words, []const common.Words, common.Words) anyerror!void = &Dispatch.run;
    try std.testing.expect(@intFromPtr(entry) != 0);
}
