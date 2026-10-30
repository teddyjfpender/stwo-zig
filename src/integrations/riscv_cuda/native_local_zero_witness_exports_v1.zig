//! Canonical V7 local-zero instruction witnesses, mechanically compiled to GPU.
//! Input retirement records and immutable predecessor-column metadata replace
//! CPU-created field columns. Global register/RAM providers remain separate.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const trace = frontend.runner.trace;
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Envelope = frontend.air.x0_native_envelope;
pub const Pruned = Envelope.WitnessPlan;
const Native = @import("native_witness_exports_v1.zig");
pub fn Writer(comptime family: trace.OpcodeFamily) type {
    return struct {
        pub const base_columns = Native.Writer(family).column_count;
        pub const column_count = Envelope.mainColumnCount(family) catch @compileError("invalid local-zero family metadata");
        pub const groups = (column_count - base_columns) / 2;
        pub fn width() callconv(.c) u32 {
            return column_count;
        }
        pub fn runPruned(raw: *const Native.EncodedRow, recipe_words: [*]const u32, output: [*]u32, stride: usize, index: usize) callconv(.c) u32 {
            if (stride == 0 or index >= stride or stride > std.math.maxInt(usize) / column_count) return 3;
            const recipe: *const Pruned.Recipe = @ptrCast(@alignCast(recipe_words));
            if (recipe.width != base_columns or recipe.group_count != groups) return 4;
            var cells: [trace.MAX_FAMILY_COLUMNS]u32 = @splat(0);
            const result = Native.Writer(family).run(raw, &cells, 1, 0);
            if (result != 0) return result;
            const fields = @as([*]M, @ptrCast(&cells))[0..column_count];
            recipe.apply(fields[0..base_columns], fields[base_columns..column_count]) catch return 4;
            inline for (0..column_count) |c| output[c * stride + index] = cells[c];
            return 0;
        }
        pub fn run(raw: *const Native.EncodedRow, predecessors: *const [3]u32, output: [*]u32, stride: usize, index: usize) callconv(.c) u32 {
            if (stride == 0 or index >= stride or stride > std.math.maxInt(usize) / column_count) return 3;
            var cells: [trace.MAX_FAMILY_COLUMNS]u32 = @splat(0);
            const base_result = Native.Writer(family).run(raw, &cells, 1, 0);
            if (base_result != 0) return base_result;
            const fields = @as([*]M, @ptrCast(&cells))[0..column_count];
            Envelope.normalizePredecessorsWithColumns(family, fields[0..base_columns], predecessors[0..groups]) catch return 4;
            Envelope.fillHints(family, fields[0..base_columns], fields[base_columns..column_count]) catch return 5;
            inline for (0..column_count) |c| output[c * stride + index] = cells[c];
            return 0;
        }
    };
}
pub fn exportDeviceWriters() void {
    comptime {
        @setEvalBranchQuota(8_000_000);
        for (std.enums.values(trace.OpcodeFamily)) |family| {
            @export(&Writer(family).run, .{ .name = "stwo_riscv_localzero_row_" ++ @tagName(family) ++ "_v1" });
            @export(&Writer(family).width, .{ .name = "stwo_riscv_localzero_width_" ++ @tagName(family) ++ "_v1" });
        }
    }
}

pub fn exportPrunedDeviceWriters() void {
    comptime {
        @setEvalBranchQuota(8_000_000);
        for (std.enums.values(trace.OpcodeFamily)) |family| {
            @export(&Writer(family).runPruned, .{ .name = "stwo_riscv_localzero_pruned_row_" ++ @tagName(family) ++ "_v1" });
            @export(&Writer(family).width, .{ .name = "stwo_riscv_localzero_pruned_width_" ++ @tagName(family) ++ "_v1" });
        }
    }
}
