//! Source-derived accounting, not a timing estimator or admitted proof layout.
const std = @import("std");
const A = @import("keccakf_authority.zig");
const T = @import("keccakf_tiled_kernel_v1.zig");
const Trace = @import("keccakf_trace.zig");
const Caller = @import("keccakf_caller.zig");
const Plan = @import("keccakf_interaction_plan.zig");
const Tables = @import("keccakf_table_component.zig");
fn domain(rows: usize) usize {
    return std.math.ceilPowerOfTwoAssert(usize, rows);
}
test "tiled Keccak table and caller costs are included across call census" {
    const old_width = Trace.Layout.preprocessed_columns + Trace.Layout.main_columns + Plan.interaction_column_count;
    const old_tables = (Tables.preprocessed_column_count + Tables.main_column_count + Tables.interaction_column_count) * (A.geometry.compact.chi_table_rows + A.geometry.compact.xor5_table_rows);
    const caller_main = Trace.Layout.main_columns - A.width_bits - A.geometry.parity_positions;
    const caller_interaction = 4 * (Caller.batch_count + 1); // original two I/O bridge events
    try std.testing.expectEqual(@as(usize, 284), caller_main);
    try std.testing.expectEqual(@as(usize, 324), caller_interaction);
    try std.testing.expectEqual(@as(usize, 110592), old_tables);
    const Full = @import("keccakf_throughput_interaction_plan_v1.zig");
    const Hybrid = @import("keccakf_xor_throughput_interaction_plan_v1.zig");
    for ([_]usize{ 2, 16, 128, 1024, 4096 }) |calls| {
        const rows = domain(((calls + 1) / 2) * 29);
        const original = old_width * rows + old_tables;
        const hybrid = (Trace.Layout.preprocessed_columns + Trace.Layout.main_columns + Hybrid.interaction_column_count) * rows + 12 * (8192 + 65536);
        const full = (Trace.Layout.preprocessed_columns + Trace.Layout.main_columns + Full.interaction_column_count) * rows + 12 * (2097152 + 65536);
        const profile = try @import("keccakf_adaptive_profile_v1.zig").compile(@intCast(calls));
        try std.testing.expectEqual(@min(original, @min(hybrid, full)), profile.costs.total_cells);
        std.debug.print("KECCAK_WIDE_MODEL calls={d} original={d} hybrid={d} full={d} selected={s} production_active=false\n", .{ calls, original, hybrid, full, @tagName(profile.mode) });
    }
    // Original caller-compatible upper-storage option keeps the complete original
    // metadata, I/O tuples and 160 caller events on the expanded tiled domain.
    // The kernel must still implement their equations; accounting is not admission.
    inline for (.{ 1, 5 }) |lanes| inline for (.{ false, true }) |chi_full| inline for (.{ false, true }) |xor_full| {
        const K = T.KernelWithTables(lanes, chi_full, xor_full);
        const interactions = 4 * ((K.chi_event_columns + 1) / 2 + (K.xor_event_columns + 1) / 2);
        const core_width = K.fixed_columns + K.main_columns + interactions;
        // Compact tuples have two packed coordinates, full tuples keep all six
        // coordinates. Individual outputs may NOT be packed without range proofs.
        const chi_table_cols: usize = if (chi_full) 12 else 8;
        const xor_table_cols: usize = if (xor_full) 12 else 8;
        const chi_rows: usize = if (chi_full) A.geometry.chi_table_rows else A.geometry.compact.chi_table_rows;
        const xor_rows = domain(if (xor_full) A.geometry.xor5_table_rows else A.geometry.compact.xor5_table_rows);
        const table_cells = chi_rows * chi_table_cols + xor_rows * xor_table_cols;
        for ([_]usize{ 2, 16, 128, 1024, 8192 }) |calls| {
            const slots = (calls + 1) / 2;
            const old_rows = domain(slots * 29);
            const rows = domain(slots * K.rows_per_slot);
            const core_cells = core_width * rows;
            const direct_caller_cells = (caller_main + caller_interaction) * rows;
            // A second, explicitly more expensive-in-witness option: retain the
            // original caller's state bits on its original domain, remove parity
            // and private lookup columns, connect a new 109-felt I/O bus to tiled
            // boundary bits. Count all duplicated state, four bridge columns
            // and two columns carrying the call identity.
            // This is a model only, not implemented or claimed as witness-once.
            const detached_caller_cells = (Trace.Layout.preprocessed_columns + caller_main + A.width_bits + caller_interaction) * old_rows + 6 * rows;
            const old_total = old_width * old_rows + old_tables;
            std.debug.print("KECCAK_COMPLETE_MODEL lanes={d} full_chi={} full_xor={} calls={d} rows={d} core_cells={d} tables={d} original_total={d} direct_caller_total={d} detached_caller_total={d} layouts_unqualified=true\n", .{ lanes, chi_full, xor_full, calls, rows, core_cells, table_cells, old_total, core_cells + table_cells + direct_caller_cells, core_cells + table_cells + detached_caller_cells });
        }
    };
}
