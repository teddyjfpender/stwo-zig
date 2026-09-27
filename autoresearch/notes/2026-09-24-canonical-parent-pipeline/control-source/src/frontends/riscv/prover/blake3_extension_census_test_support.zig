//! Census authenticated canonical parent geometry without proving the parent.
const std = @import("std");
const rows = @import("../recursion/air/blake3_native_parent_rows.zig");
const preparation = @import("../recursion/blake3_execution_parent_preparation.zig");
pub fn check(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8) !void {
    var timer = try std.time.Timer.start();
    const state = try preparation.State.init(a, admitted, capture, expected, 2);
    defer state.deinit();
    const graph_ns = timer.read();
    try @import("blake3_hash_census_test_support.zig").check(a, &capture.proof, state);
    try rows.fusionCensus(a, state.sources());
    timer.reset();
    var prepared = try state.finish();
    defer prepared.deinit();
    const layout_ns = timer.read();
    var total_main_bytes: usize = 0;
    inline for (rows.Airs, 0..) |Air, index| {
        const live = prepared.rows.fixed[index].len;
        const padded = prepared.rows.main[index][0].values.len;
        var bytes: usize = 0;
        for (prepared.rows.main[index]) |column| bytes += column.values.len * @sizeOf(@import("stwo_core").fields.m31.M31);
        total_main_bytes += bytes;
        std.debug.print("BLAKE3_PARENT_ROW_CENSUS air={d} type={s} live={d} padded={d} main_columns={d} preprocessed_columns={d} interaction_columns={d} main_bytes={d}\n", .{ index, @typeName(Air), live, padded, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.PREPROCESSED_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT, bytes });
    }
    std.debug.print("BLAKE3_PARENT_ROW_CENSUS_TOTAL child_queries={d} child_pow_bits={d} graph_preparation_ns={d} row_layout_ns={d} main_bytes={d} retained_bytes={d} parent_proved=false\n", .{ admitted.config.fri_config.n_queries, admitted.config.pow_bits, graph_ns, layout_ns, total_main_bytes, try prepared.rows.retainedBytes() });
}
