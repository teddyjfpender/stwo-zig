//! Diagnostic export of per-component committed widths (fixed, main,
//! interaction) for the cells-weighted canonical-rung tax (M4.0 open item 2).
//! Prints one `RV64_M5_WIDTHS {json}` line; changes no prover behaviour.
const std = @import("std");
const G = @import("../../word16_execution/geometry.zig");
const T = @import("../services/types.zig");
const Plan = @import("plan.zig");

fn emit(w: anytype, first: *bool, name: []const u8, widths: [3]usize) !void {
    if (!first.*) try w.writeAll(",");
    first.* = false;
    try w.print("\"{s}\":[{d},{d},{d}]", .{ name, widths[0], widths[1], widths[2] });
}
test "canon-native export per-component widths of the v3 GKR CPU layout" {
    const layout = Plan.CpuLayout.forGkrProfile(.ethereum_services_v3);
    // Every optional role present so its width is reported.
    const g = G.Geometry{ .cpu_log = 22, .alu_log = 18, .alu_tail_log = 16, .binary_log = 17, .binary_tail_log = 16, .shift_log = 17, .shift_tail_log = 15, .jalr_log = 16, .division_log = 10, .multiplication_log = 16, .ls_log = 18, .ls_tail_log = 15, .boundary_log = 5, .initial_log = 21, .terminal_log = 21, .cpu_fused_tail = layout.fused_tail, .cpu_u8_pairs = layout.u8_pairs, .cpu_compact_decode = layout.compact_decode, .mul_u8_pairs = layout.mul_u8_pairs, .ls_fused_pairs = layout.ls_fused_pairs, .alu_fused_tail = layout.alu_fused_tail, .ls_dword_fused_pairs = layout.ls_dword_fused_pairs };
    var buf: [8192]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();
    var first = true;
    try w.writeAll("{\"schema\":\"rv64-m5-widths/v1\",\"layout\":\"gkr-v3\",\"roles\":{");
    for (G.shapesForProgramLog(16, g)) |shape| try emit(w, &first, @tagName(shape.role), shape.widths);
    try w.writeAll("},\"bridges\":{");
    first = true;
    for (std.enums.values(T.Family)) |f| try emit(w, &first, @tagName(f), T.widths(f));
    try w.writeAll("},\"bulk\":{");
    first = true;
    for (T.bulk_kinds) |k| try emit(w, &first, @tagName(k), T.bulkWidths(k));
    try w.writeAll("},\"sponge\":{");
    first = true;
    for (T.sponge_kinds) |k| try emit(w, &first, @tagName(k), T.spongeWidths(k));
    try w.writeAll("},\"other\":{");
    first = true;
    try emit(w, &first, "ls_dword", T.dwordWidthsFor(g));
    try emit(w, &first, "zbb", T.zbbWidths());
    try w.writeAll("}}");
    std.debug.print("RV64_M5_WIDTHS {s}\n", .{fbs.getWritten()});
}
