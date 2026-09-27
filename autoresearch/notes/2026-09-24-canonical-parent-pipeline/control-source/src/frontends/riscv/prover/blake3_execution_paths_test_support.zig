//! Real execution capture qualification for parent opening and query custody.
const std = @import("std");
const queries_mod = @import("../recursion/air/blake3_native_queries.zig");
const terminal_mod = @import("../recursion/air/blake3_native_terminal_encoding.zig");
const roots_mod = @import("../recursion/air/blake3_execution_roots.zig");
pub fn check(a: std.mem.Allocator, admitted: anytype, capture: *@import("blake3_execution_capture.zig").Verified, expected: [32]u8, replay: *@import("../recursion/air/blake3_native_transcript.zig").Planned, deep: *@import("../recursion/air/blake3_native_deep.zig").Prepared, fri: *@import("../recursion/air/blake3_native_fri.zig").Prepared) !void {
    var queries = try queries_mod.prepare(a, replay, deep, fri);
    defer queries.deinit();
    var terminal = try terminal_mod.prepare(a, replay, fri, 1504);
    defer terminal.deinit();
    var roots = try roots_mod.prepare(a, admitted, capture, expected, replay);
    defer roots.deinit();
    try std.testing.expectEqual(capture.proof.queries.raw.len, queries.links.queries.len);
    try std.testing.expectEqual(capture.proof.last_layer_coefficients.len, terminal.rows.len);
    const root_receipt = replay.plan.fixed.root_reads[0];
    replay.operations[root_receipt.operation].routed_root.value[0] ^= 1;
    try std.testing.expectError(error.InvalidExecutionRoots, roots_mod.prepare(a, admitted, capture, expected, replay));
    replay.operations[root_receipt.operation].routed_root.value[0] ^= 1;
    const query_receipt = replay.plan.fixed.query_outputs[0];
    const positions = try a.dupe(u32, replay.operations[query_receipt.operation].queries.values);
    defer a.free(positions);
    const original = replay.operations[query_receipt.operation].queries.values;
    replay.operations[query_receipt.operation].queries.values = positions;
    positions[0] ^= 1;
    try std.testing.expectError(error.InvalidNativeQueryLink, queries_mod.prepare(a, replay, deep, fri));
    replay.operations[query_receipt.operation].queries.values = original;
    var paths = try @import("../recursion/air/blake3_stark_paths.zig").prepare(a, &capture.proof, &deep.graph, &fri.graph, &queries.links);
    defer paths.deinit();
    var openings = try @import("../recursion/air/blake3_native_openings.zig").prepare(a, &paths, deep, fri);
    defer openings.deinit();
    try std.testing.expect(openings.rows.len > 0);
    try queries_mod.applyPathReads(a, &queries, deep, paths.inputs.projection.bit_reads);
    const first = try a.dupe(@import("../recursion/air/scalar_wire_source.zig").Row, queries.rows);
    defer a.free(first);
    try queries_mod.applyPathReads(a, &queries, deep, paths.inputs.projection.bit_reads);
    try std.testing.expectEqualDeep(first, queries.rows);
    // Keep a compact census in the evidence log, not a proving-time claim.
    std.debug.print("EXECUTION_PARENT_OPENINGS trace_trees={d} fri_layers={d} queries={d} scalar_sources={d} path_g_rows={d} path_xor_rows={d}\n", .{ capture.proof.trace_paths.len, capture.proof.fri.layers.len, queries.links.queries.len, openings.rows.len, paths.live.g_rows.len, paths.live.xor_rows.len });
}
