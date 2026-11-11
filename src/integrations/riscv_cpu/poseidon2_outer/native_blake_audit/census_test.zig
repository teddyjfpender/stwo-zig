//! Closed source census of existing full-root Blake gadgets. No new suite,
//! statement, accepted proof, R7 roster or hash/root conversion is admitted.
const std = @import("std");
const C = @import("stwo_circuit_frontend");
const Q = @import("stwo_core").fields.qm31.QM31;
const M = @import("stwo_core").fields.m31.M31;
const B = C.builder;
fn leaf(comptime count: usize) !void {
    const a = std.testing.allocator;
    var ctx = try B.Context(Q).initTraceOnly(a, 8);
    defer ctx.deinit();
    var words: [count]B.wrappers.M31Wrapper(B.Var) = undefined;
    for (&words) |*word| word.* = .newUnsafe(try ctx.newVar(Q.fromBase(M.one())));
    const hash = try C.native_verifier.merkle.hashLeafM31s(Q, &ctx, &words);
    var outputs: [8]B.Var = undefined;
    for (&outputs, hash.words) |*out, word| out.* = word.get();
    try ctx.setOutputs(&outputs);
    const blocks = (count + 15) / 16;
    try std.testing.expectEqual(@as(usize, blocks * 80), ctx.gate_counts.blake_g_gate);
    try std.testing.expectEqual(@as(usize, blocks * 8), ctx.gate_counts.triple_xor);
    try std.testing.expectEqual(@as(usize, count), ctx.gate_counts.m31_to_u32);
    const PP = C.common.preprocessed;
    const List = C.common.component_list;
    const sizes = C.common.finalize.computePaddedSizes(PP.CircuitView.fromBuilder(&ctx.circuit));
    const layout = try PP.ColumnLayout.fromComponentSizes(sizes);
    const logs = try List.circuitComponentLogSizes(&layout);
    var main: u64 = 0;
    var inter: u64 = 0;
    var fixed: u64 = 0;
    for (logs.toArray(), List.component_facts.toArray()) |log, facts| {
        const rows = @as(u64, 1) << @intCast(log);
        main += rows * facts.trace_columns;
        inter += rows * facts.interaction_columns * 2;
    }
    for (layout.entries) |entry| fixed += @as(u64, 1) << @intCast(entry.log_size);
    const json = try std.json.Stringify.valueAlloc(a, .{ .words = count, .blocks = blocks, .raw = ctx.gate_counts, .logs = logs, .main_cells = main, .om_inter_cells = inter, .fixed_cells = fixed, .source_only = true, .proof_validity_claimed = false }, .{});
    defer a.free(json);
    std.debug.print("NATIVE_BLAKE_HASH_SOURCE {s}\n", .{json});
}
test "native Blake source census retains OM31-width lookup floor and full roots" {
    inline for (.{ 1, 16, 17, 64, 512, 1152 }) |count| try leaf(count);
}
