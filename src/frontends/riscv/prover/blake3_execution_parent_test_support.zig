//! Whole execution-parent assembly, including fail-atomic column handoff.
const std = @import("std");
const core = @import("stwo_core");
const parent = @import("../recursion/blake3_execution_parent_preparation.zig");
pub fn check(a: std.mem.Allocator, admitted: anytype, capture: *const @import("blake3_execution_capture.zig").Verified, expected: [32]u8, memory: *const @import("blake3_commitment_witness.zig").Witness) !void {
    const state = try parent.State.init(a, admitted, capture, expected, 2);
    var state_alive = true;
    defer if (state_alive) state.deinit();
    try std.testing.expectEqualSlices(u8, &expected, &state.context.child_key_id);
    // A missing secure claim producer must fail before final columns move.
    const destination = try claimDestination(&state.payloads);
    const circuit = destination.*;
    destination.* = core.fields.m31.M31.fromCanonical(5_000_022);
    try std.testing.expectError(error.MissingNativeParentInput, state.finish());
    try std.testing.expect(state.hash_columns.main[0].len > 0);
    destination.* = circuit;
    var prepared = try state.finishReleasingRows();
    try std.testing.expect(state.row_sources_released);
    try std.testing.expectEqual(@as(usize, 0), state.hash_columns.g_metadata.len);
    try std.testing.expectError(error.ConsumedParentRows, state.finishReleasingRows());
    try std.testing.expectError(error.ConsumedParentRows, state.finish());
    defer prepared.deinit();
    try std.testing.expectEqual(@as(usize, 0), state.hash_columns.main[0].len);
    try std.testing.expect(prepared.rows.input_count > 0);
    std.debug.print("EXECUTION_PARENT_ASSEMBLY inputs={d} retained_bytes={d}\n", .{ prepared.rows.input_count, try prepared.rows.retainedBytes() });
    state.deinit();
    state_alive = false;
    // Failure after the irreversible source release must retain column
    // ownership for cleanup, reject reuse, and leak nothing under the test allocator.
    {
        const rejected = try parent.State.init(a, admitted, capture, expected, 2);
        defer rejected.deinit();
        (try claimDestination(&rejected.payloads)).* = core.fields.m31.M31.fromCanonical(5_000_022);
        try std.testing.expectError(error.MissingNativeParentInput, rejected.finishReleasingRows());
        try std.testing.expect(rejected.row_sources_released);
        try std.testing.expect(rejected.hash_columns.main[0].len > 0);
        try std.testing.expectEqual(@as(usize, 0), rejected.hash_columns.g_metadata.len);
        try std.testing.expectError(error.ConsumedParentRows, rejected.finishReleasingRows());
    }
    try @import("blake3_execution_span_test_support.zig").check(a, admitted, capture, expected, memory, &prepared);
    try @import("blake3_parent_rebase_test_support.zig").check(a, &prepared.rows);
    try @import("blake3_execution_parent_proof_test_support.zig").check(a, &prepared);
    try @import("blake3_parent_profile_test_support.zig").check(a, &prepared);
}

fn claimDestination(payloads: *@import("../recursion/air/blake3_execution_payloads.zig").Prepared) !*core.fields.m31.M31 {
    const columns = if (payloads.columns) |*owner| owner else return error.InvalidExecutionPayload;
    if (columns.count(11) == 0 or payloads.claim_packs.len != 0 or payloads.fixed_claim_packs.len != 0) return error.InvalidExecutionPayload;
    // Logical column 10 is shared immutable schedule metadata: mutate its
    // owned compact coordinate, so both logical/fixed views see the same error.
    const Air = @import("../recursion/air/qm31_pack_wire.zig");
    return &columns.owners[1].fixed[0][10 - Air.PHYSICAL_MAIN_COLUMN_COUNT];
}
