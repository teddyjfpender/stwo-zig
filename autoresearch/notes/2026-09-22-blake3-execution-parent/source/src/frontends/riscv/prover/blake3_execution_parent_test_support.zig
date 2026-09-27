//! Whole execution-parent assembly, including fail-atomic column handoff.
const std = @import("std");
const core = @import("stwo_core");
const parent = @import("../recursion/blake3_execution_parent_preparation.zig");
pub fn check(a: std.mem.Allocator, admitted: anytype, capture: *const @import("blake3_execution_capture.zig").Verified, expected: [32]u8) !void {
    const state = try parent.State.init(a, admitted, capture, expected, 2);
    var state_alive = true;
    defer if (state_alive) state.deinit();
    try std.testing.expectEqualSlices(u8, &expected, &state.context.child_key_id);
    // A missing secure claim producer must fail before final columns move.
    const circuit = state.payloads.claim_packs[0][10];
    const fixed = state.payloads.fixed_claim_packs[0][10];
    state.payloads.claim_packs[0][10] = core.fields.m31.M31.fromCanonical(5_000_022);
    state.payloads.fixed_claim_packs[0][10] = core.fields.m31.M31.fromCanonical(5_000_022);
    try std.testing.expectError(error.MissingNativeParentInput, state.finish(a));
    try std.testing.expect(state.hash_columns.main[0].len > 0);
    state.payloads.claim_packs[0][10] = circuit;
    state.payloads.fixed_claim_packs[0][10] = fixed;
    var prepared = try state.finish(a);
    defer prepared.deinit();
    try std.testing.expectEqual(@as(usize, 0), state.hash_columns.main[0].len);
    try std.testing.expect(prepared.rows.input_count > 0);
    std.debug.print("EXECUTION_PARENT_ASSEMBLY inputs={d} retained_bytes={d}\n", .{ prepared.rows.input_count, try prepared.rows.retainedBytes() });
    state.deinit();
    state_alive = false;
    try @import("blake3_execution_parent_proof_test_support.zig").check(a, &prepared);
}
