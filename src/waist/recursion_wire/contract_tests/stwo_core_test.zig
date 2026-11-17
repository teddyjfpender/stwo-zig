//! Shape authority shared by circuit proof decode and recursive verification.
const std = @import("std");
const core = @import("stwo_core");

test "cdc: recursion wire proof shape identifies cumulative columns and rejects malformed schedules" {
    var shape = core.circuit_proof_shape.ProofShape{
        .n_preprocessed_columns = 1,
        .component_shapes = &.{.{ .trace_columns = 2, .interaction_columns = 8 }},
        .log_trace_size = 5,
        .fri = .{ .pow_bits = 0, .log_blowup_factor = 1, .log_last_layer_degree_bound = 1, .n_queries = 2, .fold_step = 3 },
    };
    try shape.validate();
    var steps: [32]u32 = undefined;
    try std.testing.expectEqualSlices(u32, &.{ 3, 1 }, shape.friFoldSteps(&steps));
    try std.testing.expect(!shape.isCumulativeSumColumn(3));
    try std.testing.expect(shape.isCumulativeSumColumn(4));
    shape.fri.fold_step = 0;
    try std.testing.expectError(error.InvalidProofShape, shape.validate());
}
