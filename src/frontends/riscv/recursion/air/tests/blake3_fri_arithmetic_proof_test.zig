//! Existing production FRI arithmetic AIRs committed under BLAKE3.
const std = @import("std");
const f = @import("../blake3_proof_fixture.zig");
const circuit = @import("../fri_verifier_circuit.zig");
test "BLAKE3 captured FRI arithmetic verifies in a complete typed CPU proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var capture = try @import("blake3_pcs_capture_test.zig").verifiedCapture(a, 4);
    defer capture.deinit(a);
    const profile = circuit.Profile{ .lifting_log_size = 6, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .fold_widths = &.{ 16, 2 }, .query_count = 17 };
    var input = try @import("../../fri_arithmetic_capture.zig").Owned.init(a, profile, &capture);
    defer input.deinit();
    var graph = try circuit.build(a, profile);
    defer graph.deinit();
    var evaluation = try graph.evaluate(a, input.inputs);
    defer evaluation.deinit();
    try @import("../blake3_arithmetic_proof_fixture.zig").check(a, graph.graph(), evaluation.values);
}
