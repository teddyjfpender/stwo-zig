//! Circuit-proof transport ownership relied on by the RV64 recursion receiver.
const std = @import("std");
const wire = @import("stwo_circuit_recursion_wire");

const codec = wire.circuit_serialize;
const config: codec.ProofConfig = .{
    .n_preprocessed_columns = 1,
    .component_shapes = &.{.{ .trace_columns = 1, .interaction_columns = 4 }},
    .log_trace_size = 3,
    .fri = .{ .pow_bits = 0, .log_blowup_factor = 1, .log_last_layer_degree_bound = 1, .n_queries = 1, .fold_step = 2 },
};

fn roundtrip(allocator: std.mem.Allocator, bytes: []const u8) !void {
    var decoded = try codec.deserializeProof(allocator, bytes, config);
    defer decoded.deinit();
    try std.testing.expectEqual(config.serializedLen(), decoded.consumed);
    const encoded = try codec.serializeProofAlloc(allocator, &decoded.proof, config);
    defer allocator.free(encoded);
    try std.testing.expectEqualSlices(u8, bytes[0..decoded.consumed], encoded);
}

test "cdc: RV64 recursion transport owns decoded storage and unwinds all allocation failures" {
    const bytes = try std.testing.allocator.alloc(u8, config.serializedLen() + 3);
    defer std.testing.allocator.free(bytes);
    @memset(bytes, 0);
    try roundtrip(std.testing.allocator, bytes);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, roundtrip, .{bytes});
    try std.testing.expectError(error.NotEnoughData, codec.deserializeProof(std.testing.allocator, bytes[0 .. config.serializedLen() - 1], config));
    std.mem.writeInt(u32, bytes[0..4], 0x7fffffff, .little);
    try std.testing.expectError(error.ValueOutOfRange, codec.deserializeProof(std.testing.allocator, bytes, config));
    try std.testing.expectEqual(@as(u16, 0x5002), wire.error_codes.fromCircuitDecode(error.ValueOutOfRange).code);
}
