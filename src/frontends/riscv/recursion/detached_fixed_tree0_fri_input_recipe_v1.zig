//! Proof-free reconstruction of detached q193 FRI input Tree0 row 29.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const KeyV1 = @import("detached_segment_protocol_v1.zig").KeyV1;
const segment = @import("segment_profile.zig");
const ids = @import("detached_fri_circuit_ids_v1.zig");
const circuit_mod = @import("air/fri_verifier_circuit.zig");
const input_air = @import("air/fri_verifier_input.zig");
const witness = @import("air/fri_verifier_input_witness.zig");

pub fn fillFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: *[witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    try key.validate();
    if (key.profile != .recursive_q193_v1) return error.InvalidFixedFriInputGeometry;
    const placement = key.manifest.placements[29] orelse return error.InvalidFixedFriInputGeometry;
    if (placement.geometry.preprocessed_columns != columns.len)
        return error.InvalidFixedFriInputGeometry;
    return fill(allocator, placement.geometry.log_size, columns);
}

fn fill(allocator: std.mem.Allocator, log_size: u32, columns: *[witness.PREPROCESSED_COLUMN_COUNT][]M31) !void {
    var circuit = try circuit_mod.build(allocator, segment.circuitProfile());
    defer circuit.deinit();
    const reference = try witness.Reference.seal(.{
        .{ .verifier_id = witness.SEGMENT_VERIFIER_ID, .circuit_id = ids.SEGMENT, .circuit = &circuit },
        .{ .verifier_id = witness.LEFT_RECURSION_VERIFIER_ID, .circuit_id = ids.LEFT_RECURSION, .circuit = &circuit },
        .{ .verifier_id = witness.RIGHT_RECURSION_VERIFIER_ID, .circuit_id = ids.RIGHT_RECURSION, .circuit = &circuit },
    });
    var preprocessing = try witness.Preprocessed.init(allocator, reference);
    defer preprocessing.deinit();
    if (preprocessing.log_size != log_size or log_size >= @bitSizeOf(usize))
        return error.InvalidFixedFriInputGeometry;
    const size = @as(usize, 1) << @intCast(log_size);
    for (columns) |column| if (column.len != size)
        return error.InvalidFixedFriInputGeometry;
    var definition = try input_air.build(allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    try executor.generatePreprocessedInto(&preprocessing, reference, columns);
}

test "q193 FRI input fixed row 29 follows canonical circuit without proof input" {
    const allocator = std.testing.allocator;
    const size: usize = 1 << 18;
    const count = witness.PREPROCESSED_COLUMN_COUNT;
    const words = try allocator.alloc(M31, size * count);
    defer allocator.free(words);
    var columns: [count][]M31 = undefined;
    for (&columns, 0..) |*column, index| column.* = words[index * size ..][0..size];
    try fill(allocator, 18, &columns);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (columns) |column| {
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, column.len, .little);
        hash.update(&length);
        for (column) |word| {
            var field: [4]u8 = undefined;
            std.mem.writeInt(u32, &field, word.toU32(), .little);
            hash.update(&field);
        }
    }
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "9d08800d43841b3ce20a27f8512c41b98b1a2faec086ac279211638dd197c57f");
    try std.testing.expectEqual(expected, hash.finalResult());
}
