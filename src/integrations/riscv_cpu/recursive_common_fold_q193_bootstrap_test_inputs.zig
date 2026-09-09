//! Input selection for reproducible bootstrap sibling proofs and CAS replay.
//! Coordinates select test statements; they grant no proof admission.
const std = @import("std");
const checkpoint = @import("recursive_node_artifact_store_v2.zig");
const node = @import("recursive_node_artifact_v2.zig");
const layout = @import("recursive_node_artifact_v1.zig");

pub fn leftIndex(allocator: std.mem.Allocator, store: ?*checkpoint.cas.Store, ref: ?checkpoint.cas.BlobRefV1) !u32 {
    if (ref) |value| {
        const artifact = try checkpoint.coldOpenRecursiveNodeTransportV2(store orelse return error.MissingRecursionCheckpointStore, value);
        return indexFromCoordinate(artifact.coordinate);
    }
    const text = std.process.getEnvVarOwned(allocator, "STWO_RECURSION_BOOTSTRAP_LEFT_INDEX") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return 210,
        else => return err,
    };
    defer allocator.free(text);
    return parseIndex(text);
}

fn parseIndex(text: []const u8) !u32 {
    return validateIndex(std.fmt.parseUnsigned(u32, text, 10) catch return error.InvalidBootstrapChildIndex);
}

fn validateIndex(index: u32) !u32 {
    if (index < layout.REAL_LEAF_COUNT or index >= layout.PADDED_LEAF_COUNT or index % 2 != 0)
        return error.InvalidBootstrapChildIndex;
    return index;
}

fn indexFromCoordinate(coordinate: node.TaskCoordinateV1) !u32 {
    try coordinate.validate();
    if (coordinate.height != 1) return error.InvalidBootstrapChildIndex;
    return validateIndex(try std.math.mul(u32, coordinate.index, 2));
}

pub fn checkpointNodeRef(allocator: std.mem.Allocator) !checkpoint.cas.BlobRefV1 {
    const encoded = std.process.getEnvVarOwned(allocator, "STWO_RECURSION_CHECKPOINT_NODE") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return error.MissingRecursionCheckpointNode,
        else => return err,
    };
    defer allocator.free(encoded);
    if (encoded.len != 64) return error.InvalidRecursionCheckpointNode;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded) catch return error.InvalidRecursionCheckpointNode;
    return checkpoint.cas.BlobRefV1.create(.recursion_node, node.SCHEMA_VERSION, node.ENCODED_BYTE_COUNT, digest);
}

pub fn exercise() !void {
    for ([_]u32{ 210, 212, 214, 254 }) |index| {
        var text: [16]u8 = undefined;
        try std.testing.expectEqual(index, try parseIndex(try std.fmt.bufPrint(&text, "{d}", .{index})));
        try std.testing.expectEqual(index, try indexFromCoordinate(try node.TaskCoordinateV1.init(1, index / 2)));
    }
    for ([_][]const u8{ "0", "209", "211", "255", "256", "4294967296", "-2", "", "text" }) |text|
        try std.testing.expectError(error.InvalidBootstrapChildIndex, parseIndex(text));
    try std.testing.expectError(error.InvalidBootstrapChildIndex, indexFromCoordinate(try node.TaskCoordinateV1.init(0, 212)));
    try std.testing.expectError(error.InvalidBootstrapChildIndex, indexFromCoordinate(try node.TaskCoordinateV1.init(2, 53)));
}
