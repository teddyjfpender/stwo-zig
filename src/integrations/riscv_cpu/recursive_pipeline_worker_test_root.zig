const std = @import("std");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const worker = @import("recursive_pipeline_worker_v1.zig");
const mock = @import("recursive_pipeline_worker_mock_v1.zig");
const native = @import(
    "recursive_pipeline_worker_native_omitted_leaf_v1.zig",
);

test "recursive worker protocol rejects seal and framing mutations" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();
    const payload = protocol.jsonObject(scratch);
    var request = protocol.jsonObject(scratch);
    try protocol.put(&request, "schema", protocol.string(protocol.request_schema));
    try protocol.put(&request, "sequence", protocol.integer(0));
    try protocol.put(&request, "action", protocol.string("shutdown"));
    try protocol.put(&request, "payload", payload);
    try protocol.sealObject(scratch, &request);
    const canonical = try protocol.canonicalAlloc(allocator, request, false);
    defer allocator.free(canonical);
    var parsed = try protocol.parseRequest(
        allocator,
        canonical[0 .. canonical.len - 1],
        0,
    );
    parsed.deinit();
    const mutated = try allocator.dupe(u8, canonical[0 .. canonical.len - 1]);
    defer allocator.free(mutated);
    mutated[0] = ' ';
    try std.testing.expectError(
        error.NonCanonicalWorkerFrame,
        protocol.parseRequest(allocator, mutated, 0),
    );
}

test "native omitted leaf remains advertised but fail closed" {
    const description = try native.Adapter.describe(.prove, 1);
    try std.testing.expectEqual(
        @as(u32, @intFromEnum(description.output_kind)),
        @as(u32, @intFromEnum(@import("stwo_artifact_store").ArtifactKindV1.proof_artifact)),
    );
    try std.testing.expect(
        native.Adapter.unavailable() == error.NativeOmittedLeafBridgeUnavailable,
    );
    try std.testing.expect(!native.Adapter.production);
}

test "mock registry advertises bounded campaign stages" {
    try std.testing.expectEqual(
        @import("stwo_artifact_store").ArtifactKindV1.proof_artifact,
        (try mock.Adapter.describe(.prove, 101)).output_kind,
    );
    try std.testing.expectEqual(
        @import("stwo_artifact_store").ArtifactKindV1.recursion_node,
        (try mock.Adapter.describe(.fold, 104)).output_kind,
    );
    try std.testing.expectError(
        error.UnsupportedRecursivePipelineStage,
        mock.Adapter.describe(.publish, 104),
    );
}

test {
    std.testing.refAllDecls(protocol);
    std.testing.refAllDecls(worker);
    std.testing.refAllDecls(mock);
    std.testing.refAllDecls(native);
}
