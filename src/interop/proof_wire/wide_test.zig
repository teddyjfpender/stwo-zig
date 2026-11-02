//! Codec fixtures only; actual OM31 STARK receiver roundtrips live in native/prover.
const std = @import("std");
const Core = @import("stwo_core");
const Legacy = @import("mod.zig");
const W = Legacy.ForField(Core.fields.om31.OM31);
const a = std.testing.allocator;

fn fixture(allocator: std.mem.Allocator) !W.Proof {
    var hashes = [_]W.HashWire{@splat(7)};
    var values = [_]W.SecureWire{.{ 1, 2, 3, 4, 5, 6, 7, 8 }};
    var columns = [_][]W.SecureWire{ &values, &.{} };
    var trees = [_][][]W.SecureWire{ &columns, &.{} };
    var decommitments = [_]W.MerkleDecommitmentWire{.{ .hash_witness = &hashes }};
    var queried_values = [_]u32{ 5, 6 };
    var queried_columns = [_][]u32{ &queried_values, &.{} };
    var queried_trees = [_][][]u32{ &queried_columns, &.{} };
    const layer = W.FriLayerWire{ .fri_witness = &values, .decommitment = decommitments[0], .commitment = @splat(8) };
    var layers = [_]W.FriLayerWire{layer};
    var polynomial = [_]W.SecureWire{ .{ 1, 0, 0, 0, 9, 10, 11, 12 }, .{ 0, 1, 0, 0, 13, 14, 15, 16 } };
    return W.wireToProof(allocator, .{
        .config = .{ .pow_bits = 26, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 4 } },
        .commitments = &hashes,
        .sampled_values = &trees,
        .decommitments = &decommitments,
        .queried_values = &queried_trees,
        .proof_of_work = 0x123456789abcdef0,
        .fri_proof = .{ .first_layer = layer, .inner_layers = &layers, .last_layer_poly = &polynomial },
    });
}
fn roundtrip(allocator: std.mem.Allocator, binary: bool, bytes: []const u8) !void {
    var proof = if (binary) try W.decodeProofBytesBinary(allocator, bytes) else try W.decodeProofBytes(allocator, bytes);
    defer proof.deinit(allocator);
    const encoded = if (binary) try W.encodeProofBytesBinary(allocator, proof) else try W.encodeProofBytes(allocator, proof);
    defer allocator.free(encoded);
    try std.testing.expectEqualSlices(u8, bytes, encoded);
}

test "OM31 wire preserves all8 coordinates nested empty siblings and exact JSON binary bytes" {
    var proof = try fixture(a);
    defer proof.deinit(a);
    for ([_]bool{ false, true }) |binary| {
        const bytes = if (binary) try W.encodeProofBytesBinary(a, proof) else try W.encodeProofBytes(a, proof);
        defer a.free(bytes);
        try roundtrip(a, binary, bytes);
        try std.testing.checkAllAllocationFailures(a, roundtrip, .{ binary, bytes });
        if (binary) {
            try std.testing.expectEqualStrings("STWOPRW8", bytes[0..8]);
            try std.testing.expectError(error.UnsupportedBinaryVersion, Legacy.decodeProofBytesBinary(a, bytes));
        } else {
            try std.testing.expect(std.mem.indexOf(u8, bytes, "stwo-om31-proof-v1") != null);
            try std.testing.expectError(error.UnknownField, Legacy.decodeProofBytes(a, bytes));
        }
    }
}

test "OM31 binary wire every truncated prefix trailing byte and wrong field reject" {
    var proof = try fixture(a);
    defer proof.deinit(a);
    const bytes = try W.encodeProofBytesBinary(a, proof);
    defer a.free(bytes);
    for (0..bytes.len) |length| try std.testing.expectError(error.InvalidBinaryProof, W.decodeProofBytesBinary(a, bytes[0..length]));
    const extra = try a.alloc(u8, bytes.len + 1);
    defer a.free(extra);
    @memcpy(extra[0..bytes.len], bytes);
    extra[bytes.len] = 0;
    try std.testing.expectError(error.InvalidBinaryProof, W.decodeProofBytesBinary(a, extra));
    @memcpy(extra[0..8], "STWOPRW1");
    try std.testing.expectError(error.UnsupportedBinaryVersion, W.decodeProofBytesBinary(a, extra[0..bytes.len]));
}

test "OM31 typed and JSON decode reject every noncanonical coordinate with owned cleanup" {
    var proof = try fixture(a);
    defer proof.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var wire = try W.proofToWire(arena.allocator(), proof);
    for (0..8) |coordinate| {
        const original = wire.sampled_values[0][0][0][coordinate];
        wire.sampled_values[0][0][0][coordinate] = Core.fields.m31.Modulus;
        try std.testing.expectError(error.NonCanonicalM31, W.wireToProof(a, wire));
        const json = try std.json.Stringify.valueAlloc(a, .{ .protocol = "stwo-om31-proof-v1", .proof = wire }, .{});
        defer a.free(json);
        try std.testing.expectError(error.NonCanonicalM31, W.decodeProofBytes(a, json));
        wire.sampled_values[0][0][0][coordinate] = original;
    }
    wire.queried_values[0][0][0] = Core.fields.m31.Modulus;
    try std.testing.expectError(error.NonCanonicalM31, W.wireToProof(a, wire));
}

test "OM31 JSON requires explicit matching field profile" {
    var proof = try fixture(a);
    defer proof.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const wire = try W.proofToWire(arena.allocator(), proof);
    const json = try std.json.Stringify.valueAlloc(a, .{ .protocol = "stwo-qm31-proof-v1", .proof = wire }, .{});
    defer a.free(json);
    try std.testing.expectError(error.UnsupportedBinaryVersion, W.decodeProofBytes(a, json));
    const missing = try std.json.Stringify.valueAlloc(a, .{ .proof = wire }, .{});
    defer a.free(missing);
    try std.testing.expectError(error.MissingField, W.decodeProofBytes(a, missing));
}

test "OM31 binary decoder validates every sampled coordinate after field-specific count bounds" {
    var proof = try fixture(a);
    defer proof.deinit(a);
    const bytes = try W.encodeProofBytesBinary(a, proof);
    defer a.free(bytes);
    // This fixture has one commitment and a first sample immediately after
    // the tree/column/value counts. Pin the offset against its actual bytes.
    for (0..8) |coordinate| {
        const at = 80 + 4 * coordinate;
        try std.testing.expectEqual(@as(u32, @intCast(coordinate + 1)), std.mem.readInt(u32, bytes[at..][0..4], .little));
        const bad = try a.dupe(u8, bytes);
        defer a.free(bad);
        std.mem.writeInt(u32, bad[at..][0..4], Core.fields.m31.Modulus, .little);
        try std.testing.expectError(error.NonCanonicalM31, W.decodeProofBytesBinary(a, bad));
    }
}
