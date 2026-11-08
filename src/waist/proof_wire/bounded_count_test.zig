const std = @import("std");
const Codec = @import("mod.zig");
const a = std.testing.allocator;

fn u32le(out: *std.ArrayList(u8), value: u32) !void {
    var raw: [4]u8 = undefined;
    std.mem.writeInt(u32, &raw, value, .little);
    try out.appendSlice(a, &raw);
}
fn header(out: *std.ArrayList(u8)) !void {
    try out.appendSlice(a, "STWOPRW1");
    for ([_]u32{ 26, 1, 0, 70, 1, std.math.maxInt(u32) }) |v| try u32le(out, v);
}
fn zeros(out: *std.ArrayList(u8), n: usize) !void {
    try out.appendNTimes(a, 0, n);
}
fn firstLayer(out: *std.ArrayList(u8)) !void {
    try u32le(out, 0); // empty secure witness
    try u32le(out, 0); // empty Merkle witness
    try zeros(out, 32); // commitment
}

// Each malicious length is reached through enough valid prefixes to exercise
// its OWN preallocation guard. FixedBufferAllocator safely converts any
// regressed giant allocation into OOM rather than reserving attacker-sized RAM.
test "binary proof rejects unsupported counts at every nested vector before allocation" {
    const Case = enum {
        commitments,
        sampled_trees,
        sampled_columns,
        sampled_values,
        decommitments,
        merkle_witness,
        queried_trees,
        queried_columns,
        queried_values,
        first_fri_values,
        first_fri_merkle,
        inner_layers,
        inner_fri_values,
        inner_fri_merkle,
        last_poly,
    };
    for (std.enums.values(Case)) |case| {
        var bytes = std.ArrayList(u8).empty;
        defer bytes.deinit(a);
        try header(&bytes);
        const huge = std.math.maxInt(u32);
        if (case == .commitments) {
            try u32le(&bytes, huge);
        } else {
            try u32le(&bytes, 0); // commitments
            if (case == .sampled_trees) {
                try u32le(&bytes, huge);
            } else if (case == .sampled_columns or case == .sampled_values) {
                try u32le(&bytes, 1);
                if (case == .sampled_columns) try u32le(&bytes, huge) else {
                    try u32le(&bytes, 1);
                    try u32le(&bytes, huge);
                }
            } else {
                try u32le(&bytes, 0); // sampled trees
                if (case == .decommitments) {
                    try u32le(&bytes, huge);
                } else if (case == .merkle_witness) {
                    try u32le(&bytes, 1);
                    try u32le(&bytes, huge);
                } else {
                    try u32le(&bytes, 0); // decommitments
                    if (case == .queried_trees) {
                        try u32le(&bytes, huge);
                    } else if (case == .queried_columns or case == .queried_values) {
                        try u32le(&bytes, 1);
                        if (case == .queried_columns) try u32le(&bytes, huge) else {
                            try u32le(&bytes, 1);
                            try u32le(&bytes, huge);
                        }
                    } else {
                        try u32le(&bytes, 0); // queried trees
                        try zeros(&bytes, 8); // proof of work
                        if (case == .first_fri_values) {
                            try u32le(&bytes, huge);
                        } else if (case == .first_fri_merkle) {
                            try u32le(&bytes, 0);
                            try u32le(&bytes, huge);
                        } else {
                            try firstLayer(&bytes);
                            if (case == .inner_layers) {
                                try u32le(&bytes, huge);
                            } else if (case == .inner_fri_values or case == .inner_fri_merkle) {
                                try u32le(&bytes, 1);
                                // A complete layer needs at least40 bytes.
                                if (case == .inner_fri_values) {
                                    try u32le(&bytes, huge);
                                    try zeros(&bytes, 36);
                                } else {
                                    try u32le(&bytes, 0);
                                    try u32le(&bytes, huge);
                                    try zeros(&bytes, 32);
                                }
                            } else {
                                try u32le(&bytes, 0); // inner layers
                                try u32le(&bytes, huge);
                            }
                        }
                    }
                }
            }
        }
        var backing: [8192]u8 = undefined;
        var fixed = std.heap.FixedBufferAllocator.init(&backing);
        try std.testing.expectError(error.InvalidBinaryProof, Codec.decodeProofBytesBinary(fixed.allocator(), bytes.items));
    }
    // Even a plausible one-item request must reject a payload one byte short,
    // without attempting its first arena allocation.
    var bytes = std.ArrayList(u8).empty;
    defer bytes.deinit(a);
    try header(&bytes);
    try u32le(&bytes, 1);
    try zeros(&bytes, 31);
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidBinaryProof, Codec.decodeProofBytesBinary(fail.allocator(), bytes.items));
    try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
}

// Serialization fixture only: not a cryptographically valid STARK. It includes
// nonempty vectors at every nesting level and empty siblings, so minimum wire
// sizes must not be confused with larger native slice/struct sizes.
fn encoding(allocator: std.mem.Allocator) ![]u8 {
    var hashes = [_]Codec.HashWire{@splat(7)};
    var values = [_]Codec.Qm31Wire{.{ 1, 2, 3, 4 }};
    var columns = [_][]Codec.Qm31Wire{ &values, &.{} };
    var trees = [_][][]Codec.Qm31Wire{ &columns, &.{} };
    var decommitments = [_]Codec.MerkleDecommitmentWire{.{ .hash_witness = &hashes }};
    var queried_values = [_]u32{ 5, 6 };
    var queried_columns = [_][]u32{ &queried_values, &.{} };
    var queried_trees = [_][][]u32{ &queried_columns, &.{} };
    const layer = Codec.FriLayerWire{ .fri_witness = &values, .decommitment = decommitments[0], .commitment = @splat(8) };
    var layers = [_]Codec.FriLayerWire{layer};
    var polynomial = [_]Codec.Qm31Wire{ .{ 1, 0, 0, 0 }, .{ 0, 1, 0, 0 } };
    var proof = try Codec.wireToProof(allocator, .{
        .config = .{ .pow_bits = 26, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70 } },
        .commitments = &hashes,
        .sampled_values = &trees,
        .decommitments = &decommitments,
        .queried_values = &queried_trees,
        .proof_of_work = 0x123456789abcdef0,
        .fri_proof = .{ .first_layer = layer, .inner_layers = &layers, .last_layer_poly = &polynomial },
    });
    defer proof.deinit(allocator);
    return Codec.encodeProofBytesBinary(allocator, proof);
}
fn decodeProbe(allocator: std.mem.Allocator, bytes: []const u8) !void {
    var proof = try Codec.decodeProofBytesBinary(allocator, bytes);
    defer proof.deinit(allocator);
}
test "binary proof count bounds preserve nested canonical bytes and all decode OOM cleanup" {
    const bytes = try encoding(a);
    defer a.free(bytes);
    var proof = try Codec.decodeProofBytesBinary(a, bytes);
    defer proof.deinit(a);
    const encoded = try Codec.encodeProofBytesBinary(a, proof);
    defer a.free(encoded);
    try std.testing.expectEqualSlices(u8, bytes, encoded);
    try std.testing.checkAllAllocationFailures(a, decodeProbe, .{bytes});
}
test "binary proof every truncated prefix and appended byte reject with balanced cleanup" {
    const bytes = try encoding(a);
    defer a.free(bytes);
    for (0..bytes.len) |length| {
        try std.testing.expectError(error.InvalidBinaryProof, Codec.decodeProofBytesBinary(a, bytes[0..length]));
    }
    const trailing = try a.alloc(u8, bytes.len + 1);
    defer a.free(trailing);
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0;
    try std.testing.expectError(error.InvalidBinaryProof, Codec.decodeProofBytesBinary(a, trailing));
}

test "binary proof invalid FRI polynomial length rejects before coefficient allocation" {
    for ([_]u32{ 0, 3 }) |length| {
        var bytes = std.ArrayList(u8).empty;
        defer bytes.deinit(a);
        try header(&bytes);
        for (0..4) |_| try u32le(&bytes, 0);
        try zeros(&bytes, 8);
        try firstLayer(&bytes);
        try u32le(&bytes, 0);
        try u32le(&bytes, length);
        try zeros(&bytes, 16 * length);
        var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
        try std.testing.expectError(error.InvalidBinaryProof, Codec.decodeProofBytesBinary(fail.allocator(), bytes.items));
        try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
    }
}
test "JSON and typed proof wire reject invalid FRI polynomial lengths without assertion" {
    const bytes = try encoding(a);
    defer a.free(bytes);
    var proof = try Codec.decodeProofBytesBinary(a, bytes);
    defer proof.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var wire = try Codec.proofToWire(arena.allocator(), proof);
    var coefficients: [3]Codec.Qm31Wire = @splat(@splat(0));
    for ([_]usize{ 0, 3 }) |length| {
        wire.fri_proof.last_layer_poly = coefficients[0..length];
        var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
        try std.testing.expectError(error.ValueOutOfRange, Codec.wireToProof(fail.allocator(), wire));
        try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
        const json = try std.json.Stringify.valueAlloc(a, wire, .{});
        defer a.free(json);
        try std.testing.expectError(error.ValueOutOfRange, Codec.decodeProofBytes(a, json));
    }
}
