const std = @import("std");
const P = @import("protocol.zig");
const W = @import("witness.zig");
const Wire = @import("wire.zig");
const Native = @import("stwo_proof_wire").ForField(P.O);
const List = @import("stwo_circuit_frontend").common.component_list;
const a = std.testing.allocator;

// Transport fixture only: algebraic acceptance is tested by the actual outer
// proof qualification. This deliberately includes nonzero upper coordinates.
fn fixture() !P.Proof {
    var hashes = [_][32]u8{@splat(7)};
    var values = [_]Native.SecureWire{.{ 1, 2, 3, 4, 5, 6, 7, 8 }};
    var columns = [_][]Native.SecureWire{&values};
    var trees = [_][][]Native.SecureWire{&columns};
    var decommitments = [_]Native.MerkleDecommitmentWire{.{ .hash_witness = &hashes }};
    var queries = [_]u32{ 8, 9 };
    var query_columns = [_][]u32{&queries};
    var query_trees = [_][][]u32{&query_columns};
    const layer = Native.FriLayerWire{ .fri_witness = &values, .decommitment = decommitments[0], .commitment = @splat(8) };
    return Native.wireToProof(a, .{
        .config = .{ .pow_bits = 20, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 108, .fold_step = 4 } },
        .commitments = &hashes,
        .sampled_values = &trees,
        .decommitments = &decommitments,
        .queried_values = &query_trees,
        .proof_of_work = 3,
        .fri_proof = .{ .first_layer = layer, .inner_layers = &.{}, .last_layer_poly = &values },
    });
}
fn claims() W.Claims {
    var values: [List.N_COMPONENTS]P.O = undefined;
    for (&values, 0..) |*v, i| {
        var coordinates: [8]P.M = undefined;
        for (&coordinates, 0..) |*c, j| c.* = P.M.fromCanonical(@intCast(i * 8 + j + 1));
        v.* = P.O.fromM31Array(coordinates);
    }
    return W.Claims.fromArray(values);
}
fn roundtrip(allocator: std.mem.Allocator, bytes: []const u8) !void {
    var decoded = try Wire.decode(allocator, @splat(19), 1, bytes);
    defer decoded.deinit();
    const again = try Wire.encode(allocator, @splat(19), decoded.outputs, decoded.claims, &decoded.proof);
    defer allocator.free(again);
    try std.testing.expectEqualSlices(u8, bytes, again);
    for (claims().toArray(), decoded.claims.toArray()) |expected, actual| try std.testing.expect(expected.eql(actual));
}
test "om31 outer wire exact transport all8 claims coordinates and allocation failure cleanup" {
    var proof = try fixture();
    defer proof.deinit(a);
    const bytes = try Wire.encode(a, @splat(19), &.{P.Q.fromU32Unchecked(2, 3, 4, 5)}, claims(), &proof);
    defer a.free(bytes);
    try roundtrip(a, bytes);
    try std.testing.checkAllAllocationFailures(a, roundtrip, .{bytes});
}
test "om31 outer wire rejects authority profile count truncation trailing and noncanonical words" {
    var proof = try fixture();
    defer proof.deinit(a);
    const bytes = try Wire.encode(a, @splat(19), &.{P.Q.one()}, claims(), &proof);
    defer a.free(bytes);
    try std.testing.expectError(error.Om31CircuitWireAuthority, Wire.decode(a, @splat(20), 1, bytes));
    try std.testing.expectError(error.Om31CircuitWireOutputCount, Wire.decode(a, @splat(19), 2, bytes));
    try std.testing.expectError(error.Om31CircuitWireLimit, Wire.decode(a, @splat(19), Wire.MAX_OUTPUTS + 1, bytes));
    bytes[8] ^= 1;
    try std.testing.expectError(error.Om31CircuitWireProfile, Wire.decode(a, @splat(19), 1, bytes));
    bytes[8] ^= 1;
    for (0..bytes.len) |n| {
        if (Wire.decode(a, @splat(19), 1, bytes[0..n])) |accepted| {
            var owned = accepted;
            owned.deinit();
            return error.AcceptedTruncatedEnvelope;
        } else |_| {}
    }
    const extra = try a.alloc(u8, bytes.len + 1);
    defer a.free(extra);
    @memcpy(extra[0..bytes.len], bytes);
    extra[bytes.len] = 0;
    try std.testing.expectError(error.InvalidOm31CircuitWire, Wire.decode(a, @splat(19), 1, extra));
    // Every output/claim coordinate is checked before allocating a native proof.
    var at: usize = 76;
    while (at < 76 + 16 + List.N_COMPONENTS * 32) : (at += 4) {
        const saved = bytes[at..][0..4].*;
        std.mem.writeInt(u32, bytes[at..][0..4], @import("stwo_core").fields.m31.Modulus, .little);
        try std.testing.expectError(error.NonCanonicalM31, Wire.decode(a, @splat(19), 1, bytes));
        @memcpy(bytes[at..][0..4], &saved);
    }
    proof.commitment_scheme_proof.config.fri_config.n_queries = 70;
    try std.testing.expectError(error.UnsupportedOm31CircuitProfile, Wire.encode(a, @splat(19), &.{}, claims(), &proof));
}
