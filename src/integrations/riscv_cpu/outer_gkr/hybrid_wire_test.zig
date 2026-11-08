//! Transport-only synthetic frames: no algebraic acceptance claim.
const std = @import("std");
const CPU = @import("stwo_circuit_cpu_integration");
const O = CPU.om31;
const Native = @import("stwo_proof_wire").ForField(O.protocol.O);
const P = @import("profile.zig");
const S = @import("section.zig");
const R = @import("hybrid_receiver.zig");
const W = @import("hybrid_wire.zig");
const a = std.testing.allocator;
fn fixture() !O.protocol.Proof {
    var hashes = [_][32]u8{@splat(7)};
    var values = [_]Native.SecureWire{.{ 1, 2, 3, 4, 5, 6, 7, 8 }};
    var columns = [_][]Native.SecureWire{&values};
    var trees = [_][][]Native.SecureWire{&columns};
    var decommitments = [_]Native.MerkleDecommitmentWire{.{ .hash_witness = &hashes }};
    var queries = [_]u32{ 8, 9 };
    var query_columns = [_][]u32{&queries};
    var query_trees = [_][][]u32{&query_columns};
    const layer = Native.FriLayerWire{ .fri_witness = &values, .decommitment = decommitments[0], .commitment = @splat(8) };
    return Native.wireToProof(a, .{ .config = (try O.protocol.targetConfig()), .commitments = &hashes, .sampled_values = &trees, .decommitments = &decommitments, .queried_values = &query_trees, .proof_of_work = 3, .fri_proof = .{ .first_layer = layer, .inner_layers = &.{}, .last_layer_poly = &values } });
}
fn section(class: *const P.Class) !S.Section {
    const words = try a.alloc(u32, S.wordCount(class));
    defer a.free(words);
    @memset(words, 1);
    words[0..5].* = .{ P.MAGIC, class.version(), class.id, @intCast(class.instances.len), class.layers() };
    return S.decode(a, class, words);
}
test "hybrid wire source-owned geometry canonical claims version authority and cross-family rejection" {
    var pp: @import("stwo_circuit_frontend").common.preprocessed.PreprocessedCircuit = undefined;
    pp.n_outputs = 1;
    var source: O.prove.Authority = undefined;
    source.pp = &pp;
    var key: R.Key = undefined;
    key.source = &source;
    key.identity = @splat(19);
    key.class = P.TEST_SMALL;
    key.class.binding_version = .cyclic_eq_v2;
    var sec = try section(&key.class);
    defer sec.deinit(a);
    var proof = try fixture();
    defer proof.deinit(a);
    const claims = O.witness.Claims.fromArray(@splat(O.protocol.O.zero()));
    const outputs = [_]O.protocol.Q{O.protocol.Q.fromU32Unchecked(2, 3, 4, 5)};
    const bytes = try W.encode(a, &key, &outputs, claims, &sec, &proof);
    defer a.free(bytes);
    var decoded = try W.decode(a, &key, bytes);
    defer decoded.deinit();
    const again = try W.encode(a, &key, decoded.base.outputs, decoded.base.claims, &decoded.section, &decoded.base.proof);
    defer a.free(again);
    try std.testing.expectEqualSlices(u8, bytes, again);
    try std.testing.expectError(error.InvalidOm31CircuitWire, O.wire.decode(a, key.identity, 1, bytes));
    const legacy = try O.wire.encode(a, key.identity, &outputs, claims, &proof);
    defer a.free(legacy);
    try std.testing.expectError(error.InvalidHybridWire, W.decode(a, &key, legacy));
    for ([_]usize{ 0, 8, 20 }) |at| {
        bytes[at] ^= 1;
        try std.testing.expectError(error.InvalidHybridWire, W.decode(a, &key, bytes));
        bytes[at] ^= 1;
    }
    bytes[24] ^= 1;
    try std.testing.expectError(error.HybridWireAuthority, W.decode(a, &key, bytes));
    bytes[24] ^= 1;
    bytes[12] ^= 1;
    try std.testing.expectError(error.HybridWireSectionLength, W.decode(a, &key, bytes));
    bytes[12] ^= 1;
    for (0..W.HEADER_BYTES) |cut| try std.testing.expectError(error.InvalidHybridWire, W.decode(a, &key, bytes[0..cut]));
    const inter = W.HEADER_BYTES + 4 * S.wordCount(&key.class);
    for ([_]usize{ W.HEADER_BYTES, inter - 1, inter, inter + 1, bytes.len - 1 }) |cut| try std.testing.expectError(error.InvalidHybridWire, W.decode(a, &key, bytes[0..cut]));
    const extra = try a.alloc(u8, bytes.len + 1);
    defer a.free(extra);
    @memcpy(extra[0..bytes.len], bytes);
    extra[bytes.len] = 0;
    try std.testing.expectError(error.InvalidHybridWire, W.decode(a, &key, extra));
    const salt_at = W.HEADER_BYTES + 5 * 4;
    const saved = bytes[salt_at..][0..4].*;
    std.mem.writeInt(u32, bytes[salt_at..][0..4], @import("stwo_core").fields.m31.Modulus, .little);
    try std.testing.expectError(error.NonCanonicalOuterGkrWord, W.decode(a, &key, bytes));
    @memcpy(bytes[salt_at..][0..4], &saved);
    var bad_claims = claims.toArray();
    bad_claims[2] = O.protocol.O.one();
    try std.testing.expectError(error.InvalidHybridClassicClaim, W.encode(a, &key, &outputs, O.witness.Claims.fromArray(bad_claims), &sec, &proof));
    const claim_at = inter + 76 + 16 + 2 * 32;
    std.mem.writeInt(u32, bytes[claim_at..][0..4], 1, .little);
    try std.testing.expectError(error.InvalidHybridClassicClaim, W.decode(a, &key, bytes));
}
