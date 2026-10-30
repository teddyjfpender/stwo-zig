//! Bounded transport exercise and durable artifact capture; no proving here.
const std = @import("std");
const Multi = @import("../block_v7_multi_union_proof_v1.zig");
const Codec = @import("../block_v7_multi_union_codec_v1.zig");
const Receiver = @import("../block_v7_execution_receiver_v1.zig");
pub fn check(a: std.mem.Allocator, encoded: []const u8, trusted: Receiver.Trusted, input: Multi.Input, limits: Multi.Limits) !Receiver.Verified {
    const policy = Codec.Limits{ .scope = limits };
    var decoded = try Codec.decode(a, encoded, trusted, input, policy);
    defer decoded.deinit();
    const repeated = try Codec.encode(a, decoded.proof, input, policy);
    defer a.free(repeated);
    try std.testing.expectEqualSlices(u8, encoded, repeated);
    const verified = try Codec.verifyBytes(a, encoded, trusted, input, policy);
    try std.testing.expectError(error.OutOfMemory, Codec.decode(a, encoded, trusted, input, .{ .scope = limits, .decode_bytes = 1 }));
    try std.testing.expectError(error.OutOfMemory, Codec.verifyBytes(a, encoded, trusted, input, .{ .scope = limits, .verification_bytes = 1 }));
    const bad = try a.dupe(u8, encoded);
    defer a.free(bad);
    for ([_]usize{ 0, 8, 40 }) |index| {
        @memcpy(bad, encoded);
        bad[index] ^= 1;
        try std.testing.expectError(error.UntrustedMultiUnionEnvelope, Codec.decode(a, bad, trusted, input, policy));
    }
    @memcpy(bad, encoded);
    std.mem.writeInt(u32, bad[Codec.HEADER_BYTES..][0..4], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.UnionClaimCountLimit, Codec.decode(a, bad, trusted, input, policy));
    @memcpy(bad, encoded);
    const claim_len = std.mem.readInt(u32, encoded[Codec.HEADER_BYTES - 12 ..][0..4], .little);
    bad[Codec.HEADER_BYTES + claim_len] ^= 1;
    try std.testing.expectError(error.InvalidProofConfig, Codec.decode(a, bad, trusted, input, policy));
    try std.testing.expectError(error.EndOfStream, Codec.decode(a, encoded[0 .. encoded.len - 1], trusted, input, policy));
    const trailer = try a.alloc(u8, encoded.len + 1);
    defer a.free(trailer);
    @memcpy(trailer[0..encoded.len], encoded);
    trailer[encoded.len] = 0;
    try std.testing.expectError(error.TrailingSectionBytes, Codec.decode(a, trailer, trusted, input, policy));
    var unqualified = trusted;
    unqualified.config.lifting_log_size = 24;
    try std.testing.expectError(error.UnsupportedMultiUnionWireLifting, Codec.decode(a, encoded, unqualified, input, policy));
    std.debug.print("V7_MULTI_UNION_WIRE bytes={d} windows={d} callers={d} trees={d} decode_peak_bytes={d} fresh_verification=true hostile_framing=true\n", .{ encoded.len, input.natives.len, input.callers.len, decoded.proof.stark.commitment_scheme_proof.commitments.items.len, decoded.budget.snapshot().peak_live_bytes });
    return verified;
}
pub fn save(a: std.mem.Allocator, path: []const u8, proof: Multi.ProofView, trusted: Receiver.Trusted, input: Multi.Input, limits: Multi.Limits, expected: Receiver.Verified) !void {
    const encoded = try Codec.encode(a, proof, input, .{ .scope = limits });
    defer a.free(encoded);
    try std.testing.expectEqualDeep(expected, try check(a, encoded, trusted, input, limits));
    try std.fs.cwd().makePath(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    try dir.writeFile(.{ .sub_path = "proof.b7mun", .data = encoded });
    try dir.writeFile(.{ .sub_path = "guest.elf", .data = trusted.elf });
    const json = try std.json.Stringify.valueAlloc(a, .{ .version = Multi.VERSION, .tag = Multi.TAG, .input = input }, .{});
    defer a.free(json);
    try dir.writeFile(.{ .sub_path = "public-metadata.json", .data = json });
}
