//! Bounded, profile/ordinal-owned physical worker container. Full P2 roots live
//! inside the separately versioned W02 proof; globals are AIR-authenticated claims.
const std = @import("std");
const core = @import("stwo_core");
const Protocol = @import("worker_protocol.zig");
const Encoded = @import("cpu_worker.zig").Encoded;
const O = Protocol.W.O;
pub const MAGIC = "P2CPUV02";
pub const HEADER: usize = 56;
pub const MAX_PROOF: usize = 64 << 20;
pub const MAX_CLAIMS: usize = 256;
pub fn encode(a: std.mem.Allocator, profile: Protocol.Profile, ordinal: u32, encoded: *const Encoded) ![]u8 {
    if (ordinal >= 256 or encoded.claims.len > MAX_CLAIMS or encoded.bytes.len == 0 or encoded.bytes.len > MAX_PROOF) return error.PoseidonNativeWireBounds;
    const claim_bytes = try std.math.mul(usize, 32, encoded.claims.len);
    const out = try a.alloc(u8, try std.math.add(usize, HEADER + claim_bytes, encoded.bytes.len));
    errdefer a.free(out);
    @memcpy(out[0..8], MAGIC);
    @memcpy(out[8..40], &profile.identity());
    std.mem.writeInt(u32, out[40..44], ordinal, .little);
    std.mem.writeInt(u32, out[44..48], @intCast(encoded.claims.len), .little);
    std.mem.writeInt(u64, out[48..56], encoded.bytes.len, .little);
    for (encoded.claims, 0..) |claim, i| for (claim.toM31Array(), 0..) |word, c| {
        if (word.v >= core.fields.m31.Modulus) return error.PoseidonNativeWireCanonical;
        std.mem.writeInt(u32, out[HEADER + 32 * i + 4 * c ..][0..4], word.v, .little);
    };
    @memcpy(out[HEADER + claim_bytes ..], encoded.bytes);
    return out;
}
pub fn decode(a: std.mem.Allocator, profile: Protocol.Profile, ordinal: u32, bytes: []const u8) !Encoded {
    if (bytes.len < HEADER or !std.mem.eql(u8, bytes[0..8], MAGIC) or !std.mem.eql(u8, bytes[8..40], &profile.identity()) or ordinal >= 256 or std.mem.readInt(u32, bytes[40..44], .little) != ordinal) return error.PoseidonNativeWireProfile;
    const n = std.mem.readInt(u32, bytes[44..48], .little);
    const proof_len = std.mem.readInt(u64, bytes[48..56], .little);
    if (n > MAX_CLAIMS or proof_len == 0 or proof_len > MAX_PROOF) return error.PoseidonNativeWireBounds;
    const claim_bytes = @as(usize, n) * 32;
    if (bytes.len != HEADER + claim_bytes + proof_len) return error.PoseidonNativeWireLength;
    // Preflight every scalar before allocation, including zero-weight claims.
    for (0..@as(usize, n) * 8) |i| if (std.mem.readInt(u32, bytes[HEADER + 4 * i ..][0..4], .little) >= core.fields.m31.Modulus) return error.PoseidonNativeWireCanonical;
    const claims = try a.alloc(O, n);
    errdefer a.free(claims);
    for (claims, 0..) |*claim, i| {
        var coordinates: [8]core.fields.m31.M31 = undefined;
        for (&coordinates, 0..) |*word, c| word.* = core.fields.m31.M31.fromCanonical(std.mem.readInt(u32, bytes[HEADER + 32 * i + 4 * c ..][0..4], .little));
        claim.* = O.fromM31Array(coordinates);
    }
    return .{ .claims = claims, .bytes = try a.dupe(u8, bytes[HEADER + claim_bytes ..]) };
}
