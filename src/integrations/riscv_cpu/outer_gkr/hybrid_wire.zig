//! Versioned hybrid envelope. Receiver-owned class fixes the complete GKR
//! section length; no producer count or legacy envelope selects a proof family.
const std = @import("std");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const R = @import("hybrid_receiver.zig");
const P = @import("profile.zig");
const S = @import("section.zig");
pub const MAGIC = "STWOHGK2";
pub const VERSION: u32 = 2;
pub const HEADER_BYTES: usize = 56;
pub const MAX_BYTES: usize = 64 << 20;
pub const Owned = struct {
    base: Outer.wire.Owned,
    section: S.Section,
    pub fn deinit(self: *@This()) void {
        self.section.deinit(self.base.allocator);
        self.base.deinit();
        self.* = undefined;
    }
};
fn word(bytes: []const u8, at: usize) u32 {
    return std.mem.readInt(u32, bytes[at..][0..4], .little);
}
fn put(bytes: []u8, at: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[at..][0..4], value, .little);
}
fn claimsCanonical(claims: Outer.witness.Claims) !void {
    for (claims.toArray(), 0..) |claim, i| if (P.gkrBound(@enumFromInt(i)) and !claim.isZero()) return error.InvalidHybridClassicClaim;
}
pub fn encode(a: std.mem.Allocator, key: *const R.Key, outputs: []const Outer.protocol.Q, claims: Outer.witness.Claims, section: *const S.Section, proof: *const Outer.protocol.Proof) ![]u8 {
    if (key.class.binding_version != .cyclic_eq_v2) return error.OuterGkrBindingVersion;
    if (outputs.len != key.source.pp.n_outputs) return error.Om31CircuitWireOutputCount;
    try claimsCanonical(claims);
    const own_section = S.Section{ .class = &key.class, .salt = section.salt, .proof = section.proof };
    const words = try S.encode(a, &own_section);
    defer a.free(words);
    const inner = try Outer.wire.encode(a, key.identity, outputs, claims, proof);
    defer a.free(inner);
    const size = try std.math.add(usize, HEADER_BYTES + 4 * words.len, inner.len);
    if (size > MAX_BYTES) return error.Om31CircuitWireLimit;
    const out = try a.alloc(u8, size);
    @memcpy(out[0..8], MAGIC);
    put(out, 8, VERSION);
    put(out, 12, @intCast(words.len));
    put(out, 16, @intCast(inner.len));
    put(out, 20, 0);
    @memcpy(out[24..56], &key.identity);
    for (words, 0..) |value, i| put(out, HEADER_BYTES + 4 * i, value);
    @memcpy(out[HEADER_BYTES + 4 * words.len ..], inner);
    return out;
}
pub fn decode(a: std.mem.Allocator, key: *const R.Key, bytes: []const u8) !Owned {
    if (bytes.len > MAX_BYTES) return error.Om31CircuitWireLimit;
    if (bytes.len < HEADER_BYTES or !std.mem.eql(u8, bytes[0..8], MAGIC) or word(bytes, 8) != VERSION or word(bytes, 20) != 0) return error.InvalidHybridWire;
    if (!std.mem.eql(u8, bytes[24..56], &key.identity)) return error.HybridWireAuthority;
    if (key.class.binding_version != .cyclic_eq_v2) return error.OuterGkrBindingVersion;
    const expected = S.wordCount(&key.class);
    if (word(bytes, 12) != expected) return error.HybridWireSectionLength;
    const inner_at = try std.math.add(usize, HEADER_BYTES, 4 * expected);
    if (inner_at > bytes.len or word(bytes, 16) != bytes.len - inner_at) return error.InvalidHybridWire;
    const words = try a.alloc(u32, expected);
    defer a.free(words);
    for (words, 0..) |*value, i| value.* = word(bytes, HEADER_BYTES + 4 * i);
    var section = try S.decode(a, &key.class, words);
    errdefer section.deinit(a);
    var inner = try Outer.wire.decode(a, key.identity, key.source.pp.n_outputs, bytes[inner_at..]);
    errdefer inner.deinit();
    try claimsCanonical(inner.claims);
    return .{ .base = inner, .section = section };
}
