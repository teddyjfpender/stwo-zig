//! Bounded transport for the native OM31 circuit proof family. The receiver
//! supplies independently reconstructed authority and output count; neither is
//! selected by this envelope. Decoding is not proof verification.
const std = @import("std");
const P = @import("protocol.zig");
const W = @import("witness.zig");
const List = @import("stwo_circuit_frontend").common.component_list;
const Native = @import("stwo_proof_wire").ForField(P.O);
pub const MAX_BYTES = 64 << 20;
pub const MAX_OUTPUTS = 65536;
const magic = "STWOCOM1";
const header_bytes = 8 + 32 + 32 + 4;
const claims_bytes = List.N_COMPONENTS * 8 * 4;

pub const Owned = struct {
    allocator: std.mem.Allocator,
    outputs: []P.Q,
    claims: W.Claims,
    proof: P.Proof,
    pub fn deinit(self: *Owned) void {
        self.proof.deinit(self.allocator);
        self.allocator.free(self.outputs);
        self.* = undefined;
    }
};
fn profile() [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(P.domainName(), &digest, .{});
    return digest;
}
fn put(bytes: []u8, at: *usize, word: u32) void {
    std.mem.writeInt(u32, bytes[at.*..][0..4], word, .little);
    at.* += 4;
}
fn get(bytes: []const u8, at: *usize) u32 {
    const word = std.mem.readInt(u32, bytes[at.*..][0..4], .little);
    at.* += 4;
    return word;
}
pub fn encode(a: std.mem.Allocator, authority: [32]u8, outputs: []const P.Q, claims: W.Claims, proof: *const P.Proof) ![]u8 {
    if (outputs.len > MAX_OUTPUTS) return error.Om31CircuitWireLimit;
    try P.validateConfig(proof.commitment_scheme_proof.config);
    const physical = try Native.encodeProofBytesBinary(a, proof.*);
    defer a.free(physical);
    const size = header_bytes + outputs.len * 16 + claims_bytes + 4 + physical.len;
    if (size > MAX_BYTES) return error.Om31CircuitWireLimit;
    const out = try a.alloc(u8, size);
    @memcpy(out[0..8], magic);
    @memcpy(out[8..40], &profile());
    @memcpy(out[40..72], &authority);
    var at: usize = 72;
    put(out, &at, @intCast(outputs.len));
    for (outputs) |value| for (value.toM31Array()) |coordinate| put(out, &at, coordinate.v);
    for (claims.toArray()) |value| for (value.toM31Array()) |coordinate| put(out, &at, coordinate.v);
    put(out, &at, @intCast(physical.len));
    @memcpy(out[at..], physical);
    return out;
}
pub fn decode(a: std.mem.Allocator, authority: [32]u8, n_outputs: usize, bytes: []const u8) !Owned {
    if (bytes.len > MAX_BYTES or n_outputs > MAX_OUTPUTS) return error.Om31CircuitWireLimit;
    if (bytes.len < header_bytes + claims_bytes + 4 or !std.mem.eql(u8, bytes[0..8], magic)) return error.InvalidOm31CircuitWire;
    if (!std.mem.eql(u8, bytes[8..40], &profile())) return error.Om31CircuitWireProfile;
    if (!std.mem.eql(u8, bytes[40..72], &authority)) return error.Om31CircuitWireAuthority;
    var at: usize = 72;
    if (get(bytes, &at) != n_outputs) return error.Om31CircuitWireOutputCount;
    const payload_at = header_bytes + n_outputs * 16 + claims_bytes + 4;
    if (bytes.len < payload_at) return error.InvalidOm31CircuitWire;
    // Validate every coordinate and the complete frame before allocating.
    var scan = at;
    while (scan < payload_at - 4) {
        if (get(bytes, &scan) >= @import("stwo_core").fields.m31.Modulus) return error.NonCanonicalM31;
    }
    const physical_len = get(bytes, &scan);
    if (physical_len != bytes.len - payload_at) return error.InvalidOm31CircuitWire;
    const outputs = try a.alloc(P.Q, n_outputs);
    errdefer a.free(outputs);
    for (outputs) |*value| {
        var coordinates: [4]P.M = undefined;
        for (&coordinates) |*coordinate| coordinate.* = P.M.fromCanonical(get(bytes, &at));
        value.* = P.Q.fromM31Array(coordinates);
    }
    var claims: [List.N_COMPONENTS]P.O = undefined;
    for (&claims) |*value| {
        var coordinates: [8]P.M = undefined;
        for (&coordinates) |*coordinate| coordinate.* = P.M.fromCanonical(get(bytes, &at));
        value.* = P.O.fromM31Array(coordinates);
    }
    var proof = try Native.decodeProofBytesBinary(a, bytes[payload_at..]);
    errdefer proof.deinit(a);
    try P.validateConfig(proof.commitment_scheme_proof.config);
    return .{ .allocator = a, .outputs = outputs, .claims = W.Claims.fromArray(claims), .proof = proof };
}
