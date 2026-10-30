//! Public operand transport for the finite original native execution verifier.
//! Values are reconstructed from independently selected policy/epoch metadata;
//! possession of Values alone is never a proof-success receipt.
const std = @import("std");
const Profile = @import("block_v7_native_fixed_profile_v1.zig");
const Statement = @import("air/block_v7_native_statement_v1.zig");
const P = struct {
    pub const Admission = struct {
        pub const Prepared = Profile.Owned;
    };
    pub const Statement = @import("air/block_v7_native_statement_v1.zig");
    pub const IDENTITY_TAG: u32 = 0x42374e49;
    pub const SCHEDULE_TAG: u32 = 0x42374e57;
};
pub const API = @import("block_v5_recursive_fused_public_bus_v1.zig").ForFamily(P);
pub const Wire = API.Wire;
pub const Values = API.Values;
pub const supply = API.supply;
pub const scheduleDigest = API.scheduleDigest;
pub const Claims = struct {
    projection: []const @import("../prover/block_v5_native_projection_fused_proof_v2.zig").Claim,
    access: []const @import("../prover/block_v5_opcode_memory_sidecar_proof_v1.zig").Claim,
};
pub fn reconstruct(a: std.mem.Allocator, profile: *const Profile.Owned, claims: Claims) !Values {
    try profile.validate();
    var statement = try Statement.init(a, profile, claims.projection, claims.access);
    errdefer statement.deinit();
    const public = try @import("air/block_v7_native_composition_v1.zig").publicInputs(a, profile, claims.projection, claims.access);
    errdefer a.free(public);
    const result = Values{ .allocator = a, .template = profile.seal, .statement = statement, .public = public, .roots_count = @intCast(profile.trace_count - 1) };
    try result.validate();
    return result;
}
pub fn requireSameFrame(got: Values, expected: Values) !void {
    try got.validate();
    try expected.validate();
    if (!std.meta.eql(got.template, expected.template) or got.roots_count != expected.roots_count or
        !std.meta.eql(got.statement.roots_offset, expected.statement.roots_offset) or got.statement.sealed_offset != expected.statement.sealed_offset or
        !std.mem.eql(u32, got.statement.words, expected.statement.words) or !std.meta.eql(got.statement.felts.len, expected.statement.felts.len) or got.public.len != expected.public.len or
        got.statement.first.len != expected.statement.first.len or got.statement.claims.len != expected.statement.claims.len) return error.UntrustedNativePublicFrame;
    for (got.statement.felts, expected.statement.felts) |x, y| if (!x.eql(y)) return error.UntrustedNativePublicFrame;
    for (got.public, expected.public) |x, y| if (!x.eql(y)) return error.UntrustedNativePublicFrame;
    for (got.statement.first, expected.statement.first) |x, y| if (!std.meta.eql(x, y)) return error.UntrustedNativePublicFrame;
    for (got.statement.claims, expected.statement.claims) |x, y| if (!std.meta.eql(x, y)) return error.UntrustedNativePublicFrame;
}
