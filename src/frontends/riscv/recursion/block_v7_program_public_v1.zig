//! Public operand transport for the finite original ROM verifier.
//! Values are reconstructed from independently selected policy/epoch metadata;
//! possession of Values alone is never a proof-success receipt.
const std = @import("std");
const Profile = @import("block_v7_program_fixed_profile_v1.zig");
const Statement = @import("air/block_v7_program_statement_v1.zig");
const P = struct {
    pub const Admission = struct {
        pub const Prepared = Profile.Owned;
    };
    pub const Statement = @import("air/block_v7_program_statement_v1.zig");
    pub const IDENTITY_TAG: u32 = 0x42375049;
    pub const SCHEDULE_TAG: u32 = 0x42375057;
};
pub const API = @import("block_v5_recursive_fused_public_bus_v1.zig").ForFamily(P);
pub const Wire = API.Wire;
pub const Values = API.Values;
pub const supply = API.supply;
pub const scheduleDigest = API.scheduleDigest;
pub fn reconstruct(a: std.mem.Allocator, profile: *const Profile.Owned) !Values {
    try profile.validate();
    var statement = try Statement.init(a, profile);
    errdefer statement.deinit();
    const public = try @import("air/block_v7_program_inputs_v1.zig").publicInputs(a, profile);
    errdefer a.free(public);
    const result = Values{ .allocator = a, .template = profile.seal, .statement = statement, .public = public, .roots_count = 2 };
    try result.validate();
    return result;
}
pub fn requireSameFrame(got: Values, expected: Values) !void {
    try got.validate();
    try expected.validate();
    if (!std.meta.eql(got.template, expected.template) or got.roots_count != expected.roots_count or
        !std.meta.eql(got.statement.roots_offset, expected.statement.roots_offset) or got.statement.sealed_offset != expected.statement.sealed_offset or
        !std.mem.eql(u32, got.statement.words, expected.statement.words) or !std.meta.eql(got.statement.felts.len, expected.statement.felts.len) or got.public.len != expected.public.len or
        got.statement.first.len != expected.statement.first.len or got.statement.claims.len != expected.statement.claims.len) return error.UntrustedProgramPublicFrame;
    for (got.statement.felts, expected.statement.felts) |x, y| if (!x.eql(y)) return error.UntrustedProgramPublicFrame;
    for (got.public, expected.public) |x, y| if (!x.eql(y)) return error.UntrustedProgramPublicFrame;
    for (got.statement.first, expected.statement.first) |x, y| if (!std.meta.eql(x, y)) return error.UntrustedProgramPublicFrame;
    for (got.statement.claims, expected.statement.claims) |x, y| if (!std.meta.eql(x, y)) return error.UntrustedProgramPublicFrame;
}
