//! Optional diagnostic cold/live setup comparison during actual collection.
//! This switch adds validation; it never grants publication or proof authority.
const std = @import("std");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
pub const ENV = "STWO_BLOCK_V6_QUALIFY_FIXED_PARITY";
pub fn enabled(a: std.mem.Allocator) !bool {
    const value = std.process.getEnvVarOwned(a, ENV) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return false,
        else => return err,
    };
    defer a.free(value);
    if (std.mem.eql(u8, value, "1")) return true;
    if (std.mem.eql(u8, value, "0")) return false;
    return error.InvalidFixedParityOption;
}
pub fn profile(config: @import("stwo_core").pcs.PcsConfig) !Base.Profile {
    inline for (std.meta.tags(Base.Profile)) |candidate| if (std.meta.eql(config, candidate.config())) return candidate;
    return error.UnsupportedFixedParityProfile;
}
