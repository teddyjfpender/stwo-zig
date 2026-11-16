//! Private qualification destinations; payload/security policy stays with each producer.
const std = @import("std");

pub const Provider = enum {
    arith_none,
    division,
    keccak_cpu,
    keccak_cpu_cyclic,
    keccak_cpu_none,
    lean,
    multiplication,
    mul_cpu,
    packed_full,
};

pub fn directory(a: std.mem.Allocator, provider: Provider) !?[]u8 {
    const root = std.process.getEnvVarOwned(a, "STWO_RV64_LEAN_ARTIFACT_DIR") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        else => return err,
    };
    defer a.free(root);
    return resolve(a, root, provider);
}

pub fn resolve(a: std.mem.Allocator, root: ?[]const u8, provider: Provider) !?[]u8 {
    const parent = root orelse return null;
    if (parent.len == 0) return error.InvalidRv64ArtifactRoot;
    return try std.fs.path.join(a, &.{ parent, @tagName(provider) });
}

test {
    _ = @import("native_artifact_root_test.zig");
}
