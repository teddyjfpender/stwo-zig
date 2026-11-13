//! Runtime selection shared by explicit BLAKE3 device qualification gates.
const std = @import("std");
pub fn initialize(comptime Engine: type, a: std.mem.Allocator, mode: []const u8) !void {
    if (std.mem.eql(u8, mode, "authenticated_aot")) {
        const bundle = try std.process.getEnvVarOwned(a, "STWO_RISCV_METAL_AOT_BUNDLE");
        defer a.free(bundle);
        var directory = try std.fs.cwd().openDir(bundle, .{});
        defer directory.close();
        const anchor = try directory.readFileAlloc(a, "stwo_zig_core.manifest.sha256", 256);
        defer a.free(anchor);
        if (anchor.len < 64) return error.InvalidManifestTrustAnchor;
        var digest: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&digest, anchor[0..64]);
        try Engine.initializeRuntime(a, .{ .authenticated_aot = .{ .bundle_path = bundle, .manifest_sha256 = digest } });
    } else if (std.mem.eql(u8, mode, "source_jit")) {
        try Engine.initializeRuntime(a, .source_jit);
    } else return error.InvalidRuntimeMode;
}
