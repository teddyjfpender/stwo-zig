//! Deployment preflight only; the outer authority still authenticates/parses
//! its own recording when constructed. No replacement path/pin is admitted.
const std = @import("std");
const Air = @import("stwo_circuit_cpu_integration").air;

pub fn require(a: std.mem.Allocator) !void {
    checkFile(a, std.fs.cwd(), Air.bundle_path, Air.bundle_sha256) catch |err| {
        std.log.err("combined circuit AIR preflight failed: path={s} expected_sha256={s} error={s}", .{ Air.bundle_path, Air.bundle_sha256, @errorName(err) });
        return err;
    };
}
fn checkFile(a: std.mem.Allocator, dir: std.fs.Dir, path: []const u8, expected: []const u8) !void {
    const bytes = dir.readFileAlloc(a, path, 64 << 20) catch |err| switch (err) {
        error.FileNotFound => return error.MissingCombinedCircuitAir,
        else => return err,
    };
    defer a.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const actual = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &actual, expected)) return error.InvalidOm31CircuitAirAuthority;
}

test "combined AIR deployment preflight rejects missing or changed file and accepts exact bytes" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const bytes = "deployment preflight fixture";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const expected = std.fmt.bytesToHex(digest, .lower);
    try std.testing.expectError(error.MissingCombinedCircuitAir, checkFile(std.testing.allocator, temporary.dir, "air.bin", &expected));
    try temporary.dir.writeFile(.{ .sub_path = "air.bin", .data = bytes });
    try checkFile(std.testing.allocator, temporary.dir, "air.bin", &expected);
    try temporary.dir.writeFile(.{ .sub_path = "air.bin", .data = "deployment preflight fixturf" });
    try std.testing.expectError(error.InvalidOm31CircuitAirAuthority, checkFile(std.testing.allocator, temporary.dir, "air.bin", &expected));
}
