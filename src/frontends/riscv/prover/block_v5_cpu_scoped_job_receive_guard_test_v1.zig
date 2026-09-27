//! Bounded transport failures must reject before any original source or base
//! proof is touched. These tests grant no source/proof authority to a manifest.
const std = @import("std");
const Receive = @import("block_v5_cpu_scoped_job_receive_v1.zig");
const Job = @import("block_v5_cpu_scoped_job_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const PATH = "block-v5-cpu-scoped-nodes.pins";
fn manifest() [356]u8 {
    var raw: [356]u8 = @splat(0);
    @memcpy(raw[0..8], "B5SCJOB1");
    std.mem.writeInt(u32, raw[8..12], 2, .little);
    for (0..2) |index| {
        const row = raw[204 + index * 76 ..][0..76];
        std.mem.writeInt(u32, row[0..4], @intCast(index), .little);
        std.mem.writeInt(u64, row[4..12], 5, .little);
    }
    return raw;
}
fn rejectBeforeSources(dir: std.fs.Dir, raw: []const u8, digest: [32]u8, options: Job.Options, expected_error: anyerror) !void {
    try dir.writeFile(.{ .sub_path = PATH, .data = raw });
    // These are deliberately uninitialized authority pointers. A valid
    // transport would require independently reconstructed actual source owners.
    try std.testing.expectError(expected_error, Receive.verify(std.testing.allocator, dir, undefined, undefined, undefined, &.{}, .{ .leaves_manifest = @splat(0), .scoped_manifest = digest }, .diagnostic_q8_pow0, .{}, options));
}
test "cpu scoped receive guard: wrong pinned hash and short envelope reject before original source access" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const raw = manifest();
    var stale = Files.hash(&raw);
    stale[0] ^= 1;
    try rejectBeforeSources(directory.dir, &raw, stale, .{}, error.TamperedV5BundleFileHash);
    try rejectBeforeSources(directory.dir, raw[0..203], Files.hash(raw[0..203]), .{}, error.CpuScopedManifestResourceLimit);
}
test "cpu scoped receive guard: exact indices count length and magic reject before base proof consumption" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var raw = manifest();
    std.mem.writeInt(u32, raw[280..284], 0, .little);
    try rejectBeforeSources(directory.dir, &raw, Files.hash(&raw), .{}, error.UntrustedCpuScopedNodeManifest);
    raw = manifest();
    std.mem.writeInt(u32, raw[8..12], 1, .little);
    try rejectBeforeSources(directory.dir, &raw, Files.hash(&raw), .{}, error.CpuScopedManifestResourceLimit);
    raw = manifest();
    raw[0] ^= 1;
    try rejectBeforeSources(directory.dir, &raw, Files.hash(&raw), .{}, error.UntrustedCpuScopedNodeManifest);
}
test "cpu scoped receive guard: zero oversized per-file and aggregate bytes reject before cryptographic reconstruction" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var raw = manifest();
    std.mem.writeInt(u64, raw[208..216], 0, .little);
    try rejectBeforeSources(directory.dir, &raw, Files.hash(&raw), .{}, error.CpuScopedFoldResourceLimit);
    raw = manifest();
    try rejectBeforeSources(directory.dir, &raw, Files.hash(&raw), .{ .fold = .{ .max_parent_bytes = 4 } }, error.CpuScopedFoldResourceLimit);
    try rejectBeforeSources(directory.dir, &raw, Files.hash(&raw), .{ .fold = .{ .max_total_parent_bytes = 9 } }, error.CpuScopedFoldResourceLimit);
    try rejectBeforeSources(directory.dir, &raw, Files.hash(&raw), .{ .fold = .{ .setup = .{ .cohorts = .{ .max_nodes = 1 } } } }, error.CpuScopedManifestResourceLimit);
}
fn readAllocation(a: std.mem.Allocator, dir: std.fs.Dir, hash: [32]u8) !void {
    const raw = try Receive.readScopedManifest(a, dir, hash, .{});
    defer a.free(raw);
    try std.testing.expectEqual(@as(usize, 356), raw.len);
}
test "cpu scoped receive guard: bounded manifest allocation failure frees transport without upstream admission work" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const raw = manifest();
    try directory.dir.writeFile(.{ .sub_path = PATH, .data = &raw });
    try readAllocation(std.testing.allocator, directory.dir, Files.hash(&raw));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, readAllocation, .{ directory.dir, Files.hash(&raw) });
}
