//! Create-only retained-corpus projection for adaptive Keccak profiles.

const std = @import("std");
const builtin = @import("builtin");
const projection = @import("air/guest_precompile/keccakf_adaptive_corpus_projection_v1.zig");

const maximum_journal_bytes: usize = 64 << 20;
const maximum_executable_bytes: usize = 256 << 20;

pub fn main() void {
    run() catch |err| {
        std.debug.print("Keccak adaptive projection failed: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };
}

fn run() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 3 or !std.fs.path.isAbsolute(args[2])) {
        std.debug.print(
            "usage: riscv-keccak-adaptive-projection <execution-v3.ndjson> " ++
                "<absolute-create-only-receipt.json>\n",
            .{},
        );
        return error.InvalidArguments;
    }

    var timer = try std.time.Timer.start();
    const journal = try readPathAlloc(
        allocator,
        args[1],
        maximum_journal_bytes,
    );
    defer allocator.free(journal);
    const self_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(self_path);
    const executable = try readPathAlloc(
        allocator,
        self_path,
        maximum_executable_bytes,
    );
    defer allocator.free(executable);
    var executable_sha256: projection.Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(executable, &executable_sha256, .{});

    var receipt = try projection.project(allocator, journal, .{
        .executable_sha256 = executable_sha256,
        .executable_bytes = executable.len,
    });
    try projection.bindRuntime(
        &receipt,
        timer.read(),
        try peakRssBytes(),
    );
    const encoded = try projection.encodeAlloc(allocator, receipt);
    defer allocator.free(encoded);
    var output = try std.fs.createFileAbsolute(args[2], .{
        .exclusive = true,
        .mode = 0o600,
    });
    defer output.close();
    try output.writeAll(encoded);
    try output.writeAll("\n");
    try output.sync();
}

fn readPathAlloc(
    allocator: std.mem.Allocator,
    path: []const u8,
    maximum_bytes: usize,
) ![]u8 {
    var file = if (std.fs.path.isAbsolute(path))
        try std.fs.openFileAbsolute(path, .{})
    else
        try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return file.readToEndAlloc(allocator, maximum_bytes);
}

fn peakRssBytes() !u64 {
    const usage = std.posix.getrusage(0);
    if (usage.maxrss <= 0) return error.ResourceUsageUnavailable;
    const native: u64 = @intCast(usage.maxrss);
    return switch (builtin.os.tag) {
        .linux => std.math.mul(u64, native, 1024) catch
            error.ResourceUsageUnavailable,
        .macos, .ios => native,
        else => error.ResourceUsageUnavailable,
    };
}
