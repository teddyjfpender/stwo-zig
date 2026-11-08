//! Sync lint (spec §3.1): nothing reachable from a `Job.enqueue` may name a
//! host-blocking or lease symbol. Reachability is approximated at file level,
//! conservatively: every `rv64/jobs/*.zig` source and every relative
//! `@import("*.zig")` it reaches (legacy files included) is scanned, plus the
//! addon CUDA under `NAT/rv64/jobs/`. The worker's single host wait and the
//! op-table entry for it are the only exceptions, fenced by
//! `lint:host-wait-begin` / `lint:host-wait-end` and allowed only in worker.zig
//! and ops.zig (and the exported wait in runtime.cu). Extern declarations are
//! not calls and are ignored. Test-only files (`*_test.zig`, fake.zig, lint.zig)
//! are not job code.
const std = @import("std");

pub const forbidden = [_][]const u8{
    "stwo_exec_context_sync",
    "stwo_exec_context_join_all_lanes",
    "cudaStreamSynchronize",
    "cudaEventSynchronize",
    "cudaDeviceSynchronize",
    "cudaStreamQuery",
    "memcpy_d2h",
    "event_sync",
    "stwo_rv64_gpu_session_submit",
    "stwo_rv64_gpu_lease",
    "lease_allocate",
    "lease_release",
};
const fence_begin = "lint:host-wait-begin";
const fence_end = "lint:host-wait-end";
const fenced_files = [_][]const u8{ "rv64/jobs/worker.zig", "rv64/jobs/ops.zig", "../../backends/cuda/native/rv64/jobs/runtime.cu" };

pub const Finding = struct { file: []const u8, line: usize, symbol: []const u8 };

/// D2 (rv64-m8-gpu-native.md §6.3): the GPU-native driver allocates device or
/// pinned memory and creates events ONLY at install, inside
/// `lint:install-begin` / `lint:install-end` fences (install runs once per
/// service). Applies to `driver*.zig` and the capture hand-off.
pub const install_only = [_][]const u8{ "alloc_u32", "host_alloc", "event_create", "cudaMalloc", "cudaHostAlloc", "cudaEventCreate" };
const install_begin = "lint:install-begin";
const install_end = "lint:install-end";

pub fn isDriverFile(path: []const u8) bool {
    const base = std.fs.path.basename(path);
    return (std.mem.startsWith(u8, base, "driver") and std.mem.endsWith(u8, base, ".zig") and !isTestOnly(base)) or std.mem.eql(u8, base, "m8_capture_stream.zig");
}

/// Request-path allocation lint for driver files (null = clean).
pub fn scanInstall(path: []const u8, text: []const u8) !?Finding {
    var fenced = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var number: usize = 0;
    var in_tests = false;
    while (lines.next()) |line| {
        number += 1;
        // Test blocks at the end of a file are not request-path code.
        if (std.mem.startsWith(u8, line, "test \"")) in_tests = true;
        if (in_tests) continue;
        if (std.mem.indexOf(u8, line, install_begin) != null) {
            if (fenced) return error.NestedLintFence;
            fenced = true;
            continue;
        }
        if (std.mem.indexOf(u8, line, install_end) != null) {
            if (!fenced) return error.UnbalancedLintFence;
            fenced = false;
            continue;
        }
        if (fenced) continue;
        const code = if (std.mem.indexOf(u8, line, "//")) |c| line[0..c] else line;
        for (install_only) |symbol| if (std.mem.indexOf(u8, code, symbol) != null) return .{ .file = path, .line = number, .symbol = symbol };
    }
    if (fenced) return error.UnbalancedLintFence;
    return null;
}

fn isTestOnly(name: []const u8) bool {
    return std.mem.endsWith(u8, name, "_test.zig") or std.mem.eql(u8, name, "fake.zig") or std.mem.eql(u8, name, "lint.zig");
}

/// Scan one source text. Returns the first offending line, or null.
pub fn scan(path: []const u8, text: []const u8) !?Finding {
    var fenced = false;
    const may_fence = for (fenced_files) |f| {
        if (std.mem.endsWith(u8, path, f[std.mem.lastIndexOfScalar(u8, f, '/').? + 1 ..])) break true;
    } else false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var number: usize = 0;
    while (lines.next()) |line| {
        number += 1;
        if (std.mem.indexOf(u8, line, fence_begin) != null) {
            if (!may_fence) return .{ .file = path, .line = number, .symbol = fence_begin };
            if (fenced) return error.NestedLintFence;
            fenced = true;
            continue;
        }
        if (std.mem.indexOf(u8, line, fence_end) != null) {
            if (!fenced) return error.UnbalancedLintFence;
            fenced = false;
            continue;
        }
        if (fenced) continue;
        const code = if (std.mem.indexOf(u8, line, "//")) |c| line[0..c] else line;
        if (std.mem.indexOf(u8, code, "extern fn") != null or std.mem.indexOf(u8, code, "extern \"C\"") != null and std.mem.indexOf(u8, code, "{") == null) continue;
        for (forbidden) |symbol| if (std.mem.indexOf(u8, code, symbol) != null) return .{ .file = path, .line = number, .symbol = symbol };
    }
    if (fenced) return error.UnbalancedLintFence;
    return null;
}

/// Scan every job source and its transitive relative imports from `root`
/// (the riscv_cuda integration directory).
pub fn scanTree(a: std.mem.Allocator, root: std.fs.Dir) !?Finding {
    var seen = std.StringHashMap(void).init(a);
    defer {
        var it = seen.keyIterator();
        while (it.next()) |k| a.free(k.*);
        seen.deinit();
    }
    var queue: std.ArrayListUnmanaged([]const u8) = .empty;
    defer queue.deinit(a);
    var jobs = try root.openDir("rv64/jobs", .{ .iterate = true });
    defer jobs.close();
    var it = jobs.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".zig") or isTestOnly(entry.name)) continue;
        const path = try std.fs.path.join(a, &.{ "rv64/jobs", entry.name });
        if ((try seen.getOrPut(path)).found_existing) a.free(path) else try queue.append(a, path);
    }
    while (queue.pop()) |path| {
        const text = try root.readFileAlloc(a, path, 16 << 20);
        defer a.free(text);
        if (try scan(path, text)) |f| return .{ .file = try a.dupe(u8, f.file), .line = f.line, .symbol = f.symbol };
        if (isDriverFile(path)) if (try scanInstall(path, text)) |f| return .{ .file = try a.dupe(u8, f.file), .line = f.line, .symbol = f.symbol };
        var at: usize = 0;
        while (std.mem.indexOfPos(u8, text, at, "@import(\"")) |i| {
            const start = i + 9;
            const end = std.mem.indexOfScalarPos(u8, text, start, '"') orelse break;
            at = end;
            const name = text[start..end];
            if (!std.mem.endsWith(u8, name, ".zig") or isTestOnly(std.fs.path.basename(name))) continue;
            const joined = try std.fs.path.join(a, &.{ std.fs.path.dirname(path) orelse ".", name });
            defer a.free(joined);
            const resolved = try std.fs.path.resolvePosix(a, &.{joined});
            if ((try seen.getOrPut(resolved)).found_existing) a.free(resolved) else try queue.append(a, resolved);
        }
    }
    // Addon CUDA: everything except the fenced exported wait.
    var native = root.openDir("../../backends/cuda/native/rv64/jobs", .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer native.close();
    var cu = native.iterate();
    while (try cu.next()) |entry| {
        if (entry.kind != .file) continue;
        const text = try native.readFileAlloc(a, entry.name, 16 << 20);
        defer a.free(text);
        if (try scan(entry.name, text)) |f| return .{ .file = try a.dupe(u8, entry.name), .line = f.line, .symbol = f.symbol };
    }
    return null;
}

test "lint rejects sync symbols and lease APIs outside the worker's fenced wait" {
    try std.testing.expect((try scan("rv64/jobs/native_stage1.zig", "fn enqueue() void {\n    _ = ops.cudaStreamSynchronize(s);\n}")) != null);
    try std.testing.expect((try scan("rv64/jobs/outer_node.zig", "x.lease_allocate(1);")) != null);
    try std.testing.expect((try scan("rv64/jobs/outer_node.zig", "// cudaStreamSynchronize in a comment\nconst y = 1;")) == null);
    try std.testing.expect((try scan("rv64/jobs/outer_node.zig", "pub extern fn stwo_exec_context_sync(*anyopaque) c_int;")) == null);
    // A fence outside the worker is itself a finding.
    try std.testing.expect((try scan("rv64/jobs/native_stage1.zig", "// lint:host-wait-begin\nevent_sync(e);\n// lint:host-wait-end")) != null);
    try std.testing.expect((try scan("rv64/jobs/worker.zig", "// lint:host-wait-begin\nevent_sync(e);\n// lint:host-wait-end")) == null);
    try std.testing.expectError(error.UnbalancedLintFence, scan("rv64/jobs/worker.zig", "// lint:host-wait-begin\n"));
}

test "D2: driver files allocate and create events only inside install fences" {
    try std.testing.expect(isDriverFile("rv64/jobs/driver_request.zig"));
    try std.testing.expect(isDriverFile("rv64/m8_capture_stream.zig"));
    try std.testing.expect(!isDriverFile("rv64/jobs/driver_test.zig"));
    try std.testing.expect((try scanInstall("rv64/jobs/driver_request.zig", "fn serve() void {\n    _ = ops.exec.alloc_u32_long(c, n, &p);\n}")) != null);
    try std.testing.expect((try scanInstall("rv64/jobs/driver_request.zig", "// lint:install-begin\n_ = wait.event_create(&e);\n// lint:install-end\n")) == null);
    try std.testing.expect((try scanInstall("rv64/jobs/driver_request.zig", "x();\ntest \"t\" {\n    _ = host_alloc(1);\n}")) == null);
    try std.testing.expectError(error.UnbalancedLintFence, scanInstall("rv64/jobs/driver_peer.zig", "// lint:install-begin\n"));
}

test "no sync symbol is reachable from any job source (file-level, transitive)" {
    var root = try std.fs.cwd().openDir(".", .{});
    defer root.close();
    if (try scanTree(std.testing.allocator, root)) |f| {
        defer std.testing.allocator.free(f.file);
        std.debug.print("sync lint: {s}:{} names {s}\n", .{ f.file, f.line, f.symbol });
        return error.SyncSymbolReachableFromEnqueue;
    }
}
