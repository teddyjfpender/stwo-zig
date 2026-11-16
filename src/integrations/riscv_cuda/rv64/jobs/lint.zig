//! Sync lint (spec §3.1): nothing reachable from a `Job.enqueue` may name a
//! host-blocking or lease symbol. Reachability is approximated at file level,
//! conservatively: every `rv64/jobs/*.zig` source and every relative
//! `@import("*.zig")` it reaches (legacy files included) is scanned, plus the
//! addon CUDA under `NAT/rv64/jobs/`. The worker's single host wait and the
//! op-table entry for it are the only exceptions, fenced by
//! `lint:host-wait-begin` / `lint:host-wait-end` and allowed only in worker.zig, worker_execution_phase.zig
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
const fenced_files = [_][]const u8{ "rv64/jobs/worker.zig", "rv64/jobs/worker_execution_phase.zig", "rv64/jobs/ops.zig", "../../backends/cuda/native/rv64/jobs/runtime.cu" };

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
        if (std.mem.eql(u8, path, f) or (path.len > f.len and path[path.len - f.len - 1] == '/' and std.mem.endsWith(u8, path, f))) break true;
    } else false;
    const worker_signature: ?[]const u8 = if (std.mem.eql(u8, std.fs.path.basename(path), "worker_execution_phase.zig"))
        "pub fn requestWait(self: *Worker, event: *anyopaque) !u64 {"
    else if (std.mem.eql(u8, std.fs.path.basename(path), "worker.zig"))
        "fn complete(self: *Worker, slot: *Slot) void {"
    else
        null;
    const wait_statement = if (std.mem.eql(u8, std.fs.path.basename(path), "worker.zig"))
        "const waited = self.ops.wait.event_sync(slot.done_event.?);"
    else
        "const waited = self.ops.wait.event_sync(event);";
    var in_wait_owner = false;
    var wait_fences: usize = 0;
    var wait_calls: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var number: usize = 0;
    while (lines.next()) |line| {
        number += 1;
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (worker_signature) |signature| if (std.mem.startsWith(u8, trimmed, "fn ") or std.mem.startsWith(u8, trimmed, "pub fn ")) {
            in_wait_owner = std.mem.eql(u8, trimmed, signature);
        };
        if (std.mem.indexOf(u8, line, fence_begin) != null) {
            if (!may_fence) return .{ .file = path, .line = number, .symbol = fence_begin };
            if (fenced) return error.NestedLintFence;
            if (worker_signature != null) {
                if (!in_wait_owner or wait_fences != 0) return .{ .file = path, .line = number, .symbol = "unreviewed worker wait fence" };
                wait_fences += 1;
            }
            fenced = true;
            continue;
        }
        if (std.mem.indexOf(u8, line, fence_end) != null) {
            if (!fenced) return error.UnbalancedLintFence;
            if (worker_signature != null and wait_calls != 1) return .{ .file = path, .line = number, .symbol = "worker wait call count" };
            fenced = false;
            continue;
        }
        const code = if (std.mem.indexOf(u8, line, "//")) |c| line[0..c] else line;
        if (fenced) {
            if (worker_signature != null) {
                const statement = std.mem.trim(u8, code, " \t\r");
                if (statement.len != 0) {
                    if (!std.mem.eql(u8, statement, wait_statement)) return .{ .file = path, .line = number, .symbol = "unreviewed worker wait body" };
                    wait_calls += 1;
                }
            }
            continue;
        }
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
        const path = try std.fs.path.join(a, &.{ "../../backends/cuda/native/rv64/jobs", entry.name });
        defer a.free(path);
        if (try scan(path, text)) |f| return .{ .file = try a.dupe(u8, path), .line = f.line, .symbol = f.symbol };
    }
    return null;
}

test "lint rejects sync symbols and lease APIs outside the worker's fenced wait" {
    try std.testing.expect((try scan("rv64/jobs/native_stage1.zig", "fn enqueue() void {\n    _ = ops.cudaStreamSynchronize(s);\n}")) != null);
    try std.testing.expect((try scan("rv64/jobs/outer_node.zig", "x.lease_allocate(1);")) != null);
    try std.testing.expect((try scan("rv64/jobs/outer_node.zig", "// cudaStreamSynchronize in a comment\nconst y = 1;")) == null);
    try std.testing.expect((try scan("rv64/jobs/outer_node.zig", "pub extern fn stwo_exec_context_sync(*anyopaque) c_int;")) == null);
    // A fence outside the worker is itself a finding.
    try std.testing.expect((try scan("rv64/jobs/other_worker.zig", "// lint:host-wait-begin\nevent_sync(e);\n// lint:host-wait-end")) != null);
    try std.testing.expect((try scan("rv64/jobs/native_stage1.zig", "// lint:host-wait-begin\nevent_sync(e);\n// lint:host-wait-end")) != null);
    try std.testing.expect((try scan("rv64/jobs/worker_execution_phase.zig", "pub fn requestWait(self: *Worker, event: *anyopaque) !u64 {\n// lint:host-wait-begin\nconst waited = self.ops.wait.event_sync(event);\n// lint:host-wait-end\n}")) == null);
    try std.testing.expect((try scan("rv64/jobs/worker.zig", "fn complete(self: *Worker, slot: *Slot) void {\n// lint:host-wait-begin\nconst waited = self.ops.wait.event_sync(slot.done_event.?);\n// lint:host-wait-end\n}")) == null);
    try std.testing.expectError(error.UnbalancedLintFence, scan("rv64/jobs/worker_execution_phase.zig", "pub fn requestWait(self: *Worker, event: *anyopaque) !u64 {\n// lint:host-wait-begin\n"));
}

test "wait ownership: phase extraction admits no added fences or extra wait calls" {
    const path = "rv64/jobs/worker_execution_phase.zig";
    const actual = @embedFile("worker_execution_phase.zig");
    try std.testing.expect((try scan(path, actual)) == null);
    const extra = actual ++ "\npub fn other() void {\n// lint:host-wait-begin\nconst waited = self.ops.wait.event_sync(event);\n// lint:host-wait-end\n}\n";
    try std.testing.expect((try scan(path, extra)) != null);
    const duplicated = try std.mem.replaceOwned(u8, std.testing.allocator, actual, "const waited = self.ops.wait.event_sync(event);", "const waited = self.ops.wait.event_sync(event);\nconst waited_again = self.ops.wait.event_sync(event);");
    defer std.testing.allocator.free(duplicated);
    try std.testing.expect((try scan(path, duplicated)) != null);
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
