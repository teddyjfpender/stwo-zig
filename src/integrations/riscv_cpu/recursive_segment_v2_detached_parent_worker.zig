//! Pinned, sequential requests sharing a worker-owned workspace. stdout is RPC;
//! candidate publication never substitutes for independent proof verification.
const std = @import("std");
const producer = @import("recursive_segment_v2_detached_parent_producer.zig");
const batch = producer.batch;

pub const CpuGuard = struct {
    pub fn check(_: *@This()) !void {}
};
const Request = struct { path: []const u8, sha256: []const u8 };

pub fn serve(comptime Engine: type, allocator: std.mem.Allocator, initial: *const batch.Admitted, guard: anytype) !void {
    const limits = initial.parsed.value;
    var workspace = producer.WorkspaceFor(Engine).init(allocator, limits.session_byte_budget, limits.retained_scratch_byte_limit);
    defer workspace.deinit();
    workspace.pcs_plans.byte_budget = limits.pcs_plan_byte_budget;
    try runOne(Engine, allocator, initial, &workspace, guard);
    // Manifest paths and pins are small. Bound framing before allocating/parsing.
    var buffer: [8192]u8 = undefined;
    while (try readLine(std.fs.File.stdin(), &buffer)) |line| {
        const request = try std.json.parseFromSlice(Request, allocator, line, .{});
        defer request.deinit();
        var admitted = try batch.admit(allocator, request.value.path, request.value.sha256);
        defer admitted.deinit();
        const value = admitted.parsed.value;
        if (value.session_byte_budget != limits.session_byte_budget or
            value.retained_scratch_byte_limit != limits.retained_scratch_byte_limit or
            value.pcs_plan_byte_budget != limits.pcs_plan_byte_budget) return error.ParentWorkerLimitsChanged;
        try runOne(Engine, allocator, &admitted, &workspace, guard);
    }
}

fn runOne(comptime Engine: type, allocator: std.mem.Allocator, input: *const batch.Admitted, workspace: *producer.WorkspaceFor(Engine), guard: anytype) !void {
    if (input.parsed.value.requests.len != 1) return error.ParentWorkerRequiresOneRequest;
    var timer = try std.time.Timer.start();
    const report = try producer.runWithWorkspace(Engine, allocator, try producer.parseArguments(input.parsed.value.requests[0]), workspace);
    if (workspace.active) return error.ParentWorkerRequestStillActive;
    try guard.check();
    const json = try std.json.Stringify.valueAlloc(allocator, .{
        .endpoint = "detached_parent_worker_candidate",
        .report = report,
        .requests = workspace.requests,
        .plan_builds = workspace.plan_builds,
        .pcs_plan_builds = workspace.pcs_plans.builds,
        .pcs_plan_hits = workspace.pcs_plans.hits,
        .pcs_plan_retained_bytes = workspace.pcs_plans.retained_bytes,
        .retained_scratch_bytes = workspace.scratch.queryCapacity(),
        .elapsed_ns = timer.read(),
    }, .{});
    defer allocator.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}

fn readLine(file: std.fs.File, buffer: []u8) !?[]const u8 {
    var used: usize = 0;
    while (used < buffer.len) {
        const count = try file.read(buffer[used .. used + 1]);
        if (count == 0) return if (used == 0) null else error.TruncatedParentWorkerRequest;
        if (buffer[used] == '\n') return buffer[0..used];
        used += 1;
    }
    return error.ParentWorkerRequestTooLarge;
}
