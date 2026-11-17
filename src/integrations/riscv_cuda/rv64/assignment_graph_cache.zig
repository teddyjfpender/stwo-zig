//! Enqueue-only assignment graph ownership, shared by lease and job adapters.
//! Graphs retain schedule metadata only; each launch rebinds every live pointer
//! through the native context/custody checks. No waits or lease operations.
const std = @import("std");
const Budget = @import("jobs/outer_graph_cache.zig").Budget;
pub const Step = extern struct { first: u32, count: u32, first_level: u32, levels: u32, kind: u32 };
pub const Api = struct {
    create: *const fn (*anyopaque, u32, *const anyopaque, [*]const Step, u32, [*]const u32, u32, *?*anyopaque) callconv(.c) c_int,
    launch: *const fn (*anyopaque, u32, *anyopaque, *const anyopaque, [*]const u32, u32) callconv(.c) c_int,
    charged_bytes: ?*const fn (*anyopaque, *anyopaque, *u64) callconv(.c) c_int = null,
    destroy: *const fn (*anyopaque, *anyopaque) callconv(.c) c_int,
    pub fn load(lib: *std.DynLib) !Api {
        return .{
            .charged_bytes = lib.lookup(*const fn (*anyopaque, *anyopaque, *u64) callconv(.c) c_int, "stwo_assignment_graph_charged_bytes_v1"),
            .create = lib.lookup(@FieldType(Api, "create"), "stwo_assignment_graph_create_v1") orelse return error.MissingAssignmentGraphRuntime,
            .launch = lib.lookup(@FieldType(Api, "launch"), "stwo_assignment_graph_launch_v1") orelse return error.MissingAssignmentGraphRuntime,
            .destroy = lib.lookup(@FieldType(Api, "destroy"), "stwo_assignment_graph_destroy_v1") orelse return error.MissingAssignmentGraphRuntime,
        };
    }
};
pub fn key(identity: [32]u8, sequence: []const Step) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64/assignment-graph/chain-wide/v1\x00");
    hash.update(&identity);
    var word: [4]u8 = undefined;
    for (sequence) |s| for ([_]u32{ s.first, s.count, s.first_level, s.levels, s.kind }) |v| {
        std.mem.writeInt(u32, &word, v, .little);
        hash.update(&word);
    };
    return hash.finalResult();
}
const Entry = struct { key: [32]u8, handle: ?*anyopaque, context: *anyopaque, token: u64, lane: u32, bytes: u64 = 0 };
pub const Cache = struct {
    allocator: ?std.mem.Allocator = null,
    budget: ?*Budget = null,
    api: ?Api = null,
    entries: std.ArrayList(Entry) = .empty,
    /// Exec-context path. The native implementation validates current context
    /// identity and every input/output custody range before rebinding all nodes.
    pub fn runDevice(self: *Cache, api: Api, context: *anyopaque, lane: u32, identity: [32]u8, sequence: []const Step, job: anytype, ends: [*]const u32, end_count: usize) !bool {
        if (@sizeOf(@TypeOf(job.*)) != 56 or @sizeOf(Step) != 20) @compileError("assignment graph ABI changed");
        if (self.api == null) self.api = api;
        return self.runBound(self.allocator orelse return error.MissingAssignmentGraphAllocator, context, 0, lane, identity, sequence, job, ends, end_count);
    }
    pub fn runBound(self: *Cache, a: std.mem.Allocator, context: *anyopaque, token: u64, lane: u32, identity: [32]u8, sequence: []const Step, job: anytype, ends: [*]const u32, end_count: usize) !bool {
        const api = self.api.?;
        if (self.budget != null and api.charged_bytes == null) return error.AssignmentGraphChargeUnknown;
        var class_hash = std.crypto.hash.sha2.Sha256.init(.{});
        class_hash.update(&key(identity, sequence));
        var count_word: [4]u8 = undefined;
        for ([_]u32{ job.value_count, job.record_count, job.index_count }) |count| {
            std.mem.writeInt(u32, &count_word, count, .little);
            class_hash.update(&count_word);
        }
        const class_key = class_hash.finalResult();
        var handle: ?*anyopaque = null;
        var hit = false;
        for (self.entries.items) |entry| {
            if (entry.context != context or entry.token != token or entry.lane != lane) return error.ForeignAssignmentGraphContext;
            if (std.mem.eql(u8, &entry.key, &class_key)) {
                handle = entry.handle;
                hit = true;
                break;
            }
        }
        if (handle == null) {
            // CUDA defers executable resource release until queued work is
            // complete; no witness allocation is retained by this cache.
            if (self.entries.items.len == 32) {
                const old = self.entries.items[0];
                if (api.destroy(context, old.handle.?) != 0) return error.AssignmentGraphDestroyFailed;
                if (self.budget) |budget| budget.release(old.bytes);
                _ = self.entries.orderedRemove(0);
            }
            try self.entries.ensureUnusedCapacity(a, 1);
            const created = api.create(context, lane, job, sequence.ptr, @intCast(sequence.len), ends, @intCast(end_count), &handle);
            if (created == 900) return error.AssignmentGraphEnclosingCapture;
            if (created != 0 or handle == null) return error.AssignmentGraphCreateFailed;
            const bytes = self.charge(context, handle.?) catch |err| {
                if (api.destroy(context, handle.?) != 0) return error.AssignmentGraphDestroyFailed;
                return err;
            };
            self.entries.appendAssumeCapacity(.{ .key = class_key, .handle = handle, .context = context, .token = token, .lane = lane, .bytes = bytes });
        }
        if (api.launch(context, lane, handle.?, job, ends, @intCast(end_count)) != 0) return error.AssignmentGraphLaunchFailed;
        return hit;
    }
    fn charge(self: *Cache, context: *anyopaque, handle: *anyopaque) !u64 {
        const budget = self.budget orelse return 0;
        var bytes: u64 = undefined;
        if (self.api.?.charged_bytes.?(context, handle, &bytes) != 0) return error.AssignmentGraphChargeQueryFailed;
        if (bytes == std.math.maxInt(u64)) return error.AssignmentGraphChargeUnknown;
        budget.observeCandidate(bytes);
        try budget.reserve(bytes);
        return bytes;
    }
    /// Call only after the worker has quiesced, before its exec context dies.
    pub fn deinitDevice(self: *Cache, context: *anyopaque) void {
        for (self.entries.items) |entry| {
            if (entry.context != context or self.api.?.destroy(context, entry.handle.?) != 0) {
                std.debug.print("GPU_ASSIGNMENT_GRAPH_CLEANUP_REFUSED fatal_worker=true\n", .{});
            } else if (self.budget) |budget| budget.release(entry.bytes);
        }
        self.entries.deinit(self.allocator orelse return);
        self.entries = .empty;
    }
};

test "assignment device graph rebinds fresh pointers and rejects foreign context and launch failure" {
    const F = struct {
        const Job = extern struct { values: [*]u32, records: [*]const u32, indices: ?[*]const u32, status: *u32, value_count: u32 = 4, record_count: u32 = 1, index_count: u32 = 0, first: u32 = 0, count: u32 = 1, reserved: u32 = 0 };
        var creates: u32 = 0;
        var launches: u32 = 0;
        var destroys: u32 = 0;
        var latest: [4]usize = @splat(0);
        var create_fail: bool = false;
        var enclosing_capture: bool = false;
        var fail: bool = false;
        var charge: u64 = 8;
        var query_fail: bool = false;
        fn charged(_: *anyopaque, _: *anyopaque, out: *u64) callconv(.c) c_int {
            out.* = charge;
            return if (query_fail) 1 else 0;
        }
        fn create(_: *anyopaque, _: u32, _: *const anyopaque, _: [*]const Step, _: u32, _: [*]const u32, _: u32, out: *?*anyopaque) callconv(.c) c_int {
            creates += 1;
            if (enclosing_capture) return 900;
            if (create_fail) {
                out.* = null;
                return 1;
            }
            out.* = @ptrFromInt(16);
            return 0;
        }
        fn launch(_: *anyopaque, _: u32, _: *anyopaque, raw: *const anyopaque, ends: [*]const u32, _: u32) callconv(.c) c_int {
            const job: *const Job = @ptrCast(@alignCast(raw));
            latest = .{ @intFromPtr(job.values), @intFromPtr(job.records), @intFromPtr(job.status), @intFromPtr(ends) };
            launches += 1;
            return if (fail) 1 else 0;
        }
        fn destroy(_: *anyopaque, _: *anyopaque) callconv(.c) c_int {
            destroys += 1;
            return 0;
        }
    };
    F.creates = 0;
    F.launches = 0;
    F.destroys = 0;
    F.fail = false;
    F.create_fail = false;
    F.charge = 8;
    F.query_fail = false;
    var budget = Budget{ .limit = 16 };
    var cache = Cache{ .allocator = std.testing.allocator, .budget = &budget, .api = .{ .charged_bytes = F.charged, .create = F.create, .launch = F.launch, .destroy = F.destroy } };
    const ctx: *anyopaque = @ptrFromInt(32);
    defer cache.deinitDevice(ctx);
    const sequence = [_]Step{.{ .first = 0, .count = 1, .first_level = 0, .levels = 1, .kind = 0 }};
    var job = F.Job{ .values = @ptrFromInt(64), .records = @ptrFromInt(128), .indices = null, .status = @ptrFromInt(192) };
    try std.testing.expect(!try cache.runDevice(undefined, ctx, 0, @splat(7), &sequence, &job, @ptrFromInt(256), 1));
    job.values = @ptrFromInt(320);
    job.records = @ptrFromInt(384);
    job.status = @ptrFromInt(448);
    try std.testing.expect(try cache.runDevice(undefined, ctx, 0, @splat(7), &sequence, &job, @ptrFromInt(512), 1));
    try std.testing.expectEqual([_]usize{ 320, 384, 448, 512 }, F.latest);
    try std.testing.expectEqual(@as(u32, 1), F.creates);
    try std.testing.expectError(error.ForeignAssignmentGraphContext, cache.runDevice(undefined, @ptrFromInt(48), 0, @splat(7), &sequence, &job, @ptrFromInt(512), 1));
    try std.testing.expectError(error.ForeignAssignmentGraphContext, cache.runDevice(undefined, ctx, 1, @splat(7), &sequence, &job, @ptrFromInt(512), 1));
    F.query_fail = true;
    try std.testing.expectError(error.AssignmentGraphChargeQueryFailed, cache.runDevice(undefined, ctx, 0, @splat(8), &sequence, &job, @ptrFromInt(512), 1));
    F.query_fail = false;
    F.charge = std.math.maxInt(u64);
    try std.testing.expectError(error.AssignmentGraphChargeUnknown, cache.runDevice(undefined, ctx, 0, @splat(8), &sequence, &job, @ptrFromInt(512), 1));
    F.charge = 9;
    try std.testing.expectError(error.GraphBudgetExceeded, cache.runDevice(undefined, ctx, 0, @splat(8), &sequence, &job, @ptrFromInt(512), 1));
    try std.testing.expectEqual(@as(u64, 8), budget.used);
    F.enclosing_capture = true;
    try std.testing.expectError(error.AssignmentGraphEnclosingCapture, cache.runDevice(undefined, ctx, 0, @splat(8), &sequence, &job, @ptrFromInt(512), 1));
    F.enclosing_capture = false;
    F.create_fail = true;
    try std.testing.expectError(error.AssignmentGraphCreateFailed, cache.runDevice(undefined, ctx, 0, @splat(8), &sequence, &job, @ptrFromInt(512), 1));
    try std.testing.expectEqual(@as(usize, 1), cache.entries.items.len);
    F.fail = true;
    try std.testing.expectError(error.AssignmentGraphLaunchFailed, cache.runDevice(undefined, ctx, 0, @splat(7), &sequence, &job, @ptrFromInt(512), 1));
    cache.deinitDevice(ctx);
    try std.testing.expectEqual(@as(u32, 4), F.destroys);
    try std.testing.expectEqual(@as(u64, 0), budget.used);
}
