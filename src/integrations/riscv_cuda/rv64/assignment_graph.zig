//! Bounded native graph metadata for the numerical assignment DAG only.
//! No device lease is retained. Every replay checks CURRENT scoped custody;
//! the cache key binds all pointer arguments and the exact task schedule.
const std = @import("std");
const SC = @import("session_context.zig");
const N = @import("pcs_native_abi.zig");
pub const Counters = struct { launches: usize = 0, ordinary: usize = 0, narrow: usize = 0, chain: usize = 0 };
const Lookup = *const fn (*anyopaque, u32, *const [32]u8, *?*anyopaque) callconv(.c) c_int;
const Begin = *const fn (*anyopaque, u32) callconv(.c) c_int;
const Store = *const fn (*anyopaque, u32, *const [32]u8, u64, *?*anyopaque) callconv(.c) c_int;
const Launch = *const fn (*anyopaque, u32, *anyopaque) callconv(.c) c_int;
const Abort = *const fn (*anyopaque) callconv(.c) c_int;
const Api = struct { lookup: Lookup, begin: Begin, store: Store, launch: Launch, abort_capture: Abort };
pub fn enabled() !bool {
    const value = std.posix.getenv("STWO_RV64_ASSIGNMENT_GRAPHS") orelse return false;
    if (std.mem.eql(u8, value, "0")) return false;
    if (std.mem.eql(u8, value, "1")) return true;
    return error.InvalidAssignmentGraphOption;
}
const Inputs = struct { values: N.Lease, tasks: N.Lease, indices: ?N.Lease, status: N.Lease, ends: ?N.Lease };
/// These checks deliberately precede a cache hit. In particular, recycled
/// addresses do not make an old generation, foreign context or scope valid.
pub fn validate(ctx: *SC.Context, inputs: Inputs) !void {
    const leases = [_]?N.Lease{ inputs.values, inputs.tasks, inputs.indices, inputs.status, inputs.ends };
    for (leases, 0..) |maybe, i| if (maybe) |lease| {
        if (i == 0 or i == 3) {
            // Mutable values/status must be request scratch, never sealed setup.
            if (lease.kind != 0) return error.InvalidAssignmentGraphInputs;
            _ = try ctx.borrow(lease);
        } else if (lease.kind == 4) {
            // Immutable task/index/end tapes are borrowed read-only through the
            // CURRENT scope alias. SC.borrow intentionally admits scratch only.
            if (lease.reserved != 0 or lease.words == null) return error.InvalidDeviceAddress;
            _ = try ctx.deviceSlicePointer(u32, .{
                .address = @intFromPtr(lease.words.?),
                .len = std.math.cast(usize, lease.count) orelse return error.SizeOverflow,
                .owner = std.math.cast(usize, lease.context_token) orelse return error.SizeOverflow,
                .generation = lease.generation,
            }, std.math.cast(usize, lease.count) orelse return error.SizeOverflow);
        } else {
            _ = try ctx.borrow(lease);
        }
        const begin = @intFromPtr(lease.words.?);
        const bytes = try std.math.mul(u64, lease.count, 4);
        const end = try std.math.add(u64, begin, bytes);
        for (leases[0..i]) |previous| if (previous) |old| {
            const old_begin = @intFromPtr(old.words.?);
            const old_end = try std.math.add(u64, old_begin, try std.math.mul(u64, old.count, 4));
            if (begin < old_end and old_begin < end) return error.AliasedAssignmentGraphInputs;
        };
    };
}
fn key(prepared: anytype, ctx: *SC.Context, job: anytype, ends: ?N.Lease) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-assignment-graph-v1");
    h.update(&prepared.identity);
    var word: [8]u8 = undefined;
    const fields = [_]u64{ ctx.token, @intFromPtr(ctx.native_context), @intFromPtr(job.values), @intFromPtr(job.records), if (job.indices) |p| @intFromPtr(p) else 0, @intFromPtr(job.status), job.value_count, job.record_count, job.index_count, if (ends) |lease| @intFromPtr(lease.words.?) else 0, if (prepared.wide_level) |f| @intFromPtr(f) else @intFromPtr(prepared.level), if (prepared.narrow_run) |f| @intFromPtr(f) else 0, if (prepared.chain_run) |f| @intFromPtr(f) else 0 };
    for (fields) |value| {
        std.mem.writeInt(u64, &word, value, .little);
        h.update(&word);
    }
    if (prepared.narrow_plan) |plan| for (plan.runs) |run| {
        const run_fields = [_]u64{ @intFromEnum(run.kind), run.first_task, run.task_count, run.first_level, run.level_count };
        for (run_fields) |value| {
            std.mem.writeInt(u64, &word, value, .little);
            h.update(&word);
        }
    };
    return h.finalResult();
}
fn traverse(prepared: anytype, ctx: *SC.Context, initial: anytype, ends: ?N.Lease, enqueue: bool) !Counters {
    var job = initial;
    var counters = Counters{};
    if (prepared.narrow_plan) |plan| {
        for (plan.runs) |run| {
            job.first = run.first_task;
            job.count = run.task_count;
            const rc = switch (run.kind) {
                .narrow => blk: {
                    const function = prepared.narrow_run orelse return error.MissingCircuitAssignmentNarrowRunKernel;
                    counters.narrow += 1;
                    break :blk if (enqueue) function(ctx.native_context, 1, &job, plan.ends[run.first_level..].ptr, run.level_count) else 0;
                },
                .chain => blk: {
                    const function = prepared.chain_run orelse return error.MissingCircuitAssignmentChainKernel;
                    const lease = ends orelse return error.MissingCircuitAssignmentChainKernel;
                    counters.chain += 1;
                    break :blk if (enqueue) function(ctx.native_context, 1, &job, lease.words.?, run.first_level, run.level_count) else 0;
                },
                .ordinary => blk: {
                    counters.ordinary += 1;
                    break :blk if (enqueue) (prepared.wide_level orelse prepared.level)(ctx.native_context, 1, &job) else 0;
                },
            };
            if (rc != 0) return error.CudaCircuitAssignmentFailed;
            counters.launches += 1;
        }
    } else {
        var begin: usize = 0;
        for (prepared.plan.level_ends) |end| {
            if (end != begin) {
                job.first = @intCast(begin);
                job.count = @intCast(end - begin);
                if (enqueue and prepared.level(ctx.native_context, 1, &job) != 0) return error.CudaCircuitAssignmentFailed;
                counters.ordinary += 1;
                counters.launches += 1;
            }
            begin = end;
        }
    }
    return counters;
}
pub fn execute(prepared: anytype, ctx: *SC.Context, library: *std.DynLib, job: anytype, values: N.Lease, tasks: N.Lease, indices: ?N.Lease, status: N.Lease, ends: ?N.Lease) !Counters {
    if (!try enabled()) return traverse(prepared, ctx, job, ends, true);
    const api = Api{
        .lookup = library.lookup(Lookup, "stwo_rv64_graph_cache_lookup_on") orelse return error.MissingAssignmentGraphCapability,
        .begin = library.lookup(Begin, "stwo_rv64_graph_capture_begin_on") orelse return error.MissingAssignmentGraphCapability,
        .store = library.lookup(Store, "stwo_rv64_graph_capture_store_on") orelse return error.MissingAssignmentGraphCapability,
        .launch = library.lookup(Launch, "stwo_rv64_graph_launch_on") orelse return error.MissingAssignmentGraphCapability,
        .abort_capture = library.lookup(Abort, "stwo_graph_capture_abort") orelse return error.MissingAssignmentGraphCapability,
    };
    try validate(ctx, .{ .values = values, .tasks = tasks, .indices = indices, .status = status, .ends = ends });
    if (values.count != @as(u64, job.value_count) * 4 or tasks.count != @as(u64, job.record_count) * 8 or status.count != 1 or (if (indices) |lease| lease.count else 0) != job.index_count or @intFromPtr(values.words.?) != @intFromPtr(job.values) or @intFromPtr(tasks.words.?) != @intFromPtr(job.records) or @intFromPtr(status.words.?) != @intFromPtr(job.status) or (if (indices) |lease| @intFromPtr(lease.words.?) else 0) != (if (job.indices) |p| @intFromPtr(p) else 0)) return error.InvalidAssignmentGraphInputs;
    if (ends) |lease| if (prepared.narrow_plan == null or lease.count != prepared.narrow_plan.?.ends.len) return error.InvalidAssignmentGraphInputs;
    const planned = try traverse(prepared, ctx, job, ends, false);
    if (planned.launches == 0 or planned.launches > 2048) return error.AssignmentGraphTooLarge;
    const digest = key(prepared, ctx, job, ends);
    var graph: ?*anyopaque = null;
    if (api.lookup(ctx.native_context, 1, &digest, &graph) != 0) return error.AssignmentGraphLookupFailed;
    const hit = graph != null;
    const counters = if (hit) planned else blk: {
        if (api.begin(ctx.native_context, 1) != 0) return error.AssignmentGraphCaptureFailed;
        var capturing = true;
        errdefer if (capturing) {
            _ = api.abort_capture(ctx.native_context);
        };
        const result = try traverse(prepared, ctx, job, ends, true);
        const rc = api.store(ctx.native_context, 1, &digest, result.launches, &graph);
        if (rc != 0 or graph == null) return error.AssignmentGraphCaptureFailed;
        capturing = false;
        break :blk result;
    };
    if (api.launch(ctx.native_context, 1, graph.?) != 0) return error.AssignmentGraphLaunchFailed;
    std.debug.print("GPU_ASSIGNMENT_GRAPH hit={} kernels={} retained_device_leases=0 metadata_entries_max=32\n", .{ hit, counters.launches });
    return counters;
}

test "assignment graph scoped custody rejects poisoned generations contexts scopes and aliases" {
    const Mock = struct {
        fn check(_: *anyopaque, ptr: [*]const u32, count: u64, token: u64, generation: u64, scope: *const [8]u32) callconv(.c) c_int {
            if (token != 3 or generation != 4 or !std.mem.allEqual(u32, scope, 7) or @intFromPtr(ptr) < 4096 or count > 512) return 1;
            return 0;
        }
    };
    const api = SC.Api{ .validate_range = Mock.check, .allocate = undefined, .release = undefined, .upload = undefined, .download = undefined, .sync = undefined, .lane_stream = undefined };
    var ctx = SC.Context{ .session = @ptrFromInt(1), .native_context = @ptrFromInt(2), .token = 3, .scope = @splat(7), .api = &api };
    var input = Inputs{
        .values = .{ .words = @ptrFromInt(4096), .count = 256, .context_token = 3, .generation = 4 },
        .tasks = .{ .words = @ptrFromInt(8192), .count = 256, .context_token = 3, .generation = 4 },
        .status = .{ .words = @ptrFromInt(12288), .count = 1, .context_token = 3, .generation = 4 },
        .indices = null,
        .ends = null,
    };
    try validate(&ctx, input);
    input.tasks.kind = 4;
    try validate(&ctx, input); // A scope-bound sealed tape is a legal read.
    input.values.kind = 4;
    try std.testing.expectError(error.InvalidAssignmentGraphInputs, validate(&ctx, input));
    input.values.kind = 0;
    input.values.generation = 5; // Same address cannot revive a stale lease.
    try std.testing.expectError(error.InvalidDeviceAddress, validate(&ctx, input));
    input.values.generation = 4;
    input.tasks.context_token = 8;
    try std.testing.expectError(error.InvalidDeviceAddress, validate(&ctx, input));
    input.tasks.context_token = 3;
    input.tasks.count = 513;
    try std.testing.expectError(error.InvalidDeviceAddress, validate(&ctx, input));
    input.tasks.count = 256;
    ctx.scope[0] = 8;
    try std.testing.expectError(error.InvalidDeviceAddress, validate(&ctx, input));
    ctx.scope[0] = 7;
    input.status.words = input.values.words;
    try std.testing.expectError(error.AliasedAssignmentGraphInputs, validate(&ctx, input));
}

test "assignment graph cache key binds schedule numerical pointers geometry and session" {
    const Run = @import("assignment_runs.zig").Run;
    const Prepared = struct {
        identity: [32]u8 = @splat(5),
        wide_level: ?*const anyopaque = null,
        level: *const anyopaque = @ptrFromInt(64),
        narrow_run: ?*const anyopaque = null,
        chain_run: ?*const anyopaque = null,
        narrow_plan: ?struct { runs: []const Run } = null,
    };
    var prepared = Prepared{};
    var ctx = SC.Context{ .session = @ptrFromInt(1), .native_context = @ptrFromInt(2), .token = 3, .scope = @splat(7), .api = undefined };
    const TestJob = struct { values: [*]u32, records: [*]const u32, indices: ?[*]const u32, status: *u32, value_count: u32, record_count: u32, index_count: u32 };
    var job: TestJob = .{ .values = @as([*]u32, @ptrFromInt(4096)), .records = @as([*]const u32, @ptrFromInt(8192)), .indices = @as(?[*]const u32, null), .status = @as(*u32, @ptrFromInt(12288)), .value_count = @as(u32, 256), .record_count = @as(u32, 256), .index_count = @as(u32, 0) };
    const original = key(&prepared, &ctx, job, null);
    job.values += 1;
    try std.testing.expect(!std.mem.eql(u8, &original, &key(&prepared, &ctx, job, null)));
    job.values -= 1;
    job.record_count += 1;
    try std.testing.expect(!std.mem.eql(u8, &original, &key(&prepared, &ctx, job, null)));
    job.record_count -= 1;
    ctx.token += 1;
    try std.testing.expect(!std.mem.eql(u8, &original, &key(&prepared, &ctx, job, null)));
    ctx.token -= 1;
    prepared.identity[0] += 1;
    try std.testing.expect(!std.mem.eql(u8, &original, &key(&prepared, &ctx, job, null)));
}
