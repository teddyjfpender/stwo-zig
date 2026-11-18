//! Class-keyed numerical assignment graphs. Cached graph metadata retains no
//! witness allocations. The native API validates and rebinds every live pointer
//! before each launch; the caller keeps all leases until its existing join.
const std = @import("std");
const N = @import("pcs_native_abi.zig");
const SC = @import("session_context.zig");
const Runs = @import("assignment_runs.zig");
const Graph = @import("assignment_graph_cache.zig");
pub const Step = Graph.Step;
pub fn enabled() !bool {
    const text = std.posix.getenv("STWO_RV64_OUTER_ASSIGNMENT_GRAPH") orelse return false;
    if (std.mem.eql(u8, text, "0")) return false;
    if (std.mem.eql(u8, text, "1")) return true;
    return error.InvalidAssignmentGraphOption;
}
pub fn steps(a: std.mem.Allocator, plan: *const Runs.Plan) ![]Step {
    if (plan.runs.len == 0 or plan.runs.len > 65536) return error.InvalidAssignmentGraphPlan;
    const out = try a.alloc(Step, plan.runs.len);
    errdefer a.free(out);
    for (out, plan.runs) |*dst, run| dst.* = .{ .first = run.first_task, .count = run.task_count, .first_level = run.first_level, .levels = run.level_count, .kind = switch (run.kind) {
        .ordinary => 0,
        .chain => 1,
        .narrow => return error.AssignmentGraphRequiresChainPlan,
    } };
    return out;
}
pub const key = Graph.key;
pub const Bindings = struct { values: N.Lease, tasks: N.Lease, indices: ?N.Lease, status: N.Lease, ends: N.Lease };
pub const Cache = struct {
    device: Graph.Cache = .{},
    validate: ?N.LeaseValidate = null,
    pub fn run(self: *Cache, a: std.mem.Allocator, lib: *std.DynLib, ctx: *SC.Context, identity: [32]u8, sequence: []const Step, job: anytype, bindings: Bindings, end_count: usize) !bool {
        if (@sizeOf(@TypeOf(job.*)) != 56 or @sizeOf(Step) != 20) @compileError("assignment graph ABI changed");
        try ctx.prepareKernelEnqueue();
        if (self.device.api == null) self.device.api = try Graph.Api.load(lib);
        if (self.validate == null) self.validate = lib.lookup(N.LeaseValidate, "stwo_rv64_gpu_lease_validate") orelse return error.MissingAssignmentGraphRuntime;
        const validate = self.validate.?;
        // Outputs are request-owned mutable leases. Schedules may instead be
        // sealed immutable cache leases aliased read-only into this scope;
        // validate their complete descriptors without granting mutation.
        for ([_]N.Lease{ bindings.values, bindings.status }) |lease| _ = try ctx.borrow(lease);
        for ([_]N.Lease{ bindings.tasks, bindings.ends }) |lease| {
            if (validate(ctx.session, &lease, &ctx.scope) != 0) return error.InvalidAssignmentGraphReadOnlyLease;
        }
        if (bindings.indices) |lease| {
            if (validate(ctx.session, &lease, &ctx.scope) != 0) return error.InvalidAssignmentGraphReadOnlyLease;
        }
        const ends = bindings.ends;
        if (@intFromPtr(bindings.values.words.?) != @intFromPtr(job.values) or @intFromPtr(bindings.tasks.words.?) != @intFromPtr(job.records) or @intFromPtr(bindings.status.words.?) != @intFromPtr(job.status) or
            @as(u64, job.value_count) * 4 > bindings.values.count or @as(u64, job.record_count) * 8 > bindings.tasks.count or bindings.status.count != 1)
            return error.InvalidAssignmentGraphBindings;
        if (bindings.indices) |lease| {
            if (job.indices != lease.words.? or job.index_count > lease.count) return error.InvalidAssignmentGraphBindings;
        } else if (job.indices != null or job.index_count != 0) return error.InvalidAssignmentGraphBindings;
        if (end_count == 0 or end_count > ends.count) return error.InvalidAssignmentGraphEnds;
        return self.device.runBound(a, ctx.native_context, ctx.token, 1, identity, sequence, job, ends.words.?, end_count);
    }
    pub fn deinit(self: *Cache, a: std.mem.Allocator, service: anytype) void {
        if (self.device.entries.items.len != 0) {
            const Cleanup = struct {
                cache: *Cache,
                fn run(raw: *anyopaque, token: u64, data: ?*anyopaque) callconv(.c) c_int {
                    const job: *@This() = @ptrCast(@alignCast(data.?));
                    const api = job.cache.device.api.?;
                    for (job.cache.device.entries.items) |*entry| {
                        if (entry.context != raw or entry.token != token) return 1;
                        if (entry.handle) |handle| {
                            if (api.destroy(raw, handle) != 0) return 1;
                            entry.handle = null;
                        }
                    }
                    return 0;
                }
            };
            var cleanup = Cleanup{ .cache = self };
            var status = service.submit(service.session, Cleanup.run, &cleanup);
            // Terminal cleanup poisons even a healthy owner. Use it only when
            // ordinary cleanup was refused; later healthy destructors must run.
            if (status != 0) {
                if (service.library.lookup(N.Submit, "stwo_rv64_gpu_session_cleanup")) |cleanup_submit|
                    status = cleanup_submit(service.session, Cleanup.run, &cleanup);
            }
            if (status != 0) {
                // A poisoned service refuses further callbacks. Preserve the
                // original proof error instead of panicking during unwinding;
                // this fatal service is destroyed and its process terminates.
                std.debug.print("GPU_ASSIGNMENT_GRAPH_CLEANUP_REFUSED graphs={} fatal_service=true\n", .{self.device.entries.items.len});
            }
        }
        self.device.entries.deinit(a);
        self.* = .{};
    }
};
test "assignment graph key binds complete grouping and rejects narrow ABI" {
    const a = std.testing.allocator;
    var p = try Runs.Plan.initChain(a, &.{ 1, 2, 4096, 4097 }, 4097, 2048);
    defer p.deinit();
    const sequence = try steps(a, &p);
    defer a.free(sequence);
    const first = key(@splat(7), sequence);
    sequence[0].levels += 1;
    try std.testing.expect(!std.mem.eql(u8, &first, &key(@splat(7), sequence)));
    sequence[0].levels -= 1;
    try std.testing.expect(!std.mem.eql(u8, &first, &key(@splat(8), sequence)));
    var old = try Runs.Plan.init(a, &.{ 1, 2 }, 2);
    defer old.deinit();
    try std.testing.expectError(error.AssignmentGraphRequiresChainPlan, steps(a, &old));
}
