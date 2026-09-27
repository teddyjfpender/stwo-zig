//! One worker's bounded immutable transform plan and request-local scratch.
const std = @import("std");
const protocol = @import("stwo_riscv_frontend").recursion.detached_parent_protocol_v1;

pub fn WorkspaceFor(comptime Engine: type) type {
    return struct {
        allocator: std.mem.Allocator,
        session: ?Engine.Session = null,
        scratch: std.heap.ArenaAllocator,
        retained_limit: usize,
        session_budget: usize,
        active: bool = false,
        plan_builds: usize = 0,
        requests: usize = 0,
        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, session_budget: usize, retained_limit: usize) Self {
            return .{ .allocator = allocator, .scratch = .init(allocator), .session_budget = session_budget, .retained_limit = retained_limit };
        }
        pub fn deinit(self: *Self) void {
            std.debug.assert(!self.active);
            if (self.session) |*session| session.deinit(self.allocator);
            self.scratch.deinit();
            self.* = undefined;
        }
        pub fn begin(self: *Self, profile: protocol.ProfileV1, required_log: u32) !void {
            if (self.active) return error.ParentWorkspaceAlreadyLeased;
            const config = profile.pcsConfig();
            const compatible = if (self.session) |*session| blk: {
                session.validateRequest(config, required_log) catch break :blk false;
                break :blk true;
            } else false;
            if (!compatible) {
                // Evict before constructing the replacement: at most one plan
                // occupies the explicit host budget, including on failures.
                if (self.session) |*session| session.deinit(self.allocator);
                self.session = null;
                self.session = try Engine.initSession(self.allocator, config, required_log, self.session_budget);
                self.plan_builds += 1;
            }
            self.active = true;
            self.requests += 1;
        }
        pub fn end(self: *Self) void {
            std.debug.assert(self.active);
            // Scheme and evaluator teardown must precede this boundary. No
            // pointer from a proof may survive reset into the next request.
            if (!self.scratch.reset(.{ .retain_with_limit = self.retained_limit })) {
                // Failed arena shrinking can retain the original oversized
                // allocation. Drop it rather than exceeding the worker budget.
                _ = self.scratch.reset(.free_all);
            }
            self.active = false;
        }
        pub fn scheme(self: *Self, profile: protocol.ProfileV1, required_log: u32) !Engine.Scheme {
            if (!self.active) return error.ParentWorkspaceNotLeased;
            var result = try Engine.initWithSession(&self.session.?, profile.pcsConfig(), required_log);
            result.setQuotientValuesAllocator(self.scratch.allocator());
            return result;
        }
    };
}

test "parent workspace reuses one compatible plan and bounds retained scratch" {
    const Engine = @import("stwo_riscv_frontend").recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
    const allocator = std.testing.allocator;
    var workspace = WorkspaceFor(Engine).init(allocator, 1 << 20, 4096);
    defer workspace.deinit();
    try std.testing.expectError(error.ParentWorkspaceNotLeased, workspace.scheme(.recursive_q193_v1, 8));
    try workspace.begin(.recursive_q193_v1, 8);
    try std.testing.expectError(error.ParentWorkspaceAlreadyLeased, workspace.begin(.recursive_q193_v1, 8));
    _ = try workspace.scratch.allocator().alloc(u8, 8192);
    var first = try workspace.scheme(.recursive_q193_v1, 8);
    Engine.deinit(&first, allocator);
    workspace.end();
    try std.testing.expect(workspace.scratch.queryCapacity() <= 4096);
    try workspace.begin(.recursive_q193_v1, 7);
    var second = try workspace.scheme(.recursive_q193_v1, 7);
    Engine.deinit(&second, allocator);
    workspace.end();
    try std.testing.expectEqual(@as(usize, 1), workspace.plan_builds);
    try workspace.begin(.recursive_q193_v1, 9);
    workspace.end();
    try std.testing.expectEqual(@as(usize, 2), workspace.plan_builds);
    try workspace.begin(.detached_continuation_development_q3_v2, 9);
    workspace.end();
    try std.testing.expectEqual(@as(usize, 3), workspace.plan_builds);
    try std.testing.expectEqual(@as(usize, 4), workspace.requests);
}

test "parent workspace rejects over-budget plans before leasing and recovers" {
    const Engine = @import("stwo_riscv_frontend").recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
    var workspace = WorkspaceFor(Engine).init(std.testing.allocator, 1024, 0);
    defer workspace.deinit();
    try workspace.begin(.recursive_q193_v1, 7);
    workspace.end();
    try std.testing.expectError(error.HostByteBudgetExceeded, workspace.begin(.recursive_q193_v1, 20));
    try std.testing.expect(!workspace.active);
    try std.testing.expect(workspace.session == null);
    try workspace.begin(.recursive_q193_v1, 7);
    workspace.end();
}

test "parent workspace drops oversized scratch if retention allocation fails" {
    const Engine = @import("stwo_riscv_frontend").recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var workspace = WorkspaceFor(Engine).init(failing.allocator(), 1 << 20, 4096);
    defer workspace.deinit();
    try workspace.begin(.recursive_q193_v1, 7);
    _ = try workspace.scratch.allocator().alloc(u8, 8192);
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    workspace.end();
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), workspace.scratch.queryCapacity());
    try std.testing.expect(!workspace.active);
}
