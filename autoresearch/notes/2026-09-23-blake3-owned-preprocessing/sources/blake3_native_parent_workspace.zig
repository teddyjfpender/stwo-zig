//! Exclusive request scratch with bounded idle retention, not a peak RAM cap.
const std = @import("std");

pub const Phase = enum { idle, preparation, main_commitment, interaction_generation, interaction_commitment, core_proof, complete };
pub const Workspace = struct {
    /// Last entered phase, retained after cleanup for failure diagnostics.
    phase: Phase = .idle,
    arena: std.heap.ArenaAllocator,
    retained_limit: usize,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, retained_limit: usize) Workspace {
        return .{ .arena = .init(allocator), .retained_limit = retained_limit };
    }

    /// Caller must ensure no request is active and no new request can start.
    pub fn deinit(self: *Workspace) void {
        if (!self.mutex.tryLock()) @panic("destroying leased parent workspace");
        self.arena.deinit();
        self.mutex.unlock();
        self.* = undefined;
    }

    pub fn begin(self: *Workspace) !std.mem.Allocator {
        if (!self.mutex.tryLock()) return error.ParentWorkspaceAlreadyLeased;
        self.phase = .preparation;
        return self.arena.allocator();
    }

    /// Invalidates all scratch allocations while preserving the exclusive lease.
    /// Caller must have finished every scratch consumer.
    pub fn releaseScratch(self: *Workspace) void {
        if (!self.arena.reset(.{ .retain_with_limit = self.retained_limit })) {
            _ = self.arena.reset(.free_all);
        }
    }

    /// All scratch users must be destroyed before ending their lease.
    pub fn end(self: *Workspace) void {
        self.releaseScratch();
        self.mutex.unlock();
    }
};

test "native parent workspace bounds retention and rejects overlapping leases" {
    var workspace = Workspace.init(std.testing.allocator, 4096);
    defer workspace.deinit();
    const first = try workspace.begin();
    _ = try first.alloc(u8, 8192);
    try std.testing.expectError(error.ParentWorkspaceAlreadyLeased, workspace.begin());
    workspace.end();
    try std.testing.expect(workspace.arena.queryCapacity() <= 4096);
    const second = try workspace.begin();
    _ = try second.alloc(u8, 16);
    workspace.end();
    try std.testing.expect(workspace.arena.queryCapacity() > 0);
    workspace.retained_limit = 0;
    _ = try workspace.begin();
    workspace.end();
    try std.testing.expectEqual(@as(usize, 0), workspace.arena.queryCapacity());
}

test "native parent workspace allocation failure releases lease and permits recovery" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var workspace = Workspace.init(failing.allocator(), 4096);
    defer workspace.deinit();
    {
        const scratch = try workspace.begin();
        defer workspace.end();
        try std.testing.expectError(error.OutOfMemory, scratch.alloc(u8, 8192));
    }
    failing.fail_index = std.math.maxInt(usize);
    const scratch = try workspace.begin();
    _ = try scratch.alloc(u8, 16);
    workspace.end();
}

test "native parent scratch release preserves lease and supports another stage" {
    var workspace = Workspace.init(std.testing.allocator, 0);
    defer workspace.deinit();
    const scratch = try workspace.begin();
    defer workspace.end();
    _ = try scratch.alloc(u8, 8192);
    workspace.releaseScratch();
    try std.testing.expectEqual(@as(usize, 0), workspace.arena.queryCapacity());
    try std.testing.expectError(error.ParentWorkspaceAlreadyLeased, workspace.begin());
    const next = try scratch.alloc(u8, 32);
    @memset(next, 7);
    try std.testing.expectEqual(@as(u8, 7), next[31]);
}
