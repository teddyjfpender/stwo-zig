//! Each concurrent concrete component owns its stage stack. The coordinator
//! moves completed trees into the request only after the proving engine joins.
//! This owner must stay at one address from binding through the final join.
const std = @import("std");
const Stage = @import("stwo_prover_engine").stage_profile;
pub const Group = struct {
    // CPU + four Keccak components + three components for each secp program.
    pub const CAPACITY = 11;
    parent: ?*Stage.Recorder,
    children: [CAPACITY]Stage.Recorder = undefined,
    used: usize = 0,
    pub fn init(parent: ?*Stage.Recorder) Group {
        return .{ .parent = parent };
    }
    pub fn next(owner: ?*Group) ?*Stage.Recorder {
        const self = owner orelse return null;
        const parent = self.parent orelse return null;
        std.debug.assert(self.used < CAPACITY);
        const child = &self.children[self.used];
        child.* = Stage.Recorder.initWithOptions(parent.allocator, parent.runtime, parent.example, .{ .capture_tasks = false, .capture_process_usage = parent.capture_process_usage });
        self.used += 1;
        return child;
    }
    /// Engine callbacks have returned and all submitted workers have drained.
    /// A partial adoption keeps every tree owned by either parent or child.
    pub fn join(self: *Group) Stage.JoinedError!void {
        return self.joinDiagnosed(null);
    }
    pub fn joinDiagnosed(self: *Group, failure: ?*?@import("stwo_core").error_codes.Entry) Stage.JoinedError!void {
        if (failure) |sink| sink.* = null;
        const parent = self.parent orelse return;
        for (self.children[0..self.used]) |*child| try parent.adoptJoinedStagesDiagnosed(child, failure);
    }
    /// Component recorder pointers must be cleared before this owner retires.
    pub fn deinit(self: *Group) void {
        for (self.children[0..self.used]) |*child| child.deinit();
        self.* = undefined;
    }
};

test "joined custody diagnostics execute actual component group without ownership transfer on refusal" {
    const a = std.testing.allocator;
    var parent = Stage.Recorder.init(a, "Debug", "joined");
    defer parent.deinit();
    var group = Group.init(&parent);
    defer group.deinit();
    const child = Group.next(&group).?;
    var scope = try Stage.StageScope.begin(child, "child", "Child");
    var failure: ?@import("stwo_core").error_codes.Entry = null;
    try std.testing.expectError(error.JoinedRecorderStillActive, group.joinDiagnosed(&failure));
    try std.testing.expectEqual(@as(u16, 0x3402), failure.?.code);
    try std.testing.expectEqual(@as(usize, 0), parent.roots.items.len);
    scope.end();
    try group.joinDiagnosed(&failure);
    try std.testing.expect(failure == null);
    try std.testing.expectEqual(@as(usize, 1), parent.roots.items.len);
    try std.testing.expectEqual(@as(usize, 0), child.roots.items.len);
}

test "joined custody diagnostics preserve ownership on self adoption and every allocation failure" {
    const a = std.testing.allocator;
    var owner = Stage.Recorder.init(a, "Debug", "self");
    defer owner.deinit();
    var failure: ?@import("stwo_core").error_codes.Entry = null;
    try std.testing.expectError(error.IncompatibleJoinedRecorder, owner.adoptJoinedDiagnosed(&owner, &failure));
    try std.testing.expectEqual(@as(u16, 0x3401), failure.?.code);
    const Runner = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var parent = Stage.Recorder.init(allocator, "Debug", "parent");
            defer parent.deinit();
            var child = Stage.Recorder.init(allocator, "Debug", "child");
            defer child.deinit();
            var scope = try Stage.StageScope.begin(&child, "work", "Work");
            scope.end();
            var detail: ?@import("stwo_core").error_codes.Entry = null;
            parent.adoptJoinedStagesDiagnosed(&child, &detail) catch |err| {
                try std.testing.expectEqual(@as(u16, 0x3403), detail.?.code);
                try std.testing.expectEqual(@as(usize, 1), child.roots.items.len);
                return err;
            };
            try std.testing.expect(detail == null);
            try std.testing.expectEqual(@as(usize, 0), child.roots.items.len);
        }
    };
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{});
}
