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
    pub fn join(self: *Group) !void {
        const parent = self.parent orelse return;
        for (self.children[0..self.used]) |*child| try parent.adoptJoinedStages(child);
    }
    /// Component recorder pointers must be cleared before this owner retires.
    pub fn deinit(self: *Group) void {
        for (self.children[0..self.used]) |*child| child.deinit();
        self.* = undefined;
    }
};
