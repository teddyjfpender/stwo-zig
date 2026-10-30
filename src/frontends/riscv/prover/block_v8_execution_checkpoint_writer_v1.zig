//! Bounded one-pass checkpoint publication for a complete execution schedule.
//! Checkpoints are proof INPUTS. Neither this writer nor its manifest grants
//! execution authority; originals and the final root must authenticate them.
const std = @import("std");
const Capture = @import("block_v7_real_window_capture_v1.zig");
pub const Plan = struct {
    boundaries: []const u64,
    pub fn validate(self: @This(), maximum: u64) !void {
        if (self.boundaries.len < 2 or self.boundaries.len > 4097 or self.boundaries[0] != 0 or self.boundaries[self.boundaries.len - 1] != maximum) return error.InvalidExecutionCheckpointCoverage;
        for (self.boundaries[1..], self.boundaries[0 .. self.boundaries.len - 1]) |next, previous| if (next <= previous or next - previous > 1 << 24) return error.InvalidExecutionCheckpointCoverage;
    }
};
pub const Owned = struct {
    a: std.mem.Allocator,
    boundaries: []u64,
    next: usize = 0,
    directory: std.fs.Dir,
    records: std.fs.File,
    pub fn init(a: std.mem.Allocator, parent: std.fs.Dir, bytes: []const u8, maximum: u64) !Owned {
        if (bytes.len > 128 << 10) return error.ExecutionCheckpointPlanTooLarge;
        const parsed = try std.json.parseFromSlice(Plan, a, bytes, .{});
        defer parsed.deinit();
        try parsed.value.validate(maximum);
        const boundaries = try a.dupe(u64, parsed.value.boundaries);
        errdefer a.free(boundaries);
        try parent.makeDir("checkpoints");
        var directory = try parent.openDir("checkpoints", .{});
        errdefer directory.close();
        const records = try directory.createFile("snapshots.jsonl", .{ .exclusive = true });
        return .{ .a = a, .boundaries = boundaries, .directory = directory, .records = records };
    }
    pub fn deinit(self: *Owned) void {
        self.records.close();
        self.directory.close();
        self.a.free(self.boundaries);
        self.* = undefined;
    }
    pub fn chunkCycles(self: *const Owned, completed: u64, proposed: u64) !u64 {
        if (self.next >= self.boundaries.len or completed >= self.boundaries[self.next] or proposed == 0) return error.InvalidExecutionCheckpointPosition;
        return @min(proposed, self.boundaries[self.next] - completed);
    }
    pub fn captureIfBoundary(self: *Owned, completed: u64, cpu: @import("../runner/cpu.zig").Cpu, memory: *@import("../runner/memory.zig").Memory) !void {
        if (self.next >= self.boundaries.len) return error.ExtraExecutionCheckpoint;
        const expected = self.boundaries[self.next];
        if (completed < expected) return;
        if (completed != expected) return error.SkippedExecutionCheckpoint;
        var snapshot = try Capture.snapshot(self.a, cpu, memory, .{});
        defer snapshot.deinit(self.a);
        const bytes = try snapshot.encode(self.a);
        defer self.a.free(bytes);
        var name_buffer: [80]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "state-{d}.b7win", .{completed});
        const file = try self.directory.createFile(name, .{ .exclusive = true });
        defer file.close();
        try file.writeAll(bytes);
        const record = try std.json.Stringify.valueAlloc(self.a, .{
            .schema = "stwo-b8-execution-checkpoint-input-v1",
            .proof_verified = false,
            .completed_cycles = completed,
            .file = name,
            .snapshot_id = std.fmt.bytesToHex(snapshot.identity(), .lower),
            .transport_sha256 = std.fmt.bytesToHex(Capture.sha(bytes), .lower),
            .bytes = bytes.len,
            .words = snapshot.words.len,
            .cpu = snapshot.cpu,
        }, .{});
        defer self.a.free(record);
        try self.records.writeAll(record);
        try self.records.writeAll("\n");
        self.next += 1;
    }
    pub fn finish(self: *const Owned, completed: u64) !void {
        if (self.next != self.boundaries.len or completed != self.boundaries[self.boundaries.len - 1]) return error.IncompleteExecutionCheckpointCoverage;
    }
};
