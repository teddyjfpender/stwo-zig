const std = @import("std");
const W = @import("../rv64_prepared_work_packet.zig");
const Fixture = @import("rv64_work_packet_test.zig").Fixture;
const a = std.testing.allocator;
const Gate = struct {
    mutex: std.Thread.Mutex = .{},
    condition: std.Thread.Condition = .{},
    ready: usize = 0,
    go: bool = false,
    fn enter(self: *Gate) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.ready += 1;
        self.condition.broadcast();
        while (!self.go) self.condition.wait(&self.mutex);
    }
    fn release(self: *Gate, wait: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (wait and self.ready != 2) self.condition.wait(&self.mutex);
        self.go = true;
        self.condition.broadcast();
    }
};
const Task = struct {
    gate: *Gate,
    directory: std.fs.Dir,
    name: []const u8,
    view: W.View,
    digest: ?W.Digest = null,
    failure: ?anyerror = null,
    fn run(self: *Task) void {
        self.gate.enter();
        self.digest = W.writeAtomic(a, self.directory, self.name, self.view) catch |err| {
            self.failure = err;
            return;
        };
    }
};
fn race(left: *Task, right: *Task) !void {
    const first = try std.Thread.spawn(.{}, Task.run, .{left});
    errdefer {
        left.gate.release(false);
        first.join();
    }
    const second = try std.Thread.spawn(.{}, Task.run, .{right});
    left.gate.release(true);
    first.join();
    second.join();
}
test "portable work packet concurrent writers publish complete jobs exclusively and identical retry is idempotent" {
    var fixture = try Fixture.init(a, .{});
    defer fixture.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    var gate = Gate{};
    var left = Task{ .gate = &gate, .directory = temp.dir, .name = "same", .view = fixture.view() };
    var right = left;
    try race(&left, &right);
    try std.testing.expect(left.failure == null and right.failure == null);
    try std.testing.expectEqualDeep(left.digest.?, right.digest.?);
    const same = try temp.dir.openFile("same", .{});
    defer same.close();
    var loaded_same = try W.read(a, same, fixture.expected(), .{});
    defer loaded_same.deinit();
    try std.testing.expectEqualDeep(left.digest.?, loaded_same.content_digest);
    var other_gate = Gate{};
    var first = Task{ .gate = &other_gate, .directory = temp.dir, .name = "different", .view = fixture.view() };
    var second = first;
    second.view.metadata.index += 1;
    try race(&first, &second);
    try std.testing.expect((first.failure == null) != (second.failure == null));
    const winner = if (first.failure == null) first else second;
    const loser = if (first.failure != null) first else second;
    try std.testing.expectEqual(error.WorkPacketPublicationConflict, loser.failure.?);
    const different = try temp.dir.openFile("different", .{});
    defer different.close();
    var loaded = try W.read(a, different, fixture.expected(), .{});
    defer loaded.deinit();
    try std.testing.expectEqual(winner.view.metadata.index, loaded.metadata.index);
    try std.testing.expectEqualDeep(winner.digest.?, loaded.content_digest);
}
