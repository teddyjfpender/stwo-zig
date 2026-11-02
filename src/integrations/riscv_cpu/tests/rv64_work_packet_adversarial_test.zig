const std = @import("std");
const W = @import("../rv64_prepared_work_packet.zig");
const IO = @import("../rv64_work_packet_io.zig");
const Fixture = @import("rv64_work_packet_test.zig").Fixture;
const R = @import("../rv64_authenticated_execution.zig").R;
const a = std.testing.allocator;
fn replace(file: std.fs.File, bytes: []const u8) !void {
    try file.setEndPos(0);
    try file.seekTo(0);
    try file.writeAll(bytes);
}
fn rehash(file: std.fs.File) !void {
    const digest = try IO.digest(file, @intCast(try file.getEndPos()));
    try file.seekTo(IO.DIGEST_OFFSET);
    try file.writeAll(&digest);
}
fn requireFailure(file: std.fs.File, expected: W.Expected, limits: W.Limits) !void {
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    if (W.read(fail.allocator(), file, expected, limits)) |value| {
        var unexpected = value;
        unexpected.deinit();
        return error.TestUnexpectedResult;
    } else |_| {}
    try std.testing.expect(!fail.has_induced_failure);
}
test "portable work packet rejects truncation budgets digest and expected identity before allocation" {
    var fixture = try Fixture.init(a, .{});
    defer fixture.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const file = try temp.dir.createFile("job", .{ .read = true });
    defer file.close();
    _ = try W.write(file, fixture.view());
    const bytes = try temp.dir.readFileAlloc(a, "job", 1 << 20);
    defer a.free(bytes);
    for ([_]usize{ 0, 383, 1151, bytes.len - 1 }) |len| {
        try replace(file, bytes[0..len]);
        try requireFailure(file, fixture.expected(), .{});
    }
    try replace(file, bytes);
    try requireFailure(file, fixture.expected(), .{ .bytes = bytes.len - 1 });
    try requireFailure(file, fixture.expected(), .{ .allocation_bytes = 1 });
    try requireFailure(file, fixture.expected(), .{ .steps = 1 });
    var expected = fixture.expected();
    expected.identity.input[0] ^= 1;
    try requireFailure(file, expected, .{});
    expected = fixture.expected();
    expected.state_policy = .cyclic_v2;
    try requireFailure(file, expected, .{});
    try file.seekTo(1200);
    try file.writeAll("X");
    try requireFailure(file, fixture.expected(), .{});
}
test "portable work packet rejects recomputed-digest provider inflation and changed policy authority" {
    var fixture = try Fixture.init(a, .{});
    defer fixture.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const file = try temp.dir.createFile("job", .{ .read = true });
    defer file.close();
    _ = try W.write(file, fixture.view());
    const bytes = try temp.dir.readFileAlloc(a, "job", 1 << 20);
    defer a.free(bytes);
    // Legal Public shape, false request count. This must fail before a huge
    // provider or even a narrow payload is allocated, independently of SHA.
    const changed = try a.dupe(u8, bytes);
    defer a.free(changed);
    std.mem.writeInt(u32, changed[384 + 3 * 4 ..][0..4], 1, .little);
    std.mem.writeInt(u32, changed[384 + 9 * 4 ..][0..4], 1, .little);
    try replace(file, changed);
    try rehash(file);
    try requireFailure(file, fixture.expected(), .{});
    std.mem.writeInt(u32, changed[384 + 12 * 4 ..][0..4], 22, .little);
    try replace(file, changed);
    try rehash(file);
    try requireFailure(file, fixture.expected(), .{});
    try replace(file, bytes);
    var memory = @import("../rv64_authenticated_execution.zig").frontend.rv64.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 8192, .size = 512, .permissions = .{ .read = true, .write = true } });
    var policy = try R.policy.Policy.fromMemory(a, &memory);
    defer policy.deinit();
    var expected = fixture.expected();
    expected.policy = &policy;
    try requireFailure(file, expected, .{});
}
test "portable work packet rejects aliased opening views and unsupported geometry without writing" {
    var fixture = try Fixture.init(a, .{});
    defer fixture.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const file = try temp.dir.createFile("job", .{ .read = true });
    defer file.close();
    const after = fixture.finished.openings.?.chunks[0].after;
    fixture.finished.openings.?.chunks[0].after = fixture.finished.openings.?.chunks[0].before;
    try std.testing.expectError(error.InvalidWorkPacketOpening, W.write(file, fixture.view()));
    fixture.finished.openings.?.chunks[0].after = after;
    try std.testing.expectEqual(@as(u64, 0), try file.getEndPos());
    var view = fixture.view();
    view.metadata.geometry = .page4096;
    try std.testing.expectError(error.WorkPacketResourceLimit, W.write(file, view));
    try std.testing.expectEqual(@as(u64, 0), try file.getEndPos());
}
const Callback = struct {
    directory: std.fs.Dir,
    view: W.View,
    attempts: usize = 0,
    fn persist(context: ?*anyopaque, _: *const R.native_frontier.Prepared) !void {
        const self: *Callback = @ptrCast(@alignCast(context.?));
        self.attempts += 1;
        _ = try W.writeAtomic(a, self.directory, "job", self.view);
    }
};
test "portable work packet exclusive durable handoff never overwrites target or advances Cache on failure" {
    var fixture = try Fixture.init(a, .{});
    defer fixture.deinit();
    var temp = std.testing.tmpDir(.{ .iterate = true });
    defer temp.cleanup();
    {
        const old = try temp.dir.createFile("job", .{ .exclusive = true });
        defer old.close();
        try old.writeAll("KEEP");
    }
    var context = Callback{ .directory = temp.dir, .view = fixture.view() };
    const handoff = R.native_frontier.Handoff{ .context = &context, .persist = Callback.persist };
    try std.testing.expectError(error.WorkPacketPublicationConflict, fixture.native.?.handoffAndPublish(&fixture.cache.?, handoff));
    try std.testing.expectEqual(R.native_frontier.Phase.prepared, fixture.native.?.phase);
    try std.testing.expectEqualDeep(fixture.metadata.before, fixture.cache.?.root());
    const keep = try temp.dir.readFileAlloc(a, "job", 4);
    defer a.free(keep);
    try std.testing.expectEqualStrings("KEEP", keep);
    var iterator = temp.dir.iterate();
    var entries: usize = 0;
    while (try iterator.next()) |entry| {
        try std.testing.expectEqualStrings("job", entry.name);
        entries += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), entries);
    try temp.dir.deleteFile("job"); // Test-owned sentinel, never codec cleanup.
    try fixture.native.?.handoffAndPublish(&fixture.cache.?, handoff);
    try std.testing.expectEqual(@as(usize, 2), context.attempts);
    try std.testing.expectEqual(R.native_frontier.Phase.published, fixture.native.?.phase);
    try std.testing.expectEqualDeep(fixture.metadata.after, fixture.cache.?.root());
    const digest = try W.writeAtomic(a, temp.dir, "job", fixture.view());
    const file = try temp.dir.openFile("job", .{ .mode = .read_write });
    defer file.close();
    var decoded = try W.read(a, file, fixture.expected(), .{});
    defer decoded.deinit();
    try std.testing.expectEqualDeep(digest, decoded.content_digest);
    // Same body with a corrupt recorded digest is NOT an idempotent job.
    try file.seekTo(IO.DIGEST_OFFSET);
    try file.writeAll(&.{digest[0] ^ 1});
    try std.testing.expectError(error.WorkPacketPublicationConflict, W.writeAtomic(a, temp.dir, "job", fixture.view()));
}
