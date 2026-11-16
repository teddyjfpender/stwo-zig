//! Diagnostic filesystem/lease laws; no GPU or proof acceptance is exercised.
const std = @import("std");
const R = @import("recording_dataset.zig");
const a = std.testing.allocator;
fn identity(n: u8, purpose: R.Purpose) R.Identity {
    return .{ .execution = @splat(n), .program = @splat(n + 1), .input = @splat(n + 2), .attempt = @splat(n), .purpose = purpose };
}
fn rootPath(tmp: *std.testing.TmpDir) ![]u8 {
    return tmp.dir.realpathAlloc(a, ".");
}

test "recording dataset: ordinal zero belongs to distinct executions and installation purposes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try rootPath(&tmp);
    defer a.free(root);
    var first = try R.Dataset.create(a, root, identity(1, .execution));
    defer first.destroy() catch unreachable;
    var second = try R.Dataset.create(a, root, identity(2, .execution));
    defer second.destroy() catch unreachable;
    var install = try R.Dataset.create(a, root, identity(1, .class_install));
    defer install.destroy() catch unreachable;
    var next_install_id = identity(1, .class_install);
    next_install_id.attempt = @splat(33); // A second actual installation invocation resets ordinal zero.
    const next_install = try R.Dataset.create(a, root, next_install_id);
    defer next_install.destroy() catch unreachable;
    try std.testing.expect(try first.write(.pack, "seg-0.gnp", "first"));
    try std.testing.expect(try second.write(.pack, "seg-0.gnp", "second"));
    try std.testing.expect(try install.write(.pack, "seg-0.gnp", "install"));
    try first.finish(true);
    try second.finish(true);
    try install.finish(true);
    _ = try next_install.write(.pack, "seg-0.gnp", "second install invocation");
    try next_install.finish(true);
    var paths = try R.replay(a, root, .pack);
    defer paths.deinit();
    try std.testing.expectEqual(@as(usize, 4), paths.items.len);
    try std.testing.expect(!std.mem.eql(u8, first.path, second.path));
    try std.testing.expect(!std.mem.eql(u8, first.path, install.path));
}

test "recording dataset: active borrows refuse finalization and cannot outlive their owner" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try rootPath(&tmp);
    defer a.free(root);
    const id = identity(3, .execution);
    const owner = try R.Dataset.create(a, root, id);
    var left = R.Slot{};
    var right = R.Slot{};
    try left.attach(owner);
    try right.attach(owner);
    try left.requireExecution(id.execution);
    try std.testing.expectError(error.RecordingExecutionMismatch, right.requireExecution(@splat(99)));
    var inflight = (try left.borrow()).?;
    try std.testing.expectError(error.RecordingStillBorrowed, owner.finish(true));
    try std.testing.expectError(error.RecordingStillBorrowed, owner.destroy());
    left.detach();
    right.detach();
    try std.testing.expectError(error.RecordingStillBorrowed, owner.finish(true));
    try inflight.release();
    try std.testing.expectError(error.RecordingBorrowReleased, inflight.release());
    try owner.finish(true);
    try std.testing.expectError(error.RecordingClosed, owner.borrow());
    try std.testing.expectError(error.RecordingClosed, owner.write(.pack, "late.gnp", "late"));
    try R.verify(a, owner.path);
    try owner.destroy();
}

test "recording dataset: failure remains incomplete and a fresh attempt can retry" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try rootPath(&tmp);
    defer a.free(root);
    const owner = try R.Dataset.create(a, root, identity(4, .execution));
    defer owner.destroy() catch unreachable;
    _ = try owner.write(.nodes, "node-0.gnr", "partial");
    owner.fail(error.NoSpaceLeft);
    try owner.finish(true);
    try std.testing.expectError(error.RecordingIncomplete, R.verify(a, owner.path));
    var id = identity(4, .execution);
    id.attempt = @splat(5);
    const retry = try R.Dataset.create(a, root, id);
    defer retry.destroy() catch unreachable;
    _ = try retry.write(.nodes, "node-0.gnr", "healthy");
    try retry.finish(true);
    try R.verify(a, retry.path);
}

test "recording dataset: identity and payload conflicts refuse rather than reuse stale ordinals" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try rootPath(&tmp);
    defer a.free(root);
    const id = identity(6, .execution);
    const owner = try R.Dataset.create(a, root, id);
    defer owner.destroy() catch unreachable;
    try std.testing.expectError(error.PathAlreadyExists, R.Dataset.create(a, root, id));
    try std.testing.expect(try owner.write(.pack, "seg-0.gnp", "same"));
    try std.testing.expect(!try owner.write(.pack, "seg-0.gnp", "same"));
    try std.testing.expectError(error.RecordingContentConflict, owner.write(.pack, "seg-0.gnp", "different"));
    owner.fail(error.RecordingContentConflict);
    try owner.finish(false);
}

test "recording dataset: modern replay rejects corruption and undeclared extra payloads" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try rootPath(&tmp);
    defer a.free(root);
    const owner = try R.Dataset.create(a, root, identity(7, .execution));
    defer owner.destroy() catch unreachable;
    _ = try owner.write(.pack, "seg-0.gnp", "valid");
    try owner.finish(true);
    var dir = try std.fs.cwd().openDir(owner.path, .{});
    defer dir.close();
    try dir.writeFile(.{ .sub_path = "pack/seg-0.gnp", .data = "corrupt" });
    try std.testing.expectError(error.RecordingInventoryMismatch, R.verify(a, owner.path));
    try dir.writeFile(.{ .sub_path = "pack/seg-0.gnp", .data = "valid" });
    try dir.writeFile(.{ .sub_path = "pack/seg-1.gnp", .data = "extra" });
    try std.testing.expectError(error.RecordingInventoryMismatch, R.verify(a, owner.path));
}

test "recording dataset: every independent historical family is retained and sorted" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try rootPath(&tmp);
    defer a.free(root);
    for ([_][]const u8{ "z-family", "a-family" }) |family| {
        const path = try std.fs.path.join(a, &.{ "recordings/historical/pack", family });
        defer a.free(path);
        var dir = try tmp.dir.makeOpenPath(path, .{});
        defer dir.close();
        try dir.writeFile(.{ .sub_path = "seg-0.gnp", .data = family });
    }
    var paths = try R.replay(a, root, .pack);
    defer paths.deinit();
    try std.testing.expectEqual(@as(usize, 2), paths.items.len);
    try std.testing.expect(std.mem.endsWith(u8, paths.items[0], "a-family"));
    try std.testing.expect(std.mem.endsWith(u8, paths.items[1], "z-family"));
    for (paths.items) |path| {
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        const payload = try dir.readFileAlloc(a, "seg-0.gnp", 64);
        defer a.free(payload);
        try std.testing.expectEqualStrings(std.fs.path.basename(path), payload);
    }
}

test "recording dataset: simultaneous contexts serialize identical publication and drain before completion" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try rootPath(&tmp);
    defer a.free(root);
    const owner = try R.Dataset.create(a, root, identity(8, .execution));
    defer owner.destroy() catch unreachable;
    const Work = struct {
        dataset: *R.Dataset,
        ready: *std.atomic.Value(u32),
        done: *std.Thread.ResetEvent,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            var lease = self.dataset.borrow() catch unreachable;
            defer lease.release() catch unreachable;
            _ = self.dataset.write(.pack, "same.gnp", "identical concurrent payload") catch |err| {
                self.failure = err;
            };
            _ = self.ready.fetchAdd(1, .release);
            self.done.wait();
        }
    };
    var ready = std.atomic.Value(u32).init(0);
    var done = std.Thread.ResetEvent{};
    var work = [_]Work{.{ .dataset = owner, .ready = &ready, .done = &done }} ** 2;
    const left = try std.Thread.spawn(.{}, Work.run, .{&work[0]});
    const right = try std.Thread.spawn(.{}, Work.run, .{&work[1]});
    while (ready.load(.acquire) != 2) std.Thread.yield() catch {};
    try std.testing.expectError(error.RecordingStillBorrowed, owner.finish(true));
    done.set();
    left.join();
    right.join();
    for (work) |item| try std.testing.expect(item.failure == null);
    try owner.finish(true);
    try R.verify(a, owner.path);
}

test "recording dataset: device binding refuses duplicate contexts rather than borrowing a foreign request" {
    var first = R.Slot{};
    var second = R.Slot{};
    const services = [_]R.DeviceSlot{ .{ .ordinal = 2, .slot = &first }, .{ .ordinal = 7, .slot = &second } };
    try std.testing.expect((try R.uniqueSlot(&services, 7)).? == &second);
    try std.testing.expectEqual(@as(?*R.Slot, null), try R.uniqueSlot(&services, 0));
    const duplicate = [_]R.DeviceSlot{ services[0], .{ .ordinal = 2, .slot = &second } };
    try std.testing.expectError(error.AmbiguousRecordingDevice, R.uniqueSlot(&duplicate, 2));
}

test "recording dataset: unrelated roots and auxiliary-only roles remain absent but incomplete families reject" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try rootPath(&tmp);
    defer a.free(root);
    try tmp.dir.writeFile(.{ .sub_path = "cpu-proof.bin", .data = "unrelated" });
    try std.testing.expectError(error.NoRecordingDatasets, R.replay(a, root, .pack));
    const owner = try R.Dataset.create(a, root, identity(9, .execution));
    defer owner.destroy() catch unreachable;
    _ = try owner.write(.nodes, "pcs-aux.gnp", "auxiliary child PCS");
    try owner.finish(true);
    try std.testing.expectError(error.NoRecordingDatasets, R.replay(a, root, .nodes));
    try std.testing.expectError(error.NoRecordingDatasets, R.replay(a, root, .pack));
    const node = try R.Dataset.create(a, root, identity(10, .execution));
    defer node.destroy() catch unreachable;
    _ = try node.write(.nodes, "node-0.gnr", "node");
    try node.finish(true);
    var nodes = try R.replay(a, root, .nodes);
    defer nodes.deinit();
    try std.testing.expectEqual(@as(usize, 1), nodes.items.len);
    const incomplete = try R.Dataset.create(a, root, identity(11, .execution));
    defer incomplete.destroy() catch unreachable;
    try incomplete.finish(false);
    try std.testing.expectError(error.RecordingIncomplete, R.replay(a, root, .nodes));
    try std.testing.expectError(error.RecordingIncomplete, R.replay(a, root, .pack));
}
