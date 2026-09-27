//! Actual exclusive transport files and original typed Store slot layout only.
//! No Store admission, synthetic proof/Fresh, PCS, STARK or guest is invoked.
const std = @import("std");
const Rollback = @import("block_v5_cpu_recursive_publication_rollback_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Providers = @import("block_v5_recursive_provider_store_v1.zig");
const Executions = @import("block_v5_recursive_execution_leaf_store_v1.zig");
const Pin = @import("block_v5_recursive_leaf_store_core_v1.zig").FilePin;
const Modules = .{
    Providers.ForFamily(.range16),
    Providers.ForFamily(.ram_lanes),
    Providers.ForFamily(.program_table),
    Providers.ForFamily(.native_lookup),
    Executions.ForFamily(.caller_arithmetic),
    Executions.ForFamily(.caller_fused),
    Executions.ForFamily(.native_capacity_fused),
};
fn Fixture(comptime Module: type) type {
    const Slot = std.meta.Child(@FieldType(Module.Store, "slots"));
    return struct {
        slots: [4]Slot = [_]Slot{.{ .policy = undefined }} ** 4,
        store: Module.Store = undefined,
        denied: std.testing.FailingAllocator = undefined,
        fn init(self: *@This(), dir: std.fs.Dir) void {
            self.denied = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
            // This is a transport-only borrowed stack view of original slot
            // ownership. Undefined policy authority is deliberately untouched.
            // Do not call original Store.deinit on these borrowed stack slots.
            self.store = .{ .a = self.denied.allocator(), .dir = dir, .slots = &self.slots, .limits = .{}, .mode = .writer };
        }
        fn publish(self: *@This(), slot: usize, index: u32, bytes: []const u8) !void {
            var name: [96]u8 = undefined;
            // Record a custody pin ONLY after real exclusive publication.
            try Files.publish(self.store.dir, try Module.fileName(&name, index), bytes);
            self.slots[slot].pin = Pin{ .index = index, .byte_len = bytes.len, .sha256 = Files.hash(bytes) };
            self.store.total_bytes += bytes.len;
        }
        fn expectFile(self: *@This(), index: u32, expected: []const u8) !void {
            var name: [96]u8 = undefined;
            var file = try self.store.dir.openFile(try Module.fileName(&name, index), .{});
            defer file.close();
            var buffer: [64]u8 = undefined;
            const count = try file.readAll(&buffer);
            try std.testing.expectEqualSlices(u8, expected, buffer[0..count]);
        }
        fn expectAbsent(self: *@This(), index: u32) !void {
            var name: [96]u8 = undefined;
            try std.testing.expectError(error.FileNotFound, self.store.dir.access(try Module.fileName(&name, index), .{}));
        }
    };
}
test "cpu recursive rollback: all seven real filenames sparse successful pins pending collisions and denied allocation" {
    inline for (Modules) |Module| {
        var temporary = std.testing.tmpDir(.{});
        defer temporary.cleanup();
        var fixture = Fixture(Module){};
        fixture.init(temporary.dir);
        try fixture.publish(0, 2, "first-success");
        try fixture.publish(2, 19, "second-success");
        var name: [96]u8 = undefined;
        const pending = try Module.fileName(&name, 11);
        try Files.publish(temporary.dir, pending, "pre-existing-pending");
        try std.testing.expectError(error.ExistingV5BundleArtifact, fixture.publish(1, 11, "must-not-replace"));
        try std.testing.expect(fixture.slots[1].pin == null);
        const result = Rollback.rollbackWriter(Module, &fixture.store);
        try std.testing.expectEqual(.complete, result.status);
        try std.testing.expectEqual(@as(usize, 2), result.removed);
        try std.testing.expectEqual(@as(usize, 0), result.failed);
        try std.testing.expectEqual(@as(u64, 0), fixture.store.total_bytes);
        try fixture.expectAbsent(2);
        try fixture.expectAbsent(19);
        try fixture.expectFile(11, "pre-existing-pending");
        // A new unrelated file at the old path is not owned after cleanup.
        try Files.publish(temporary.dir, try Module.fileName(&name, 2), "new-after-rollback");
        const repeated = Rollback.rollbackWriter(Module, &fixture.store);
        try std.testing.expectEqual(.complete, repeated.status);
        try std.testing.expectEqual(@as(usize, 0), repeated.removed);
        try fixture.expectFile(2, "new-after-rollback");
        try fixture.expectFile(11, "pre-existing-pending");
        try std.testing.expectEqual(@as(usize, 0), fixture.denied.alloc_index);
    }
}
test "cpu recursive rollback: reader and active reader ownership excludes every deletion" {
    const Module = Providers.ForFamily(.ram_lanes);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var fixture = Fixture(Module){};
    fixture.init(temporary.dir);
    try fixture.publish(0, 0, "reader-owned-original");
    fixture.store.mode = .reader;
    try std.testing.expectEqual(.reader, Rollback.rollbackWriter(Module, &fixture.store).status);
    try fixture.expectFile(0, "reader-owned-original");
    fixture.store.mode = .writer;
    fixture.store.active_readers = 1;
    try std.testing.expectEqual(.active_readers, Rollback.rollbackWriter(Module, &fixture.store).status);
    fixture.store.active_readers = 0;
    fixture.slots[0].state = .reading;
    try std.testing.expectEqual(.active_readers, Rollback.rollbackWriter(Module, &fixture.store).status);
    try fixture.expectFile(0, "reader-owned-original");
    fixture.slots[0].state = .pending;
    try std.testing.expectEqual(.complete, Rollback.rollbackWriter(Module, &fixture.store).status);
    try fixture.expectAbsent(0);
    try std.testing.expectEqual(@as(usize, 0), fixture.denied.alloc_index);
}
test "cpu recursive rollback: malformed bounded inventory rejects before any partial deletion" {
    const Module = Executions.ForFamily(.caller_fused);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var fixture = Fixture(Module){};
    fixture.init(temporary.dir);
    try fixture.publish(0, 1, "first");
    try fixture.publish(3, 23, "last");
    const original_total = fixture.store.total_bytes;
    fixture.store.total_bytes += 1;
    try std.testing.expectEqual(.invalid_inventory, Rollback.rollbackWriter(Module, &fixture.store).status);
    fixture.store.total_bytes = original_total;
    fixture.store.limits.max_files = 3;
    try std.testing.expectEqual(.invalid_inventory, Rollback.rollbackWriter(Module, &fixture.store).status);
    fixture.store.limits.max_files = 4;
    fixture.slots[3].pin.?.index = 1;
    try std.testing.expectEqual(.invalid_inventory, Rollback.rollbackWriter(Module, &fixture.store).status);
    fixture.slots[3].pin.?.index = 23;
    fixture.slots[3].pin.?.byte_len = std.math.maxInt(u64);
    try std.testing.expectEqual(.invalid_inventory, Rollback.rollbackWriter(Module, &fixture.store).status);
    fixture.slots[3].pin.?.byte_len = 4;
    try fixture.expectFile(1, "first");
    try fixture.expectFile(23, "last");
    try std.testing.expectEqual(.complete, Rollback.rollbackWriter(Module, &fixture.store).status);
    try std.testing.expectEqual(@as(usize, 0), fixture.denied.alloc_index);
}
test "cpu recursive rollback: missing files release pins and I/O failure retains only retryable ownership" {
    const Module = Providers.ForFamily(.range16);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var fixture = Fixture(Module){};
    fixture.init(temporary.dir);
    try fixture.publish(0, 3, "missing");
    try fixture.publish(1, 5, "blocked");
    try fixture.publish(3, 8, "remove");
    var first: [96]u8 = undefined;
    var second: [96]u8 = undefined;
    try temporary.dir.deleteFile(try Module.fileName(&first, 3));
    const blocked = try Module.fileName(&second, 5);
    try temporary.dir.deleteFile(blocked);
    try temporary.dir.makeDir(blocked);
    const result = Rollback.rollbackWriter(Module, &fixture.store);
    try std.testing.expectEqual(.io_failure, result.status);
    try std.testing.expectEqual(@as(usize, 1), result.missing);
    try std.testing.expectEqual(@as(usize, 1), result.removed);
    try std.testing.expectEqual(@as(usize, 1), result.failed);
    try std.testing.expect(fixture.slots[0].pin == null and fixture.slots[3].pin == null);
    try std.testing.expect(fixture.slots[1].pin != null);
    try std.testing.expectEqual(@as(u64, 7), fixture.store.total_bytes);
    try temporary.dir.deleteDir(blocked);
    const retried = Rollback.rollbackWriter(Module, &fixture.store);
    try std.testing.expectEqual(.complete, retried.status);
    try std.testing.expectEqual(@as(usize, 1), retried.missing);
    try std.testing.expectEqual(@as(u64, 0), fixture.store.total_bytes);
    try std.testing.expectEqual(@as(usize, 0), fixture.denied.alloc_index);
}
