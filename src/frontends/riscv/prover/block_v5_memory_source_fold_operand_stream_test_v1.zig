//! Byte-compatible bounded operand transport fixtures. No PCS/STARK/guest.
const std = @import("std");
const Store = @import("block_v5_memory_source_fold_operand_store_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const plan_id: [32]u8 = @splat(19);
const page_id: [32]u8 = @splat(23);

fn page(count: u32) Protocol.Page {
    return .{ .index = 7, .first = 91, .count = count, .row_log = 12 };
}
fn operation(ordinal: u64) Fold.Operation {
    return .{ .ordinal = ordinal, .kind = .leaf, .coordinate = .{ .height = 0, .index = @intCast(ordinal) }, .value = .{ .before = @splat(3), .after = @splat(5) }, .leaf = .{ .address = @intCast(ordinal * 4), .before = 17, .after = 29, .clock = 12345, .image = .rw, .touched = true, .image_ordinal = ordinal, .touch_ordinal = ordinal + 1 }, .left = .{ .before = @splat(7), .after = @splat(11) }, .right = .{ .before = @splat(13), .after = @splat(17) } };
}
// Previous complete-envelope encoding is the compatibility oracle; this fixture
// constructs the normative header directly and uses the unchanged record codec.
fn oldEnvelope(a: std.mem.Allocator, descriptor: Protocol.Page, operations: []const Fold.Operation) ![]u8 {
    const raw = try a.alloc(u8, Store.HEADER_BYTES + Store.RECORD_BYTES * operations.len);
    errdefer a.free(raw);
    @memset(raw[0..Store.HEADER_BYTES], 0);
    @memcpy(raw[0..8], Store.MAGIC);
    @memcpy(raw[8..40], &plan_id);
    @memcpy(raw[40..72], &page_id);
    std.mem.writeInt(u32, raw[72..76], descriptor.index, .little);
    std.mem.writeInt(u64, raw[76..84], descriptor.first, .little);
    std.mem.writeInt(u32, raw[84..88], descriptor.count, .little);
    std.mem.writeInt(u32, raw[88..92], descriptor.row_log, .little);
    std.mem.writeInt(u32, raw[92..96], Store.RECORD_BYTES, .little);
    for (operations, 0..) |value, index| try Store.encodeOperation(value, raw[Store.HEADER_BYTES + index * Store.RECORD_BYTES ..][0..Store.RECORD_BYTES]);
    return raw;
}
fn makeOperations(a: std.mem.Allocator, descriptor: Protocol.Page) ![]Fold.Operation {
    const operations = try a.alloc(Fold.Operation, descriptor.count);
    for (operations, 0..) |*value, index| value.* = operation(descriptor.first + index);
    return operations;
}
test "fold operand stream: previous envelope bytes and pin survive all buffer boundaries with bounded allocation" {
    const a = std.testing.allocator;
    for ([_]u32{ 1, 63, 64, 65, 129, 4096 }) |count| {
        var temporary = std.testing.tmpDir(.{});
        defer temporary.cleanup();
        const descriptor = page(count);
        const operations = try makeOperations(a, descriptor);
        defer a.free(operations);
        const oracle = try oldEnvelope(a, descriptor, operations);
        defer a.free(oracle);
        var deny = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
        const pin = try Store.publish(deny.allocator(), temporary.dir, "fold.operands", descriptor, plan_id, page_id, operations, .{});
        try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
        try std.testing.expectEqual(@as(u64, oracle.len), pin.byte_len);
        try std.testing.expectEqualSlices(u8, &Files.hash(oracle), &pin.sha256);
        const actual = try Files.readPinned(a, temporary.dir, "fold.operands", pin.byte_len, pin.sha256, 2 << 20);
        defer a.free(actual);
        try std.testing.expectEqualSlices(u8, oracle, actual);

        // Exactly enough heap for decoded operations plus alignment, never a
        // full encoded page as a second allocation.
        const storage = try a.alloc(u8, @sizeOf(Fold.Operation) * count + @alignOf(Fold.Operation) - 1);
        defer a.free(storage);
        var bounded = std.heap.FixedBufferAllocator.init(storage);
        var loaded = try Store.load(bounded.allocator(), temporary.dir, "fold.operands", descriptor, plan_id, page_id, pin, .{});
        defer loaded.deinit();
        for (operations, loaded.operations) |expected, value| try std.testing.expect(std.meta.eql(expected, value));
        try std.testing.expect(bounded.end_index <= storage.len);
    }
}
test "fold operand stream: late encoder failure and existing destination never publish or replace bytes" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const a = std.testing.allocator;
    const descriptor = page(65);
    const operations = try makeOperations(a, descriptor);
    defer a.free(operations);
    operations[64].ordinal += 1;
    try std.testing.expectError(error.InvalidSourceFoldOperandOrder, Store.publish(a, temporary.dir, "bad", descriptor, plan_id, page_id, operations, .{}));
    try std.testing.expectError(error.FileNotFound, temporary.dir.access("bad", .{}));
    try std.testing.expectError(error.FileNotFound, temporary.dir.access("bad.part", .{}));
    operations[64].ordinal -= 1;
    const pin = try Store.publish(a, temporary.dir, "good", descriptor, plan_id, page_id, operations, .{});
    operations[0].value.before[0] ^= 1;
    try std.testing.expectError(error.ExistingV5BundleArtifact, Store.publish(a, temporary.dir, "good", descriptor, plan_id, page_id, operations, .{}));
    var loaded = try Store.load(a, temporary.dir, "good", descriptor, plan_id, page_id, pin, .{});
    defer loaded.deinit();
    try std.testing.expect(std.meta.eql(operation(descriptor.first), loaded.operations[0]));
    try std.testing.expectError(error.FileNotFound, temporary.dir.access("good.part", .{}));
}
fn loadFault(a: std.mem.Allocator, dir: std.fs.Dir, descriptor: Protocol.Page, pin: Store.Pin) !void {
    var loaded = try Store.load(a, dir, "good", descriptor, plan_id, page_id, pin, .{});
    defer loaded.deinit();
    try std.testing.expectEqual(@as(usize, descriptor.count), loaded.operations.len);
}
test "fold operand stream: digest guards precede decoded proposals and all load allocations roll back" {
    const a = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const descriptor = page(65);
    const operations = try makeOperations(a, descriptor);
    defer a.free(operations);
    const pin = try Store.publish(a, temporary.dir, "good", descriptor, plan_id, page_id, operations, .{});
    try std.testing.checkAllAllocationFailures(a, loadFault, .{ temporary.dir, descriptor, pin });
    const file = try temporary.dir.openFile("good", .{ .mode = .read_write });
    defer file.close();
    // Malformed operation kind must not mask an incorrect file digest.
    try file.pwriteAll(&.{ 255, 255, 255, 255 }, Store.HEADER_BYTES + 8);
    try std.testing.expectError(error.TamperedV5BundleFileHash, Store.load(a, temporary.dir, "good", descriptor, plan_id, page_id, pin, .{}));
    const mutated = try file.readToEndAlloc(a, 2 << 20);
    defer a.free(mutated);
    var proposed = pin;
    proposed.sha256 = Files.hash(mutated);
    try std.testing.expectError(error.InvalidSourceFoldOperandKind, Store.load(a, temporary.dir, "good", descriptor, plan_id, page_id, proposed, .{}));
    try file.setEndPos(pin.byte_len - 1);
    try std.testing.expectError(error.TamperedV5BundleFileLength, Store.load(a, temporary.dir, "good", descriptor, plan_id, page_id, pin, .{}));
}
test "fold operand stream: caps and overflow reject before allocation or filesystem access" {
    var deny = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var descriptor = page(1);
    const values = [_]Fold.Operation{operation(descriptor.first)};
    try std.testing.expectError(error.SourceFoldOperandResourceLimit, Store.publish(deny.allocator(), undefined, "unused", descriptor, plan_id, page_id, &values, .{ .max_file_bytes = 1 }));
    descriptor.count = 2;
    descriptor.first = std.math.maxInt(u64);
    const overflowing = [_]Fold.Operation{ values[0], values[0] };
    try std.testing.expectError(error.Overflow, Store.publish(deny.allocator(), undefined, "unused", descriptor, plan_id, page_id, &overflowing, .{}));
    const pin = Store.Pin{ .byte_len = Store.HEADER_BYTES + 2 * Store.RECORD_BYTES, .sha256 = @splat(1), .page_identity = page_id };
    try std.testing.expectError(error.Overflow, Store.load(deny.allocator(), undefined, "unused", descriptor, plan_id, page_id, pin, .{}));
    try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
}
test "fold operand stream: failed emitters clean only their own unpublished inode" {
    const FailingEmitter = struct {
        pub fn write(_: @This(), file: std.fs.File) !void {
            try file.writeAll("partial private bytes");
            return error.InjectedOperandWriteFailure;
        }
    };
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try std.testing.expectError(error.InjectedOperandWriteFailure, Files.publishStream(temporary.dir, "absent", FailingEmitter{}));
    try std.testing.expectError(error.FileNotFound, temporary.dir.access("absent", .{}));
    try std.testing.expectError(error.FileNotFound, temporary.dir.access("absent.part", .{}));
    try Files.publish(temporary.dir, "existing", "original");
    try std.testing.expectError(error.InjectedOperandWriteFailure, Files.publishStream(temporary.dir, "existing", FailingEmitter{}));
    const original = try Files.readPinned(std.testing.allocator, temporary.dir, "existing", 8, Files.hash("original"), 8);
    defer std.testing.allocator.free(original);
    try std.testing.expectEqualSlices(u8, "original", original);
    try std.testing.expectError(error.FileNotFound, temporary.dir.access("existing.part", .{}));
    const prior = try temporary.dir.createFile("reserved.part", .{ .exclusive = true });
    defer prior.close();
    try prior.writeAll("previous owner");
    try std.testing.expectError(error.PathAlreadyExists, Files.publishStream(temporary.dir, "reserved", FailingEmitter{}));
    // A failed exclusive create must never unlink another caller's temporary.
    try temporary.dir.access("reserved.part", .{});
}
