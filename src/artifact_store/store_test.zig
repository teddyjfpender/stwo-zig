const std = @import("std");
const encoding = @import("encoding.zig");
const types = @import("types.zig");
const store_mod = @import("store.zig");

fn rootPath(allocator: std.mem.Allocator, temporary: *std.testing.TmpDir) ![]u8 {
    const parent = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(parent);
    return std.fs.path.join(allocator, &.{ parent, "artifact-store" });
}

fn objectPath(
    allocator: std.mem.Allocator,
    root: []const u8,
    digest: encoding.Digest,
) ![]u8 {
    const encoded = std.fmt.bytesToHex(digest, .lower);
    return std.fmt.allocPrint(
        allocator,
        "{s}/objects/sha256/{s}/{s}.blob",
        .{ root, encoded[0..2], encoded },
    );
}

test "artifact store: zero-byte blob persists across reopened instances" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try rootPath(std.testing.allocator, &temporary);
    defer std.testing.allocator.free(root);
    var first = try store_mod.Store.openOrCreate(std.testing.allocator, root, false);
    const ref = try first.putBytes(.raw, 1, "");
    first.deinit();
    try std.testing.expectEqual(@as(u64, 0), ref.byte_count);
    try std.testing.expectEqual(encoding.digestBytes(""), ref.sha256);

    var reopened = try store_mod.Store.openOrCreate(std.testing.allocator, root, false);
    defer reopened.deinit();
    var blob = try reopened.openBlob(ref, .raw, 1, 0);
    defer blob.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), blob.bytes.len);
}

test "artifact store: dedup retains one sharded raw object" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try rootPath(std.testing.allocator, &temporary);
    defer std.testing.allocator.free(root);
    var store = try store_mod.Store.openOrCreate(std.testing.allocator, root, false);
    defer store.deinit();
    const first = try store.putBytes(.proof_artifact, 4, "same-content");
    const second = try store.putBytes(.proof_artifact, 4, "same-content");
    try std.testing.expect(types.BlobRefV1.eql(first, second));
    const path = try objectPath(std.testing.allocator, root, first.sha256);
    defer std.testing.allocator.free(path);
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    try std.testing.expectEqual(@as(u64, "same-content".len), (try file.stat()).size);
}

test "artifact store: lazy open ignores unrelated corruption but audit detects it" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try rootPath(std.testing.allocator, &temporary);
    defer std.testing.allocator.free(root);
    var writer = try store_mod.Store.openOrCreate(std.testing.allocator, root, false);
    const valid = try writer.putBytes(.proof_artifact, 4, "valid-target");
    const unrelated = try writer.putBytes(.raw, 1, "unrelated");
    writer.deinit();

    const unrelated_path = try objectPath(
        std.testing.allocator,
        root,
        unrelated.sha256,
    );
    defer std.testing.allocator.free(unrelated_path);
    const read_only = try std.fs.openFileAbsolute(unrelated_path, .{});
    try read_only.chmod(0o600);
    read_only.close();
    const corrupt = try std.fs.openFileAbsolute(unrelated_path, .{ .mode = .read_write });
    try corrupt.pwriteAll("corrupted", 0);
    try corrupt.chmod(0o400);
    try corrupt.sync();
    corrupt.close();

    var lazy = try store_mod.Store.openOrCreate(std.testing.allocator, root, false);
    defer lazy.deinit();
    var reopened = try lazy.openBlob(valid, .proof_artifact, 4, 64);
    defer reopened.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("valid-target", reopened.bytes);
    try std.testing.expectError(error.ArtifactStoreCorrupt, lazy.auditAndRebuildIndex());
}

test "artifact store: exact kind and schema checks precede content reuse" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try rootPath(std.testing.allocator, &temporary);
    defer std.testing.allocator.free(root);
    var store = try store_mod.Store.openOrCreate(std.testing.allocator, root, false);
    defer store.deinit();
    const ref = try store.putBytes(.proof_artifact, 4, "proof");
    try std.testing.expectError(
        error.ArtifactKindMismatch,
        store.openBlob(ref, .execution_artifact, 4, 64),
    );
    try std.testing.expectError(
        error.ArtifactSchemaMismatch,
        store.openBlob(ref, .proof_artifact, 5, 64),
    );
}

test "artifact store: truncation and same-name corruption fail closed" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try rootPath(std.testing.allocator, &temporary);
    defer std.testing.allocator.free(root);
    var store = try store_mod.Store.openOrCreate(std.testing.allocator, root, false);
    defer store.deinit();
    const ref = try store.putBytes(.raw, 1, "protected");
    const path = try objectPath(std.testing.allocator, root, ref.sha256);
    defer std.testing.allocator.free(path);
    const read_only = try std.fs.openFileAbsolute(path, .{});
    try read_only.chmod(0o600);
    read_only.close();
    const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_write });
    try file.pwriteAll("tampered!", 0);
    try file.chmod(0o400);
    try file.sync();
    try std.testing.expectError(
        error.ArtifactStoreCorrupt,
        store.openBlob(ref, .raw, 1, 64),
    );
    try file.chmod(0o600);
    try file.setEndPos(1);
    try file.chmod(0o400);
    try file.sync();
    file.close();
    try std.testing.expectError(
        error.ArtifactStoreCorrupt,
        store.openBlob(ref, .raw, 1, 64),
    );
}

test "artifact store: preexisting digest-name collision is rejected" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try rootPath(std.testing.allocator, &temporary);
    defer std.testing.allocator.free(root);
    var store = try store_mod.Store.openOrCreate(std.testing.allocator, root, false);
    defer store.deinit();
    const expected = encoding.digestBytes("expected");
    const encoded = std.fmt.bytesToHex(expected, .lower);
    const shard = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/objects/sha256/{s}",
        .{ root, encoded[0..2] },
    );
    defer std.testing.allocator.free(shard);
    try std.posix.mkdir(shard, 0o700);
    const path = try objectPath(std.testing.allocator, root, expected);
    defer std.testing.allocator.free(path);
    const file = try std.fs.createFileAbsolute(path, .{
        .read = true,
        .exclusive = true,
        .mode = 0o600,
    });
    try file.writeAll("wrong");
    try file.chmod(0o400);
    try file.sync();
    file.close();
    try std.testing.expectError(
        error.ArtifactStoreCollision,
        store.putBytes(.raw, 1, "expected"),
    );
}

const PublishContext = struct {
    store: *store_mod.Store,
    result: ?types.BlobRefV1 = null,
    failure: ?anyerror = null,
};

fn publishFromThread(context: *PublishContext) void {
    context.result = context.store.putBytes(.execution_artifact, 2, "parallel") catch |err| {
        context.failure = err;
        return;
    };
}

test "artifact store: concurrent store instances publish one object" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try rootPath(std.heap.page_allocator, &temporary);
    defer std.heap.page_allocator.free(root);
    var first = try store_mod.Store.openOrCreate(std.heap.page_allocator, root, false);
    defer first.deinit();
    var second = try store_mod.Store.openOrCreate(std.heap.page_allocator, root, false);
    defer second.deinit();
    var first_context = PublishContext{ .store = &first };
    var second_context = PublishContext{ .store = &second };
    const first_thread = try std.Thread.spawn(.{}, publishFromThread, .{&first_context});
    const second_thread = try std.Thread.spawn(.{}, publishFromThread, .{&second_context});
    first_thread.join();
    second_thread.join();
    try std.testing.expect(first_context.failure == null);
    try std.testing.expect(second_context.failure == null);
    try std.testing.expect(types.BlobRefV1.eql(
        first_context.result.?,
        second_context.result.?,
    ));
}

const ResolveContext = struct {
    store: *store_mod.Store,
    ref: store_mod.ObjectRef,
    failure: ?anyerror = null,
};

fn resolveFromThread(context: *ResolveContext) void {
    var snapshot = context.store.resolveRef(context.ref) catch |err| {
        context.failure = err;
        return;
    };
    snapshot.deinit(std.heap.page_allocator);
}

test "artifact store: Metal initNew retains owner-thread behavior" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try rootPath(std.heap.page_allocator, &temporary);
    defer std.heap.page_allocator.free(root);
    try temporary.dir.writeFile(.{ .sub_path = "source", .data = "metal" });
    const source = try temporary.dir.realpathAlloc(std.heap.page_allocator, "source");
    defer std.heap.page_allocator.free(source);
    var store = try store_mod.Store.initNew(std.heap.page_allocator, root, false);
    defer store.deinit();
    var snapshot = try store.ingestPathWithPolicy(source, .byte_copy);
    defer snapshot.deinit(std.heap.page_allocator);
    var context = ResolveContext{ .store = &store, .ref = snapshot.ref() };
    const thread = try std.Thread.spawn(.{}, resolveFromThread, .{&context});
    thread.join();
    try std.testing.expectEqual(error.ArtifactStoreWrongThread, context.failure.?);
}

fn coldOpenAllocationCase(
    allocator: std.mem.Allocator,
    root: []const u8,
    ref: types.BlobRefV1,
) !void {
    var store = try store_mod.Store.openOrCreate(allocator, root, false);
    defer store.deinit();
    var blob = try store.openBlob(ref, .proof_artifact, 3, 64);
    defer blob.deinit(allocator);
    try std.testing.expectEqualStrings("allocation-safe", blob.bytes);
}

test "artifact store: cold open releases every failed allocation" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try rootPath(std.testing.allocator, &temporary);
    defer std.testing.allocator.free(root);
    var writer = try store_mod.Store.openOrCreate(std.testing.allocator, root, false);
    const ref = try writer.putBytes(.proof_artifact, 3, "allocation-safe");
    writer.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        coldOpenAllocationCase,
        .{ root, ref },
    );
}
