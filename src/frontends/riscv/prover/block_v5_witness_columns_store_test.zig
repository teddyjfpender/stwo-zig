const std = @import("std");
const core = @import("stwo_core");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const Store = @import("block_v5_witness_columns_store_v1.zig");
const M = core.fields.m31.M31;
const limits = Store.Limits{ .max_columns = 8, .max_log_size = 20, .max_file_bytes = 1 << 24, .max_loaded_bytes = 1 << 24 };
const scope = Store.Scope{ .kind = .native, .execution_index = 7, .first_cycle = 29, .cycle_count = 11,
    .descriptor_digest = @splat(17), .first_roots = .{ @splat(3), @splat(9) } };

test "witness proposal streams multiple buffers and canonical ordered columns" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const large = try a.alloc(M, 1 << 14);
    defer a.free(large);
    for (large, 0..) |*value, index| value.* = M.fromCanonical(@intCast((index * 65537) % core.fields.m31.Modulus));
    var small = [_]M{ M.zero(), M.one(), M.fromCanonical(77), M.fromCanonical(core.fields.m31.Modulus - 1) };
    const columns = [_]Column{ .{ .log_size = 14, .values = large }, .{ .log_size = 2, .values = &small } };
    const pin = try Store.write(a, tmp.dir, "native.columns", scope, &columns, limits);
    try std.testing.expectEqual(@as(u64, 140 + 24 + 4 * (large.len + small.len)), pin.bytes);
    var owned = try Store.load(a, tmp.dir, "native.columns", scope, &.{ 14, 2 }, pin, limits);
    defer owned.deinit();
    for (columns, owned.columns) |expected, actual| {
        try std.testing.expectEqual(expected.log_size, actual.log_size);
        for (expected.values, actual.values) |left, right| try std.testing.expectEqual(left.toU32(), right.toU32());
    }
    try std.testing.expectError(error.V5WitnessFileAlreadyExists, Store.write(a, tmp.dir, "native.columns", scope, &columns, limits));
    var wrong_scope = scope;
    wrong_scope.execution_index += 1;
    try std.testing.expectError(error.ChangedV5WitnessScope, Store.load(a, tmp.dir, "native.columns", wrong_scope, &.{ 14, 2 }, pin, limits));
    try std.testing.expectError(error.InvalidV5WitnessFileLength, Store.load(a, tmp.dir, "native.columns", scope, &.{ 13, 2 }, pin, limits));
    var small_cap = limits;
    small_cap.max_loaded_bytes = 128;
    try std.testing.expectError(error.V5WitnessColumnLimit, Store.load(a, tmp.dir, "native.columns", scope, &.{ 14, 2 }, pin, small_cap));
}

test "witness proposal rejects canonical tamper noncanonical words and changed length" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var values = [_]M{ M.zero(), M.one(), M.fromCanonical(7), M.fromCanonical(31) };
    const columns = [_]Column{.{ .log_size = 2, .values = &values }};
    const pin = try Store.write(a, tmp.dir, "native.columns", scope, &columns, limits);
    const file = try tmp.dir.openFile("native.columns", .{ .mode = .read_write });
    defer file.close();
    var raw: [4]u8 = undefined;
    std.mem.writeInt(u32, &raw, 123, .little);
    try file.pwriteAll(&raw, 140 + 12);
    try std.testing.expectError(error.TamperedV5WitnessFile, Store.load(a, tmp.dir, "native.columns", scope, &.{2}, pin, limits));
    std.mem.writeInt(u32, &raw, core.fields.m31.Modulus, .little);
    try file.pwriteAll(&raw, 140 + 12);
    try std.testing.expectError(error.NonCanonicalV5WitnessM31, Store.load(a, tmp.dir, "native.columns", scope, &.{2}, pin, limits));
    try file.setEndPos(pin.bytes - 1);
    try std.testing.expectError(error.InvalidV5WitnessFileLength, Store.load(a, tmp.dir, "native.columns", scope, &.{2}, pin, limits));
}

test "witness proposal empty logical tree remains a scoped file not a receipt" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const pin = try Store.write(a, tmp.dir, "empty.columns", scope, &.{}, limits);
    var owned = try Store.load(a, tmp.dir, "empty.columns", scope, &.{}, pin, limits);
    defer owned.deinit();
    try std.testing.expectEqual(@as(usize, 0), owned.columns.len);
    var forged = pin;
    forged.sha256[0] ^= 1;
    try std.testing.expectError(error.TamperedV5WitnessFile, Store.load(a, tmp.dir, "empty.columns", scope, &.{}, forged, limits));
    try std.testing.expectError(error.InvalidV5WitnessFileName, Store.write(a, tmp.dir, "../escape", scope, &.{}, limits));
}
