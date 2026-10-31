const std = @import("std");
const core = @import("stwo_core");
const Audit = @import("ownership.zig");
const a = std.testing.allocator;
test "allocation ledger counts identical owners once and rejects overlapping owner claims" {
    const values = try a.alloc(u32, 32);
    defer a.free(values);
    var account = Audit.Accountant{ .allocator = a };
    defer account.deinit();
    var first = Audit.Record{ .kind = "first", .index = 0 };
    var alias = Audit.Record{ .kind = "alias", .index = 1 };
    try account.add(&first, "original_fixed", values);
    try account.add(&alias, "original_fixed", values);
    try std.testing.expectEqual(@as(u64, 128), first.payload.original_fixed);
    try std.testing.expectEqual(@as(u64, 0), alias.payload.total());
    try std.testing.expectError(error.OverlappingOwnedAuditRanges, account.add(&alias, "coefficients", values[1..]));
    try std.testing.expectEqual(@as(u64, 128), account.totals.total());
}
test "real sealed compact key owns native coefficients and retained lease aliases payload" {
    const R = @import("../word16_global_execution/services/roster.zig");
    var setup = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &.{0x00108093} }, .{ .cpu_log = 5 }, .{});
    defer setup.deinit();
    var account = Audit.Accountant{ .allocator = a };
    defer account.deinit();
    var first = Audit.Record{ .kind = "tree", .index = 0 };
    try account.tree(&first, setup.key.tree);
    try std.testing.expect(first.payload.coefficients > 0 and first.payload.merkle > 0);
    try std.testing.expectEqual(@as(u64, 0), first.retained_evaluation_bytes);
    try std.testing.expectEqual(@as(u64, 0), first.uncovered_coefficient_bytes);
    var native: u64 = 0;
    for (setup.key.tree.columns) |column| native += (@as(u64, 1) << @intCast(column.log_size - 1)) * @sizeOf(core.fields.m31.M31);
    try std.testing.expectEqual(native, first.coefficient_view_bytes);
    try std.testing.expectEqual(native, first.payload.coefficients);
    var lease = setup.key.tree.retainShared();
    defer lease.deinit(a);
    var second = Audit.Record{ .kind = "lease", .index = 1 };
    try account.tree(&second, lease);
    try std.testing.expectEqual(@as(u64, 0), second.payload.total());
    try std.testing.expectEqual(first.coefficient_view_bytes, second.coefficient_view_bytes);
}
