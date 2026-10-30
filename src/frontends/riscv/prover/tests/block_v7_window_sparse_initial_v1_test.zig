const std = @import("std");
const Initial = @import("../block_v7_initial_intervals_v1.zig");
const Sparse = @import("../block_v7_window_sparse_initial_v1.zig");
test "sparse initialization independently reconstructs values and forbids unlisted first touches" {
    const a = std.testing.allocator;
    var source_rows = [_]Initial.Interval{
        .{ .lower = 0, .upper = 2, .allowed = false, .private = false, .value = 0 },
        .{ .lower = 2, .upper = 7, .allowed = true, .private = false, .value = 0xdeadbeef },
        .{ .lower = 7, .upper = Initial.WORD_LIMIT, .allowed = true, .private = false, .value = 0 },
    };
    const source: Initial.Owned = .{ .a = a, .elf_sha256 = @splat(9), .info = undefined, .intervals = &source_rows };
    var chosen = try Sparse.derive(a, &source, &.{ 20, 8, 20, 0xfffffffc }, .{});
    defer chosen.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 8, 20, 0xfffffffc }, chosen.addresses);
    try Sparse.require(&source, chosen.addresses, chosen.intervals);
    var view = source;
    view.intervals = chosen.intervals;
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), (try view.find(8)).value);
    try std.testing.expect(!(try view.find(12)).allowed);
    try std.testing.expectEqual(@as(u32, 0), (try view.find(0xfffffffc)).value);
    chosen.intervals[1].value = 0;
    try std.testing.expectError(error.UntrustedV7SparseInitialization, Sparse.require(&source, chosen.addresses, chosen.intervals));
    chosen.intervals[1].value = 0xdeadbeef;
    chosen.intervals[2].allowed = true;
    try std.testing.expectError(error.UntrustedV7SparseInitialization, Sparse.require(&source, chosen.addresses, chosen.intervals));
    chosen.intervals[2].allowed = false;
    chosen.addresses[1] = 24;
    try std.testing.expectError(error.UntrustedV7SparseInitialization, Sparse.require(&source, chosen.addresses, chosen.intervals));
    chosen.addresses[1] = 20;
    try std.testing.expectError(error.UntrustedV7SparseInitialization, Sparse.derive(a, &source, &.{0}, .{}));
    try std.testing.expectError(error.UnalignedV7InitializationAddress, Sparse.derive(a, &source, &.{9}, .{}));
    source_rows[1].private = true;
    source_rows[1].value = 0;
    try std.testing.expectError(error.UntrustedV7SparseInitialization, Sparse.derive(a, &source, &.{8}, .{}));
}
