const std = @import("std");
const W = @import("wire.zig");
const F = @import("fixture.zig");
const E = @import("execution.zig");
fn allocationRead(a: std.mem.Allocator, dir: std.fs.Dir) !void {
    var loaded = try W.read(a, dir, .{});
    defer loaded.deinit(a);
}
test "Combined compact transport preserves all physical proofs and cleans every read allocation failure" {
    const a = std.testing.allocator;
    var c = try F.Case.init(a);
    defer c.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const keys = c.keys();
    const truths = c.truths();
    try W.write(a, tmp.dir, &keys, &truths, &c.bundle);
    var loaded = try W.read(a, tmp.dir, .{});
    defer loaded.deinit(a);
    for (c.bundle.cpus, loaded.bundle.cpus) |x, y| try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
    for (c.bundle.truths, loaded.bundle.truths) |x, y| try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
    try E.verify(a, &keys, &truths, c.expected(), &loaded.bundle);
    try std.testing.checkAllAllocationFailures(a, allocationRead, .{tmp.dir});
    try std.testing.expectError(error.InvalidServicesWireRoster, W.read(a, tmp.dir, .{ .max_cpus = 1 }));
    try std.testing.expectError(error.ServicesWireBudget, W.read(a, tmp.dir, .{ .max_total_steps = 6 }));
    try std.testing.expectError(error.ServicesProofLimit, W.read(a, tmp.dir, .{ .max_proof_bytes = 1 }));
    var proof = try tmp.dir.openFile("cpu-0.bin", .{ .mode = .read_write });
    defer proof.close();
    try proof.pwriteAll(&.{0xff}, 0);
    try std.testing.expectError(error.ServicesProofChanged, W.read(a, tmp.dir, .{}));
}
