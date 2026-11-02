const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("../rv64_main_arena.zig");
const M = core.fields.m31.M31;
const specs = [_]A.Spec{ .{ .role = .ram_poseidon, .log_size = 5, .width = 2 }, .{ .role = .rom, .log_size = 4, .width = 1 }, .{ .role = .cpu, .log_size = 6, .width = 3 }, .{ .role = .bytes, .log_size = 8, .width = 1 }, .{ .role = .secp_add_product, .log_size = 5, .width = 2 }, .{ .role = .ram_policy, .log_size = 4, .width = 1 } };
fn initialize(arena: *A.Arena) !void {
    for (specs) |spec| {
        const matrix = try arena.matrix(spec.role);
        const n = @as(usize, 1) << @intCast(matrix.log_size);
        for (matrix.values, 0..) |*v, i| v.* = M.fromCanonical(@intCast((@as(usize, @intFromEnum(spec.role)) + 1) * 173 + (i / n) * 37 + (i % n) * (i % n) + i % n));
        try arena.markInitialized(spec.role);
    }
}
test "combined main arena packs native heights and keeps canonical role column order" {
    const a = std.testing.allocator;
    var arena = try A.Arena.init(a, &specs);
    defer arena.deinit();
    try std.testing.expectError(error.MainRoleNotInitialized, arena.canonicalColumns(a));
    const cpu = try arena.span(.cpu);
    const bytes = try arena.span(.bytes);
    const rom = try arena.span(.rom);
    const product = try arena.span(.secp_add_product);
    const poseidon = try arena.span(.ram_poseidon);
    try std.testing.expect(bytes.offset < cpu.offset and cpu.offset < product.offset and product.offset < poseidon.offset and poseidon.offset < rom.offset);
    try std.testing.expectEqual(product.offset + product.cells, poseidon.offset);
    for (specs) |spec| {
        const matrix = try arena.matrix(spec.role);
        try std.testing.expectEqual(@as(usize, 0), @intFromPtr(matrix.values.ptr) % 64);
    }
    try initialize(&arena);
    const columns = try arena.canonicalColumns(a);
    defer a.free(columns);
    try std.testing.expectEqual(@as(usize, 10), columns.len);
    try std.testing.expectEqual(@as(u32, 6), columns[0].log_size);
    try std.testing.expectEqual(@as(u32, 4), columns[3].log_size);
    try std.testing.expectEqual(@as(u32, 8), columns[4].log_size);
    try std.testing.expectError(error.InvalidMainAllocator, arena.takeForCommit(std.heap.page_allocator));
    const original = arena.raw;
    var transfer = try arena.takeForCommit(a);
    defer transfer.deinit(a);
    try std.testing.expectEqual(@as(usize, 1), transfer.backing.len);
    try std.testing.expect(transfer.backing[0].ptr == original.ptr and transfer.backing[0].len == original.len);
    try std.testing.expectError(error.InvalidMainPhase, arena.matrix(.cpu));
    try std.testing.expectError(error.InvalidMainPhase, arena.takeForCommit(a));
}
test "combined main arena rejects duplicates missing roles overflow and incomplete initialization" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.EmptyMainArena, A.Arena.init(a, &.{}));
    try std.testing.expectError(error.DuplicateMainRole, A.Arena.init(a, &.{ specs[0], specs[0] }));
    try std.testing.expectError(error.InvalidMainSpec, A.Arena.init(a, &.{.{ .role = .cpu, .log_size = 3, .width = 1 }}));
    try std.testing.expectError(error.Overflow, A.Arena.init(a, &.{.{ .role = .cpu, .log_size = 30, .width = std.math.maxInt(usize) }}));
    try std.testing.expectError(error.Overflow, A.Arena.init(a, &.{.{ .role = .cpu, .log_size = 30, .width = std.math.maxInt(usize) >> 30 }}));
    var arena = try A.Arena.init(a, &specs);
    defer arena.deinit();
    try std.testing.expectError(error.MissingMainRole, arena.matrix(.division));
    try arena.markInitialized(.cpu);
    try std.testing.expectError(error.MainRoleAlreadyInitialized, arena.markInitialized(.cpu));
    try std.testing.expectError(error.MainRoleNotInitialized, arena.takeForCommit(a));
}
fn allocationRun(a: std.mem.Allocator) !void {
    var arena = try A.Arena.init(a, &specs);
    defer arena.deinit();
    try initialize(&arena);
    var transfer = try arena.takeForCommit(a);
    defer transfer.deinit(a);
}
test "combined main arena transfers exactly one allocation on every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationRun, .{});
}
