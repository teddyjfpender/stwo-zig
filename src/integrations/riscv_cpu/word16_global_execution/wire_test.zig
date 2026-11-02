const std = @import("std");
const W = @import("wire.zig");
const P = @import("protocol.zig");
const E = @import("execution.zig");
const G = @import("../word16_execution/geometry.zig");
const F = @import("fixture.zig");
const Cell = @import("../word16_execution/memory/statement.zig").Cell;
const Receipt = @import("../rv64_ethereum_batch_receipt.zig");
const a = std.testing.allocator;
fn opaqueTransport(allocator: std.mem.Allocator, dir: std.fs.Dir, cells: []const Cell) !void {
    const geometries = [_]G.Geometry{ .{ .cpu_log = 5, .boundary_log = 12 }, .{ .cpu_log = 5, .boundary_log = 12 } };
    var manifest = try P.Manifest.init(allocator, &.{ @splat(1), @splat(2) }, &.{ .{ .fixed = .{ .bytes = @splat(3) }, .main = .{ .bytes = @splat(4) } }, .{ .fixed = .{ .bytes = @splat(3) }, .main = .{ .bytes = @splat(5) } } });
    defer manifest.deinit();
    var requests: [2]P.Old.Request = undefined;
    for (&requests, 0..) |*r, i| r.* = .{ .cpu = .{ .steps = 1, .initial_pc = 4096 + 4 * i, .final_pc = 4100 + 4 * i, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) }, .epoch = @intCast(i + 1), .division_requests = 0, .multiplication_requests = 0, .memory = .{ .initial = if (i == 0) cells else &.{}, .terminal = if (i == 1) cells else &.{}, .epoch = @intCast(i + 1), .ls_count = 1 } };
    // Opaque codec bytes are NEVER passed to an accepting proof receiver.
    var proofs = [_]E.Encoded{ .{ .bytes = @constCast("abc"), .request = requests[0], .claims = std.mem.zeroes(P.Old.Claims) }, .{ .bytes = @constCast("def"), .request = requests[1], .claims = std.mem.zeroes(P.Old.Claims) } };
    const bundle = E.Bundle{ .manifest = manifest, .proofs = &proofs };
    try W.write(allocator, dir, geometries, &bundle);
}
fn changeByte(dir: std.fs.Dir, offset: u64, value: u8) !void {
    var file = try dir.openFile("cells.bin", .{ .mode = .read_write });
    defer file.close();
    try file.seekTo(offset);
    try file.writeAll(&.{value});
}
test "global wire v2 streams beyond full cell blocks and rejects tampering headers truncation overwrite" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cells = try a.alloc(Cell, 2051);
    defer a.free(cells);
    for (cells, 0..) |*c, i| c.* = .{ .address = 0xfedcba9800000000 + 8 * @as(u64, @intCast(i)), .state = .{ .value = 0x9876543200000000 + @as(u64, @intCast(i)), .epoch = 65535, .tick = 0xffffff, .rights = 3 } };
    try opaqueTransport(a, tmp.dir, cells);
    var loaded = try W.read(a, tmp.dir);
    defer loaded.deinit(a);
    try std.testing.expectEqualSlices(Cell, cells, loaded.bundle.proofs[0].request.memory.initial);
    try std.testing.expectEqualSlices(Cell, cells, loaded.bundle.proofs[1].request.memory.terminal);
    try std.testing.expectEqualStrings("abc", loaded.bundle.proofs[0].bytes);
    try std.testing.expectError(error.PathAlreadyExists, opaqueTransport(a, tmp.dir, cells));
    var file = try tmp.dir.openFile("cells.bin", .{ .mode = .read_write });
    defer file.close();
    const length = try file.getEndPos();
    try changeByte(tmp.dir, length - 1, 2);
    try std.testing.expectError(error.GlobalMemorySidecarChanged, W.read(a, tmp.dir));
    try changeByte(tmp.dir, length - 1, 3);
    try changeByte(tmp.dir, 0, 'X');
    try std.testing.expectError(error.GlobalMemorySidecarChanged, W.read(a, tmp.dir));
    try changeByte(tmp.dir, 0, 'R');
    try file.setEndPos(length - 1);
    try std.testing.expectError(error.InvalidMemorySidecarSize, W.read(a, tmp.dir));
}
fn oomRead(allocator: std.mem.Allocator, dir: std.fs.Dir) !void {
    var loaded = try W.read(allocator, dir);
    defer loaded.deinit(allocator);
}
test "global wire read cleans every allocation failure" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try opaqueTransport(a, tmp.dir, &.{});
    try std.testing.checkAllAllocationFailures(a, oomRead, .{tmp.dir});
}
fn rejected(result: anyerror!void) !void {
    if (result) |_| return error.ExpectedPhysicalProofRejection else |_| {}
}
test "actual two CPU proof transport preserves bytes and physical claims reject tampering" {
    var case = try F.Case.init(a);
    defer case.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const geometries = [2]G.Geometry{ case.setups[0].materials.geometry, case.setups[1].materials.geometry };
    try W.write(a, tmp.dir, geometries, &case.bundle);
    var loaded = try W.read(a, tmp.dir);
    defer loaded.deinit(a);
    for (loaded.bundle.proofs, case.bundle.proofs) |x, y| try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
    const keys = case.keys();
    try E.verify(a, &keys, case.expected(), &loaded.bundle);
    const json = try tmp.dir.readFileAlloc(a, "bundle.json", 1 << 20);
    defer a.free(json);
    const parsed = try std.json.parseFromSlice(W.Metadata, a, json, .{});
    defer parsed.deinit();
    var bad = parsed.value;
    bad.claims[0].ls.ram = bad.claims[0].ls.ram.add(P.Q.one());
    bad.claims[1].ls.ram = bad.claims[1].ls.ram.sub(P.Q.one());
    const corrupted = try std.json.Stringify.valueAlloc(a, bad, .{});
    defer a.free(corrupted);
    var meta = try tmp.dir.openFile("bundle.json", .{ .mode = .read_write });
    defer meta.close();
    try meta.setEndPos(0);
    try meta.writeAll(corrupted);
    var forged = try W.read(a, tmp.dir);
    defer forged.deinit(a);
    try rejected(E.verify(a, &keys, case.expected(), &forged.bundle));
    var legacy = std.testing.tmpDir(.{});
    defer legacy.cleanup();
    const old = .{ .schema = @as(u32, 1), .geometries = geometries, .requests = [2]P.Old.Request{ case.bundle.proofs[0].request, case.bundle.proofs[1].request }, .claims = [2]P.Old.Claims{ case.bundle.proofs[0].claims, case.bundle.proofs[1].claims }, .specs = case.bundle.manifest.specs[0..2].*, .roots = case.bundle.manifest.roots[0..2].*, .seal = case.bundle.manifest.digest };
    const old_json = try std.json.Stringify.valueAlloc(a, old, .{});
    defer a.free(old_json);
    try Receipt.writeExclusive(legacy.dir, "bundle.json", old_json);
    try Receipt.writeExclusive(legacy.dir, "proof0.bin", case.bundle.proofs[0].bytes);
    try Receipt.writeExclusive(legacy.dir, "proof1.bin", case.bundle.proofs[1].bytes);
    var compatibility = try W.read(a, legacy.dir);
    defer compatibility.deinit(a);
    try E.verify(a, &keys, case.expected(), &compatibility.bundle);
}
