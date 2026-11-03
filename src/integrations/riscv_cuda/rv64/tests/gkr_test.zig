const std = @import("std");
const G = @import("../gkr.zig");
const R = @import("../resident.zig");
const A = @import("../abi.zig");
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
test "complete GKR arena admits exact requested payload and rejects invalid geometry before allocation" {
    const p = try G.Plan.init(&.{ 1, 3, 2 }, std.math.maxInt(usize));
    try std.testing.expectEqual(@as(u32, 3), p.layers);
    try std.testing.expectEqual(@as(u32, 3), p.count);
    for (p.layer[0..3], [_]u32{ 1, 2, 3 }, 0..) |l, active, depth| {
        try std.testing.expectEqual(active, l.active);
        try std.testing.expectEqual(active * 32, l.masks.words);
        try std.testing.expectEqual(depth * A.round_record_words, l.records.words);
        try std.testing.expect(l.records.offset_words % 64 == 0 and l.masks.offset_words % 64 == 0);
    }
    _ = try G.Plan.init(&.{ 1, 3, 2 }, p.total_words * 4);
    try std.testing.expectError(error.GkrWorkspaceBudgetExceeded, G.Plan.init(&.{ 1, 3, 2 }, p.total_words * 4 - 1));
    try std.testing.expectError(error.InvalidGeometry, G.Plan.init(&.{}, 1));
    try std.testing.expectError(error.InvalidGeometry, G.Plan.init(&.{0}, std.math.maxInt(usize)));
    try std.testing.expectError(error.InvalidGeometry, G.Plan.init(&.{29}, std.math.maxInt(usize)));
    const largest = try G.Plan.init(&.{28}, std.math.maxInt(usize));
    try std.testing.expect(largest.total_words > 1 << 30);
    try std.testing.expectError(error.GkrWorkspaceBudgetExceeded, G.Plan.init(&.{28}, 16 << 30));
}
const Context = struct {
    pub fn deviceSlicePointer(_: *@This(), comptime T: type, slice: Slice, count: usize) ![*]T {
        if (slice.owner != 1 or slice.generation != 2 or count > slice.len) return error.InvalidDeviceAddress;
        return @ptrFromInt(slice.address);
    }
};
const Commands = struct {
    context: *Context,
    poisoned: bool = false,
    calls: usize = 0,
    layers: u32 = 0,
    batches: u32 = 0,
    masks: u32 = 0,
    parents: u32 = 0,
    closures: u32 = 0,
    pub fn closeLocalRoots(s: *@This(), _: Slice, _: u32, _: Slice) !void {
        s.calls += 1;
        s.closures += 1;
    }
    pub fn layer(s: *@This(), input: R.Fraction, levels: u32, output: R.Fraction) !void {
        try std.testing.expectEqual(@as(u32, 1), levels);
        try std.testing.expectEqual(input.count / 2, output.count);
        s.calls += 1;
        s.layers += 1;
    }
    pub fn packRoots(s: *@This(), roots: []const R.Fraction, _: Slice) !void {
        for (roots) |r| try std.testing.expectEqual(@as(u32, 1), r.count);
        s.calls += 1;
    }
    pub fn initGkr(s: *@This(), _: Slice, _: Slice, _: []const u32, _: u32, _: u64) !void {
        s.calls += 1;
    }
    pub fn beginGkr(s: *@This(), _: Slice, depth: u32, _: u32, _: u32, _: Slice, _: Slice) !void {
        try std.testing.expectEqual(s.parents, depth);
        s.calls += 1;
    }
    pub fn closeGkr(s: *@This(), _: Slice, _: Slice, _: Slice, _: Slice, depth: u32, _: u32, _: u32) !void {
        try std.testing.expectEqual(s.parents, depth);
        s.parents += 1;
        s.calls += 1;
    }
    pub fn initBatch(s: *@This(), _: Slice, _: Slice, _: Slice, _: Slice, _: []const R.BatchOracle, _: u32) !void {
        s.batches += 1;
        s.calls += 1;
    }
    pub fn eq(s: *@This(), _: Slice, _: u32, _: R.Plane) !void {
        s.calls += 1;
    }
    pub fn sum(s: *@This(), _: R.Fraction, _: R.Plane, _: Slice, _: R.Plane, _: R.Plane, _: R.Plane) !void {
        s.calls += 1;
    }
    pub fn batchRound(s: *@This(), _: Slice, _: []const R.BatchOracle, _: u32, _: u32, _: Slice, _: Slice) !void {
        s.calls += 1;
    }
    pub fn fold(s: *@This(), _: R.Fraction, _: Slice, _: R.Fraction) !void {
        s.calls += 1;
    }
    pub fn packBatchMask(s: *@This(), input: R.Fraction, _: Slice) !void {
        try std.testing.expectEqual(@as(u32, 2), input.count);
        s.masks += 1;
        s.calls += 1;
    }
};
const Factory = struct {
    at: usize = 4096,
    fn slice(s: *@This(), words: usize) Slice {
        const at = s.at;
        s.at += (words * 4 + 255) & ~@as(usize, 255);
        return .{ .address = at, .len = words, .owner = 1, .generation = 2 };
    }
    fn plane(s: *@This(), count: u32, coordinates: u32) R.Plane {
        return .{ .data = s.slice(count * coordinates), .stride = count, .coordinates = coordinates };
    }
    fn fraction(s: *@This(), count: u32) R.Fraction {
        return .{ .n = s.plane(count, 1), .d = s.plane(count, 8), .count = count };
    }
};
test "complete GKR uses one arena and native mixed batch traversal without host claims" {
    var f = Factory{};
    var context = Context{};
    var commands = Commands{ .context = &context };
    const inputs = [_]R.Fraction{ f.fraction(2), f.fraction(8), f.fraction(4) };
    const seed = f.slice(9);
    const p = try G.Plan.init(&.{ 1, 3, 2 }, std.math.maxInt(usize));
    const done = try G.enqueue(&commands, &inputs, seed, f.slice(p.total_words), p.total_words * 4, 123);
    try std.testing.expectEqual(@as(u32, 6), commands.layers);
    try std.testing.expectEqual(@as(u32, 3), commands.batches);
    try std.testing.expectEqual(@as(u32, 3), commands.parents);
    try std.testing.expectEqual(@as(u32, 6), commands.masks);
    try std.testing.expectEqual(p.total_words * 4, done.requested_workspace_bytes);
    var h = G.Header{ .channel = .{ .digest = @splat(0), .draws = 1, .cursor = 6, .status = 0, .reserved = 0, .chain = 123, .padding = .{ 0, 0 } }, .layers = 3, .count = 3, .next_layer = 3, .phase = 2 };
    try h.validate(done);
    h.phase = 1;
    try std.testing.expectError(error.IncompleteGkrTraversal, h.validate(done));
    h.phase = 2;
    h.channel.chain += 1;
    try std.testing.expectError(error.InvalidDeviceTranscript, h.validate(done));
}
test "complete GKR rejects late invalid input alias generation and cap before any launch" {
    var f = Factory{};
    var context = Context{};
    var commands = Commands{ .context = &context };
    var inputs = [_]R.Fraction{ f.fraction(2), f.fraction(8), f.fraction(4) };
    const seed = f.slice(9);
    const p = try G.Plan.init(&.{ 1, 3, 2 }, std.math.maxInt(usize));
    const arena = f.slice(p.total_words);
    try std.testing.expectError(error.GkrWorkspaceBudgetExceeded, G.enqueue(&commands, &inputs, seed, arena, p.total_words * 4 - 1, 1));
    var short = arena;
    short.len -= 1;
    try std.testing.expectError(error.InvalidDeviceAddress, G.enqueue(&commands, &inputs, seed, short, p.total_words * 4, 1));
    var stale = arena;
    stale.generation = 1;
    try std.testing.expectError(error.InvalidDeviceAddress, G.enqueue(&commands, &inputs, seed, stale, p.total_words * 4, 1));
    try std.testing.expectError(error.OverlappingWorkspace, G.enqueue(&commands, &inputs, try arena.sub(0, 9), arena, p.total_words * 4, 1));
    const before = inputs[2].d.data;
    inputs[2].d.data = try arena.sub(0, before.len);
    try std.testing.expectError(error.OverlappingWorkspace, G.enqueue(&commands, &inputs, seed, arena, p.total_words * 4, 1));
    inputs[2].d.data = before;
    inputs[2].d.data.len -= 1;
    try std.testing.expectError(error.InvalidDeviceAddress, G.enqueue(&commands, &inputs, seed, arena, p.total_words * 4, 1));
    try std.testing.expectEqual(@as(usize, 0), commands.calls);
}

test "closure GKR path reserves its verdict before any launch and requires it after completion" {
    var f = Factory{};
    var context = Context{};
    var commands = Commands{ .context = &context };
    const inputs = [_]R.Fraction{ f.fraction(2), f.fraction(8), f.fraction(4) };
    const seed = f.slice(9);
    const p = try G.Plan.init(&.{ 1, 3, 2 }, std.math.maxInt(usize));
    const arena = f.slice(p.total_words);
    try std.testing.expectError(error.OverlappingWorkspace, G.enqueueWithClosure(&commands, &inputs, seed, arena, p.total_words * 4, 123, try arena.sub(0, 1)));
    var status = f.slice(1);
    status.generation = 1;
    try std.testing.expectError(error.InvalidDeviceAddress, G.enqueueWithClosure(&commands, &inputs, seed, arena, p.total_words * 4, 123, status));
    try std.testing.expectEqual(@as(usize, 0), commands.calls);
    status.generation = 2;
    const done = try G.enqueueWithClosure(&commands, &inputs, seed, arena, p.total_words * 4, 123, status);
    try std.testing.expectEqual(@as(u32, 1), commands.closures);
    const header = G.Header{ .channel = .{ .digest = @splat(0), .draws = 1, .cursor = 6, .status = 0, .reserved = 0, .chain = 123, .padding = .{ 0, 0 } }, .layers = 3, .count = 3, .next_layer = 3, .phase = 2 };
    try done.validate(header, 0);
    try std.testing.expectError(error.LocalGkrClosureRejected, done.validate(header, 8));
}
