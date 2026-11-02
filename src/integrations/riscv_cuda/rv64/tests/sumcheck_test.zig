const std = @import("std");
const S = @import("../sumcheck.zig");
const R = @import("../resident.zig");
const abi = @import("../abi.zig");
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
const Context = struct {
    pub fn deviceSlicePointer(_: *@This(), comptime F: type, s: Slice, words: usize) ![*]F {
        if (s.owner != 17 or s.generation != 3 or words > s.len) return error.InvalidDeviceAddress;
        return @ptrFromInt(s.address);
    }
};
fn slice(i: usize) Slice {
    return .{ .address = 4096 + 8192 * i, .len = 2048, .owner = 17, .generation = 3 };
}
fn plane(i: usize, n: u32, c: u32) R.Plane {
    return .{ .data = slice(i), .stride = n, .coordinates = c };
}
fn fraction(i: usize, n: u32, c: u32) R.Fraction {
    return .{ .n = plane(i, n, c), .d = plane(i + 1, n, 8), .count = n };
}
fn input() S.Input {
    return .{ .fractions = fraction(0, 16, 1), .point = slice(2), .lambda = slice(3), .claim = slice(4), .seed = slice(5) };
}
fn workspace() S.Workspace {
    return .{ .banks = .{ fraction(6, 8, 8), fraction(8, 4, 8) }, .eq = plane(10, 4, 8), .scratch_a = plane(11, 2, 8), .scratch_b = plane(12, 2, 8), .sums = plane(13, 2, 8), .state = slice(14), .records = slice(15), .terminal_mask = slice(16) };
}
const Commands = struct {
    context: *Context,
    poisoned: bool = false,
    fused_fold_sum: bool = false,
    calls: usize = 0,
    folds: usize = 0,
    rounds: usize = 0,
    pub fn initSumcheck(self: *@This(), _: Slice, _: Slice, _: Slice, variables: u32) !void {
        try std.testing.expectEqual(@as(u32, 3), variables);
        self.calls += 1;
    }
    pub fn eq(self: *@This(), _: Slice, _: u32, _: R.Plane) !void {
        self.calls += 1;
    }
    pub fn sum(self: *@This(), f: R.Fraction, _: R.Plane, _: Slice, _: R.Plane, _: R.Plane, _: R.Plane) !void {
        try std.testing.expectEqual(@as(u32, 16) >> @as(u5, @intCast(self.rounds)), f.count);
        self.calls += 1;
    }
    pub fn foldSum(self: *@This(), f: R.Fraction, challenge: Slice, out: R.Fraction, _: R.Plane, _: Slice, _: R.Plane, _: R.Plane, _: R.Plane) !void {
        try std.testing.expect(f.count >= 8);
        try self.fold(f, challenge, out);
    }
    pub fn round(self: *@This(), _: Slice, _: u32, expected: u32, _: R.Plane, _: Slice, record: Slice) !void {
        try std.testing.expectEqual(@as(u32, @intCast(self.rounds)), expected);
        try std.testing.expectEqual(slice(15).address + self.rounds * abi.round_record_words * 4, record.address);
        self.rounds += 1;
        self.calls += 1;
    }
    pub fn packMask(self: *@This(), f: R.Fraction, out: Slice) !void {
        try std.testing.expectEqual(@as(u32, 2), f.count);
        try std.testing.expectEqual(slice(16).address, out.address);
        self.calls += 1;
    }
    pub fn fold(self: *@This(), f: R.Fraction, challenge: Slice, out: R.Fraction) !void {
        try std.testing.expectEqual(slice(15).address + self.folds * abi.round_record_words * 4 + 128, challenge.address);
        try std.testing.expectEqual(f.count / 2, out.count);
        self.folds += 1;
        self.calls += 1;
    }
};
test "RV64 CUDA full sumcheck enqueues resident round feedback and ping-pong folds" {
    var context = Context{};
    var commands = Commands{ .context = &context };
    const result = try S.enqueue(&commands, input(), workspace());
    try std.testing.expectEqual(@as(usize, 12), commands.calls);
    try std.testing.expectEqual(@as(u32, 2), result.terminal.count);
    try std.testing.expectEqual(slice(6).address, result.terminal.n.data.address);
    try std.testing.expectEqual(@as(u32, 3), result.rounds);
}
test "RV64 CUDA preflight rejects alias stale generation and short reservations before enqueue" {
    var context = Context{};
    var commands = Commands{ .context = &context };
    var w = workspace();
    w.banks[1].n.data = w.banks[0].n.data;
    try std.testing.expectError(error.OverlappingWorkspace, S.enqueue(&commands, input(), w));
    try std.testing.expectEqual(@as(usize, 0), commands.calls);
    w = workspace();
    w.records.len = 44 * 3 - 1;
    try std.testing.expectError(error.InvalidDeviceAddress, S.enqueue(&commands, input(), w));
    w = workspace();
    w.state.generation = 2;
    try std.testing.expectError(error.InvalidDeviceAddress, S.enqueue(&commands, input(), w));
    w = workspace();
    w.scratch_b = w.scratch_a;
    try std.testing.expectError(error.OverlappingWorkspace, S.enqueue(&commands, input(), w));
    try std.testing.expectEqual(@as(usize, 0), commands.calls);
    commands.poisoned = true;
    try std.testing.expectError(error.JobPoisoned, S.enqueue(&commands, input(), workspace()));
}

test "RV64 CUDA fused pipeline primes sums once and keeps terminal fold separate" {
    var context = Context{};
    var commands = Commands{ .context = &context, .fused_fold_sum = true };
    const result = try S.enqueue(&commands, input(), workspace());
    try std.testing.expectEqual(@as(usize, 10), commands.calls);
    try std.testing.expectEqual(@as(usize, 3), commands.folds);
    try std.testing.expectEqual(@as(u32, 2), result.terminal.count);
}
