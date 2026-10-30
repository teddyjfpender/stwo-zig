const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const K = @import("../block_v8_ram_clock_v3_kernel.zig");
const L = @import("../block_v8_ram_clock_v3_layout.zig");
const T = @import("../block_v8_ram_clock_v3_tracker.zig");
const Canonical = @import("../../runner/state_chain.zig");
const Halt = @import("../block_v8_native_halt_policy_v1.zig");
fn zero(checks: [K.CONSTRAINT_COUNT]M) bool {
    for (checks) |value| if (!value.isZero()) return false;
    return true;
}
fn ranged(row: [K.COLUMN_COUNT]M) bool {
    for (row) |value| if (value.v >= 65536) return false;
    return true;
}
test "ram clock v3 three ranged limbs prove exact positive integer order across long gaps" {
    const policy = K.Policy{ .max_clock = K.CLOCK_BOUND - 1 };
    for ([_]u32{ 1, 3, 65535, 65536, 65537, 1048575, 1048576, 1048577, K.CLOCK_BOUND - 1 }) |current| {
        for ([_]u32{ 0, current - 1 }) |previous| {
            const row = try K.witness(policy, true, current, previous);
            try K.checkIntegerTheorem(policy, current, previous, row);
            try std.testing.expect(zero(K.constraints(M, M.one(), M.fromCanonical(current), M.fromCanonical(previous), row)));
            for (0..K.COLUMN_COUNT) |i| {
                var changed = row;
                changed[i] = changed[i].add(M.one());
                try std.testing.expect(!zero(K.constraints(M, M.one(), M.fromCanonical(current), M.fromCanonical(previous), changed)));
            }
        }
    }
    for ([_][2]u32{ .{ 7, 7 }, .{ 3, 7 }, .{ 1, K.CLOCK_BOUND - 1 } }) |clocks| {
        const field_gap = M.fromCanonical(clocks[0]).sub(M.fromCanonical(clocks[1])).sub(M.one()).v;
        const low = field_gap & 65535;
        const high = field_gap >> 16;
        const fake = [3]M{ M.fromCanonical(low), M.fromCanonical(high), M.fromCanonical(K.HIGH_MAX).sub(M.fromCanonical(high)) };
        // Algebra alone can represent a negative clock difference modulo p;
        // the three real range16 supplies exclude the forged high/slack.
        try std.testing.expect(zero(K.constraints(M, M.one(), M.fromCanonical(clocks[0]), M.fromCanonical(clocks[1]), fake)));
        try std.testing.expect(!ranged(fake));
        try std.testing.expectError(error.UnclosedV3RamClockRange16, K.checkIntegerTheorem(policy, clocks[0], clocks[1], fake));
    }
}
test "ram clock v3 refuses an unbounded predecessor even when its field residue fits" {
    const policy = K.Policy{ .max_clock = K.CLOCK_BOUND - 1 };
    const forged_previous = core.fields.m31.Modulus - 1;
    const fake = [3]M{ M.fromCanonical(3), M.zero(), M.fromCanonical(K.HIGH_MAX) };
    try std.testing.expect(zero(K.constraints(M, M.one(), M.fromCanonical(3), M.fromCanonical(forged_previous), fake)));
    try std.testing.expect(ranged(fake));
    try std.testing.expectError(error.UnboundedV3RamClock, K.checkIntegerTheorem(policy, 3, forged_previous, fake));
    try std.testing.expectError(error.UnboundedV3RamClock, K.witness(policy, true, 3, forged_previous));
}
test "ram clock v3 load store role split preserves both register gap queries" {
    const policy = try K.Policy.fromCycles(2000000);
    for ([_]usize{ 34, 35, 36, 37, 38, 39, 40, 41 }) |opcode_flag| {
        const store = opcode_flag >= 39;
        var main: [Halt.NativeColumns.width]M = @splat(M.zero());
        main[0] = M.fromCanonical(1000000);
        main[opcode_flag] = M.one();
        main[23] = M.fromCanonical(3);
        main[7] = M.fromCanonical(7);
        const row = try K.witness(policy, true, 3999999, if (store) 7 else 3);
        try std.testing.expect(zero(try K.constraintsNative(M, M.one(), &main, row)));
        const weights = try L.retainedRegisterWeights(M, M.one(), &main);
        try std.testing.expectEqual(@as(u32, @intFromBool(store)), weights[0].v);
        try std.testing.expectEqual(@as(u32, @intFromBool(!store)), weights[1].v);
        const wrong = try K.witness(policy, true, 3999999, if (store) 3 else 7);
        try std.testing.expect(!zero(try K.constraintsNative(M, M.one(), &main, wrong)));
    }
    const inactive: [Halt.NativeColumns.width]M = @splat(M.zero());
    try std.testing.expect(zero(try K.constraintsNative(M, M.zero(), &inactive, @splat(M.zero()))));
    for (0..3) |i| {
        var fake: [3]M = @splat(M.zero());
        fake[i] = M.one();
        try std.testing.expect(!zero(try K.constraintsNative(M, M.zero(), &inactive, fake)));
    }
}
const Degree = struct {
    n: usize,
    pub fn one() @This() {
        return .{ .n = 0 };
    }
    pub fn splat(_: core.fields.qm31.QM31) @This() {
        return .{ .n = 0 };
    }
    pub fn add(a: @This(), b: @This()) @This() {
        return .{ .n = @max(a.n, b.n) };
    }
    pub fn sub(a: @This(), b: @This()) @This() {
        return a.add(b);
    }
    pub fn mul(a: @This(), b: @This()) @This() {
        return .{ .n = a.n + b.n };
    }
};
test "ram clock v3 native gap degree remains within q2" {
    const d = Degree{ .n = 1 };
    const main: [50]Degree = @splat(d);
    for (try K.constraintsNative(Degree, d, &main, @splat(d))) |check| try std.testing.expect(check.n <= K.MAX_DEGREE);
}
test "ram clock v3 opt in tracker retains register hops and removes only RAM hops" {
    var candidate = try T.Tracker.init(std.testing.allocator, 4000000);
    defer candidate.deinit();
    const clock = 8 * Canonical.MAX_CLOCK_DIFF + 3;
    try candidate.recordRegTransition(1, clock - 2, 17, 18);
    const first = try candidate.recordMemTransition(0x100100, clock, 7, 9);
    const second = try candidate.recordMemTransition(0x100100, clock + 4, 9, 10);
    try K.checkIntegerTheorem(candidate.policy, clock, 0, first);
    try K.checkIntegerTheorem(candidate.policy, clock + 4, clock, second);
    try std.testing.expectEqual(@as(usize, 0), candidate.chain.clock_updates_mem.items.len);
    try std.testing.expect(candidate.chain.clock_updates_reg.items.len != 0);
    try std.testing.expectEqual(@as(u64, 8), candidate.avoided_ram_hops);
    try std.testing.expectEqual(clock, candidate.chain.accesses.items[2].clk_prev);
    try std.testing.expectEqual(@as(u32, 7), candidate.chain.mem_initial.get(0x100100).?);
    try std.testing.expectError(error.NonIncreasingV3RamClock, candidate.recordMemTransition(0x100100, clock, 10, 11));
    try std.testing.expectError(error.InvalidV3RamAccessOrdinal, candidate.recordMemTransition(0x100100, clock + 1, 10, 11));
}
fn trackerAllocations(a: std.mem.Allocator) !void {
    var tracker = try T.Tracker.init(a, 2000000);
    defer tracker.deinit();
    _ = tracker.recordMemTransition(0x100100, 3, 7, 8) catch |err| {
        try std.testing.expectEqual(@as(usize, 0), tracker.chain.accesses.items.len);
        try std.testing.expectEqual(@as(u32, 0), tracker.chain.mem_initial.count());
        try std.testing.expectEqual(@as(u64, 0), tracker.avoided_ram_hops);
        return err;
    };
    _ = tracker.recordMemTransition(0x100104, 4 * 1500000 - 1, 9, 10) catch |err| {
        try std.testing.expectEqual(@as(usize, 1), tracker.chain.accesses.items.len);
        try std.testing.expectEqual(@as(u32, 1), tracker.chain.mem_initial.count());
        try std.testing.expectEqual(@as(u64, 0), tracker.avoided_ram_hops);
        return err;
    };
}
test "ram clock v3 candidate memory collector is atomic on allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, trackerAllocations, .{});
}
test "ram clock v3 layout is disabled and binds only the conditional RAM gap replacement" {
    const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
    var shape = std.mem.zeroes(Shape);
    shape.initializeDescriptorStorage();
    shape.n_components = 1;
    shape.component_descs[0] = .{ .family = .load_store, .log_size = 1, .n_rows = 1, .n_columns = 50 };
    shape.n_infra = 1;
    shape.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 1, .n_columns = 10 };
    shape.total_steps = 1;
    shape.public_data.clock = 1;
    shape.public_data.program_root = .{ .bytes = @splat(1) };
    shape.public_data.completion = @import("../../air/public_data.zig").Completion.canonicalSelfLoop(0);
    shape.public_data.io_entries.input_words = &.{};
    shape.public_data.io_entries.output_words = &.{};
    var recipe = try L.Recipe.init(std.testing.allocator, &shape, 0);
    defer recipe.deinit();
    try std.testing.expectEqual(@as(usize, 55), recipe.logs.len);
    try std.testing.expectEqual(@as(usize, 52), recipe.groups[0].auxiliary_offset);
    try std.testing.expectEqual(@as(u32, 0), recipe.register_hop_bound);
    try std.testing.expectEqual(@as(u32, 0), recipe.candidate_shape.n_infra);
    try std.testing.expectEqual(@as(u8, 10), L.replacements[0].ordinal);
    try std.testing.expectEqual(@as(u8, 13), L.replacements[1].ordinal);
    try std.testing.expect(!L.production_active and !L.whole_source_qualified and !K.whole_source_qualified);
    var tracker = try T.Tracker.init(std.testing.allocator, 1);
    defer tracker.deinit();
    _ = try tracker.recordMemTransition(0x100100, 3, 0, 1);
    try recipe.requireCollector(&tracker.chain);
    var old = Canonical.StateChainTracker.init(std.testing.allocator);
    defer old.deinit();
    try old.recordMemTransition(0x100100, 2 * Canonical.MAX_CLOCK_DIFF + 3, 0, 1);
    try std.testing.expectError(error.UnadaptedV3RamClockCollector, recipe.requireCollector(&old));
}
