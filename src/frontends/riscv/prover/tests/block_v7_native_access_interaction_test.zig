const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Joint = @import("../block_v7_native_access_interaction_v1.zig");
const Word = @import("../block_v5_word_memory_protocol_v1.zig");
const Transition = @import("../block_v5_word_execution_transition_v1.zig");
const Range = @import("../block_execution_byte_range_v2.zig");
const Universal = @import("../block_v5_opcode_memory_interaction_v1.zig");
const Source = @import("../block_execution_access_bridge_v2.zig");
const Integer = @import("../block_execution_integer_bridge_v2.zig");
const Bus = @import("../block_memory_relation_v2.zig");
const Counter = @import("../../air/lookups/tables/counter.zig").Counter;
const Trace = struct {
    log_size: u32,
    inactive: bool = false,
    malformed: bool = false,
    pair_reads: ?*std.atomic.Value(usize) = null,
    pub fn domainSize(self: *const @This()) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    fn rawPair(self: *const @This(), logical: usize) Source.Pair(Q) {
        const enabled = !self.inactive and logical % 7 != 0;
        var before: [4]Q = undefined;
        var after: [4]Q = undefined;
        for (&before, &after, 0..) |*b, *e, i| {
            b.* = Q.fromBase(M.fromCanonical(@intCast((logical * 19 + i * 37) % 256)));
            e.* = Q.fromBase(M.fromCanonical(@intCast((logical * 23 + i * 41 + 17) % 256)));
        }
        return .{ .active = if (enabled) Q.one() else Q.zero(), .space = Q.one(), .source_address = if (self.malformed and logical == 1) Q.fromU32Unchecked(1, 1, 0, 0) else Q.fromBase(M.fromU64(101 + logical)), .local_clock = Q.fromBase(M.fromU64(4 * logical + 10)), .consume_clock = Q.fromBase(M.fromU64(4 * logical + 7)), .before = before, .after = after, .pair_residuals = @splat(Q.zero()), .access_ordinal = 0 };
    }
    pub fn pairAt(self: *const @This(), logical: usize) !Source.Pair(Q) {
        if (self.pair_reads) |reads| _ = reads.fetchAdd(1, .monotonic);
        return self.rawPair(logical);
    }
    pub fn witnessAt(self: *const @This(), logical: usize) !Integer.Witness {
        return Integer.Witness.fromPair(self.rawPair(logical), 0x1_0000_0010);
    }
    pub fn row(self: *const @This(), logical: usize) !Transition.Row {
        const pair = try self.pairAt(logical);
        const decoded = try Source.decodePair(pair);
        if (!decoded.active) return .{ .active = false, .tuple = @splat(M.zero()) };
        const secure = Integer.transitionAtPoint(pair, try self.witnessAt(logical));
        var tuple: Bus.TransitionTuple = undefined;
        for (secure, &tuple) |value, *out| out.* = value.toM31Array()[0];
        _ = try Bus.decodeTransitionTuple(tuple);
        return .{ .active = true, .tuple = tuple };
    }
};
fn challenges(a: std.mem.Allocator) !Word.Challenges {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x173591, 0x203701 });
    return Word.Challenges.drawFromChannel(a, &channel);
}
fn snapshot(a: std.mem.Allocator, trace: *const Trace) !Range.SNAPSHOT {
    var counter = try Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    return Range.collectCounter(a, trace, &counter);
}
fn compare(a: std.mem.Allocator, trace: *const Trace, ch: *const Word.Challenges) !void {
    const sealed = try snapshot(a, trace);
    const rows = try a.alloc(Transition.Row, trace.domainSize());
    defer a.free(rows);
    const opposite = try a.alloc(Universal.Row, trace.domainSize());
    defer a.free(opposite);
    for (rows, opposite, 0..) |*row, *other, i| {
        row.* = try trace.row(i);
        other.* = try Universal.rowFromPair(try trace.pairAt(i));
    }
    var transition = try Transition.generate(a, ch, rows, trace.log_size);
    defer transition.deinit(a);
    var ranges = try Range.generate(a, trace, ch.universal_prefix.get(.range_check_8_8), sealed);
    defer ranges.deinit(a);
    var universal = try Universal.generate(a, ch.universal_prefix.get(.memory_access), opposite, trace.log_size);
    defer universal.deinit(a);
    if (trace.pair_reads) |reads| reads.store(0, .monotonic);
    var actual = try Joint.generate(a, trace, ch, sealed);
    defer actual.deinit(a);
    if (trace.pair_reads) |reads| try std.testing.expectEqual(trace.domainSize(), reads.load(.monotonic));
    for (transition.columns, actual.columns[0..9]) |left, right| try std.testing.expectEqualSlices(M, left, right);
    for (ranges.columns, actual.columns[9..37]) |left, right| try std.testing.expectEqualSlices(M, left, right);
    for (universal.columns, actual.columns[37..49]) |left, right| try std.testing.expectEqualSlices(M, left, right);
    try std.testing.expectEqualDeep(transition.claim, actual.transition_sum);
    try std.testing.expectEqualDeep(ranges.claims, actual.range_claims);
    try std.testing.expectEqualDeep(universal.claim, actual.universal_sum);
    try std.testing.expectEqual(transition.count, actual.active_count);
}
test "v7 fused native access matches all49 columns and nine physical sums across bounded tiles" {
    const a = std.testing.allocator;
    const ch = try challenges(a);
    for ([_]u32{ 1, 8, 10 }) |log| {
        var reads = std.atomic.Value(usize).init(0);
        try compare(a, &.{ .log_size = log, .pair_reads = &reads }, &ch);
    }
    try compare(a, &.{ .log_size = 9, .inactive = true }, &ch);
}
test "v7 fused native access parallel uneven partition and nested lease fallback match old generators" {
    const a = std.testing.allocator;
    const ch = try challenges(a);
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var reads = std.atomic.Value(usize).init(0);
    try compare(a, &.{ .log_size = 15, .pair_reads = &reads }, &ch);
    var held = try pool.acquire(try engine.work_pool.WorkerBudget.init(3));
    defer held.deinit();
    try compare(a, &.{ .log_size = 14 }, &ch);
}
test "v7 fused access rejects active zero denominators changed seals and malformed native tuples" {
    const a = std.testing.allocator;
    const ch = try challenges(a);
    const trace = Trace{ .log_size = 2 };
    const sealed = try snapshot(a, &trace);
    var bad_seal = sealed;
    bad_seal[0] ^= 1;
    try std.testing.expectError(error.ExecutionRangeCounterChangedAfterSeal, Joint.generate(a, &trace, &ch, bad_seal));
    const malformed = Trace{ .log_size = 2, .malformed = true };
    const expected = if (malformed.row(1)) |_| return error.ExpectedMalformedTrace else |err| err;
    try std.testing.expectError(expected, Joint.generate(a, &malformed, &ch, sealed));
    const inverse_error = if (Q.zero().inv()) |_| unreachable else |err| err;
    for (0..3) |which| {
        var zero = ch;
        if (which == 0) {
            zero.transition.z = Q.zero();
            @memset(&zero.transition.alpha_powers, Q.zero());
        } else {
            const kind: @import("../../air/lang/relation.zig").Domain = if (which == 1) .memory_access else .range_check_8_8;
            const element = &zero.universal_prefix.elements[@intFromEnum(kind)];
            element.z = Q.zero();
            @memset(&element.alpha_powers, Q.zero());
        }
        try std.testing.expectError(inverse_error, Joint.generate(a, &trace, &zero, sealed));
        // Original generators skip unused denominators on wholly inactive rows.
        const inactive = Trace{ .log_size = 2, .inactive = true };
        try compare(a, &inactive, &zero);
    }
}
test "v7 fused access allocation failures unwind output and bounded worker scratch" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}
fn allocationCase(a: std.mem.Allocator) !void {
    const ch = try challenges(a);
    const trace = Trace{ .log_size = 1 };
    const sealed = try snapshot(a, &trace);
    var result = try Joint.generate(a, &trace, &ch, sealed);
    result.deinit(a);
}
