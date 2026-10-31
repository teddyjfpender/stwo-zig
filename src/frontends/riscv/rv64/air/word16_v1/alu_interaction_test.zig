const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const S = @import("alu_source.zig");
const A = @import("alu.zig");
const P = @import("alu_lookup.zig");
const I = @import("alu_interaction.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const Data = struct {
    source: S.Source,
    ch: P.Challenges,
    dictionary: []Q,
    fn init() !Data {
        return initMode(false);
    }
    fn initMode(weighted: bool) !Data {
        const facts = try a.alloc(S.Fact, 8193);
        defer a.free(facts);
        for (facts, 0..) |*fact, i| {
            const op: @import("operations.zig").Alu = @enumFromInt(i % 10);
            const x = 0x8000000000000000 | (@as(u64, @intCast(i)) + 1);
            const y = 0xffff000012345678 - @as(u64, @intCast(i));
            fact.* = .{ .op = op, .a = x, .b = y, .c = A.nativeResult(op, x, y) };
        }
        const weights = try a.alloc(u32, facts.len);
        defer a.free(weights);
        for (weights, 0..) |*weight, i| weight.* = if (i == 0) 70000 else @intCast(i % 7);
        var source = if (weighted) try S.Source.initWeighted(a, facts, weights, 16) else try S.Source.init(a, facts, 16);
        errdefer source.deinit();
        source.releaseMain();
        var channel = core.channel.blake2s.Blake2sChannel{};
        var ch = P.Challenges{ .range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() }, .function = .{ .offset = channel.drawSecureFelt(), .coefficients = undefined } };
        for (&ch.function.coefficients) |*coefficient| coefficient.* = channel.drawSecureFelt();
        const denominators = try a.alloc(Q, 65536);
        defer a.free(denominators);
        const dictionary = try a.alloc(Q, 65536);
        errdefer a.free(dictionary);
        for (denominators, 0..) |*value, i| value.* = ch.range16.offset.sub(ch.range16.coefficient.mulM31(M.fromCanonical(@intCast(i))));
        try core.fields.batchInverseInPlace(Q, denominators, dictionary);
        return .{ .source = source, .ch = ch, .dictionary = dictionary };
    }
    fn deinit(self: *Data) void {
        self.source.deinit();
        a.free(self.dictionary);
    }
};
fn copy(allocator: std.mem.Allocator, source: S.Source) !S.Source {
    var result = source;
    result.allocator = allocator;
    result.metadata = try allocator.dupe(S.Metadata, source.metadata);
    result.interaction = &.{};
    return result;
}
fn clear(source: *S.Source) void {
    source.allocator.free(source.metadata);
    source.allocator.free(source.interaction);
}
fn poolInit(pool: *engine.work_pool.WorkPool, workers: usize) !void {
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = I.MIN_STACK_BYTES });
}
test "ALU joint prefix all48 columns and claims equal serial at1 4 16workers aftermainrelease" {
    var data = try Data.init();
    defer data.deinit();
    var serial = try copy(a, data.source);
    defer clear(&serial);
    const expected = try serial.generateSerial(data.ch, data.dictionary);
    try std.testing.expectEqual(@as(usize, 0), serial.metadata.len);
    for ([_]usize{ 1, 4, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = .{};
        try poolInit(&pool, workers);
        defer pool.deinit();
        var parallel = try copy(a, data.source);
        defer clear(&parallel);
        const actual = try I.generate(&parallel, data.ch, data.dictionary, &pool);
        try std.testing.expectEqualDeep(expected, actual);
        try std.testing.expectEqualSlices(M, serial.interaction, parallel.interaction);
        try std.testing.expectEqual(@as(usize, 0), parallel.metadata.len);
    }
}
fn allocationCase(allocator: std.mem.Allocator, data: *const Data, pool: *engine.work_pool.WorkPool) !void {
    var source = try copy(allocator, data.source);
    defer clear(&source);
    _ = try I.generate(&source, data.ch, data.dictionary, pool);
}
test "ALU interaction poles ledger andbothwave failure drain preservemetadata and retry" {
    var data = try Data.init();
    defer data.deinit();
    var pool: engine.work_pool.WorkPool = .{};
    try poolInit(&pool, 4);
    defer pool.deinit();
    var source = try copy(a, data.source);
    defer clear(&source);
    const before = try a.dupe(S.Metadata, source.metadata);
    defer a.free(before);
    for (0..2) |wave| for (0..2) |after| {
        try std.testing.expectError(error.InjectedAluInteractionSubmissionFailure, I.testing.failSubmission(&source, data.ch, data.dictionary, &pool, wave, after));
        try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
        try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(before), std.mem.sliceAsBytes(source.metadata));
    };
    var ch = data.ch;
    ch.function.coefficients = @splat(Q.zero());
    ch.function.coefficients[1] = Q.one();
    ch.function.offset = Q.zero();
    // All active lowA limbs are nonzero; only padding creates this strictpole.
    try std.testing.expectError(error.DivisionByZero, I.generate(&source, ch, data.dictionary, &pool));
    const last = source.metadata.len - 1;
    source.metadata[last].payload[1] = 65535;
    ch.function.offset = Q.fromBase(M.fromCanonical(65535));
    try std.testing.expectError(error.DivisionByZero, I.generate(&source, ch, data.dictionary, &pool));
    source.metadata[last] = before[last];
    const count = source.range16_counts[0];
    source.range16_counts[0] += 1;
    try std.testing.expectError(error.InvalidAluMetadata, I.generate(&source, data.ch, data.dictionary, &pool));
    source.range16_counts[0] = count;
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(before), std.mem.sliceAsBytes(source.metadata));
    var small_stack: engine.work_pool.WorkPool = .{};
    try small_stack.initInPlaceWithOptions(.{ .worker_count = 1, .stack_size = I.MIN_STACK_BYTES - 1 });
    defer small_stack.deinit();
    try std.testing.expectError(error.InvalidAluInteractionStack, I.generate(&source, data.ch, data.dictionary, &small_stack));
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{ &data, &pool });
    _ = try I.generate(&source, data.ch, data.dictionary, &pool);
    try std.testing.expectError(error.InvalidAluSourcePhase, I.generate(&source, data.ch, data.dictionary, &pool));
}

test "ALU weighted joint prefix all48 columns and claims equal serial at1 4 16workers afterinputrelease" {
    var data = try Data.initMode(true);
    defer data.deinit();
    var serial = try copy(a, data.source);
    defer clear(&serial);
    const expected = try serial.generateSerial(data.ch, data.dictionary);
    for ([_]usize{ 1, 4, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = .{};
        try poolInit(&pool, workers);
        defer pool.deinit();
        var parallel = try copy(a, data.source);
        defer clear(&parallel);
        const actual = try I.generate(&parallel, data.ch, data.dictionary, &pool);
        try std.testing.expectEqualDeep(expected, actual);
        try std.testing.expectEqualSlices(M, serial.interaction, parallel.interaction);
    }
}
