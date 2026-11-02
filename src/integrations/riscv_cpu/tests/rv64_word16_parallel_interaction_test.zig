//! Serial oracle vs bounded two-wave native interaction generation.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const air = @import("stwo_riscv_frontend").rv64_air;
const W = air.word16_cpu;
const I = W.interaction;
const Native = @import("../word16/alu_cpu_fixture_data.zig");
const Loop = @import("../word16/loop_fixture.zig");
const CPU = @import("../word16/cpu.zig");
const Index = @import("../word16_index/proof.zig");
const Protocol = @import("../word16/cpu_protocol.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const Data = struct {
    native: Native.Fixture,
    rom: W.rom.Setup,
    source: W.trace.Source,
    table: W.table_trace.Source,
    challenges: W.lookup.Challenges,
    range16: []Q,
    range8: []Q,
    cache: I.RomCache,
    fn init() !Data {
        const public = try Loop.expected(4097);
        var words: std.ArrayList(u32) = .empty;
        errdefer words.deinit(a);
        try words.appendSlice(a, &Loop.WORDS);
        const records = try Loop.capture(a, public);
        var native = Native.Fixture{ .allocator = a, .words = words, .records = .fromOwnedSlice(records), .public = public };
        errdefer native.deinit();
        var rom = try W.rom.Setup.initWithProfile(a, .{ .base = 4096, .words = native.words.items }, .alu_binary_v2);
        errdefer rom.deinit();
        var source = try W.trace.Source.init(a, &rom, native.public, 16, native.records.items);
        errdefer source.deinit();
        var channel = air.protocol.Channel{};
        const challenges = Protocol.drawProfile(&channel, null, .alu_binary_v2).cpu;
        const r16 = try dictionary(challenges.range16, 65536);
        errdefer a.free(r16);
        const r8 = try dictionary(challenges.range8, 256);
        errdefer a.free(r8);
        var table = try W.table_trace.Source.initRom(a, &rom, source.rom_counts);
        errdefer table.deinit();
        _ = try table.generate(challenges);
        const pad = source.rowValues(source.public.steps);
        const fields = W.equations.romTupleProfile(M, .alu_binary_v2, &pad);
        var denominator = challenges.rom.offset;
        for (challenges.rom.coefficients, fields[0..16]) |coefficient, value| denominator = denominator.sub(coefficient.mulM31(value));
        for (challenges.rom.control_coefficients, fields[16..]) |coefficient, value| denominator = denominator.sub(coefficient.mulM31(value));
        const padding = try denominator.inv();
        return .{ .native = native, .rom = rom, .source = source, .table = table, .challenges = challenges, .range16 = r16, .range8 = r8, .cache = .{ .inverses = table.dictionary, .padding_inverse = padding } };
    }
    fn deinit(self: *Data) void {
        self.table.deinit();
        a.free(self.range16);
        a.free(self.range8);
        self.source.deinit();
        self.rom.deinit();
        self.native.deinit();
    }
};
fn dictionary(ch: W.lookup.RangeChallenges, n: usize) ![]Q {
    const input = try a.alloc(Q, n);
    defer a.free(input);
    const out = try a.alloc(Q, n);
    errdefer a.free(out);
    for (input, 0..) |*value, i| value.* = ch.offset.sub(ch.coefficient.mulM31(M.fromCanonical(@intCast(i))));
    try core.fields.batchInverseInPlace(Q, input, out);
    return out;
}
fn initPool(pool: *engine.work_pool.WorkPool, workers: usize) !void {
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = I.MIN_STACK_BYTES });
}
test "native interactions raw cached serial and one four sixteen worker matrices and claims match" {
    var data = try Data.init();
    defer data.deinit();
    var reference = data.source;
    const claims = try I.generate(&reference, data.challenges, data.range16, data.range8);
    defer a.free(reference.interaction);
    for ([_]usize{ 1, 4, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = .{};
        try initPool(&pool, workers);
        defer pool.deinit();
        for ([_]?I.RomCache{ null, data.cache }) |cache| {
            var source = data.source;
            const got = try I.generateWithRomCacheParallel(&source, data.challenges, data.range16, data.range8, cache, &pool);
            defer a.free(source.interaction);
            try std.testing.expectEqualDeep(claims, got);
            try std.testing.expectEqualSlices(M, reference.interaction, source.interaction);
        }
    }
}
fn allocationCase(allocator: std.mem.Allocator, data: *const Data, pool: *engine.work_pool.WorkPool) !void {
    var source = data.source;
    source.allocator = allocator;
    defer allocator.free(source.interaction);
    _ = try I.generateWithRomCacheParallel(&source, data.challenges, data.range16, data.range8, data.cache, pool);
}
test "native interaction poles partial submissions allocation failures preserve source and allow retry" {
    var data = try Data.init();
    defer data.deinit();
    var pool: engine.work_pool.WorkPool = .{};
    try initPool(&pool, 4);
    defer pool.deinit();
    for ([_]usize{ 0, 4096, 8192, data.source.size() - 1 }) |row| {
        var ch = data.challenges;
        ch.register.coefficients = @splat(Q.zero());
        ch.register.coefficients[5] = Q.one();
        ch.register.offset = Q.fromBase(M.fromCanonical(@intCast(4 * row + 1)));
        for ([_]?I.RomCache{ null, data.cache }) |cache| {
            try std.testing.expectError(error.DivisionByZero, I.generateWithRomCacheParallel(&data.source, ch, data.range16, data.range8, cache, &pool));
            try std.testing.expectEqual(@as(usize, 0), data.source.interaction.len);
        }
    }
    for (0..2) |wave| for (0..2) |after| {
        try std.testing.expectError(error.InjectedInteractionSubmissionFailure, I.testing.failSubmission(&data.source, data.challenges, data.range16, data.range8, data.cache, &pool, wave, after));
        try std.testing.expectEqual(@as(usize, 0), data.source.interaction.len);
    };
    var small_stack: engine.work_pool.WorkPool = .{};
    try small_stack.initInPlaceWithOptions(.{ .worker_count = 1, .stack_size = I.MIN_STACK_BYTES - 1 });
    defer small_stack.deinit();
    try std.testing.expectError(error.InvalidWord16InteractionStack, I.generateWithRomCacheParallel(&data.source, data.challenges, data.range16, data.range8, data.cache, &small_stack));
    var bad_cache = data.cache;
    bad_cache.padding_inverse = Q.zero();
    try std.testing.expectError(error.InvalidWord16RomCache, I.generateWithRomCacheParallel(&data.source, data.challenges, data.range16, data.range8, bad_cache, &pool));
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{ &data, &pool });
    _ = try I.generateWithRomCacheParallel(&data.source, data.challenges, data.range16, data.range8, data.cache, &pool);
    try std.testing.expectError(error.InvalidWord16CpuPhase, I.generateWithRomCacheParallel(&data.source, data.challenges, data.range16, data.range8, data.cache, &pool));
}
fn rawProof(materials: *const CPU.Materials, data: *const Data, workers: usize) !CPU.Encoded {
    var pool: engine.work_pool.WorkPool = .{};
    try initPool(&pool, workers);
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    return CPU.produce(a, materials, data.native.public, data.native.records.items, false);
}
fn indexProof(materials: *const Index.Materials, data: *const Data, workers: usize) !Index.Encoded {
    var pool: engine.work_pool.WorkPool = .{};
    try initPool(&pool, workers);
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    return Index.produce(a, materials, data.native.public, data.native.records.items, &.{});
}
test "native parallel interactions preserve raw and indexed complete proof bytes at one four sixteen workers" {
    var data = try Data.init();
    defer data.deinit();
    var raw = try CPU.Materials.init(a, .{ .base = 4096, .words = data.native.words.items }, .{ .cpu_log = 16, .alu_log = 16, .binary_log = 13, .profile = .alu_binary_v2 });
    defer raw.deinit();
    var first = try rawProof(&raw, &data, 1);
    defer first.deinit(a);
    for ([_]usize{ 4, 16 }) |workers| {
        var next = try rawProof(&raw, &data, workers);
        defer next.deinit(a);
        try std.testing.expectEqualSlices(u8, first.bytes, next.bytes);
        try CPU.verifyClosed(a, &raw, data.native.public, next);
    }
    var indexed = try Index.Materials.init(a, .{ .base = 4096, .words = data.native.words.items }, .{ .cpu_log = 16, .alu_log = 16, .binary_log = 13 });
    defer indexed.deinit();
    var base = try indexProof(&indexed, &data, 1);
    defer base.deinit(a);
    for ([_]usize{ 4, 16 }) |workers| {
        var next = try indexProof(&indexed, &data, workers);
        defer next.deinit(a);
        try std.testing.expectEqualSlices(u8, base.bytes, next.bytes);
        try Index.verify(a, &indexed, data.native.public, &.{}, next);
    }
}
