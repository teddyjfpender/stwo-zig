//! Physical matrix formatting is compared with the strict logical reference.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const W = front.rv64_air.word16_cpu;
const I = front.rv64_air.word16_index_control;
const Projection = W.native_projection;
const Loop = @import("../word16/loop_fixture.zig");
const M = core.fields.m31.M31;
const Record = front.rv64.machine.Retirement;
const a = std.testing.allocator;
const LOG = 16;
fn checkMetadata(x: []const W.trace.Metadata, y: []const W.trace.Metadata) !void {
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(x), std.mem.sliceAsBytes(y));
}
fn checkRaw(rom: *const W.rom.Setup, public: W.public.Public, records: []const Record) !void {
    var reference = try W.trace.Source.initMetadata(a, rom.metadataView(), public, LOG, records);
    defer reference.deinit();
    const n = reference.size();
    const width = W.profile.mainCount(rom.profile);
    const expected = try a.alloc(M, width * n);
    defer a.free(expected);
    for (0..n) |logical| {
        const row = reference.projectRow(logical);
        const position = W.layout.physical(logical, LOG);
        for (row[0..width], 0..) |value, column| expected[column * n + position] = value;
    }
    for ([_]usize{ 1, 4, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = Projection.MIN_STACK_BYTES });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var source = try W.trace.Source.init(a, rom, public, LOG, records);
        defer source.deinit();
        try std.testing.expectEqualSlices(M, expected, source.main);
        try std.testing.expectEqualSlices(u64, reference.range16_counts, source.range16_counts);
        try std.testing.expectEqualSlices(u64, reference.range8_counts, source.range8_counts);
        try std.testing.expectEqualSlices(u64, reference.rom_counts, source.rom_counts);
        try checkMetadata(reference.metadata, source.metadata);
        try std.testing.expectEqual(n, source.rows_projected);
        try std.testing.expectError(error.InvalidWord16ProjectionPhase, source.fillMain());
    }
}
fn checkIndex(authority: *const I.authority.Authority, public: W.public.Public, records: []const Record) !void {
    var reference = try I.trace.Source.initMetadata(a, authority, public, LOG, records);
    defer reference.deinit();
    const n = reference.base.size();
    const expected = try a.alloc(M, I.equations.MAIN * n);
    defer a.free(expected);
    for (0..n) |logical| {
        const row = reference.rowValues(logical);
        _ = reference.base.projectDataRow(logical);
        const position = W.layout.physical(logical, LOG);
        for (row, 0..) |value, column| expected[column * n + position] = value;
    }
    for ([_]usize{ 1, 4, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = Projection.MIN_STACK_BYTES });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var source = try I.trace.Source.init(a, authority, public, LOG, records);
        defer source.deinit();
        try std.testing.expectEqualSlices(M, expected, source.main);
        try std.testing.expectEqual(@as(usize, 0), source.base.main.len);
        try std.testing.expectEqualSlices(u64, reference.base.range16_counts, source.base.range16_counts);
        try std.testing.expectEqualSlices(u64, reference.base.range8_counts, source.base.range8_counts);
        try std.testing.expectEqualSlices(u64, reference.base.rom_counts, source.base.rom_counts);
        try checkMetadata(reference.base.metadata, source.base.metadata);
        try std.testing.expectEqual(n, source.base.rows_projected);
        try std.testing.expectError(error.InvalidIndexProjectionPhase, source.fillMain());
    }
}
fn binaryRecords(public: *W.public.Public) ![4]Record {
    const words = [_]u32{ 0x0020f1b3, 0x0011e0b3, 0x0020c033, 0x0030c133 };
    var memory = front.rv64.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = public.initial_pc, .size = 16, .permissions = .{ .read = true, .execute = true } });
    for (words, 0..) |word, i| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word, .little);
        try memory.initialize(public.initial_pc + 4 * i, &bytes);
    }
    var cpu = front.rv64.machine.Cpu.init(public.initial_pc, 0);
    cpu.regs = public.initial_registers;
    var records: [4]Record = undefined;
    for (&records, 0..) |*record, i| {
        record.* = try cpu.step(&memory);
        for ([_]u5{ record.rs1, record.rs2, record.rd }, 0..) |id, slot| if (id != 0) {
            public.register_clocks[id] = @intCast(4 * i + slot + 1);
        };
    }
    public.final_registers = cpu.regs;
    public.final_pc = cpu.pc;
    return records;
}
test "native physical raw44 raw46 index40 match logical matrices metadata and histograms at1 4 16" {
    var public = W.public.Public{ .steps = 4, .initial_pc = 0x8000000000001000, .final_pc = 0, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
    public.initial_registers[1] = 0xffff000180007fff;
    public.initial_registers[2] = 0x7fffffff8000ffff;
    const records = try binaryRecords(&public);
    const words = [_]u32{ 0x0020f1b3, 0x0011e0b3, 0x0020c033, 0x0030c133 };
    var binary = try W.rom.Setup.init(a, .{ .base = public.initial_pc, .words = &words });
    defer binary.deinit();
    try checkRaw(&binary, public, &records);
    var sparse_public = public;
    sparse_public.steps = 1;
    sparse_public.final_pc = records[0].next_pc.toInt();
    sparse_public.final_registers = public.initial_registers;
    sparse_public.final_registers[3] = records[0].result.toInt();
    sparse_public.register_clocks = @splat(0);
    sparse_public.register_clocks[1] = 1;
    sparse_public.register_clocks[2] = 2;
    sparse_public.register_clocks[3] = 3;
    const sparse_addresses = [_]u64{ 4096, public.initial_pc };
    const sparse_words = [_]u32{ words[0], words[0] };
    var sparse = try I.authority.Authority.init(a, .{ .base = 4096, .words = &sparse_words, .addresses = &sparse_addresses });
    defer sparse.deinit();
    try checkIndex(&sparse, sparse_public, records[0..1]);
    const loop_public = try Loop.expected(4097);
    const loop_records = try Loop.capture(a, loop_public);
    defer a.free(loop_records);
    var raw = try W.rom.Setup.initWithProfile(a, .{ .base = Loop.BASE, .words = &Loop.WORDS }, .alu_binary_v2);
    defer raw.deinit();
    try checkRaw(&raw, loop_public, loop_records);
    var indexed = try I.authority.Authority.init(a, .{ .base = Loop.BASE, .words = &Loop.WORDS });
    defer indexed.deinit();
    try checkIndex(&indexed, loop_public, loop_records);
}
fn allocationCase(allocator: std.mem.Allocator, raw: *const W.rom.Setup, indexed: *const I.authority.Authority, public: W.public.Public, records: []const Record) !void {
    var source = try W.trace.Source.init(allocator, raw, public, LOG, records);
    defer source.deinit();
    var next = try I.trace.Source.init(allocator, indexed, public, LOG, records);
    defer next.deinit();
}
test "native CPU projection cancelled helpers OOM and phase errors preserve source for retry" {
    const public = try Loop.expected(4097);
    const records = try Loop.capture(a, public);
    defer a.free(records);
    var raw = try W.rom.Setup.initWithProfile(a, .{ .base = Loop.BASE, .words = &Loop.WORDS }, .alu_binary_v2);
    defer raw.deinit();
    var indexed = try I.authority.Authority.init(a, .{ .base = Loop.BASE, .words = &Loop.WORDS });
    defer indexed.deinit();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = Projection.MIN_STACK_BYTES });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var source = try W.trace.Source.initMetadata(a, raw.metadataView(), public, LOG, records);
    defer source.deinit();
    var next = try I.trace.Source.initMetadata(a, &indexed, public, LOG, records);
    defer next.deinit();
    const Canary = struct {
        calls: std.atomic.Value(usize) = .init(0),
        fn rows(ctx: *const anyopaque, start: usize, end: usize, counts16: []u64, counts8: []u64) void {
            const self: *@This() = @ptrCast(@alignCast(@constCast(ctx)));
            _ = self.calls.fetchAdd(1, .monotonic);
            counts16[0] += 3 * (end - start);
            counts8[0] += 3 * (end - start);
        }
    };
    var canary = Canary{};
    const counts16 = try a.alloc(u64, 65536);
    defer a.free(counts16);
    const counts8 = try a.alloc(u64, 256);
    defer a.free(counts8);
    @memset(counts16, 0);
    @memset(counts8, 0);
    for (0..2) |after| {
        try std.testing.expectError(error.InjectedNativeProjectionSubmissionFailure, Projection.testing.failSubmission(a, LOG, .{ .context = &canary, .rows = Canary.rows }, counts16, counts8, &pool, after));
        try std.testing.expectEqual(@as(usize, 0), canary.calls.load(.monotonic));
    }
    var small_stack: engine.work_pool.WorkPool = .{};
    try small_stack.initInPlaceWithOptions(.{ .worker_count = 1, .stack_size = Projection.MIN_STACK_BYTES - 1 });
    defer small_stack.deinit();
    try std.testing.expectError(error.InvalidNativeProjectionStack, Projection.fill(a, LOG, .{ .context = &canary, .rows = Canary.rows }, counts16, counts8, &small_stack));
    const metadata = try a.dupe(W.trace.Metadata, source.metadata);
    defer a.free(metadata);
    for (0..2) |after| {
        try std.testing.expectError(error.InjectedNativeProjectionSubmissionFailure, W.trace.testing.failProjectionSubmission(&source, &pool, after));
        try std.testing.expectError(error.InjectedNativeProjectionSubmissionFailure, I.trace.testing.failProjectionSubmission(&next, &pool, after));
        try std.testing.expectEqual(@as(usize, 0), source.main.len);
        try std.testing.expectEqual(@as(usize, 0), next.main.len);
        try std.testing.expectEqual(@as(usize, 0), source.rows_projected);
        try std.testing.expectEqual(@as(usize, 0), next.base.rows_projected);
        for (source.range16_counts) |count| try std.testing.expectEqual(@as(u64, 0), count);
        for (source.range8_counts) |count| try std.testing.expectEqual(@as(u64, 0), count);
        for (next.base.range16_counts) |count| try std.testing.expectEqual(@as(u64, 0), count);
        for (next.base.range8_counts) |count| try std.testing.expectEqual(@as(u64, 0), count);
        try checkMetadata(metadata, source.metadata);
        try checkMetadata(metadata, next.base.metadata);
    }
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{ &raw, &indexed, public, records });
    try source.fillMain();
    try next.fillMain();
    try std.testing.expectEqual(source.size(), source.rows_projected);
    try std.testing.expectEqual(next.base.size(), next.base.rows_projected);
}
