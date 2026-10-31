const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.word16_execution;
const S = @import("../word16_execution/cpu_source.zig").Source;
const I = @import("../word16_execution/cpu_interaction.zig");
const R = @import("../word16_execution/rom_source.zig").Source;
const Program = @import("../word16_execution/program.zig").Program;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const a = std.testing.allocator;
const Fixture = struct {
    program: Program,
    tape: front.rv64.compact_tape.Tape,
    public: X.types.Boundary,
    fn init() !Fixture {
        var program = try Program.init(a, .{ .base = 4096, .words = &.{ 0x00500093, 0x001080b3, 0x00010067 } });
        errdefer program.deinit();
        var tape = try front.rv64.compact_tape.Tape.init(a, 3, 4096, 9000, .ethereum_services_v2);
        errdefer tape.deinit();
        tape.len = 3;
        tape.storage[0] = .{ .next_pc = 4100, .lhs = 0, .rhs = 0, .previous_rd = 0, .result = 5, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        tape.storage[1] = .{ .next_pc = 4104, .lhs = 5, .rhs = 5, .previous_rd = 5, .result = 10, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        tape.storage[2] = .{ .next_pc = 4108, .lhs = 4108, .rhs = 0, .previous_rd = 0, .result = 4108, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 1 };
        var public: X.types.Boundary = .{ .steps = 3, .initial_pc = 4096, .final_pc = 4108, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
        public.initial_registers[2] = 4108;
        public.final_registers = public.initial_registers;
        public.final_registers[1] = 10;
        public.register_clocks[1] = 7;
        public.register_clocks[2] = 9;
        return .{ .program = program, .tape = tape, .public = public };
    }
    fn deinit(self: *Fixture) void {
        self.tape.deinit();
        self.program.deinit();
    }
};
fn challenges() X.types.Challenges {
    var result: X.types.Challenges = undefined;
    inline for (std.meta.fields(X.types.Challenges), 0..) |field, family| {
        var ch: field.type = undefined;
        ch.offset = Q.fromM31Array(.{ M.fromCanonical(@intCast(100003 + family)), M.fromCanonical(7), M.fromCanonical(11), M.fromCanonical(19) });
        if (@hasField(field.type, "coefficients")) {
            for (&ch.coefficients, 0..) |*coefficient, index| coefficient.* = Q.fromM31Array(.{ M.fromCanonical(@intCast(31 + index)), M.fromCanonical(@intCast(family + 1)), M.fromCanonical(3), M.fromCanonical(@intCast(index + 2)) });
        } else ch.coefficient = Q.zero();
        @field(result, field.name) = ch;
    }
    return result;
}
fn rangeDictionary(allocator: std.mem.Allocator, count: usize, ch: anytype) ![]Q {
    const values = try allocator.alloc(Q, count);
    errdefer allocator.free(values);
    for (values, 0..) |*value, index| {
        const d = ch.offset.sub(ch.coefficient.mulM31(M.fromCanonical(@intCast(index))));
        if (d.isZero()) return error.DivisionByZero;
        value.* = try d.inv();
    }
    return values;
}
fn gather(data: []const M, n: usize, p: usize, comptime count: usize) [count]Q {
    var result: [count]Q = undefined;
    for (&result, 0..) |*value, c| value.* = Q.fromBase(data[c * n + p]);
    return result;
}
fn checkRows(main: []const M, inter: []const M, log: u32, public: X.types.Boundary, claim: Q, ch: X.types.Challenges) !void {
    const n = @as(usize, 1) << @intCast(log);
    for (0..n) |logical| {
        const p = X.layout.physical(logical, log);
        const prev = X.layout.physical((logical + n - 1) % n, log);
        const row = gather(main, n, p, 53);
        const prior = gather(main, n, prev, 53);
        const current = gather(inter, n, p, 40);
        const previous = gather(inter, n, prev, 40);
        const fixed = [_]Q{ X.types.literal(Q, @intCast(logical)), X.types.literal(Q, @intFromBool(logical == 0)), X.types.literal(Q, @intFromBool(logical == n - 1)) };
        var residuals: [55]Q = undefined;
        var sink = front.rv64_air.evaluation.Sink{ .values = &residuals };
        X.equations.emitFor(Q, &fixed, &row, &prior, &current, &previous, try X.types.inputs(public, 7, log), claim, ch, &sink);
        try std.testing.expectEqual(@as(usize, 55), sink.count);
        for (residuals) |r| try std.testing.expect(r.isZero());
    }
}
fn initCase(allocator: std.mem.Allocator, fixture: *const Fixture) !void {
    var source = try S.init(allocator, &fixture.program, fixture.public, 7, 5, &fixture.tape);
    defer source.deinit();
}
test "full execution source preserves architectural aliases normalized JALR and sealed row counts" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var source = try S.init(a, &fixture.program, fixture.public, 7, 5, &fixture.tape);
    defer source.deinit();
    try std.testing.expectEqual(@as(usize, 3), source.functions.items.len);
    try std.testing.expectEqual(@as(u8, 16), source.functions.items[2].operation);
    try std.testing.expectEqual(~@as(u64, 1), source.functions.items[2].b);
    try std.testing.expectEqual(@as(usize, 0), source.memory.items.len);
    try std.testing.expectEqual(@as(usize, 0), source.services.items.len);
    const alias = try source.row(1);
    try std.testing.expectEqual(@as(u32, 3), alias[X.layout.main.previous_clock].v);
    try std.testing.expectEqual(@as(u32, 5), alias[X.layout.main.previous_clock + 1].v);
    try std.testing.expectEqual(@as(u32, 6), alias[X.layout.main.previous_clock + 2].v);
    var total16: u64 = 0;
    var total8: u64 = 0;
    var totalRom: u64 = 0;
    for (source.counts16) |count| total16 += count;
    for (source.counts8) |count| total8 += count;
    for (source.rom_counts) |count| totalRom += count;
    try std.testing.expectEqual(@as(u64, 96), total16);
    try std.testing.expectEqual(@as(u64, 96), total8);
    try std.testing.expectEqual(@as(u64, 3), totalRom);
    for (0..32) |logical| {
        const row = try source.row(logical);
        const p = X.layout.physical(logical, 5);
        for (row, 0..) |value, column| try std.testing.expectEqual(value.v, source.main[column * 32 + p].v);
    }
    const saved = fixture.tape.storage[1].lhs;
    fixture.tape.storage[1].lhs = 6;
    try std.testing.expectError(error.InvalidExecutionAdvice, S.init(a, &fixture.program, fixture.public, 7, 5, &fixture.tape));
    fixture.tape.storage[1].lhs = saved;
    var bad = fixture.public;
    bad.register_clocks[1] -= 1;
    try std.testing.expectError(error.InvalidExecutionBoundary, S.init(a, &fixture.program, bad, 7, 5, &fixture.tape));
    try std.testing.checkAllAllocationFailures(a, initCase, .{&fixture});
}
test "full CPU native interactions exactly satisfy authority after source main release" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var source = try S.init(a, &fixture.program, fixture.public, 7, 5, &fixture.tape);
    defer source.deinit();
    const ch = challenges();
    var rom = try R.init(a, &fixture.program, source.rom_counts);
    defer rom.deinit();
    _ = try rom.generate(ch.rom);
    const r16 = try rangeDictionary(a, 65536, ch.range16);
    defer a.free(r16);
    const r8 = try rangeDictionary(a, 256, ch.range8);
    defer a.free(r8);
    const saved = try a.dupe(M, source.main);
    defer a.free(saved);
    source.releaseMain();
    const claim = try I.generate(&source, ch, .{ .rom = rom.dictionary, .range16 = r16, .range8 = r8 }, null);
    try checkRows(saved, source.interaction, 5, fixture.public, claim, ch);
    try std.testing.expectEqual(@as(usize, 0), source.metadata.len);
    try std.testing.expectError(error.InvalidExecutionInteractionPhase, source.generate(ch, .{ .rom = rom.dictionary, .range16 = r16, .range8 = r8 }));
}
fn generateCase(allocator: std.mem.Allocator, fixture: *const Fixture, ch: X.types.Challenges, dict: I.Dictionaries) !void {
    var source = try S.init(allocator, &fixture.program, fixture.public, 7, 5, &fixture.tape);
    defer source.deinit();
    _ = try I.generate(&source, ch, dict, null);
}
test "full CPU strict padding ROM pole invalid dictionary and OOM remain retryable" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var source = try S.init(a, &fixture.program, fixture.public, 7, 5, &fixture.tape);
    defer source.deinit();
    var ch = challenges();
    ch.rom.offset = Q.fromBase(M.fromCanonical(4108));
    @memset(&ch.rom.coefficients, Q.zero());
    ch.rom.coefficients[X.layout.rom.pc] = Q.one();
    var rom = try R.init(a, &fixture.program, source.rom_counts);
    defer rom.deinit();
    _ = try rom.generate(ch.rom);
    const r16 = try rangeDictionary(a, 65536, ch.range16);
    defer a.free(r16);
    const r8 = try rangeDictionary(a, 256, ch.range8);
    defer a.free(r8);
    const dict = I.Dictionaries{ .rom = rom.dictionary, .range16 = r16, .range8 = r8 };
    try std.testing.expectError(error.DivisionByZero, I.generate(&source, ch, dict, null));
    try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
    try std.testing.expectEqual(@as(usize, 3), source.metadata.len);
    const good = challenges();
    var good_rom = try R.init(a, &fixture.program, source.rom_counts);
    defer good_rom.deinit();
    good_rom.releaseMain();
    _ = try good_rom.generate(good.rom);
    const good_dict = I.Dictionaries{ .rom = good_rom.dictionary, .range16 = r16, .range8 = r8 };
    r16[17] = r16[17].add(Q.one());
    try std.testing.expectError(error.InvalidExecutionDictionary, I.generate(&source, good, good_dict, null));
    r16[17] = r16[17].sub(Q.one());
    try std.testing.checkAllAllocationFailures(a, generateCase, .{ &fixture, good, good_dict });
    _ = try I.generate(&source, good, good_dict, null);
}
test "full CPU joined native waves reproduce every serial interaction column and claim" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const log = 13;
    var serial = try S.init(a, &fixture.program, fixture.public, 7, log, &fixture.tape);
    defer serial.deinit();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = 262144 });
    defer pool.deinit();
    var parallel = blk: {
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        break :blk try S.init(a, &fixture.program, fixture.public, 7, log, &fixture.tape);
    };
    defer parallel.deinit();
    const ch = challenges();
    var rom = try R.init(a, &fixture.program, serial.rom_counts);
    defer rom.deinit();
    _ = try rom.generate(ch.rom);
    const r16 = try rangeDictionary(a, 65536, ch.range16);
    defer a.free(r16);
    const r8 = try rangeDictionary(a, 256, ch.range8);
    defer a.free(r8);
    const dict = I.Dictionaries{ .rom = rom.dictionary, .range16 = r16, .range8 = r8 };
    const expected = try I.generate(&serial, ch, dict, null);
    try std.testing.expectEqualSlices(M, serial.main, parallel.main);
    try std.testing.expectEqualSlices(u64, serial.counts16, parallel.counts16);
    try std.testing.expectEqualSlices(u64, serial.counts8, parallel.counts8);
    parallel.releaseMain();
    const actual = try I.generate(&parallel, ch, dict, &pool);
    try std.testing.expect(actual.eql(expected));
    try std.testing.expectEqualSlices(M, serial.interaction, parallel.interaction);
    try checkRows(serial.main, parallel.interaction, log, fixture.public, actual, ch);
}
test "full source keeps store input distinct from immediate and service pointer distinct from tag" {
    const address: u64 = 0x8000000000000080;
    const word: u64 = 0xfedcba9876543210;
    var program = try Program.init(a, .{ .base = 4096, .words = &.{ 0x00113023, 0x00013183 } });
    defer program.deinit();
    var tape = try front.rv64.compact_tape.Tape.init(a, 2, 4096, 1234, .ethereum_services_v2);
    defer tape.deinit();
    tape.len = 2;
    try tape.memory_before.appendSlice(a, &.{ 0, word });
    tape.storage[0] = .{ .next_pc = 4100, .lhs = address, .rhs = word, .previous_rd = 0, .result = 0, .memory_index = 0, .flags = 0 };
    tape.storage[1] = .{ .next_pc = 4104, .lhs = address, .rhs = 0, .previous_rd = 0, .result = word, .memory_index = 1, .flags = 0 };
    var public: X.types.Boundary = .{ .steps = 2, .initial_pc = 4096, .final_pc = 4104, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
    public.initial_registers[1] = word;
    public.initial_registers[2] = address;
    public.final_registers = public.initial_registers;
    public.final_registers[3] = word;
    public.register_clocks[1] = 2;
    public.register_clocks[2] = 5;
    public.register_clocks[3] = 7;
    var source = try S.init(a, &program, public, 7, 5, &tape);
    defer source.deinit();
    try std.testing.expectEqual(@as(usize, 0), source.functions.items.len);
    try std.testing.expectEqual(@as(usize, 2), source.memory.items.len);
    const store = source.memory.items[0];
    const load = source.memory.items[1];
    try std.testing.expectEqual(word, store.b);
    try std.testing.expectEqual(@as(u64, 0), store.immediate);
    try std.testing.expectEqual(address, store.effect.address.toInt());
    try std.testing.expectEqual(word, store.effect.after_word.toInt());
    try std.testing.expectEqual(@as(u24, 4), store.tick);
    try std.testing.expectEqual(word, load.c);
    try std.testing.expectEqual(@as(u64, 0), load.b);
    try std.testing.expectEqual(@as(u24, 8), load.tick);
    var services = try Program.init(a, .{ .base = 4096, .words = &.{0x00000073} });
    defer services.deinit();
    tape.len = 1;
    tape.storage[0] = .{ .next_pc = 4100, .lhs = address, .rhs = 0x123456789abcdef0, .previous_rd = 0, .result = 0, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
    public = .{ .steps = 1, .initial_pc = 4096, .final_pc = 4100, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
    public.initial_registers[10] = address;
    public.initial_registers[17] = tape.storage[0].rhs;
    public.final_registers = public.initial_registers;
    public.register_clocks[10] = 1;
    public.register_clocks[17] = 2;
    var service = try S.init(a, &services, public, 7, 5, &tape);
    defer service.deinit();
    try std.testing.expectEqual(@as(usize, 1), service.services.items.len);
    try std.testing.expectEqual(address, service.services.items[0].pointer);
    try std.testing.expectEqual(tape.storage[0].rhs, service.services.items[0].tag);
    try std.testing.expectEqual(@as(u24, 4), service.services.items[0].tick);
}
