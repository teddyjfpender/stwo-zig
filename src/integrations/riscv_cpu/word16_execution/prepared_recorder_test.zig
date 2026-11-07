//! M8 T10: the STWO_RV64_M8_CAPTURE_RECORDER route returns the legacy
//! Prepared field for field (and the legacy error), on a real executed tape
//! mixing ALU/BINARY/SHIFT/JALR/MUL/DIV/load/store facts, at every chunking.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const P = @import("prepared.zig");
const Dedup = @import("stable_dedup.zig");
const Program = @import("program.zig").Program;
const Coverage = @import("coverage.zig");
const X = front.rv64_air.word16_execution;
const a = std.testing.allocator;

fn r(f7: u32, rs2: u32, rs1: u32, f3: u32, rd: u32, op: u32) u32 {
    return f7 << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 | rd << 7 | op;
}
fn i(imm: i32, rs1: u32, f3: u32, rd: u32, op: u32) u32 {
    return @as(u32, @bitCast(imm)) << 20 | rs1 << 15 | f3 << 12 | rd << 7 | op;
}
fn s(imm: u32, rs2: u32, rs1: u32, f3: u32) u32 {
    return (imm >> 5) << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 | (imm & 31) << 7 | 0x23;
}
fn jal(offset: i32, rd: u32) u32 {
    const v: u32 = @bitCast(offset);
    return ((v >> 20) & 1) << 31 | ((v >> 1) & 0x3ff) << 21 | ((v >> 11) & 1) << 20 | ((v >> 12) & 0xff) << 12 | rd << 7 | 0x6f;
}
const DATA = 0x20000;
const WORDS = [_]u32{
    i(1, 5, 0, 5, 0x13), // addi x5,x5,1
    i(7, 5, 7, 6, 0x13), // andi x6,x5,7
    i(3, 6, 1, 7, 0x13), // slli x7,x6,3
    r(0, 7, 9, 0, 8, 0x33), // add x8,x9,x7
    i(0, 8, 3, 10, 0x03), // ld x10,0(x8)
    r(0, 5, 10, 4, 10, 0x33), // xor x10,x10,x5
    s(0, 10, 8, 3), // sd x10,0(x8)
    r(0, 6, 10, 5, 11, 0x33), // srl x11,x10,x6
    r(0x20, 6, 11, 0, 12, 0x33), // sub x12,x11,x6
    r(0, 6, 12, 6, 13, 0x33), // or x13,x12,x6
    0x00000717, // auipc x14,0
    i(8, 14, 0, 15, 0x67), // jalr x15,8(x14)
    r(1, 6, 5, 0, 17, 0x33), // mul x17,x5,x6
    r(1, 6, 5, 5, 18, 0x33), // divu x18,x5,x6
    r(1, 6, 5, 7, 19, 0x33), // remu x19,x5,x6
    r(0, 5, 6, 3, 16, 0x33), // sltu x16,x6,x5
    jal(-64, 0), // jal x0,-64
};
/// Ends on the dead `sltu x16` (index 15) so its result can be corrupted
/// without any later read noticing.
const STEPS = WORDS.len * 40 + 16;
const Fixture = struct {
    tape: front.rv64.compact_tape.Tape,
    boundary: X.types.Boundary,
    fn init() !@This() {
        var memory = front.rv64.memory.Memory.init(a, .{});
        defer memory.deinit();
        try memory.map(.{ .start = 4096, .size = 4 * WORDS.len, .permissions = .{ .read = true, .execute = true } });
        try memory.map(.{ .start = DATA, .size = 64, .permissions = .{ .read = true, .write = true } });
        for (WORDS, 0..) |word, k| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            try memory.initialize(4096 + 4 * k, &bytes);
        }
        var cpu = front.rv64.machine.Cpu.init(4096, 0);
        cpu.regs[9] = DATA;
        const initial = cpu.regs;
        var tape = try front.rv64.compact_tape.Tape.init(a, STEPS, 4096, 0, .ethereum_services_v2);
        errdefer tape.deinit();
        var clocks: [32]u32 = @splat(0);
        for (0..STEPS) |k| {
            const record = try cpu.step(&memory);
            try tape.append(record);
            const tick: u32 = @intCast(4 * k);
            if (record.rs1 != 0) clocks[record.rs1] = tick + 1;
            if (record.rs2 != 0) clocks[record.rs2] = tick + 2;
            if (record.writes_rd and record.rd != 0) clocks[record.rd] = tick + 3;
        }
        return .{ .tape = tape, .boundary = .{ .steps = STEPS, .initial_pc = 4096, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .register_clocks = clocks } };
    }
    fn deinit(self: *@This()) void {
        self.tape.deinit();
    }
};
fn capture(program: *const Program, f: *const Fixture, options: P.Options, route: P.Prepared.Route) !P.Prepared {
    return P.Prepared.captureRoute(a, program, f.boundary, 1, try Coverage.minimalCpuLog(STEPS), &f.tape, options, .none, route);
}
fn expectSame(legacy: *const P.Prepared, recorder: *const P.Prepared) !void {
    try std.testing.expectEqual(legacy.diagnosticDigest(), recorder.diagnosticDigest());
    try std.testing.expectEqualDeep(legacy.alu.facts, recorder.alu.facts);
    try std.testing.expectEqualSlices(u32, legacy.alu.weights, recorder.alu.weights);
    try std.testing.expectEqualDeep(legacy.binary.facts, recorder.binary.facts);
    try std.testing.expectEqualSlices(u32, legacy.binary.weights, recorder.binary.weights);
    try std.testing.expectEqualDeep(legacy.shift, recorder.shift);
    try std.testing.expectEqualSlices(u32, legacy.shift_weights, recorder.shift_weights);
    try std.testing.expectEqualDeep(legacy.division, recorder.division);
    try std.testing.expectEqualDeep(legacy.multiplication, recorder.multiplication);
    try std.testing.expectEqualDeep(legacy.raw_counts, recorder.raw_counts);
    try std.testing.expectEqual(legacy.unique_memory_words, recorder.unique_memory_words);
    try std.testing.expectEqualDeep(legacy.jalr.?.facts, recorder.jalr.?.facts);
    const lc = &legacy.cpu.?;
    const rc = &recorder.cpu.?;
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(lc.metadata), std.mem.sliceAsBytes(rc.metadata));
    try std.testing.expectEqualSlices(u64, lc.rom_counts, rc.rom_counts);
    try std.testing.expectEqualDeep(lc.memory.items, rc.memory.items);
    try std.testing.expectEqualDeep(lc.services.items, rc.services.items);
}
test "recorder route equals the legacy Prepared at every chunking and grouping option" {
    var f = try Fixture.init();
    defer f.deinit();
    var program = try Program.init(a, .{ .base = 4096, .words = &WORDS });
    defer program.deinit();
    for ([_]P.Options{ .{}, .{ .deduplicate_shift = true }, .{ .deduplicate_binary = false }, .{ .deduplicate_binary = false, .deduplicate_shift = true } }) |options| {
        for ([_]usize{ 1, 2, 3, 7, 16 }) |chunks| {
            var legacy = try capture(&program, &f, options, .{ .recorder = false, .chunks = chunks });
            defer legacy.deinit();
            var recorder = try capture(&program, &f, options, .{ .recorder = true, .chunks = chunks });
            defer recorder.deinit();
            try expectSame(&legacy, &recorder);
            // The tape exercises every grouped family, with duplicates.
            try std.testing.expect(legacy.alu.facts.len < legacy.raw_counts.alu);
            try std.testing.expect(legacy.binary.facts.len != 0 and legacy.division.len != 0 and legacy.raw_counts.multiplication != 0);
            try std.testing.expect(legacy.raw_counts.jalr != 0 and legacy.unique_memory_words == 8);
            if (options.deduplicate_shift) try std.testing.expect(legacy.shift.len < legacy.raw_counts.shift);
        }
    }
}
test "recorder route reports the legacy error for invalid advice and invalid provider facts" {
    var program = try Program.init(a, .{ .base = 4096, .words = &WORDS });
    defer program.deinit();
    {
        // Scan failure (a register read disagrees with the prefix state).
        var f = try Fixture.init();
        defer f.deinit();
        f.tape.storage[100].lhs +%= 1;
        for ([_]usize{ 1, 3 }) |chunks| {
            const legacy = capture(&program, &f, .{}, .{ .recorder = false, .chunks = chunks });
            const recorder = capture(&program, &f, .{}, .{ .recorder = true, .chunks = chunks });
            try std.testing.expectError(error.InvalidExecutionAdvice, legacy);
            try std.testing.expectError(error.InvalidExecutionAdvice, recorder);
        }
    }
    {
        // Grouping failure: the final (dead) SLTU result is wrong.
        var f = try Fixture.init();
        defer f.deinit();
        f.tape.storage[STEPS - 1].result ^= 1;
        f.boundary.final_registers[16] ^= 1;
        for ([_]usize{ 1, 3 }) |chunks| {
            try std.testing.expectError(error.InvalidAluFact, capture(&program, &f, .{}, .{ .recorder = false, .chunks = chunks }));
            try std.testing.expectError(error.InvalidAluFact, capture(&program, &f, .{}, .{ .recorder = true, .chunks = chunks }));
        }
    }
}
fn recorderCase(allocator: std.mem.Allocator, program: *const Program, f: *const Fixture) !void {
    var prepared = try P.Prepared.captureRoute(allocator, program, f.boundary, 1, try Coverage.minimalCpuLog(STEPS), &f.tape, .{ .deduplicate_shift = true }, .none, .{ .recorder = true, .chunks = 1 });
    prepared.deinit();
}
test "recorder route allocation failures leak nothing" {
    var f = try Fixture.init();
    defer f.deinit();
    var program = try Program.init(a, .{ .base = 4096, .words = &WORDS });
    defer program.deinit();
    try std.testing.checkAllAllocationFailures(a, recorderCase, .{ &program, &f });
}
test "stable grouper matches std AutoHashMap first-occurrence grouping" {
    const Fact = front.rv64_air.word16_v1.operations.AluFact;
    var prng = std.Random.DefaultPrng.init(0x7110);
    const rnd = prng.random();
    for ([_]usize{ 0, 1, 2, 17, 1000, 70000 }) |n| {
        const input = try a.alloc(Fact, n);
        defer a.free(input);
        // Small value ranges force heavy duplication and tag collisions.
        for (input) |*fact| fact.* = .{ .op = @enumFromInt(rnd.uintLessThan(u8, 3)), .a = rnd.uintLessThan(u64, 40), .b = rnd.uintLessThan(u64, 3) << 40, .c = rnd.uintLessThan(u64, 2) };
        var map: std.AutoHashMapUnmanaged(Fact, usize) = .empty;
        defer map.deinit(a);
        var facts: std.ArrayList(Fact) = .empty;
        defer facts.deinit(a);
        var weights: std.ArrayList(u32) = .empty;
        defer weights.deinit(a);
        for (input) |fact| {
            const entry = try map.getOrPut(a, fact);
            if (entry.found_existing) weights.items[entry.value_ptr.*] += 1 else {
                entry.value_ptr.* = facts.items.len;
                try facts.append(a, fact);
                try weights.append(a, 1);
            }
        }
        var g = try Dedup.Grouper(Fact).init(a, n, true);
        for (input) |fact| g.add(fact);
        const out = try g.finish();
        defer a.free(out.facts);
        defer a.free(out.weights);
        try std.testing.expectEqualDeep(facts.items, out.facts);
        try std.testing.expectEqualSlices(u32, weights.items, out.weights);
        var words = try Dedup.DistinctWords.init(a, n);
        defer words.deinit();
        var set: std.AutoHashMapUnmanaged(u64, void) = .empty;
        defer set.deinit(a);
        for (input) |fact| {
            words.add(fact.a * 8);
            try set.put(a, fact.a * 8, {});
        }
        try std.testing.expectEqual(@as(u32, @intCast(set.count())), words.distinct);
    }
}
