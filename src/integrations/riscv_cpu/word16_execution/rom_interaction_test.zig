//! Joined parallel ROM interaction generation against the serial oracle, with
//! both the resident fixed matrix and the retired (tuple-derived) program.
const std = @import("std");
const core = @import("stwo_core");
const work = @import("stwo_prover_engine").work_pool;
const X = @import("stwo_riscv_frontend").rv64_air.word16_execution;
const Program = @import("program.zig").Program;
const ROM = @import("rom_source.zig");
const G = @import("rom_interaction.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const a = std.testing.allocator;
const Challenges = @FieldType(X.types.Challenges, "rom");
fn challenges() Challenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    var ch: Challenges = undefined;
    ch.offset = channel.drawSecureFelt();
    for (&ch.coefficients) |*c| c.* = channel.drawSecureFelt();
    return ch;
}
fn words(count: usize) ![]u32 {
    const out = try a.alloc(u32, count);
    // ADDI/XORI/ORI x(1+i%7), x(i%5), imm over a varied immediate field.
    for (out, 0..) |*w, i| {
        const funct3: u32 = switch (i % 3) {
            0 => 0,
            1 => 4,
            else => 6,
        };
        w.* = (@as(u32, @intCast(i % 2048)) << 20) | (@as(u32, @intCast(i % 5)) << 15) | (funct3 << 12) | (@as(u32, @intCast(1 + i % 7)) << 7) | 0x13;
    }
    return out;
}
fn counts(program: *const Program, used: usize) ![]u64 {
    const out = try a.alloc(u64, program.size());
    @memset(out, 0);
    for (0..@min(used, program.size())) |logical| {
        const tuple = try program.tupleAt(logical);
        if (!tuple[0].isZero()) out[X.layout.physical(logical, program.log_size)] = (logical * 7) % 5;
    }
    return out;
}
fn expectSame(expected: anytype, actual: @TypeOf(expected)) !void {
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(expected), std.mem.sliceAsBytes(actual));
}
test "joined parallel ROM interactions equal the serial oracle byte for byte for fixed and retired programs" {
    const raw = try words(12000);
    defer a.free(raw);
    var program = try Program.init(a, .{ .base = 4096, .words = raw });
    defer program.deinit();
    try std.testing.expect(program.size() >= 4 * ROM.CHUNK);
    const ch = challenges();
    for ([_]bool{ false, true }) |retire| {
        if (retire) try program.releaseFixedWitness();
        const multiplicities = try counts(&program, raw.len);
        defer a.free(multiplicities);
        var oracle = try ROM.Source.init(a, &program, multiplicities);
        defer oracle.deinit();
        const expected = try oracle.generateSerial(ch);
        for ([_]usize{ 1, 2, 3, 8 }) |workers| {
            var pool: work.WorkPool = .{};
            try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = G.MIN_STACK_BYTES, .backing_allocator = a });
            defer pool.deinit();
            var source = try ROM.Source.init(a, &program, multiplicities);
            defer source.deinit();
            const claim = try G.generate(&source, ch, &pool);
            try std.testing.expect(claim.eql(expected));
            try expectSame(oracle.dictionary, source.dictionary);
            try expectSame(oracle.interaction, source.interaction);
            try std.testing.expectEqual(workers, pool.availableWorkers());
            try std.testing.expectError(error.InvalidExecutionRomPhase, G.generate(&source, ch, &pool));
        }
        // Allocation failure publishes nothing and permits an identical retry.
        var pool: work.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = G.MIN_STACK_BYTES, .backing_allocator = a });
        defer pool.deinit();
        var source = try ROM.Source.init(a, &program, multiplicities);
        defer source.deinit();
        for (0..4) |fail_index| {
            var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = fail_index });
            source.allocator = failing.allocator();
            try std.testing.expectError(error.OutOfMemory, G.generate(&source, ch, &pool));
            source.allocator = a;
            try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
            try std.testing.expectEqual(@as(usize, 0), source.dictionary.len);
        }
        var poles = ch;
        poles.offset = Q.zero();
        for (&poles.coefficients) |*c| c.* = Q.zero();
        try std.testing.expectError(error.DivisionByZero, G.generate(&source, poles, &pool));
        try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
        try std.testing.expect((try G.generate(&source, ch, &pool)).eql(expected));
        try expectSame(oracle.interaction, source.interaction);
        if (retire) {
            // The CPU consumer's joined physical-range ROM dictionary check.
            const Check = @import("cpu_interaction.zig").testing;
            try Check.validateRom(&program, ch, source.dictionary, &pool);
            try Check.validateRom(&program, ch, source.dictionary, null);
            const last = source.dictionary.len - 1;
            for ([_]usize{ 0, last / 2, last }) |at| {
                const saved = source.dictionary[at];
                source.dictionary[at] = saved.add(Q.one());
                try std.testing.expectError(error.InvalidExecutionDictionary, Check.validateRom(&program, ch, source.dictionary, &pool));
                try std.testing.expectError(error.InvalidExecutionDictionary, Check.validateRom(&program, ch, source.dictionary, null));
                source.dictionary[at] = saved;
            }
            try std.testing.expectEqual(@as(usize, 4), pool.availableWorkers());
        }
    }
}
