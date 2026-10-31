const std = @import("std");
const front = @import("stwo_riscv_frontend");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const B = front.rv64_air.word16_v1;
const X = B.shift_word_packed_experiment;
const S = X.source;
const U = B.alu_experiment.range_source;
const P = X.lookup;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn inputs(n: usize) ![]S.Fact {
    const out = try a.alloc(S.Fact, n);
    for (out, 0..) |*f, i| {
        const x = @as(u64, @intCast(i)) *% 0x9e3779b97f4a7c15;
        const y = ~x ^ (x << 13);
        const op: B.operations.Shift = @enumFromInt(i % 6);
        f.* = .{ .op = op, .a = x, .b = y, .c = X.equations.nativeResult(op, x, y) };
    }
    return out;
}
fn challenges() P.Challenges {
    const q = front.rv64_air.evaluation.q;
    return .{ .shift = .{ .offset = Q.fromU32Unchecked(5, 7, 11, 13), .coefficients = .{ q(3), q(7), q(11), q(13), q(17), q(19) } }, .range16 = .{ .offset = Q.fromU32Unchecked(23, 29, 31, 37), .coefficient = q(41) }, .function = .{ .offset = Q.fromU32Unchecked(43, 47, 53, 59), .coefficients = .{ q(2), q(3), q(5), q(7), q(11), q(13), q(17), q(19), q(23), q(29), q(31), q(37), q(41) } } };
}
const Dictionaries = struct {
    table_setup: X.table.Setup,
    table: X.table.Request,
    range_setup: U.Setup,
    range: U.Source,
    fn init(source: *const S.Source) !Dictionaries {
        var ts = try X.table.Setup.init(a);
        errdefer ts.deinit();
        var tr = try X.table.Request.init(a, &ts, source.shift_counts);
        errdefer tr.deinit();
        var rs = try U.Setup.init(a);
        errdefer rs.deinit();
        var rr = try U.Source.init(a, &rs, source.range16_counts);
        errdefer rr.deinit();
        _ = try tr.generateInteraction(challenges().shift);
        _ = try rr.generate(challenges().range16);
        return .{ .table_setup = ts, .table = tr, .range_setup = rs, .range = rr };
    }
    fn deinit(self: *Dictionaries) void {
        self.table.deinit();
        self.table_setup.deinit();
        self.range.deinit();
        self.range_setup.deinit();
    }
};
const Group = @import("shift_dedup.zig");
const Prepared = @import("prepared.zig").Prepared;
const Program = @import("program.zig").Program;
const Setup = @import("setup.zig").Setup;
const Sources = @import("sources.zig").Source;
const Execution = @import("execution.zig");
const Q = core.fields.qm31.QM31;
test "Weighted SHIFT native1 3 16workers preserves all physical rows counts and interactions after MAIN retirement" {
    const facts = try inputs(10001);
    defer a.free(facts);
    const weights = try a.alloc(u32, facts.len);
    defer a.free(weights);
    for (weights, 0..) |*w, i| w.* = if (i % 17 == 16) 70001 else @intCast(i % 17);
    var reference = try S.Source.testing.initWeightedSerial(a, facts, weights, 16);
    defer reference.deinit();
    const metadata = try a.dupe(S.Metadata, reference.metadata);
    defer a.free(metadata);
    var dictionaries = try Dictionaries.init(&reference);
    defer dictionaries.deinit();
    const expected = try reference.generate(challenges(), dictionaries.table.dictionary, dictionaries.range.dictionary);
    for ([_]usize{ 1, 3, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1024 * 1024, .backing_allocator = a });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var actual = try S.Source.initWeighted(a, facts, weights, 16);
        defer actual.deinit();
        try std.testing.expectEqualSlices(M, reference.main, actual.main);
        try std.testing.expectEqualDeep(metadata, actual.metadata);
        try std.testing.expectEqualSlices(u64, reference.shift_counts, actual.shift_counts);
        try std.testing.expectEqualSlices(u64, reference.range16_counts, actual.range16_counts);
        actual.releaseMain();
        try std.testing.expectEqualDeep(expected, try actual.generate(challenges(), dictionaries.table.dictionary, dictionaries.range.dictionary));
        try std.testing.expectEqualSlices(M, reference.interaction, actual.interaction);
    }
}
fn allocate(allocator: std.mem.Allocator, fs: []const S.Fact, weights: []const u32, buf: []M) !void {
    var source = S.Source.initWeightedWithMainBuffers(allocator, fs, weights, 5, .{ .main = buf }) catch |err| {
        for (buf) |v| try std.testing.expectEqual(@as(u32, 97), v.v);
        return err;
    };
    defer source.deinit();
    @memset(buf, M.fromCanonical(97));
}
test "Weighted SHIFT canonical mass alias OOM and zero-weight strict poles reject before publish and retry" {
    const facts = try inputs(2);
    defer a.free(facts);
    const buf = try a.alloc(M, P.MAIN * 32);
    defer a.free(buf);
    @memset(buf, M.fromCanonical(97));
    try std.testing.expectError(error.InvalidShiftWeights, S.Source.initWeightedWithMainBuffers(a, facts, &.{1}, 5, .{ .main = buf }));
    try std.testing.expectError(error.InvalidShiftWeights, S.Source.initWeightedWithMainBuffers(a, facts, &.{ core.fields.m31.Modulus, 1 }, 5, .{ .main = buf }));
    try std.testing.expectError(error.ShiftMultiplicityMassExceeded, S.Source.initWeightedWithMainBuffers(a, facts, &.{ core.fields.m31.Modulus - 1, 1 }, 5, .{ .main = buf }));
    const alias: []u32 = @as([*]u32, @ptrCast(buf.ptr))[0..2];
    alias[0] = 1;
    alias[1] = 1;
    try std.testing.expectError(error.OverlappingShiftInputs, S.Source.initWeightedWithMainBuffers(a, facts, alias, 5, .{ .main = buf }));
    @memset(buf, M.fromCanonical(97));
    try std.testing.checkAllAllocationFailures(a, allocate, .{ facts, &[_]u32{ 0, 70001 }, buf });
    var source = try S.Source.initWeighted(a, facts, &.{ 0, 70001 }, 5);
    defer source.deinit();
    try std.testing.expectEqual(@as(u32, 70001), source.metadata[1].multiplicity());
    var dictionaries = try Dictionaries.init(&source);
    defer dictionaries.deinit();
    source.releaseMain();
    var pole = challenges();
    pole.function = .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) };
    try std.testing.expectError(error.DivisionByZero, source.generate(pole, dictionaries.table.dictionary, dictionaries.range.dictionary));
    try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
    // A pole only on inactive padding still fails, even with zero multiplicity.
    pole.function.coefficients[0] = Q.one();
    try std.testing.expectError(error.DivisionByZero, source.generate(pole, dictionaries.table.dictionary, dictionaries.range.dictionary));
    source.metadata[31].multiplicity_words = .{ 1, 0 };
    try std.testing.expectError(error.InvalidShiftMetadata, source.generate(challenges(), dictionaries.table.dictionary, dictionaries.range.dictionary));
    source.metadata[31].multiplicity_words = .{ 0, 0 };
    _ = try source.generate(challenges(), dictionaries.table.dictionary, dictionaries.range.dictionary);
}
const WORDS = [_]u32{ 0x002091b3, 0xfe000ee3 }; // SLL x3,x1,x2; BEQ x0,x0,-4
const Fixture = struct {
    tape: front.rv64.compact_tape.Tape,
    boundary: front.rv64_air.word16_execution.types.Boundary,
    fn init() !@This() {
        var memory = front.rv64.memory.Memory.init(a, .{});
        defer memory.deinit();
        try memory.map(.{ .start = 4096, .size = 8, .permissions = .{ .read = true, .execute = true } });
        for (WORDS, 0..) |word, i| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            try memory.initialize(4096 + 4 * i, &bytes);
        }
        var cpu = front.rv64.machine.Cpu.init(4096, 0);
        cpu.regs[1] = 0x80000001fedcba98;
        cpu.regs[2] = 13;
        const initial = cpu.regs;
        var tape = try front.rv64.compact_tape.Tape.init(a, 130, 4096, 0, .ethereum_services_v2);
        errdefer tape.deinit();
        var clocks: [32]u32 = @splat(0);
        for (0..130) |i| {
            const record = try cpu.step(&memory);
            try tape.append(record);
            const tick: u32 = @intCast(4 * i);
            if (record.rs1 != 0) clocks[record.rs1] = tick + 1;
            if (record.rs2 != 0) clocks[record.rs2] = tick + 2;
            if (record.writes_rd and record.rd != 0) clocks[record.rd] = tick + 3;
        }
        return .{ .tape = tape, .boundary = .{ .steps = 130, .initial_pc = 4096, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .register_clocks = clocks } };
    }
    fn deinit(self: *@This()) void {
        self.tape.deinit();
    }
};
var image_context: u8 = 0;
const Empty = struct {
    fn word(_: *const anyopaque, _: u64) !u64 {
        return 0;
    }
    fn rights(_: *const anyopaque, _: u64) !u2 {
        return 0;
    }
};
fn admission(f: *const Fixture) Execution.Admission {
    return .{ .image = .{ .context = &image_context, .initial_word = Empty.word, .rights_at = Empty.rights }, .image_identity = @splat(9), .initial_pc = f.boundary.initial_pc, .initial_registers = f.boundary.initial_registers };
}
fn prove(f: *const Fixture, grouped: bool, bad_weight: bool) !Execution.Encoded {
    var program = try Program.init(a, .{ .base = 4096, .words = &WORDS });
    defer program.deinit();
    var prepared = try Prepared.init(a, &program, f.boundary, 1, 8, &f.tape, .{ .deduplicate_shift = grouped });
    defer prepared.deinit();
    try std.testing.expectEqual(@as(u32, 65), prepared.raw_counts.shift);
    try std.testing.expectEqual(@as(usize, if (grouped) 1 else 65), prepared.shift.len);
    if (grouped) {
        try std.testing.expectEqualSlices(u32, &.{65}, prepared.shift_weights);
        if (bad_weight) prepared.shift_weights[0] -= 1;
    }
    const geometry = try prepared.geometry();
    try std.testing.expectEqual(@as(u32, if (grouped) 5 else 7), geometry.shift_log);
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, geometry);
    defer setup.deinit();
    const source = try Sources.fromPrepared(a, &setup.materials, admission(f).image, &prepared);
    return Execution.provePrepared(a, &setup, admission(f), source, null);
}
test "Weighted SHIFT actual native loop closes full table and CPU claims at smaller geometry fresh receiver and rejects wrong weight" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var unit = try prove(&fixture, false, false);
    defer unit.deinit(a);
    var grouped = try prove(&fixture, true, false);
    defer grouped.deinit(a);
    try std.testing.expectEqualDeep(unit.request, grouped.request);
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, .{ .cpu_log = 8, .shift_log = 5 });
    defer setup.deinit();
    try Execution.verify(a, &setup, admission(&fixture), grouped);
    if (prove(&fixture, true, true)) |value| {
        var invalid = value;
        invalid.deinit(a);
        return error.ExpectedWrongMultiplicityRejection;
    } else |_| {}
}
fn collectFailure(allocator: std.mem.Allocator, fs: []const S.Fact) !void {
    var value = try Group.collect(allocator, fs, true);
    defer value.deinit();
}
test "SHIFT grouping is stable and includes full operation operand and result bits with allocation custody" {
    const fs = try inputs(7);
    defer a.free(fs);
    fs[6] = fs[0];
    var grouped = try Group.collect(a, fs, true);
    defer grouped.deinit();
    try std.testing.expectEqual(@as(usize, 6), grouped.facts.len);
    try std.testing.expectEqualSlices(u32, &.{ 2, 1, 1, 1, 1, 1 }, grouped.weights);
    try std.testing.expectEqualDeep(fs[0], grouped.facts[0]);
    try std.testing.checkAllAllocationFailures(a, collectFailure, .{fs});
}
