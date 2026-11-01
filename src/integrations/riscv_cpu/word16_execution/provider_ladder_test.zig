const std = @import("std");
const front = @import("stwo_riscv_frontend");
const core = @import("stwo_core");
const G = @import("geometry.zig");
const P = @import("protocol.zig");
const Setup = @import("setup.zig").Setup;
const Program = @import("program.zig").Program;
const Prepared = @import("prepared.zig").Prepared;
const S = @import("sources.zig").Source;
const E = @import("execution.zig");
const Tail = @import("provider_tails.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
// ADDI x1,x1,1; XOR x2,x1,x3; SLL x4,x1,x5; BLTU x1,x6,-12.
const WORDS = [_]u32{ 0x00108093, 0x0030c133, 0x00509233, 0xfe60eae3 };
var image_context: u8 = 0;
const Fixture = struct {
    tape: front.rv64.compact_tape.Tape,
    boundary: front.rv64_air.word16_execution.types.Boundary,
    fn init() !@This() {
        return initWithRegisters(null, 40);
    }
    fn initWithRegisters(initial_regs: ?[32]u64, limit: u64) !@This() {
        return initSteps(initial_regs, limit, 160);
    }
    fn initSteps(initial_regs: ?[32]u64, limit: u64, steps: u32) !@This() {
        var memory = front.rv64.memory.Memory.init(a, .{});
        defer memory.deinit();
        try memory.map(.{ .start = 4096, .size = 16, .permissions = .{ .read = true, .execute = true } });
        var bytes: [16]u8 = undefined;
        for (WORDS, 0..) |instruction, i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], instruction, .little);
        try memory.initialize(4096, &bytes);
        var cpu = front.rv64.machine.Cpu.init(4096, 0);
        cpu.regs[3] = 0x80000000fedcba98;
        cpu.regs[5] = 3;
        cpu.regs[6] = limit;
        if (initial_regs) |values| cpu.regs = values;
        const initial = cpu.regs;
        var tape = try front.rv64.compact_tape.Tape.init(a, steps, 4096, 0, .ethereum_services_v2);
        errdefer tape.deinit();
        var clocks: [32]u32 = @splat(0);
        for (0..steps) |i| {
            const r = try cpu.step(&memory);
            try tape.append(r);
            const tick: u32 = @intCast(4 * i);
            if (r.rs1 != 0) clocks[r.rs1] = tick + 1;
            if (r.rs2 != 0) clocks[r.rs2] = tick + 2;
            if (r.writes_rd and r.rd != 0) clocks[r.rd] = tick + 3;
        }
        try std.testing.expectEqual(if (cpu.regs[1] < cpu.regs[6]) @as(u64, 4096) else @as(u64, 4112), cpu.pc);
        return .{ .tape = tape, .boundary = .{ .steps = steps, .initial_pc = 4096, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .register_clocks = clocks } };
    }
    fn deinit(self: *@This()) void {
        self.tape.deinit();
    }
};
fn word(_: *const anyopaque, _: u64) !u64 {
    return 0;
}
fn rights(_: *const anyopaque, _: u64) !u2 {
    return 0;
}
fn admission(f: *const Fixture) E.Admission {
    return .{ .image = .{ .context = &image_context, .initial_word = word, .rights_at = rights }, .image_identity = @splat(8), .initial_pc = f.boundary.initial_pc, .initial_registers = f.boundary.initial_registers };
}
const SINGLE = G.Geometry{ .cpu_log = 8, .alu_log = 7, .binary_log = 6, .shift_log = 6 };
const LADDER = G.Geometry{ .cpu_log = 8, .alu_log = 5, .alu_tail_log = 6, .binary_log = 5, .binary_tail_log = 5, .shift_log = 5, .shift_tail_log = 5 };
fn prove(f: *const Fixture, g: G.Geometry) !E.Encoded {
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, g);
    defer setup.deinit();
    return E.prove(a, &setup, admission(f), f.boundary, &f.tape, null);
}
fn reject(setup: *const Setup, f: *const Fixture, encoded: E.Encoded) !void {
    if (E.verify(a, setup, admission(f), encoded)) |_| return error.ExpectedProviderLadderRejection else |_| {}
}
test "pure provider partition permits full head and rejects missing or overflowing tail before allocations" {
    try std.testing.expectEqualDeep(G.FactCounts{ .head = 32, .tail = 0 }, try G.factCounts(32, 5, null));
    try std.testing.expectEqualDeep(G.FactCounts{ .head = 32, .tail = 32 }, try G.factCounts(64, 5, 5));
    try std.testing.expectError(error.InvalidProviderTailCapacity, G.factCounts(32, 5, 5));
    try std.testing.expectError(error.InvalidProviderTailCapacity, G.factCounts(33, 5, null));
    try std.testing.expectError(error.InvalidProviderTailCapacity, G.factCounts(65, 5, 5));
    try std.testing.expectError(error.InvalidExecutionGeometry, G.factCounts(1, 32, null));
    try std.testing.expectError(error.ProviderMultiplicityMassExceeded, Tail.weights(2, &.{ core.fields.m31.Modulus - 1, 1 }));
    try std.testing.expectError(error.InvalidProviderWeights, Tail.weights(2, &.{1}));
    var program = try Program.init(a, .{ .base = 4096, .words = &WORDS });
    defer program.deinit();
    const absent = G.shapes(&program, SINGLE);
    const present = G.shapes(&program, LADDER);
    try std.testing.expectEqual(@as(usize, 45), P.CLAIM_COUNT);
    inline for (.{ .alu_tail, .binary_tail, .shift_tail }, 18..) |role, i| {
        try std.testing.expectEqual(i, @as(usize, @intFromEnum(@as(G.Role, role))));
        try std.testing.expect(!absent[i].present());
        try std.testing.expect(present[i].present());
    }
    // Combined padding masses are admitted before fixed/witness allocations.
    const expected16: u64 = 3 * 256 + 12 * 96 + 5 * 64 + 12 * 32 + front.rv64_air.memory.load_store_v2.layout.BOUND_U16.len * 64;
    try std.testing.expectEqual(expected16, try LADDER.range16Mass());
}
test "one PCS all three pure function tails closes actual native loop and independent receiver" {
    var f = try Fixture.init();
    defer f.deinit();
    var encoded = try prove(&f, LADDER);
    defer encoded.deinit(a);
    var fresh = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, LADDER);
    defer fresh.deinit();
    try E.verify(a, &fresh, admission(&f), encoded);
    try encoded.claims.validate();
    // Different fact counts and endpoints reuse the SAME immutable fixed key.
    var later_fixture = try Fixture.initSteps(null, 42, 168);
    defer later_fixture.deinit();
    var later = try E.prove(a, &fresh, admission(&later_fixture), later_fixture.boundary, &later_fixture.tape, null);
    defer later.deinit(a);
    try E.verify(a, &fresh, admission(&later_fixture), later);
    var single = try prove(&f, SINGLE);
    defer single.deinit(a);
    try std.testing.expectEqualDeep(single.request.cpu, encoded.request.cpu);
    try std.testing.expectEqualDeep(single.request.memory, encoded.request.memory);
    try std.testing.expect(!std.mem.eql(u8, single.bytes, encoded.bytes));
}
test "tail physical histograms include padding and native fact weights preserve whole family mass" {
    var f = try Fixture.init();
    defer f.deinit();
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, LADDER);
    defer setup.deinit();
    var source = try S.init(a, &setup.materials, admission(&f).image, f.boundary, 1, &f.tape);
    defer source.deinit();
    try std.testing.expectEqual(@as(usize, 32), source.alu.fact_count);
    try std.testing.expectEqual(@as(usize, 48), source.tails.alu.?.fact_count);
    try std.testing.expectEqual(@as(usize, 8), source.tails.binary.?.fact_count);
    try std.testing.expectEqual(@as(usize, 8), source.tails.shift.?.fact_count);
    try std.testing.expectEqual(@as(u64, 80), @as(u64, source.alu.function_mass) + source.tails.alu.?.function_mass);
    try std.testing.expectEqual(@as(u64, 40), @as(u64, source.binary.function_mass) + source.tails.binary.?.function_mass);
    var range_mass: u64 = 0;
    for (source.counts16) |count| range_mass += count;
    try std.testing.expectEqual(try LADDER.range16Mass(), range_mass);
    var and_mass: u64 = 0;
    for (source.and_table.main) |count| and_mass += count.v;
    try std.testing.expectEqual(@as(u64, 8 * 64), and_mass);
    var shift_mass: u64 = 0;
    for (source.shift_table.main) |count| shift_mass += count.v;
    try std.testing.expectEqual(@as(u64, 5 * 64), shift_mass);
}
test "balanced tail claims missing roster and omitted ghosts rejected by physical verifier" {
    var f = try Fixture.init();
    defer f.deinit();
    var encoded = try prove(&f, LADDER);
    defer encoded.deinit(a);
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, LADDER);
    defer setup.deinit();
    var bad = encoded;
    bad.claims.alu_tail.function = bad.claims.alu_tail.function.add(Q.one());
    bad.claims.alu.function = bad.claims.alu.function.sub(Q.one());
    try bad.claims.validate();
    try reject(&setup, &f, bad);
    bad = encoded;
    bad.claims.binary_tail.and_ = bad.claims.binary_tail.and_.add(Q.one());
    bad.claims.shift_tail.shift = bad.claims.shift_tail.shift.sub(Q.one());
    try bad.claims.validate();
    try reject(&setup, &f, bad);
    var no_tail = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, SINGLE);
    defer no_tail.deinit();
    try reject(&no_tail, &f, encoded);
    var ghost = std.mem.zeroes(P.Claims);
    inline for (.{ "alu_tail", "binary_tail", "shift_tail" }, .{ error.NonzeroOmittedAluTailClaim, error.NonzeroOmittedBinaryTailClaim, error.NonzeroOmittedShiftTailClaim }) |name, expected_error| {
        @field(ghost, name).function = Q.one();
        ghost.cpu = Q.one().neg();
        try ghost.validate();
        try std.testing.expectError(expected_error, P.validateProviderTailClaims(SINGLE, ghost));
        @field(ghost, name).function = Q.zero();
    }
}
test "owned MAIN INTER handoff of every function tail equals borrowed proof and omitted extra owner stays owned" {
    var f = try Fixture.init();
    defer f.deinit();
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, LADDER);
    defer setup.deinit();
    var owned = try E.prove(a, &setup, admission(&f), f.boundary, &f.tape, null);
    defer owned.deinit(a);
    const source = try S.init(a, &setup.materials, admission(&f).image, f.boundary, 1, &f.tape);
    var borrowed = try E.provePreparedBorrowedMain(a, &setup, admission(&f), source, null);
    defer borrowed.deinit(a);
    try std.testing.expectEqualSlices(u8, owned.bytes, borrowed.bytes);
    try std.testing.expectEqualDeep(owned.claims, borrowed.claims);
    var single = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, SINGLE);
    defer single.deinit();
    var extra = try S.init(a, &single.materials, admission(&f).image, f.boundary, 1, &f.tape);
    defer extra.deinit();
    extra.tails.binary = try front.rv64_air.word16_v1.binary_source.Source.init(a, &.{}, 5);
    const commit = try extra.takeMainForCommit();
    defer commit.deinit(a);
    try std.testing.expect(extra.tails.binary.?.owns_main);
    try std.testing.expect(extra.tails.binary.?.main.len != 0);
}
fn tailFailure(allocator: std.mem.Allocator, prepared: *const Prepared, splits: Tail.Splits) !void {
    var tails = try Tail.Tails.init(allocator, LADDER, prepared, splits, null);
    defer tails.deinit();
}
test "tail constructor exhaustive allocation failures preserve captured facts and failed whole span admission precedes transfer" {
    var f = try Fixture.init();
    defer f.deinit();
    var program = try Program.init(a, .{ .base = 4096, .words = &WORDS });
    defer program.deinit();
    var prepared = try Prepared.capture(a, &program, f.boundary, 1, 8, &f.tape, .{});
    defer prepared.deinit();
    const splits = try Tail.validate(LADDER, &prepared);
    try std.testing.checkAllAllocationFailures(a, tailFailure, .{ &prepared, splits });
    var bad = LADDER;
    bad.shift_tail_log = null;
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, bad);
    defer setup.deinit();
    try std.testing.expectError(error.InvalidProviderTailCapacity, S.fromPrepared(a, &setup.materials, admission(&f).image, &prepared));
    try std.testing.expect(prepared.cpu != null);
    try std.testing.expectEqual(@as(usize, 40), prepared.shift.len);
}
test "actual false prover cannot alter a committed function tail truth row after narrow metadata capture" {
    var f = try Fixture.init();
    defer f.deinit();
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, LADDER);
    defer setup.deinit();
    inline for (.{ "alu", "binary", "shift" }) |name| {
        var source = try S.init(a, &setup.materials, admission(&f).image, f.boundary, 1, &f.tape);
        @field(source.tails, name).?.main[0] = M.fromCanonical(3);
        if (E.provePrepared(a, &setup, admission(&f), source, null)) |value| {
            var unexpected = value;
            unexpected.deinit(a);
            return error.FalseProviderTailProved;
        } else |err| try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
    }
}

test "actual two shard global execution closes all function tails and rejects balanced cross-shard tail debt" {
    const Global = @import("../word16_global_execution/execution.zig");
    const GP = @import("../word16_global_execution/protocol.zig");
    var first = try Fixture.initWithRegisters(null, 80);
    defer first.deinit();
    var second = try Fixture.initWithRegisters(first.boundary.final_registers, 80);
    defer second.deinit();
    var program = try Program.init(a, .{ .base = 4096, .words = &WORDS });
    defer program.deinit();
    var n0 = try Prepared.capture(a, &program, first.boundary, 1, 8, &first.tape, .{});
    defer n0.deinit();
    var n1 = try Prepared.capture(a, &program, second.boundary, 2, 8, &second.tape, .{});
    defer n1.deinit();
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, LADDER);
    defer setup.deinit();
    const expected = GP.Expected{ .admission = admission(&first), .program_identity = program.identity, .total_steps = 320, .max_total_steps = 320, .final_pc = second.boundary.final_pc, .final_registers = second.boundary.final_registers };
    var advice = try Global.collectAdvice(a, &.{ &n0, &n1 }, admission(&first).image);
    defer advice.deinit();
    var bundle = try Global.produceWithAdvice(a, &.{ &setup, &setup }, &.{ &n0, &n1 }, &advice, expected);
    defer bundle.deinit(a);
    var fresh = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, LADDER);
    defer fresh.deinit();
    try Global.verify(a, &.{ &fresh, &fresh }, expected, &bundle);
    bundle.proofs[0].claims.shift_tail.function = bundle.proofs[0].claims.shift_tail.function.add(Q.one());
    bundle.proofs[1].claims.shift_tail.function = bundle.proofs[1].claims.shift_tail.function.sub(Q.one());
    if (Global.verify(a, &.{ &fresh, &fresh }, expected, &bundle)) |_| return error.BalancedGlobalFunctionTailAccepted else |_| {}
}
