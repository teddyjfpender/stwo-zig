const std = @import("std");
const front = @import("stwo_riscv_frontend");
const core = @import("stwo_core");
const G = @import("geometry.zig");
const P = @import("protocol.zig");
const Prepared = @import("prepared.zig").Prepared;
const Program = @import("program.zig").Program;
const Setup = @import("setup.zig").Setup;
const Sources = @import("sources.zig").Source;
const Memory = @import("memory/prepared.zig").Prepared;
const E = @import("execution.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const WORDS = [_]u32{ 0x0000b183, 0xfe000ee3 }; // LD x3,0(x1); BEQ x0,x0,-4
var image_context: u8 = 0;
const Image = struct {
    fn word(_: *const anyopaque, address: u64) !u64 {
        return switch (address) {
            8192 => 17,
            4096 => @as(u64, WORDS[0]) | (@as(u64, WORDS[1]) << 32),
            else => 0,
        };
    }
    fn rights(_: *const anyopaque, address: u64) !u2 {
        return if (address >= 8192 and address < 8200) 3 else if (address >= 4096 and address < 4104) 1 else 0;
    }
};
const Fixture = struct {
    tape: front.rv64.compact_tape.Tape,
    boundary: front.rv64_air.word16_execution.types.Boundary,
    fn init() !@This() {
        return initWithRd(0);
    }
    fn initWithRd(initial_rd: u64) !@This() {
        return initWithSteps(initial_rd, 130);
    }
    fn initWithSteps(initial_rd: u64, steps: u32) !@This() {
        var memory = front.rv64.memory.Memory.init(a, .{});
        defer memory.deinit();
        try memory.map(.{ .start = 4096, .size = 8, .permissions = .{ .read = true, .execute = true } });
        try memory.map(.{ .start = 8192, .size = 8, .permissions = .{ .read = true, .write = true } });
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, try Image.word(&image_context, 4096), .little);
        try memory.initialize(4096, &bytes);
        std.mem.writeInt(u64, &bytes, 17, .little);
        try memory.initialize(8192, &bytes);
        var cpu = front.rv64.machine.Cpu.init(4096, 0);
        cpu.regs[1] = 8192;
        cpu.regs[3] = initial_rd;
        const initial = cpu.regs;
        var tape = try front.rv64.compact_tape.Tape.init(a, steps, 4096, 0, .ethereum_services_v2);
        errdefer tape.deinit();
        var clocks: [32]u32 = @splat(0);
        for (0..steps) |i| {
            const record = try cpu.step(&memory);
            try tape.append(record);
            const tick: u32 = @intCast(4 * i);
            if (record.rs1 != 0) clocks[record.rs1] = tick + 1;
            if (record.rs2 != 0) clocks[record.rs2] = tick + 2;
            if (record.writes_rd and record.rd != 0) clocks[record.rd] = tick + 3;
        }
        return .{ .tape = tape, .boundary = .{ .steps = steps, .initial_pc = 4096, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .register_clocks = clocks } };
    }
    fn deinit(self: *@This()) void {
        self.tape.deinit();
    }
};
fn admission(f: *const Fixture) E.Admission {
    return .{ .image = .{ .context = &image_context, .initial_word = Image.word, .rights_at = Image.rights }, .image_identity = @splat(9), .initial_pc = f.boundary.initial_pc, .initial_registers = f.boundary.initial_registers };
}
const LADDER = G.Geometry{ .cpu_log = 8, .ls_log = 5, .ls_tail_log = 6 };
fn prove(f: *const Fixture, geometry: G.Geometry) !E.Encoded {
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, geometry);
    defer setup.deinit();
    return E.prove(a, &setup, admission(f), f.boundary, &f.tape, null);
}
fn reject(setup: *const Setup, f: *const Fixture, encoded: E.Encoded) !void {
    if (E.verify(a, setup, admission(f), encoded)) |_| return error.ExpectedLsLadderRejection else |_| {}
}
test "LS ladder deterministic padding capacities and absent physical role and ledger admission" {
    const absent = G.Geometry{ .cpu_log = 8, .ls_log = 5 };
    try std.testing.expectEqualDeep(G.Geometry.LsCounts{ .head = 31, .tail = 0 }, try absent.lsCounts(31));
    try std.testing.expectError(error.InvalidLsTailCapacity, absent.lsCounts(32));
    try std.testing.expectError(error.InvalidLsTailCapacity, LADDER.lsCounts(31));
    try std.testing.expectEqualDeep(G.Geometry.LsCounts{ .head = 31, .tail = 1 }, try LADDER.lsCounts(32));
    try std.testing.expectEqualDeep(G.Geometry.LsCounts{ .head = 31, .tail = 63 }, try LADDER.lsCounts(94));
    try std.testing.expectError(error.InvalidLsTailCapacity, LADDER.lsCounts(95));
    var program = try Program.init(a, .{ .base = 4096, .words = &WORDS });
    defer program.deinit();
    const none = G.shapes(&program, absent);
    const both = G.shapes(&program, LADDER);
    try std.testing.expectEqual(@as(usize, 17), @intFromEnum(G.Role.ls_tail));
    try std.testing.expect(!none[17].present());
    try std.testing.expectEqualDeep(front.rv64_air.memory.load_store_v2.layout.widths(.ls), both[17].widths);
    for (none[0..17], both[0..17]) |old, actual| try std.testing.expectEqualDeep(old, actual);
    try P.validateLsTailClass(absent, 31, P.zeroMemoryClaim());
    var bad = P.zeroMemoryClaim();
    bad.owner = Q.one();
    try std.testing.expectError(error.NonzeroOmittedLsTailClaim, P.validateLsTailClass(absent, 31, bad));
    // Durable rejection happens before attempting missing sidecars/key material.
    const Driver = @import("driver.zig");
    const Mixed = @import("../tests/rv64_word16_execution_fixture.zig").Fixture;
    var fixture = try Mixed.init(a);
    defer fixture.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    var ghost = std.mem.zeroes(P.Claims);
    ghost.ls_tail.owner = Q.one();
    ghost.cpu = Q.one().neg();
    try Driver.writeJson(a, temp.dir, "statement.json", Driver.Bundle{ .geometry = .{ .cpu_log = 5 }, .cpu = fixture.boundary, .epoch = 1, .division_requests = 0, .multiplication_requests = 0, .ls_count = 1, .memory_words = 0, .claims = ghost });
    const directory = try temp.dir.realpathAlloc(a, ".");
    defer a.free(directory);
    try std.testing.expectError(error.NonzeroOmittedLsTailClaim, Driver.verifyDirectory(a, &fixture.image, directory));
}
test "One PCS two LS instances native loop closes all claims and retained histograms include all padding" {
    var f = try Fixture.init();
    defer f.deinit();
    var program = try Program.init(a, .{ .base = 4096, .words = &WORDS });
    defer program.deinit();
    var captured = try Prepared.capture(a, &program, f.boundary, 1, 8, &f.tape, .{});
    defer captured.deinit();
    var memory = try Memory.initIndependentLadderProfiled(a, admission(&f).image, captured.cpu.?.memory.items, 1, 5, 6, 5, 5, null);
    defer memory.deinit();
    try std.testing.expectEqual(@as(u32, 31), memory.ls.rows);
    try std.testing.expectEqual(@as(u32, 34), memory.ls_tail.?.rows);
    var selection: u64 = 0;
    for (memory.selection.counts) |c| selection += c;
    try std.testing.expectEqual(@as(u64, 96), selection);
    var r16: u64 = 0;
    for (memory.counts16) |c| r16 += c;
    const Ram = front.rv64_air.memory.load_store_v2.layout;
    try std.testing.expectEqual(@as(u64, 35 * 96 + Ram.BOUND_U16.len * 64), r16);
    var encoded = try prove(&f, LADDER);
    defer encoded.deinit(a);
    var fresh = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, LADDER);
    defer fresh.deinit();
    try E.verify(a, &fresh, admission(&f), encoded);
    try std.testing.expectEqual(@as(u32, 65), encoded.request.memory.ls_count);
    try encoded.claims.validate();
    try std.testing.expectEqual(@as(usize, 38), encoded.claims.values().len);
    // Different authenticated counts/endpoints reuse the SAME immutable key.
    var later_fixture = try Fixture.initWithSteps(0, 132);
    defer later_fixture.deinit();
    var later = try E.prove(a, &fresh, admission(&later_fixture), later_fixture.boundary, &later_fixture.tape, null);
    defer later.deinit(a);
    try std.testing.expectEqual(@as(u32, 66), later.request.memory.ls_count);
    try E.verify(a, &fresh, admission(&later_fixture), later);
}
test "LS tail missing span count and balanced cross-instance or omitted claims reject in real receiver" {
    var f = try Fixture.init();
    defer f.deinit();
    var encoded = try prove(&f, LADDER);
    defer encoded.deinit(a);
    var fresh = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, LADDER);
    defer fresh.deinit();
    var forged = encoded;
    forged.request.memory.ls_count -= 1;
    try reject(&fresh, &f, forged);
    forged = encoded;
    forged.claims.ls_tail.ram = forged.claims.ls_tail.ram.add(Q.one());
    forged.claims.ls.ram = forged.claims.ls.ram.sub(Q.one());
    try forged.claims.validate();
    try reject(&fresh, &f, forged);
    const single = G.Geometry{ .cpu_log = 8, .ls_log = 7 };
    var unit = try prove(&f, single);
    defer unit.deinit(a);
    var single_setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, single);
    defer single_setup.deinit();
    // A receiver roster missing the physical tail cannot accept its fragment.
    try reject(&single_setup, &f, encoded);
    var absent = unit;
    absent.claims.ls_tail.owner = Q.one();
    absent.claims.cpu = absent.claims.cpu.sub(Q.one());
    try absent.claims.validate();
    try std.testing.expectError(error.NonzeroOmittedLsTailClaim, E.verify(a, &single_setup, admission(&f), absent));
}
fn memoryFailure(allocator: std.mem.Allocator, image: @import("memory/statement.zig").Image, records: []const @import("cpu_source.zig").MemoryRecord) !void {
    var value = try Memory.initIndependentLadderProfiled(allocator, image, records, 1, 5, 6, 5, 5, null);
    defer value.deinit();
}
test "LS ladder native construction allocation errors retain inputs and owned MAIN INTER handoffs are exact" {
    var f = try Fixture.init();
    defer f.deinit();
    var program = try Program.init(a, .{ .base = 4096, .words = &WORDS });
    defer program.deinit();
    var captured = try Prepared.capture(a, &program, f.boundary, 1, 8, &f.tape, .{});
    defer captured.deinit();
    try std.testing.checkAllAllocationFailures(a, memoryFailure, .{ admission(&f).image, captured.cpu.?.memory.items });
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, LADDER);
    defer setup.deinit();
    var one = try E.prove(a, &setup, admission(&f), f.boundary, &f.tape, null);
    defer one.deinit(a);
    const source = try Sources.init(a, &setup.materials, admission(&f).image, f.boundary, 1, &f.tape);
    var borrowed = try E.provePreparedBorrowedMain(a, &setup, admission(&f), source, null);
    defer borrowed.deinit(a);
    try std.testing.expectEqualSlices(u8, one.bytes, borrowed.bytes);
    try std.testing.expectEqualDeep(one.claims, borrowed.claims);
    // Even a private extra owner outside the physical roster must stay owned;
    // custody cannot clear an untransferred allocation's flag.
    const single = G.Geometry{ .cpu_log = 8, .ls_log = 7 };
    var single_setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, single);
    defer single_setup.deinit();
    var extra = try Sources.init(a, &single_setup.materials, admission(&f).image, f.boundary, 1, &f.tape);
    defer extra.deinit();
    extra.memory.ls_tail = try front.rv64_air.memory.load_store_v2.source.Source.init(a, &.{}, 5);
    const commit = try extra.takeMainForCommit();
    defer commit.deinit(a);
    try std.testing.expect(extra.memory.ls_tail.?.owns_main);
    try std.testing.expect(extra.memory.ls_tail.?.main.len != 0);
}
test "LS ladder actual two shard global RAM proof shares both LS debts and rejects balanced tail forks" {
    const Global = @import("../word16_global_execution/execution.zig");
    const GP = @import("../word16_global_execution/protocol.zig");
    var first = try Fixture.init();
    defer first.deinit();
    var second = try Fixture.initWithRd(17);
    defer second.deinit();
    var program = try Program.init(a, .{ .base = 4096, .words = &WORDS });
    defer program.deinit();
    var n0 = try Prepared.capture(a, &program, first.boundary, 1, 8, &first.tape, .{});
    defer n0.deinit();
    var n1 = try Prepared.capture(a, &program, second.boundary, 2, 8, &second.tape, .{});
    defer n1.deinit();
    var s0 = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, LADDER);
    defer s0.deinit();
    var s1 = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, LADDER);
    defer s1.deinit();
    const expected = GP.Expected{ .admission = admission(&first), .program_identity = program.identity, .total_steps = 260, .max_total_steps = 260, .final_pc = second.boundary.final_pc, .final_registers = second.boundary.final_registers };
    var advice = try Global.collectAdvice(a, &.{ &n0, &n1 }, admission(&first).image);
    defer advice.deinit();
    var bundle = try Global.produceWithAdvice(a, &.{ &s0, &s1 }, &.{ &n0, &n1 }, &advice, expected);
    defer bundle.deinit(a);
    var fresh0 = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, LADDER);
    defer fresh0.deinit();
    var fresh1 = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, LADDER);
    defer fresh1.deinit();
    try Global.verify(a, &.{ &fresh0, &fresh1 }, expected, &bundle);
    const tail = bundle.proofs[0].claims.ls_tail.ram;
    const other = bundle.proofs[1].claims.ls_tail.ram;
    bundle.proofs[0].claims.ls_tail.ram = tail.add(Q.one());
    bundle.proofs[1].claims.ls_tail.ram = other.sub(Q.one());
    if (Global.verify(a, &.{ &fresh0, &fresh1 }, expected, &bundle)) |_| return error.ExpectedGlobalTailRejection else |_| {}
}
fn serviceExpected(program: [32]u8) @import("../word16_global_execution/protocol.zig").Expected {
    const F = @import("../word16_global_execution/keccak/fixture.zig");
    var expected = F.Case.expectedFor(program);
    expected.admission.max_prefix_steps = 63;
    expected.total_steps = 66;
    expected.max_total_steps = 66;
    expected.final_pc = 4096 + 66 * 4;
    return expected;
}
test "LS ladder Keccak CPU bridge one PCS and shared truth protocols fresh verify canonical extended ledgers" {
    const F = @import("../word16_global_execution/keccak/fixture.zig");
    const K = @import("../word16_global_execution/keccak/execution.zig");
    const KR = @import("../word16_global_execution/keccak/roster.zig");
    {
        var c = try F.Captured.initLsRepeats(a, 32);
        defer c.deinit();
        var g0 = try c.native[0].geometry();
        g0.ls_log = 5;
        g0.ls_tail_log = 5;
        var g1 = try c.native[1].geometry();
        g1.ls_log = 5;
        g1.ls_tail_log = 5;
        const expected_program = front.rv64_air.program.setup.Program{ .base = 4096, .words = c.program.words };
        var s0 = try KR.Setup.initProgram(a, expected_program, g0, .{ .klog = 5, .blog = 5 });
        defer s0.deinit();
        var s1 = try KR.Setup.initProgram(a, expected_program, g1, .{ .klog = 5, .blog = 5 });
        defer s1.deinit();
        const expected = serviceExpected(c.program.identity);
        var bundle = try K.produce(a, &.{ &s0, &s1 }, &.{ &c.native[0], &c.native[1] }, &c.advice, expected);
        defer bundle.deinit(a);
        try std.testing.expectEqual(P.CLAIM_COUNT + 8, bundle.proofs[0].claims.values().len);
        var f0 = try KR.Setup.initProgram(a, expected_program, g0, .{ .klog = 5, .blog = 5 });
        defer f0.deinit();
        var f1 = try KR.Setup.initProgram(a, expected_program, g1, .{ .klog = 5, .blog = 5 });
        defer f1.deinit();
        try K.verify(a, &.{ &f0, &f1 }, expected, &bundle);
    }
    {
        const Shared = @import("../word16_global_execution/keccak/shared/execution.zig");
        const Roster = @import("../word16_global_execution/keccak/shared/roster.zig");
        var c = try F.Captured.initLsRepeats(a, 32);
        defer c.deinit();
        var g0 = try c.native[0].geometry();
        g0.ls_log = 5;
        g0.ls_tail_log = 5;
        var g1 = try c.native[1].geometry();
        g1.ls_log = 5;
        g1.ls_tail_log = 5;
        const expected_program = front.rv64_air.program.setup.Program{ .base = 4096, .words = c.program.words };
        var s0 = try Roster.CpuSetup.initProgram(a, expected_program, g0, 5);
        defer s0.deinit();
        var s1 = try Roster.CpuSetup.initProgram(a, expected_program, g1, 5);
        defer s1.deinit();
        var truth = try Roster.TruthSetup.init(a, 5);
        defer truth.deinit();
        const expected = serviceExpected(c.program.identity);
        var bundle = try Shared.produce(a, &.{ &s0, &s1 }, &truth, &.{ &c.native[0], &c.native[1] }, &c.advice, expected);
        defer bundle.deinit(a);
        try std.testing.expectEqual(P.CLAIM_COUNT + 5, bundle.cpus[0].claims.values().len);
        var f0 = try Roster.CpuSetup.initProgram(a, expected_program, g0, 5);
        defer f0.deinit();
        var f1 = try Roster.CpuSetup.initProgram(a, expected_program, g1, 5);
        defer f1.deinit();
        var ft = try Roster.TruthSetup.init(a, 5);
        defer ft.deinit();
        try Shared.verify(a, &.{ &f0, &f1 }, &ft, expected, &bundle);
    }
}
test "LS ladder Secp ADD DOUBLE shared RAM receiver derives extended canonical base claims" {
    const F = @import("../word16_global_execution/secp/fixture.zig");
    const Secp = @import("../word16_global_execution/secp/execution.zig");
    const R = @import("../word16_global_execution/secp/roster.zig");
    const S = front.rv64_air.crypto.secp256k1;
    var c = try F.Captured.initLsRepeats(a, 32);
    defer c.deinit();
    var g0 = try c.native[0].geometry();
    g0.ls_log = 5;
    g0.ls_tail_log = 5;
    const g1 = try c.native[1].geometry();
    const expected_program = front.rv64_air.program.setup.Program{ .base = 4096, .words = c.program.words };
    var s0 = try R.CpuSetup.initProgram(a, expected_program, g0, .{ 5, 5 });
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, expected_program, g1, .{ 5, 5 });
    defer s1.deinit();
    const add_logs = [2]u32{ try S.layout.logSize(.product, &S.program.add, 1), try S.layout.logSize(.linear, &S.program.add, 1) };
    const double_logs = [2]u32{ try S.layout.logSize(.product, &S.program.double, 1), try S.layout.logSize(.linear, &S.program.double, 1) };
    var add = try R.TruthSetup.init(a, .add, add_logs);
    defer add.deinit();
    var double = try R.TruthSetup.init(a, .double, double_logs);
    defer double.deinit();
    var expected = F.expectedFor(c.program.identity);
    expected.admission.max_prefix_steps = 63;
    expected.total_steps = 35;
    expected.max_total_steps = 35;
    expected.final_pc = 4096 + 35 * 4;
    var bundle = try Secp.produce(a, &.{ &s0, &s1 }, .{ &add, &double }, &.{ &c.native[0], &c.native[1] }, &c.advice, expected);
    defer bundle.deinit(a);
    try std.testing.expectEqual(P.CLAIM_COUNT + 10, bundle.cpus[0].claims.values().len);
    var f0 = try R.CpuSetup.initProgram(a, expected_program, g0, .{ 5, 5 });
    defer f0.deinit();
    var f1 = try R.CpuSetup.initProgram(a, expected_program, g1, .{ 5, 5 });
    defer f1.deinit();
    var fa = try R.TruthSetup.init(a, .add, add_logs);
    defer fa.deinit();
    var fd = try R.TruthSetup.init(a, .double, double_logs);
    defer fd.deinit();
    try Secp.verify(a, &.{ &f0, &f1 }, .{ &fa, &fd }, expected, &bundle);
}
