//! Real limited-profile native execution and closed CPU+ALU+BINARY+U16 proof.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const front = @import("stwo_riscv_frontend");
const air = front.rv64_air;
const W = air.word16_cpu;
const E = air.evaluation;
const CPU = @import("../word16/cpu.zig");
const Sources = @import("../word16/cpu_sources.zig");
const Protocol = @import("../word16/cpu_protocol.zig");
const Components = @import("../word16/cpu_components.zig").Components;
const T = @import("../rv64_distributed_v1/manifest.zig").T;
const Backend = @import("stwo_cpu_backend").CpuBackend;
const M = core.fields.m31.M31;
const Q = E.Q;
const a = std.testing.allocator;
fn reg(f3: u32, rd: u32, rs1: u32, rs2: u32, sub: bool, word: bool) u32 {
    return (if (word) @as(u32, 0x3b) else 0x33) | (rd << 7) | (f3 << 12) | (rs1 << 15) | (rs2 << 20) | (if (sub) @as(u32, 0x40000000) else 0);
}
fn imm(f3: u32, rd: u32, rs1: u32, value: i12, word: bool) u32 {
    return (if (word) @as(u32, 0x1b) else 0x13) | (rd << 7) | (f3 << 12) | (rs1 << 15) | (@as(u32, @as(u12, @bitCast(value))) << 20);
}
fn branch(f3: u32, rs1: u32, rs2: u32, offset: i13) u32 {
    const value: u13 = @bitCast(offset);
    return 0x63 | (@as(u32, (value >> 11) & 1) << 7) | (@as(u32, (value >> 1) & 15) << 8) | (f3 << 12) | (rs1 << 15) | (rs2 << 20) | (@as(u32, (value >> 5) & 63) << 25) | (@as(u32, value >> 12) << 31);
}
const Fixture = struct {
    words: std.ArrayList(u32),
    records: std.ArrayList(front.rv64.machine.Retirement),
    public: CPU.Public,
    fn init() !Fixture {
        var words: std.ArrayList(u32) = .empty;
        errdefer words.deinit(a);
        try words.appendSlice(a, &.{
            reg(0, 3, 1, 2, false, false),    reg(0, 4, 0, 1, true, false),
            reg(0, 5, 6, 7, false, true),     reg(0, 8, 9, 10, true, true),
            reg(2, 11, 12, 13, false, false), reg(3, 14, 12, 13, false, false),
            imm(0, 15, 0, -1, false),         imm(0, 16, 17, 1, true),
            imm(2, 18, 12, -1, false),        imm(3, 19, 0, -1, false),
            imm(7, 20, 15, -2, false),        imm(6, 21, 0, -2048, false),
            imm(4, 22, 20, -1, false),        reg(7, 23, 1, 2, false, false),
            reg(6, 24, 3, 4, false, false),   reg(4, 25, 5, 8, false, false),
        });
        // All six branch predicates, each taken and untaken; target skips one
        // real instruction. The mapping is the shared Operations authority.
        const cases = [_][3]u32{
            .{ 0, 0, 0 },   .{ 0, 0, 29 },  .{ 1, 0, 0 },   .{ 1, 0, 29 },
            .{ 4, 30, 29 }, .{ 4, 29, 30 }, .{ 5, 30, 29 }, .{ 5, 29, 30 },
            .{ 6, 30, 29 }, .{ 6, 29, 30 }, .{ 7, 30, 29 }, .{ 7, 29, 30 },
        };
        for (cases) |item| {
            try words.append(a, branch(item[0], item[1], item[2], 8));
            try words.append(a, reg(0, 0, 0, 0, false, false));
        }
        try words.append(a, imm(0, 26, 26, -1, false));
        try words.append(a, branch(1, 26, 0, -4)); // backward edge, three iterations
        var memory = front.rv64.memory.Memory.init(a, .{});
        defer memory.deinit();
        try memory.map(.{ .start = 4096, .size = @intCast(words.items.len * 4), .permissions = .{ .read = true, .execute = true } });
        for (words.items, 0..) |word, index| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            try memory.initialize(4096 + 4 * index, &bytes);
        }
        var cpu = front.rv64.machine.Cpu.init(4096, 0);
        cpu.regs[1] = 0xffffffffffffffff;
        cpu.regs[2] = 1;
        cpu.regs[6] = 0x7fffffff;
        cpu.regs[7] = 1;
        cpu.regs[9] = 0x80000000;
        cpu.regs[10] = 1;
        cpu.regs[12] = 0x8000000000000000;
        cpu.regs[13] = 1;
        cpu.regs[17] = 0x7fffffff;
        cpu.regs[26] = 3;
        cpu.regs[29] = 1;
        cpu.regs[30] = 0x8000000000000000;
        cpu.regs[31] = 0xffffffffffffffff;
        const initial = cpu.regs;
        var records: std.ArrayList(front.rv64.machine.Retirement) = .empty;
        errdefer records.deinit(a);
        var clocks: [32]u32 = @splat(0);
        while (cpu.pc != 4096 + 4 * words.items.len) {
            if (records.items.len >= 63) return error.BadAluFixtureLoop;
            const record = try cpu.step(&memory);
            for ([_]u5{ record.rs1, record.rs2, record.rd }, 0..) |id, slot| if (id != 0) {
                clocks[id] = @intCast(4 * records.items.len + slot + 1);
            };
            try records.append(a, record);
        }
        return .{ .words = words, .records = records, .public = .{ .steps = @intCast(records.items.len), .initial_pc = 4096, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .register_clocks = clocks } };
    }
    fn deinit(self: *Fixture) void {
        self.words.deinit(a);
        self.records.deinit(a);
    }
};
fn materials(fixture: *const Fixture) !CPU.Materials {
    return CPU.Materials.init(a, .{ .base = 4096, .words = fixture.words.items }, .{ .cpu_log = 6, .binary_log = 5, .alu_log = 6, .profile = .alu_binary_v2 });
}
fn rejects(setup: *const CPU.Materials, public: CPU.Public, proof: CPU.Encoded) !void {
    if (CPU.verifyClosed(a, setup, public, proof)) |_| return error.ExpectedAluCpuRejection else |_| {}
}
test "ALU binary v2 real native signed W immediate and branch execution closes one PCS" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var setup = try materials(&fixture);
    defer setup.deinit();
    try std.testing.expectEqual(@as(usize, 46), (try setup.shape(.cpu)).widths[1]);
    try std.testing.expectEqual(@as(usize, 56), (try setup.shape(.cpu)).widths[2]);
    var proof = try CPU.produce(a, &setup, fixture.public, fixture.records.items, false);
    defer proof.deinit(a);
    var receiver = try materials(&fixture);
    defer receiver.deinit();
    try CPU.verifyClosed(a, &receiver, fixture.public, proof);
    var scalar = try CPU.produce(a, &setup, fixture.public, fixture.records.items, true);
    defer scalar.deinit(a);
    try std.testing.expectEqualSlices(u8, proof.bytes, scalar.bytes);
    var forged = proof;
    forged.claims.cpu.function = forged.claims.cpu.function.add(Q.one());
    forged.alu_claims.function = forged.alu_claims.function.sub(Q.one());
    try rejects(&receiver, fixture.public, forged);
    forged = proof;
    forged.claims.cpu.range16 = forged.claims.cpu.range16.add(Q.one());
    forged.alu_claims.range16 = forged.alu_claims.range16.sub(Q.one());
    try rejects(&receiver, fixture.public, forged);
    // Changing count and endpoints never changes the immutable ROM/shape key.
    var short = fixture.public;
    short.steps = 16;
    short.final_pc = fixture.records.items[15].next_pc.toInt();
    short.final_registers = short.initial_registers;
    short.register_clocks = @splat(0);
    for (fixture.records.items[0..16], 0..) |record, index| {
        for ([_]u5{ record.rs1, record.rs2, record.rd }, 0..) |id, slot| if (id != 0) {
            short.register_clocks[id] = @intCast(4 * index + slot + 1);
        };
        if (record.writes_rd) short.final_registers[record.rd] = record.result.toInt();
    }
    var shorter = try CPU.produce(a, &setup, short, fixture.records.items[0..16], false);
    defer shorter.deinit(a);
    try CPU.verifyClosed(a, &receiver, short, shorter);
    try rejects(&receiver, fixture.public, shorter);
    var wrong = fixture.public;
    wrong.final_registers[16] ^= 1 << 63;
    try rejects(&receiver, wrong, proof);
}
const Attack = enum { operand, result, pc, immediate, w_extension, predicate };
fn falseProof(setup: *const CPU.Materials, fixture: *const Fixture, attack: Attack) !void {
    var source = try Sources.Source.init(a, setup, fixture.public, fixture.records.items);
    defer source.deinit();
    const n = source.cpu.size();
    const logical: usize = switch (attack) {
        .immediate => 6,
        .w_extension => 2,
        .predicate => 16,
        else => 0,
    };
    const pos = W.layout.physical(logical, 6);
    const column: usize = switch (attack) {
        .operand => W.layout.main.a,
        .result => W.layout.main.c,
        .pc => W.layout.main.next_pc + 3,
        .immediate => W.profile.immediate,
        .w_extension => W.layout.main.c + 2,
        .predicate => W.layout.main.c,
    };
    source.cpu.main[column * n + pos] = source.cpu.main[column * n + pos].add(M.one());
    var scheme = try T.Scheme.init(a, Protocol.P.config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = Protocol.P.Channel{};
    try Protocol.mixLocal(&channel, setup, fixture.public);
    try setup.appendFixed(a, &scheme, &channel);
    const main = try source.columns(a, 1);
    defer a.free(main);
    try scheme.commitBorrowedStreaming(a, main, 8, &channel);
    const draw = Protocol.drawProfile(&channel, null, .alu_binary_v2);
    const claims = try source.generate(draw.cpu, draw.and_);
    const alu = source.alu_claims.?;
    Protocol.mixClaimsProfile(&channel, claims, .alu_binary_v2, alu);
    const inter = try source.columns(a, 2);
    defer a.free(inter);
    try scheme.commitBorrowedStreaming(a, inter, 8, &channel);
    var components = try Components.initWithAlu(setup, fixture.public, draw, claims, alu, false);
    const handles = try components.provers(a);
    defer a.free(handles);
    owns = false;
    var proof = try engine.prove.prove(Backend, T.P.Hasher, T.P.MerkleChannel, a, handles, &channel, scheme);
    defer proof.deinit(a);
}
test "ALU binary v2 physical engine rejects forged operand result PC immediate W and predicate" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var setup = try materials(&fixture);
    defer setup.deinit();
    for (std.enums.values(Attack)) |attack| try std.testing.expectError(error.ConstraintsNotSatisfied, falseProof(&setup, &fixture, attack));
}
fn dense(value: u32) Q {
    return Q.fromPartialEvals(.{ E.q(value), E.q(value + 1), E.q(value + 3), E.q(value + 7) });
}
fn fill(values: []Q, t: Q, seed: u32) void {
    for (values, 0..) |*value, i| value.* = dense(seed + @as(u32, @intCast(2 * i))).add(t.mul(dense(seed + @as(u32, @intCast(2 * i + 1)))));
}
test "ALU binary v2 full CPU dense OODS lines have degree at most three" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var ch: W.lookup.Challenges = undefined;
    ch.register.offset = dense(100);
    ch.function.offset = dense(200);
    ch.rom.offset = dense(300);
    for (&ch.register.coefficients, 0..) |*v, i| v.* = dense(@intCast(i + 400));
    for (&ch.function.coefficients, 0..) |*v, i| v.* = dense(@intCast(i + 500));
    for (&ch.rom.coefficients, 0..) |*v, i| v.* = dense(@intCast(i + 600));
    for (&ch.rom.control_coefficients, 0..) |*v, i| v.* = dense(@intCast(i + 700));
    ch.range16 = .{ .offset = dense(800), .coefficient = dense(801) };
    ch.range8 = .{ .offset = dense(900), .coefficient = dense(901) };
    const claims = W.public.Claims{ .register = dense(1), .function = dense(2), .rom = dense(3), .range16 = dense(4), .range8 = dense(5) };
    var samples: [5][W.layout.CONSTRAINTS]Q = undefined;
    var fixed: [3]Q = undefined;
    var main: [46]Q = undefined;
    var previous_main: [46]Q = undefined;
    var current: [56]Q = undefined;
    var previous: [56]Q = undefined;
    for (0..5) |i| {
        const t = E.q(@intCast(i));
        fill(&fixed, t, 1);
        fill(&main, t, 100);
        fill(&previous_main, t, 200);
        fill(&current, t, 300);
        fill(&previous, t, 400);
        var sink = E.Sink{ .values = &samples[i] };
        W.equations.emitProfileFor(Q, .alu_binary_v2, &fixed, &main, &previous_main, &current, &previous, fixture.public, claims, ch, &sink);
        try std.testing.expectEqual(W.layout.CONSTRAINTS, sink.count);
    }
    for (0..W.layout.CONSTRAINTS) |i| try std.testing.expect(samples[4][i].sub(samples[3][i].mul(E.q(4))).add(samples[2][i].mul(E.q(6))).sub(samples[1][i].mul(E.q(4))).add(samples[0][i]).isZero());
}

test "ALU binary v2 wrapping branch and invalid taken edge follow native RV64" {
    const top = std.math.maxInt(u64) - 3;
    const word = branch(0, 0, 0, 4);
    var memory = front.rv64.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = top, .size = 4, .permissions = .{ .read = true, .execute = true } });
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, word, .little);
    try memory.initialize(top, &bytes);
    var cpu = front.rv64.machine.Cpu.init(top, 0);
    const record = try cpu.step(&memory);
    try std.testing.expect(record.branch_taken);
    try std.testing.expectEqual(@as(u64, 0), cpu.pc);
    const public = CPU.Public{ .steps = 1, .initial_pc = top, .final_pc = 0, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
    var setup = try CPU.Materials.init(a, .{ .base = top, .words = &.{word} }, .{ .cpu_log = 5, .profile = .alu_binary_v2 });
    defer setup.deinit();
    var proof = try CPU.produce(a, &setup, public, &.{record}, false);
    defer proof.deinit(a);
    var receiver = try CPU.Materials.init(a, .{ .base = top, .words = &.{word} }, .{ .cpu_log = 5, .profile = .alu_binary_v2 });
    defer receiver.deinit();
    try CPU.verifyClosed(a, &receiver, public, proof);
    // An untaken branch with misaligned unused target is executable; only its
    // invalid taken edge is absent from the independently derived ROM.
    const misaligned = branch(1, 0, 0, 2);
    var rom = try W.rom.Setup.initWithProfile(a, .{ .base = 4096, .words = &.{misaligned} }, .alu_binary_v2);
    defer rom.deinit();
    try std.testing.expectEqual(@as(usize, 1), rom.row_words.len);
    try std.testing.expectError(error.InvalidWord16BranchEdge, rom.factIndex(0, true));
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.UnsupportedThinCpuProfile, CPU.Materials.init(failing.allocator(), .{ .base = top, .words = &.{word} }, .{ .cpu_log = 5, .profile = .alu_binary_v2, .mode = .open_function }));
}

fn sourceAllocationCase(allocator: std.mem.Allocator, setup: *const CPU.Materials, fixture: *const Fixture) !void {
    var source = try Sources.Source.init(allocator, setup, fixture.public, fixture.records.items);
    defer source.deinit();
}
test "ALU binary v2 combined source unwinds every construction allocation failure" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var setup = try materials(&fixture);
    defer setup.deinit();
    try std.testing.checkAllAllocationFailures(a, sourceAllocationCase, .{ &setup, &fixture });
}
