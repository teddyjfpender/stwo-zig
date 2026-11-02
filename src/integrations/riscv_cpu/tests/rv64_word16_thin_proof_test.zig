//! Actual one-PCS CPU+ROM+REG+U16/U8+BINARY/AND proof, not a view-only test.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const front = @import("stwo_riscv_frontend");
const air = front.rv64_air;
const CPU = @import("../word16/cpu.zig");
const Sources = @import("../word16/cpu_sources.zig");
const Protocol = @import("../word16/cpu_protocol.zig");
const Components = @import("../word16/cpu_components.zig").Components;
const Scheme = @import("../rv64_distributed_v1/manifest.zig").T.Scheme;
const Backend = @import("stwo_cpu_backend").CpuBackend;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const L = air.word16_cpu.layout;
const a = std.testing.allocator;
fn raw(funct3: u32, rd: u32, rs1: u32, rs2: u32) u32 {
    return 0x33 | (rd << 7) | (funct3 << 12) | (rs1 << 15) | (rs2 << 20);
}
const words = [_]u32{ raw(7, 3, 1, 2), raw(6, 1, 3, 1), raw(4, 0, 1, 2), raw(4, 2, 1, 3) };
const Fixture = struct {
    public: CPU.Public,
    records: [4]front.rv64.machine.Retirement,
    fn init() !Fixture {
        var memory = front.rv64.memory.Memory.init(a, .{});
        defer memory.deinit();
        try memory.map(.{ .start = 4096, .size = 16, .permissions = .{ .read = true, .execute = true } });
        for (words, 0..) |word, i| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            try memory.initialize(4096 + 4 * i, &bytes);
        }
        var cpu = front.rv64.machine.Cpu.init(4096, 0);
        cpu.regs[1] = 0xffff000180007fff;
        cpu.regs[2] = 0x7fffffff8000ffff;
        const initial = cpu.regs;
        var records: [4]front.rv64.machine.Retirement = undefined;
        for (&records) |*record| record.* = try cpu.step(&memory);
        var clocks: [32]u32 = @splat(0);
        clocks[1] = 13;
        clocks[2] = 15;
        clocks[3] = 14;
        return .{ .public = .{ .steps = 4, .initial_pc = 4096, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .register_clocks = clocks }, .records = records };
    }
};
fn reject(materials: *const CPU.Materials, public: CPU.Public, encoded: CPU.Encoded) !void {
    if (CPU.verifyClosed(a, materials, public, encoded)) |_| return error.ExpectedThinCpuRejection else |_| {}
}
test "thin closed seven-role proof fresh-verifies and scalar SIMD proof bytes match" {
    const fixture = try Fixture.init(); // native VM and memory die here.
    var materials = try CPU.Materials.init(a, .{ .base = 4096, .words = &words }, .{ .cpu_log = 5, .binary_log = 5 });
    defer materials.deinit();
    var proof = try CPU.produce(a, &materials, fixture.public, &fixture.records, false);
    defer proof.deinit(a);
    var reference = try referenceProof(&materials, fixture, null);
    defer reference.deinit(a);
    try std.testing.expectEqualSlices(u8, proof.bytes, reference.bytes);
    var independent = try CPU.Materials.init(a, .{ .base = 4096, .words = &words }, .{ .cpu_log = 5, .binary_log = 5 });
    defer independent.deinit();
    try CPU.verifyClosed(a, &independent, fixture.public, proof);
    try std.testing.expectEqualSlices(u8, &materials.fixed_root.value, &independent.fixed_root.value);
    var scalar = try CPU.produce(a, &materials, fixture.public, &fixture.records, true);
    defer scalar.deinit(a);
    try std.testing.expectEqualSlices(u8, proof.bytes, scalar.bytes);
    var wrong = fixture.public;
    wrong.final_pc +%= 4;
    try reject(&independent, wrong, proof);
    wrong = fixture.public;
    wrong.initial_registers[1] ^= 1 << 63;
    try reject(&independent, wrong, proof);
    wrong = fixture.public;
    wrong.register_clocks[1] = 17;
    try reject(&independent, wrong, proof);
    var forged = proof;
    forged.claims.cpu.register = forged.claims.cpu.register.add(Q.one());
    forged.claims.boundary = forged.claims.boundary.sub(Q.one());
    try reject(&independent, fixture.public, forged);
    forged = proof;
    forged.claims.cpu.function = forged.claims.cpu.function.add(Q.one());
    forged.claims.binary.function = forged.claims.binary.function.sub(Q.one());
    try reject(&independent, fixture.public, forged);
    // Different active count/state uses the SAME immutable fixed key.
    var short = fixture.public;
    short.steps = 3;
    short.final_pc = 4108;
    short.final_registers[2] = short.initial_registers[2];
    short.register_clocks = @splat(0);
    short.register_clocks[1] = 9;
    short.register_clocks[2] = 10;
    short.register_clocks[3] = 5;
    var short_proof = try CPU.produce(a, &materials, short, fixture.records[0..3], false);
    defer short_proof.deinit(a);
    try CPU.verifyClosed(a, &independent, short, short_proof);
    try reject(&independent, fixture.public, short_proof);
}
const Attack = enum { previous_clock_wrap, unbounded_previous_rd, result, global_opcode, high_pc };
fn referenceProof(materials: *const CPU.Materials, fixture: Fixture, attack: ?Attack) !CPU.Encoded {
    var source = try Sources.Source.init(a, materials, fixture.public, &fixture.records);
    defer source.deinit();
    const n = source.cpu.size();
    const p = L.physical(0, materials.geometry.cpu_log);
    if (attack) |value| switch (value) {
        .previous_clock_wrap => {
            source.cpu.main[L.main.previous_clock * n + p] = M.fromCanonical(core.fields.m31.Modulus - 1);
            source.cpu.main[L.main.gap16 * n + p] = M.one();
        },
        .unbounded_previous_rd => source.cpu.main[L.main.previous_rd * n + p] = M.fromCanonical(65536),
        .result => source.cpu.main[L.main.c * n + p] = source.cpu.main[L.main.c * n + p].add(M.one()),
        .global_opcode => source.cpu.main[L.main.opcode * n + p] = M.fromCanonical(0),
        .high_pc => source.cpu.main[(L.main.pc + 3) * n + p] = M.one(),
    };
    var scheme = try Scheme.init(a, Protocol.P.config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = Protocol.P.Channel{};
    try Protocol.mixLocal(&channel, materials, fixture.public);
    for ([_]usize{ 0, 1 }) |tree| {
        const columns = try source.columns(a, tree);
        defer a.free(columns);
        try scheme.commitBorrowedStreaming(a, columns, 8, &channel);
    }
    const draw = Protocol.drawLocal(&channel, null);
    // Hints remain honestly generated from captured metadata. The actual
    // committed false matrix MUST be caught by physical AIR/composition.
    const claims = try source.generate(draw.cpu, draw.and_);
    Protocol.mixClaims(&channel, claims);
    const columns = try source.columns(a, 2);
    defer a.free(columns);
    try scheme.commitBorrowedStreaming(a, columns, 8, &channel);
    var components = try Components.init(materials, fixture.public, draw, claims, false);
    const handles = try components.provers(a);
    defer a.free(handles);
    owns = false;
    var proof = try engine.prove.prove(Backend, Protocol.P.Hasher, Protocol.P.MerkleChannel, a, handles, &channel, scheme);
    defer proof.deinit(a);
    return .{ .bytes = try wire.encodeProofBytesBinary(a, proof), .claims = claims };
}
fn falseProof(materials: *const CPU.Materials, fixture: Fixture, attack: Attack) !void {
    var unexpected = try referenceProof(materials, fixture, attack);
    defer unexpected.deinit(a);
}
test "physical thin CPU proving rejects forged clocks values opcode and PC" {
    const fixture = try Fixture.init();
    var materials = try CPU.Materials.init(a, .{ .base = 4096, .words = &words }, .{ .cpu_log = 5, .binary_log = 5 });
    defer materials.deinit();
    for (std.enums.values(Attack)) |attack| try std.testing.expectError(error.ConstraintsNotSatisfied, falseProof(&materials, fixture, attack));
}

test "immutable thin fixed commitment leases match fresh commits and survive owner release" {
    var materials = try CPU.Materials.init(a, .{ .base = 4096, .words = &words }, .{ .cpu_log = 5 });
    var owner_live = true;
    defer if (owner_live) materials.deinit();
    var retained = try Scheme.init(a, Protocol.P.config());
    defer retained.deinit(a);
    retained.setCompactPolynomialStorage(5);
    var channel = Protocol.P.Channel{};
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, materials.appendFixed(failing.allocator(), &retained, &channel));
    try std.testing.expectEqual(@as(usize, 0), retained.trees.items.len);
    try materials.appendFixed(a, &retained, &channel);
    try std.testing.expectError(error.InvalidThinCpuFixedPhase, materials.appendFixed(a, &retained, &channel));
    var reference = try Scheme.init(a, Protocol.P.config());
    defer reference.deinit(a);
    reference.setCompactPolynomialStorage(5);
    var reference_channel = Protocol.P.Channel{};
    const columns = try materials.fixedColumns(a);
    defer a.free(columns);
    try reference.commitBorrowedStreaming(a, columns, 8, &reference_channel);
    try std.testing.expectEqualSlices(u8, &channel.digestBytes(), &reference_channel.digestBytes());
    const expected_root = materials.fixed_root.value;
    try std.testing.expectEqualSlices(u8, &expected_root, &retained.trees.items[0].root());
    // Shared immutable storage is retained, never cloned per request.
    try std.testing.expect(materials.fixed_tree.columns.ptr == retained.trees.items[0].columns.ptr);
    materials.deinit();
    owner_live = false;
    try std.testing.expectEqualSlices(u8, &expected_root, &retained.trees.items[0].root());
}
