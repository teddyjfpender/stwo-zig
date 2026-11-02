const std = @import("std");
const front = @import("stwo_riscv_frontend");
const F = @import("zbb_fixture.zig");
const V3 = @import("v3_fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const W = @import("wire.zig");
const T = @import("types.zig");
const HR = @import("../sha256/roster.zig");
const AR = @import("../arith256/roster.zig");
const G = @import("../protocol.zig");
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const a = std.testing.allocator;


test "v3_zbb: every Zbb BINARY instruction plus the v3 services verify in-process and with fresh keys over the wire" {
    try roundTrip(.historical, F.BRIDGES);
}

test "v3_zbb on the v3 default layout (fused tail + U8 pairs + LS-D64 + fused2 pairs): verify in-process and with fresh keys over the wire" {
    try roundTrip(.v3_default, F.V3_BRIDGES);
}

fn roundTrip(layout: F.Layout, bridges: [2]T.Logs) !void {
    var c = try F.Case.initLayout(a, .none, bridges, layout);
    defer c.deinit();
    for (c.setups) |s| {
        try std.testing.expectEqual(layout == .v3_default, s.materials.geometry.cpu_fused_tail);
        try std.testing.expectEqual(layout == .v3_default, s.materials.geometry.cpu_u8_pairs);
        try std.testing.expectEqual(layout == .v3_default, s.materials.geometry.mul_u8_pairs and s.materials.geometry.ls_fused_pairs and s.materials.geometry.alu_fused_tail and s.materials.geometry.ls_dword_fused_pairs);
    }
    for (c.bundle.cpus, F.DWORD_ROWS) |cpu, d| try std.testing.expectEqual(if (layout == .v3_default) d else 0, cpu.request.ls_dword);
    const keys = c.keys();
    const truths = c.truths();
    try E.verify(a, &keys, &truths, c.expected(), &c.bundle);
    // Known answers from the executor's own registers.
    const regs = c.final_registers;
    try std.testing.expectEqual(@as(u64, 0xffff_ffff_ffff_ff80), regs[22]); // sext.b 0x80
    try std.testing.expectEqual(@as(u64, 0x7f), regs[23]); // sext.b 0x7f
    try std.testing.expectEqual(@as(u64, 0xffff_ffff_ffff_8000), regs[24]); // sext.h 0x8000
    try std.testing.expectEqual(@byteSwap(regs[9]), regs[25]); // rev8
    try std.testing.expectEqual(regs[25], regs[26]); // SD/LD round trip
    try std.testing.expectEqual(regs[15] & 0xffff, regs[27]); // zext.h
    try std.testing.expectEqual(~(regs[12] ^ regs[13]), regs[14]); // xnor
    for (c.bundle.cpus) |cpu| try std.testing.expect(!cpu.claims.zbb.function.isZero());
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try W.write(a, tmp.dir, &keys, &truths, &c.bundle);
    var loaded = try W.read(a, tmp.dir, .{ .max_cpus = 2, .max_truths = 2, .max_total_steps = F.STEPS });
    defer loaded.deinit(a);
    for (bridges, loaded.cpu_declarations) |x, y| try std.testing.expect(std.meta.eql(x, y.bridges));
    // Fresh receiver: Zbb ROM and component keys rebuilt from the receiver's program and profile.
    var s0 = try R.CpuSetup.initProgramWithProfile(a, F.programImage(), loaded.cpu_declarations[0].geometry, bridges[0], F.PROFILE);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgramWithProfile(a, F.programImage(), loaded.cpu_declarations[1].geometry, bridges[1], F.PROFILE);
    defer s1.deinit();
    var sha = try HR.TruthSetup.init(a, V3.SHA_LOG);
    defer sha.deinit();
    var arith = try AR.TruthSetup.init(a, V3.ARITH_LOG);
    defer arith.deinit();
    const fresh = V3.truthsFor(&sha, &arith);
    const expected = F.expectedFor(s0.materials.program.identity, c.final_registers);
    try E.verify(a, &.{ &s0, &s1 }, &fresh, expected, &loaded.bundle);

    // A receiver whose ROM is not the Zbb ROM cannot even key a Zbb component.
    try std.testing.expectError(error.UnexpectedZbbComponent, R.CpuSetup.initProgramWithProfile(a, F.programImage(), loaded.cpu_declarations[0].geometry, bridges[0], .ethereum_services_v3));
    // A Zbb ROM without the Zbb component rejects the proof (presence/roster).
    var bare_logs = bridges[1];
    bare_logs.zbb = null;
    var bare = try R.CpuSetup.initProgramWithProfile(a, F.programImage(), loaded.cpu_declarations[1].geometry, bare_logs, F.PROFILE);
    defer bare.deinit();
    try std.testing.expectError(error.GlobalExecutionInventoryMismatch, E.verify(a, &.{ &s0, &bare }, &fresh, expected, &loaded.bundle));
    // A v3 (RV64IM) ROM receiver with no Zbb component rejects it too
    // (different program identity; Zbb words are invalid ROM entries).
    var v3_logs = bridges;
    v3_logs[0].zbb = null;
    v3_logs[1].zbb = null;
    var r0 = try R.CpuSetup.initProgramWithProfile(a, F.programImage(), loaded.cpu_declarations[0].geometry, v3_logs[0], .ethereum_services_v3);
    defer r0.deinit();
    var r1 = try R.CpuSetup.initProgramWithProfile(a, F.programImage(), loaded.cpu_declarations[1].geometry, v3_logs[1], .ethereum_services_v3);
    defer r1.deinit();
    try std.testing.expectError(error.GlobalExecutionInventoryMismatch, E.verify(a, &.{ &r0, &r1 }, &fresh, F.expectedFor(r0.materials.program.identity, c.final_registers), &loaded.bundle));
    // Tampered Zbb claims are rejected.
    const saved = loaded.bundle.cpus[1].claims.zbb;
    loaded.bundle.cpus[1].claims.zbb.function = loaded.bundle.cpus[1].claims.zbb.function.add(G.Q.one());
    try std.testing.expectError(error.OodsNotMatching, E.verify(a, &.{ &s0, &s1 }, &fresh, expected, &loaded.bundle));
    loaded.bundle.cpus[1].claims.zbb = saved;
    try E.verify(a, &.{ &s0, &s1 }, &fresh, expected, &loaded.bundle);
}

test "v3_zbb adversarial: forged CPU results with true provider facts fail FUNCTION closure" {
    for ([_]F.Layout{ .historical, .v3_default }, [_][2]T.Logs{ F.BRIDGES, F.V3_BRIDGES }) |layout, bridges| for ([_]F.Mutation{ .forged_zbb_result, .forged_zext_result }) |m| {
        // The prover produces locally valid proofs; only the CPU's FUNCTION
        // closure (request c' != provider c) rejects them.
        var c = try F.Case.initLayout(a, m, bridges, layout);
        defer c.deinit();
        const keys = c.keys();
        const truths = c.truths();
        try std.testing.expectError(error.UnclosedCombinedCpuRelations, E.verify(a, &keys, &truths, c.expected(), &c.bundle));
    };
}

test "v3_zbb fail closed: missing Zbb component, Zbb component on a non-Zbb ROM, mismatched tape/ROM profiles" {
    // The prover refuses a Zbb shard without its Zbb provider.
    var logs = F.BRIDGES;
    logs[0].zbb = null;
    try std.testing.expectError(error.MissingZbbComponent, F.Case.init(a, .none, logs));
    // A v3_zbb tape cannot be captured against a v3 (RV64IM) ROM, nor a v3
    // tape against the Zbb ROM.
    var captured = try F.Captured.init(a, .none);
    defer captured.deinit();
    const Program = @import("../../word16_execution/program.zig").Program;
    var v2_rom = try Program.init(a, F.programImage());
    defer v2_rom.deinit();
    const boundary = captured.native[0].cpu.?.public;
    try std.testing.expectError(error.UnqualifiedWord16ServiceOwners, Native.captureForCombinedServicesV3(a, &v2_rom, boundary, 1, F.CPU_LOG, &captured.tapes[0], .{}));
    var v3_tape = try front.rv64.compact_tape.Tape.init(a, 1, 4096, 0, .ethereum_services_v3);
    defer v3_tape.deinit();
    try std.testing.expectError(error.UnqualifiedWord16ServiceOwners, Native.captureForCombinedServicesV3(a, captured.program, boundary, 1, F.CPU_LOG, &v3_tape, .{}));
    // A plain v3 program never gets a Zbb component key.
    try std.testing.expectError(error.UnexpectedZbbComponent, R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &V3.WORDS }, try captured.native[0].geometry(), .{ .zbb = 5 }));
}
