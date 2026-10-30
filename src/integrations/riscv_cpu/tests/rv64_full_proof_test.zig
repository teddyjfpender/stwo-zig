const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
const native = @import("../rv64_full.zig");
const wire = @import("stwo_proof_wire");
const Q = @import("stwo_core").fields.qm31.QM31;

test "full native proof closes private-path execution and rejects substituted claims" {
    const a = std.testing.allocator;
    const program = [_]u32{0x00100093};
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 0x1000, .size = 4, .permissions = .{ .read = true, .execute = true } });
    var code: [4]u8 = undefined;
    std.mem.writeInt(u32, &code, program[0], .little);
    try memory.initialize(0x1000, &code);
    var cpu = rv.machine.Cpu.init(0x1000, 0);
    const records = [_]rv.machine.Retirement{try cpu.step(&memory)};
    var statement = native.Statement{ .program = .{ .base = 0x1000, .words = &program }, .steps = 1, .initial_pc = 0x1000, .final_pc = cpu.pc, .initial_registers = @splat(0), .final_registers = cpu.regs, .cells = &.{}, .register_clocks = @splat(0), .memory_clocks = &.{}, .opcodes = @splat(false) };
    statement.opcodes[@intFromEnum(rv.decode.Opcode.ADDI)] = true;
    statement.register_clocks[1] = 3;
    var setup = try native.PreparedSetup.init(a, statement);
    defer setup.deinit();
    var trace = try native.Trace.init(a, &records, statement, &setup.program, &setup.plan);
    defer trace.deinit();
    var other_allocator = std.heap.ArenaAllocator.init(a);
    defer other_allocator.deinit();
    const retained_main = trace.main_backing.ptr;
    try std.testing.expectError(error.Rv64FullCommitAllocatorMismatch, native.proveTrace(other_allocator.allocator(), &setup, statement, &trace));
    try std.testing.expectEqual(retained_main, trace.main_backing.ptr);
    var bundle = try native.proveTrace(a, &setup, statement, &trace);
    defer bundle.deinit(a);
    try std.testing.expectEqual(@as(usize, 0), trace.main.len);
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    // Stage capture is observational: the same request must retain exact wire
    // bytes, including transcript challenges, openings, and PoW nonce.
    const Stage = @import("stwo_prover_api").stage_profile;
    var recorder = Stage.Recorder.initWithOptions(a, "cpu", "rv64-full-test", .{ .capture_tasks = false });
    defer recorder.deinit();
    var profiled_trace = try native.Trace.init(a, &records, statement, &setup.program, &setup.plan);
    defer profiled_trace.deinit();
    var profiled = try native.proveTraceProfiled(a, &setup, statement, &profiled_trace, &recorder);
    defer profiled.deinit(a);
    const profiled_bytes = try wire.encodeProofBytesBinary(a, profiled.proof);
    defer a.free(profiled_bytes);
    try std.testing.expectEqualSlices(u8, encoded, profiled_bytes);
    var stages = try recorder.snapshot(a);
    defer stages.deinit(a);
    try std.testing.expect(stages.stages.len > 0);
    // A fresh receiving setup derives the combined preprocessing root itself.
    var receiver = try native.PreparedSetup.init(a, statement);
    defer receiver.deinit();
    try receiver.verifyOwned(a, statement, bundle.claims, try wire.decodeProofBytesBinary(a, encoded));
    var wrong = bundle.claims;
    wrong.state = wrong.state.add(Q.one());
    try std.testing.expectError(error.Rv64FullStateClosure, receiver.verifyOwned(a, statement, wrong, try wire.decodeProofBytesBinary(a, encoded)));
    wrong = bundle.claims;
    wrong.rom = Q.zero();
    wrong.rom.c0.a.v = @import("stwo_core").fields.m31.Modulus;
    try std.testing.expectError(error.InvalidRv64FullClaimEncoding, receiver.verifyOwned(a, statement, wrong, try wire.decodeProofBytesBinary(a, encoded)));
    wrong = bundle.claims;
    wrong.rom = wrong.rom.add(Q.one());
    try std.testing.expectError(error.OodsNotMatching, receiver.verifyOwned(a, statement, wrong, try wire.decodeProofBytesBinary(a, encoded)));
    var corrupted = try wire.decodeProofBytesBinary(a, encoded);
    const sample = &corrupted.commitment_scheme_proof.sampled_values.items[1][setup.plan.main_count + air.full.frame.NEXT_PC][1];
    sample.* = sample.add(Q.one());
    try std.testing.expectError(error.OodsNotMatching, receiver.verifyOwned(a, statement, bundle.claims, corrupted));
    var substituted = statement;
    substituted.final_registers[1] = 2;
    try std.testing.expectError(error.Rv64FullStateClosure, receiver.verifyOwned(a, substituted, bundle.claims, try wire.decodeProofBytesBinary(a, encoded)));
}

fn setupAndRelease(a: std.mem.Allocator) !void {
    const program = [_]u32{0x00100093};
    var final: [32]u64 = @splat(0);
    final[1] = 1;
    var statement = native.Statement{ .program = .{ .base = 0x1000, .words = &program }, .steps = 1, .initial_pc = 0x1000, .final_pc = 0x1004, .initial_registers = @splat(0), .final_registers = final, .cells = &.{}, .register_clocks = @splat(0), .memory_clocks = &.{}, .opcodes = @splat(false) };
    statement.register_clocks[1] = 3;
    statement.opcodes[@intFromEnum(rv.decode.Opcode.ADDI)] = true;
    var setup = try native.PreparedSetup.init(a, statement);
    defer setup.deinit();
}
test "full native immutable setup releases every failed allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, setupAndRelease, .{});
}

test "full native immutable setup is reused across fresh execution boundaries" {
    const a = std.testing.allocator;
    const program = [_]u32{ 0x00100093, 0x00200093 }; // x1=1; x1=2
    var original_final: [32]u64 = @splat(0);
    original_final[1] = 2;
    var original = native.Statement{ .program = .{ .base = 0x1000, .words = &program }, .steps = 2, .initial_pc = 0x1000, .final_pc = 0x1008, .initial_registers = @splat(0), .final_registers = original_final, .cells = &.{}, .register_clocks = @splat(0), .memory_clocks = &.{}, .opcodes = @splat(false) };
    original.opcodes[@intFromEnum(rv.decode.Opcode.ADDI)] = true;
    original.register_clocks[1] = 7;
    var setup = try native.PreparedSetup.init(a, original);
    defer setup.deinit();

    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 0x1000, .size = 8, .permissions = .{ .read = true, .execute = true } });
    for (program, 0..) |raw, i| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, raw, .little);
        try memory.initialize(0x1000 + 4 * i, &bytes);
    }
    var fresh = original;
    fresh.steps = 1;
    fresh.initial_pc = 0x1004;
    fresh.initial_registers[1] = 99;
    fresh.initial_registers[2] = 17;
    fresh.register_clocks[1] = 3;
    var cpu = rv.machine.Cpu.init(fresh.initial_pc, 0);
    cpu.regs = fresh.initial_registers;
    const records = [_]rv.machine.Retirement{try cpu.step(&memory)};
    fresh.final_pc = cpu.pc;
    fresh.final_registers = cpu.regs;
    try fresh.validate();
    try std.testing.expectEqual(original.logSize(), fresh.logSize());

    var trace = try native.Trace.init(a, &records, fresh, &setup.program, &setup.plan);
    defer trace.deinit();
    var bundle = try native.proveTrace(a, &setup, fresh, &trace);
    defer bundle.deinit(a);
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    // The reused setup receives the newly expected request, including its own
    // initial state and clocks. No original execution boundary grants authority.
    try setup.verifyOwned(a, fresh, bundle.claims, try wire.decodeProofBytesBinary(a, encoded));
    var receiver = try native.PreparedSetup.init(a, fresh);
    defer receiver.deinit();
    try std.testing.expectEqualSlices(u8, &setup.root, &receiver.root);
    try receiver.verifyOwned(a, fresh, bundle.claims, try wire.decodeProofBytesBinary(a, encoded));
    try std.testing.expectError(error.Rv64FullStateClosure, setup.verifyOwned(a, original, bundle.claims, try wire.decodeProofBytesBinary(a, encoded)));

    const altered_program = [_]u32{ 0x00100093, 0x00300093 };
    var changed = fresh;
    changed.program.words = &altered_program;
    try std.testing.expectError(error.Rv64FullSetupMismatch, setup.verifyOwned(a, changed, bundle.claims, try wire.decodeProofBytesBinary(a, encoded)));
    changed = fresh;
    changed.opcodes[@intFromEnum(rv.decode.Opcode.ADD)] = true;
    try std.testing.expectError(error.Rv64FullSetupMismatch, setup.verifyOwned(a, changed, bundle.claims, try wire.decodeProofBytesBinary(a, encoded)));
    changed = fresh;
    changed.steps = 33;
    try std.testing.expectError(error.Rv64FullSetupMismatch, setup.verifyOwned(a, changed, bundle.claims, try wire.decodeProofBytesBinary(a, encoded)));
}
