//! No-call batches still admit ECALL in immutable program support. Its absence
//! follows from the CPU's constrained counter, not a path-pruned opcode policy.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
const service = @import("../rv64_keccak_cpu.zig");
const Cell = @import("../rv64_full_statement.zig").Cell;
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const wire = @import("stwo_proof_wire");
const a = std.testing.allocator;
test "absent Keccak roster proves ECALL absence and omits all crypto providers" {
    const pc: u64 = 0x100002000;
    const address: u64 = 0xf123456780004000;
    const words = [_]u32{ 0x00000463, 0x00000073, 0x0220c1bb, 0x00323023, 0x00023303, 0x002375b3, 0x40235633 };
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = pc, .size = words.len * 4, .permissions = .{ .read = true, .execute = true } });
    try memory.map(.{ .start = address, .size = 8, .permissions = .{ .read = true, .write = true } });
    for (words, 0..) |raw, i| {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, raw, .little);
        try memory.initialize(pc + 4 * i, &b);
    }
    var cpu = rv.machine.Cpu.init(pc, 0);
    cpu.regs[1] = 0x1234567880000001;
    cpu.regs[2] = 2;
    cpu.regs[4] = address;
    const initial = cpu.regs;
    var records: [6]rv.machine.Retirement = undefined;
    var registers: [32]u32 = @splat(0);
    for (&records, 0..) |*record, i| {
        record.* = try cpu.step(&memory);
        const instruction = try rv.execution_profile.decode(.keccak_service_v1, record.instruction);
        const effects = rv.execution_profile.effects(.keccak_service_v1, record.opcode);
        if (effects.reads_rs1 and instruction.rs1 != 0) registers[instruction.rs1] = @intCast(4 * i + 1);
        if (effects.reads_rs2 and instruction.rs2 != 0) registers[instruction.rs2] = @intCast(4 * i + 2);
        if (effects.writes_rd and instruction.rd != 0) registers[instruction.rd] = @intCast(4 * i + 3);
    }
    const cells = [_]Cell{.{ .address = address, .initial = 0, .final = try memory.load(address, 8), .readable = true, .writable = true }};
    const clocks = [_]u32{16};
    const public = service.Public{ .roster = .none, .state_policy = .cyclic_v2, .statement = .{ .program = .{ .base = pc, .words = &words }, .steps = records.len, .initial_pc = pc, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .register_clocks = registers, .cells = &cells, .memory_clocks = &clocks, .opcodes = try air.program.opcode_policy.derive(.{ .base = pc, .words = &words }, .keccak_service_v1) }, .division_requests = 1, .keccak_calls = 0 };
    try std.testing.expect(public.statement.opcodes[@intFromEnum(rv.decode.Opcode.ECALL)]);
    var setup = try service.PreparedSetup.init(a, public);
    defer setup.deinit();
    try std.testing.expect(setup.materials.crypto == null);
    try std.testing.checkAllAllocationFailures(a, initRelease, .{ &records, public, &setup.materials });
    var trace = try service.Trace.init(a, &records, &.{}, public, &setup.materials);
    defer trace.deinit();
    try std.testing.expect(trace.crypto == null);
    var bundle = try service.proveTrace(a, &setup, public, &trace);
    defer bundle.deinit(a);
    try std.testing.expect(bundle.claims.header.isZero() and bundle.claims.permutation.isZero() and bundle.claims.chi.isZero() and bundle.claims.xor5.isZero() and bundle.claims.bridge.isZero());
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    var receiver = try service.PreparedSetup.init(a, public);
    defer receiver.deinit();
    try receiver.verifyOwned(a, public, bundle.claims, try wire.decodeProofBytesBinary(a, encoded));
    for (0..5) |family| {
        var bad = bundle.claims;
        switch (family) {
            0 => bad.header = Q.one(),
            1 => bad.permutation = Q.one(),
            2 => bad.chi = Q.one(),
            3 => bad.xor5 = Q.one(),
            4 => bad.bridge = Q.one(),
            else => unreachable,
        }
        try std.testing.expectError(error.Rv64ServiceOmittedClaim, receiver.verifyOwned(a, public, bad, try wire.decodeProofBytesBinary(a, encoded)));
    }
    var invalid = public;
    invalid.keccak_calls = 1;
    try std.testing.expectError(error.InvalidRv64ServiceRoster, invalid.validate());
    var paired = public;
    paired.roster = .paired;
    var paired_setup = try service.PreparedSetup.init(a, paired);
    defer paired_setup.deinit();
    try std.testing.expect(!std.mem.eql(u8, &setup.root, &paired_setup.root));
    try std.testing.expect(!std.mem.eql(u8, &setup.cacheIdentity(), &paired_setup.cacheIdentity()));
    try std.testing.expectError(error.Rv64ServiceFixedRootMismatch, paired_setup.verifyOwned(a, paired, bundle.claims, try wire.decodeProofBytesBinary(a, encoded)));
    var paired_trace = try service.Trace.init(a, &records, &.{}, paired, &paired_setup.materials);
    defer paired_trace.deinit();
    var paired_bundle = try service.proveTrace(a, &paired_setup, paired, &paired_trace);
    defer paired_bundle.deinit(a);
    const paired_encoded = try wire.encodeProofBytesBinary(a, paired_bundle.proof);
    defer a.free(paired_encoded);
    var fresh_paired = try service.PreparedSetup.init(a, paired);
    defer fresh_paired.deinit();
    try fresh_paired.verifyOwned(a, paired, paired_bundle.claims, try wire.decodeProofBytesBinary(a, paired_encoded));
    try std.testing.expect(encoded.len < paired_encoded.len);
    std.debug.print("K roster same execution proof bytes none={d} pairedC0={d}\n", .{ encoded.len, paired_encoded.len });
    const artifact = std.process.getEnvVarOwned(a, "STWO_RV64_KECCAK_CPU_NONE_ARTIFACT_DIR") catch null;
    defer if (artifact) |path| a.free(path);
    if (artifact) |path| {
        try std.fs.cwd().makePath(path);
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        const p = try std.json.Stringify.valueAlloc(a, public, .{});
        defer a.free(p);
        const c = try std.json.Stringify.valueAlloc(a, bundle.claims, .{});
        defer a.free(c);
        try dir.writeFile(.{ .sub_path = "public.json", .data = p });
        try dir.writeFile(.{ .sub_path = "claims.json", .data = c });
        try dir.writeFile(.{ .sub_path = "proof.bin", .data = encoded });
        const size = try std.json.Stringify.valueAlloc(a, .{ .none_proof_bytes = encoded.len, .paired_c0_proof_bytes = paired_encoded.len, .identical_execution_and_admitted_program = true, .ethereum_block_proof = false }, .{});
        defer a.free(size);
        try dir.writeFile(.{ .sub_path = "roster-comparison.json", .data = size });
        for (0..2) |family| {
            var wrong = try wire.decodeProofBytesBinary(a, encoded);
            defer wrong.deinit(a);
            const tree: usize = if (family == 0) 1 else 2;
            const column = if (family == 0) setup.materials.base.plan.main_count + air.full.frame.WIDTH else setup.materials.base.plan.stateInteractionCount() - 1;
            wrong.commitment_scheme_proof.sampled_values.items[tree][column][1] = wrong.commitment_scheme_proof.sampled_values.items[tree][column][1].add(Q.one());
            const corrupt = try wire.encodeProofBytesBinary(a, wrong);
            defer a.free(corrupt);
            try dir.writeFile(.{ .sub_path = if (family == 0) "bad-count-prefix.bin" else "bad-state-prefix.bin", .data = corrupt });
        }
        try dir.makePath("paired-c0");
        var paired_dir = try dir.openDir("paired-c0", .{});
        defer paired_dir.close();
        const pp = try std.json.Stringify.valueAlloc(a, paired, .{});
        defer a.free(pp);
        const pcj = try std.json.Stringify.valueAlloc(a, paired_bundle.claims, .{});
        defer a.free(pcj);
        try paired_dir.writeFile(.{ .sub_path = "public.json", .data = pp });
        try paired_dir.writeFile(.{ .sub_path = "claims.json", .data = pcj });
        try paired_dir.writeFile(.{ .sub_path = "proof.bin", .data = paired_encoded });
    }
}
fn initRelease(allocator: std.mem.Allocator, records: []const rv.machine.Retirement, public: service.Public, setup: *const service.PreparedMaterials) !void {
    var trace = try service.Trace.init(allocator, records, &.{}, public, setup);
    defer trace.deinit();
}
