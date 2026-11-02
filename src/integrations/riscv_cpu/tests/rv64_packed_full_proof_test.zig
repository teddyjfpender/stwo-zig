const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const native = @import("../rv64_full.zig");
const wire = @import("stwo_proof_wire");
const a = std.testing.allocator;

test "standalone packed Full proves wrapped AUIPC and JALR with receiver-selected control" {
    const high: u64 = 0xfffffffffffff000;
    const addresses = [_]u64{ 0, high, high + 4, high + 8 };
    const words = [_]u32{ 0x00000013, 0x00001097, 0x00108093, 0x00008167 };
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 0, .size = 4, .permissions = .{ .read = true, .execute = true } });
    try memory.map(.{ .start = high, .size = 12, .permissions = .{ .read = true, .execute = true } });
    for (words, addresses) |raw, pc| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, raw, .little);
        try memory.initialize(pc, &bytes);
    }
    var cpu = rv.machine.Cpu.init(high, 0);
    var records: [3]rv.machine.Retirement = undefined;
    for (&records) |*record| record.* = try cpu.step(&memory);
    try std.testing.expectEqual(@as(u64, 0), cpu.pc);
    try std.testing.expectEqual(@as(u64, 1), cpu.regs[1]);
    try std.testing.expectEqual(high + 12, cpu.regs[2]);
    var public = native.Statement{ .program = .{ .base = 0, .words = &words, .addresses = &addresses }, .steps = 3, .initial_pc = high, .final_pc = cpu.pc, .initial_registers = @splat(0), .final_registers = cpu.regs, .cells = &.{}, .register_clocks = @splat(0), .memory_clocks = &.{}, .opcodes = @splat(false) };
    for ([_]rv.decode.Opcode{ .AUIPC, .ADDI, .JALR }) |op| public.opcodes[@intFromEnum(op)] = true;
    public.register_clocks[1] = 9;
    public.register_clocks[2] = 11;
    var packed_setup = try native.PreparedSetup.initWithControl(a, public, .limbs24_v2);
    defer packed_setup.deinit();
    var legacy = try native.PreparedSetup.init(a, public);
    defer legacy.deinit();
    try std.testing.expect(!std.mem.eql(u8, &packed_setup.root, &legacy.root));
    // Policy mismatch fails before ownership transfer or a main commitment.
    var mismatch = try native.Trace.init(a, &records, public, &legacy.materials.program, &legacy.materials.plan);
    defer mismatch.deinit();
    const retained = mismatch.main.ptr;
    try std.testing.expectError(error.InvalidRv64FullPlan, native.proveTrace(a, &packed_setup, public, &mismatch));
    try std.testing.expectEqual(retained, mismatch.main.ptr);
    var trace = try native.Trace.init(a, &records, public, &packed_setup.materials.program, &packed_setup.materials.plan);
    defer trace.deinit();
    var bundle = try native.proveTrace(a, &packed_setup, public, &trace);
    defer bundle.deinit(a);
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    var receiver = try native.PreparedSetup.initWithControl(a, public, .limbs24_v2);
    defer receiver.deinit();
    try receiver.verifyOwned(a, public, bundle.claims, try wire.decodeProofBytesBinary(a, encoded));
    if (legacy.verifyOwned(a, public, bundle.claims, try wire.decodeProofBytesBinary(a, encoded))) |_| return error.WrongTrustedControlAccepted else |_| {}
    var wrong_pc = public;
    wrong_pc.final_pc = 1 << 48;
    if (receiver.verifyOwned(a, wrong_pc, bundle.claims, try wire.decodeProofBytesBinary(a, encoded))) |_| return error.WrongTerminalPcAccepted else |_| {}
    const artifact = std.process.getEnvVarOwned(a, "STWO_RV64_PACKED_FULL_ARTIFACT_DIR") catch null;
    defer if (artifact) |path| a.free(path);
    if (artifact) |path| {
        try std.fs.cwd().makePath(path);
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        const statement_json = try std.json.Stringify.valueAlloc(a, public, .{});
        defer a.free(statement_json);
        const claims_json = try std.json.Stringify.valueAlloc(a, bundle.claims, .{});
        defer a.free(claims_json);
        try dir.writeFile(.{ .sub_path = "statement.json", .data = statement_json });
        try dir.writeFile(.{ .sub_path = "claims.json", .data = claims_json });
        try dir.writeFile(.{ .sub_path = "proof.bin", .data = encoded });
    }
}
