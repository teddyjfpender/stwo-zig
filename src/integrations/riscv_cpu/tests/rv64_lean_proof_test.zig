const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
const lean = @import("../rv64_lean.zig");
const full = @import("../rv64_full.zig");
const wire = @import("stwo_proof_wire");
const a = std.testing.allocator;

test "lean one PCS proof joins CPU ROM bytes AND SHIFT DIV signedW zero and RAM" {
    const work = @import("stwo_prover_engine").work_pool;
    const workers_env = std.process.getEnvVarOwned(a, "STWO_RV64_LEAN_WORKERS") catch null;
    defer if (workers_env) |value| a.free(value);
    var pool: work.WorkPool = .{};
    var owns_pool = false;
    defer if (owns_pool) pool.deinit();
    var binding: ?work.ScopedPoolBinding = null;
    defer if (binding) |*value| value.deinit();
    if (workers_env) |value| {
        try pool.initInPlaceWithOptions(.{ .worker_count = try std.fmt.parseInt(usize, value, 10), .stack_size = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024, .backing_allocator = a });
        owns_pool = true;
        binding = try work.ScopedPoolBinding.init(&pool);
    }
    const pc: u64 = 0x100001000;
    const address: u64 = 0xf123456780002000;
    var program: [65]u32 = @splat(0x00148493);
    @memcpy(program[0..8], &[_]u32{ 0x0220c1bb, 0x0220e2bb, 0x00323023, 0x00023303, 0x0200d3b3, 0x0200f433, 0x0051f533, 0x4021d5b3 });
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = pc, .size = program.len * 4, .permissions = .{ .read = true, .execute = true } });
    try memory.map(.{ .start = address, .size = 8, .permissions = .{ .read = true, .write = true } });
    for (program, 0..) |word, i| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word, .little);
        try memory.initialize(pc + 4 * i, &bytes);
    }
    var cpu = rv.machine.Cpu.init(pc, 0);
    cpu.regs[1] = 0x1234567880000001;
    cpu.regs[2] = 2;
    cpu.regs[4] = address;
    const initial = cpu.regs;
    var records: [65]rv.machine.Retirement = undefined;
    var register_clocks: [32]u32 = @splat(0);
    var allowed: [65]bool = @splat(false);
    for (&records, 0..) |*record, i| {
        record.* = try cpu.step(&memory);
        allowed[@intFromEnum(record.opcode)] = true;
        const instruction = try rv.decode.Instruction.decode(program[i]);
        const effects = rv.decode.effects(instruction.opcode);
        if (effects.reads_rs1 and instruction.rs1 != 0) register_clocks[instruction.rs1] = @intCast(4 * i + 1);
        if (effects.reads_rs2 and instruction.rs2 != 0) register_clocks[instruction.rs2] = @intCast(4 * i + 2);
        if (effects.writes_rd and instruction.rd != 0) register_clocks[instruction.rd] = @intCast(4 * i + 3);
    }
    try std.testing.expectEqual(@as(u64, 0xffffffffc0000001), cpu.regs[3]);
    try std.testing.expectEqual(@as(u64, 0xffffffffffffffff), cpu.regs[5]);
    try std.testing.expectEqual(cpu.regs[3], cpu.regs[6]);
    try std.testing.expectEqual(@as(u64, 0xffffffffffffffff), cpu.regs[7]);
    try std.testing.expectEqual(initial[1], cpu.regs[8]);
    try std.testing.expectEqual(@as(u64, 57), cpu.regs[9]);
    const ram = [_]@import("../rv64_full_statement.zig").Cell{.{ .address = address, .initial = 0, .final = cpu.regs[3], .readable = true, .writable = true }};
    const memory_clocks = [_]u32{16};
    const statement = full.Statement{ .program = .{ .base = pc, .words = &program }, .steps = 65, .initial_pc = pc, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .cells = &ram, .register_clocks = register_clocks, .memory_clocks = &memory_clocks, .opcodes = allowed };
    const public = lean.Public{ .statement = statement, .division_requests = 4 };
    try std.testing.expect((try public.byteQueryBudget()) < core.fields.m31.Modulus);
    var setup = try lean.PreparedSetup.init(a, public);
    defer setup.deinit();
    try std.testing.expectEqual(@as(u32, 7), setup.base.log_size);
    try std.testing.expectEqual(@as(u32, 5), setup.division_log);
    const artifact_dir = std.process.getEnvVarOwned(a, "STWO_RV64_LEAN_ARTIFACT_DIR") catch null;
    defer if (artifact_dir) |path| a.free(path);
    try std.testing.checkAllAllocationFailures(a, initializeRelease, .{ &records, public, &setup });
    // Same-allocator failures at all four header allocations preserve exactly
    // one owner. Once the CPU transfer succeeds, a later failure may consume
    // its source; DIV remains owned until the combined transfer succeeds.
    var provider_columns: [4]@import("stwo_prover_engine").pcs.ColumnEvaluation = undefined;
    const logs = [_]u32{ setup.base.program.log_size, 8, 16, 11 };
    for (&provider_columns, logs) |*column, log| {
        const values = try a.alloc(core.fields.m31.M31, @as(usize, 1) << @intCast(log));
        @memset(values, core.fields.m31.M31.zero());
        column.* = .{ .log_size = log, .values = values };
    }
    defer for (provider_columns) |column| a.free(column.values);
    for (0..5) |failure| {
        var failing = std.testing.FailingAllocator.init(a, .{});
        {
            var pending = try lean.Trace.init(failing.allocator(), &records, public, &setup);
            defer pending.deinit();
            var other = std.heap.ArenaAllocator.init(a);
            defer other.deinit();
            const before = pending.cpu.main_backing.ptr;
            try std.testing.expectError(error.Rv64FullCommitAllocatorMismatch, pending.takeMainForCommit(other.allocator(), &provider_columns));
            try std.testing.expectEqual(before, pending.cpu.main_backing.ptr);
            failing.fail_index = failing.alloc_index + failure;
            if (failure < 4) {
                try std.testing.expectError(error.OutOfMemory, pending.takeMainForCommit(failing.allocator(), &provider_columns));
                try std.testing.expectEqual(failure < 2, pending.cpu.main.len != 0);
                try std.testing.expect(pending.division.main.len != 0);
            } else {
                var transfer = try pending.takeMainForCommit(failing.allocator(), &provider_columns);
                defer transfer.deinit(failing.allocator());
                try std.testing.expectEqual(@as(usize, 0), pending.cpu.main.len);
                try std.testing.expectEqual(@as(usize, 0), pending.division.main.len);
            }
        }
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
    var trace = try lean.Trace.init(a, &records, public, &setup);
    defer trace.deinit();
    // Old coordinator remains fail closed with a service plan; no source moves.
    var incompatible = try full.PreparedSetup.initWithPolicy(a, statement, .division_service_v2);
    defer incompatible.deinit();
    try std.testing.expect(!@hasField(full.PreparedMaterials, "root"));
    try std.testing.expectError(error.InvalidRv64FullPlan, full.proveTrace(a, &incompatible, statement, &trace.cpu));
    var bundle = try lean.proveTrace(a, &setup, public, &trace);
    defer bundle.deinit(a);
    try std.testing.expectEqual(@as(usize, 0), trace.cpu.main.len);
    try std.testing.expectEqual(@as(usize, 0), trace.division.main.len);
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    if (artifact_dir) |path| {
        try std.fs.cwd().makePath(path);
        var directory = try std.fs.cwd().openDir(path, .{});
        defer directory.close();
        const public_bytes = try std.json.Stringify.valueAlloc(a, public, .{});
        defer a.free(public_bytes);
        const claims_bytes = try std.json.Stringify.valueAlloc(a, bundle.claims, .{});
        defer a.free(claims_bytes);
        try directory.writeFile(.{ .sub_path = "public.json", .data = public_bytes });
        try directory.writeFile(.{ .sub_path = "claims.json", .data = claims_bytes });
        try directory.writeFile(.{ .sub_path = "proof.bin", .data = encoded });
    }
    var receiver = try lean.PreparedSetup.init(a, public);
    defer receiver.deinit();
    try receiver.verifyOwned(a, public, bundle.claims, try wire.decodeProofBytesBinary(a, encoded));
    var changed = bundle.claims;
    changed.division = changed.division.add(core.fields.qm31.QM31.one());
    try std.testing.expectError(error.OodsNotMatching, receiver.verifyOwned(a, public, changed, try wire.decodeProofBytesBinary(a, encoded)));
    var bad_public = public;
    bad_public.statement.final_registers[3] ^= 1;
    try std.testing.expectError(error.Rv64FullStateClosure, receiver.verifyOwned(a, bad_public, bundle.claims, try wire.decodeProofBytesBinary(a, encoded)));
    var corrupted = try wire.decodeProofBytesBinary(a, encoded);
    const cpu_base_inter = air.layout.INTERACTION + 8 + air.range.cpu.interactionCount(&setup.base.plan) + air.range.table_cpu.interactionCount(&setup.base.plan, .byte_and) + air.range.table_cpu.interactionCount(&setup.base.plan, .byte_shift);
    const sample = &corrupted.commitment_scheme_proof.sampled_values.items[2][cpu_base_inter + 4][1];
    sample.* = sample.add(core.fields.qm31.QM31.one());
    if (artifact_dir) |path| {
        var directory = try std.fs.cwd().openDir(path, .{});
        defer directory.close();
        const changed_bytes = try wire.encodeProofBytesBinary(a, corrupted);
        defer a.free(changed_bytes);
        try directory.writeFile(.{ .sub_path = "bad-previous-prefix.bin", .data = changed_bytes });
    }
    try std.testing.expectError(error.OodsNotMatching, receiver.verifyOwned(a, public, bundle.claims, corrupted));
}

fn initializeRelease(allocator: std.mem.Allocator, records: []const rv.machine.Retirement, public: lean.Public, setup: *const lean.PreparedSetup) !void {
    var trace = try lean.Trace.init(allocator, records, public, setup);
    defer trace.deinit();
}

test "lean caller and service forgery fails arithmetic OODS consistency" {
    const program = [_]u32{0x0220d1b3}; // DIVU x3,x1,x2
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 0x1000, .size = 4, .permissions = .{ .read = true, .execute = true } });
    var code: [4]u8 = undefined;
    std.mem.writeInt(u32, &code, program[0], .little);
    try memory.initialize(0x1000, &code);
    var cpu = rv.machine.Cpu.init(0x1000, 0);
    cpu.regs[1] = 7;
    cpu.regs[2] = 3;
    const initial = cpu.regs;
    var record = try cpu.step(&memory);
    try std.testing.expectEqual(@as(u64, 2), record.result.toInt());
    record.result = @TypeOf(record.result).fromInt(1); // malicious producer
    var final = cpu.regs;
    final[3] = 1;
    var statement = full.Statement{ .program = .{ .base = 0x1000, .words = &program }, .steps = 1, .initial_pc = 0x1000, .final_pc = 0x1004, .initial_registers = initial, .final_registers = final, .cells = &.{}, .register_clocks = @splat(0), .memory_clocks = &.{}, .opcodes = @splat(false) };
    statement.register_clocks[1] = 1;
    statement.register_clocks[2] = 2;
    statement.register_clocks[3] = 3;
    statement.opcodes[@intFromEnum(rv.decode.Opcode.DIVU)] = true;
    const public = lean.Public{ .statement = statement, .division_requests = 1 };
    var setup = try lean.PreparedSetup.init(a, public);
    defer setup.deinit();
    var trace = try lean.Trace.init(a, &.{record}, public, &setup);
    defer trace.deinit();
    // CPU state, ROM, range and both typed bus claims agree on the forgery.
    // Only the independent division polynomials can rule it out.
    try std.testing.expectError(error.ConstraintsNotSatisfied, lean.proveTrace(a, &setup, public, &trace));
}

test "lean geometry key reuses across branch-dependent DIV counts with full ROM opcode policy" {
    const program = [_]u32{ 0x00008463, 0x025251b3, 0x02525333, 0x00138393, 0x0252043b }; // BEQ; DIVU; DIVU; ADDI; unreachable MULW
    var prepared: ?lean.PreparedSetup = null;
    defer if (prepared) |*value| value.deinit();
    for (0..2) |branch| {
        var memory = rv.memory.Memory.init(a, .{});
        defer memory.deinit();
        try memory.map(.{ .start = 0x1000, .size = program.len * 4, .permissions = .{ .read = true, .execute = true } });
        for (program, 0..) |raw, i| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, raw, .little);
            try memory.initialize(0x1000 + 4 * i, &bytes);
        }
        var cpu = rv.machine.Cpu.init(0x1000, 0);
        cpu.regs[1] = branch;
        cpu.regs[4] = 7;
        cpu.regs[5] = 3;
        const initial = cpu.regs;
        var records: [4]rv.machine.Retirement = undefined;
        var count: usize = 0;
        var clocks: [32]u32 = @splat(0);
        while (cpu.pc < 0x1010) : (count += 1) {
            if (count == records.len) return error.BadBranchFixture;
            records[count] = try cpu.step(&memory);
            const instruction = try rv.decode.Instruction.decode(records[count].instruction);
            const effects = rv.decode.effects(instruction.opcode);
            if (effects.reads_rs1 and instruction.rs1 != 0) clocks[instruction.rs1] = @intCast(4 * count + 1);
            if (effects.reads_rs2 and instruction.rs2 != 0) clocks[instruction.rs2] = @intCast(4 * count + 2);
            if (effects.writes_rd and instruction.rd != 0) clocks[instruction.rd] = @intCast(4 * count + 3);
        }
        const immutable = air.program.setup.Program{ .base = 0x1000, .words = &program };
        const allowed = try air.program.opcode_policy.derive(immutable, .rv64im);
        try std.testing.expect(allowed[@intFromEnum(rv.decode.Opcode.MULW)]);
        const statement = full.Statement{ .program = immutable, .steps = @intCast(count), .initial_pc = 0x1000, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .cells = &.{}, .register_clocks = clocks, .memory_clocks = &.{}, .opcodes = allowed };
        const public = lean.Public{ .statement = statement, .division_requests = @intCast(branch + 1) };
        var missing = public;
        missing.statement.opcodes[@intFromEnum(rv.decode.Opcode.MULW)] = false;
        try std.testing.expectError(error.InvalidRv64LeanOpcodePolicy, missing.validate());
        if (prepared == null) prepared = try lean.PreparedSetup.init(a, public);
        // Reuse the same program+geometry key, not a new setup per observed path.
        var trace = try lean.Trace.init(a, records[0..count], public, &prepared.?);
        defer trace.deinit();
        var bundle = try lean.proveTrace(a, &prepared.?, public, &trace);
        defer bundle.deinit(a);
        const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
        defer a.free(encoded);
        try prepared.?.verifyOwned(a, public, bundle.claims, try wire.decodeProofBytesBinary(a, encoded));
        var fresh = try lean.PreparedSetup.init(a, public);
        defer fresh.deinit();
        try std.testing.expectEqualSlices(u8, &prepared.?.root, &fresh.root);
        try std.testing.expectEqualSlices(u8, &prepared.?.cacheIdentity(), &fresh.cacheIdentity());
        try fresh.verifyOwned(a, public, bundle.claims, try wire.decodeProofBytesBinary(a, encoded));
    }
}
