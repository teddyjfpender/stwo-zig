//! Explicit count-zero provider omission, retaining both authenticated CPU buses.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
const C = @import("../rv64_keccak_cpu.zig");
const wire = @import("stwo_proof_wire");
const Q = @import("stwo_core").fields.qm31.QM31;
const a = std.testing.allocator;
const pc: u64 = 4096;
const program = [_]u32{ 0x01100093, 0x0210c133, 0x021081b3 };
fn execute(records: []rv.machine.Retirement) !C.Public {
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = pc, .size = program.len * 4, .permissions = .{ .read = true, .execute = true } });
    for (program, 0..) |raw, i| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, raw, .little);
        try memory.initialize(pc + 4 * i, &bytes);
    }
    var cpu = rv.machine.Cpu.init(pc, 0);
    const initial = cpu.regs;
    var clocks: [32]u32 = @splat(0);
    for (records, 0..) |*record, i| {
        record.* = try cpu.step(&memory);
        const inst = try rv.execution_profile.decode(.ethereum_services_v2, record.instruction);
        const effects = rv.execution_profile.effects(.ethereum_services_v2, record.opcode);
        if (effects.reads_rs1 and inst.rs1 != 0) clocks[inst.rs1] = @intCast(4 * i + 1);
        if (effects.reads_rs2 and inst.rs2 != 0) clocks[inst.rs2] = @intCast(4 * i + 2);
        if (effects.writes_rd and inst.rd != 0) clocks[inst.rd] = @intCast(4 * i + 3);
    }
    return .{ .execution_profile = .ethereum_services_v2, .arithmetic_policy = .division_multiplication_services_v3, .state_policy = .cyclic_v2, .roster = .none, .division_requests = if (records.len > 1) 1 else 0, .multiplication_requests = if (records.len > 2) 1 else 0, .keccak_calls = 0, .statement = .{ .program = .{ .base = pc, .words = &program }, .steps = @intCast(records.len), .initial_pc = pc, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .register_clocks = clocks, .cells = &.{}, .memory_clocks = &.{}, .opcodes = try air.program.opcode_policy.derive(.{ .base = pc, .words = &program }, .ethereum_services_v2) } };
}
test "count-zero DIV MUL rosters omit provider openings while keeping CPU request buses" {
    var records: [1]rv.machine.Retirement = undefined;
    const present = try execute(&records);
    var omitted = present;
    omitted.division_roster = .none;
    omitted.multiplication_roster = .none;
    var setup = try C.PreparedSetup.init(a, omitted);
    defer setup.deinit();
    var control = try C.PreparedSetup.init(a, present);
    defer control.deinit();
    try std.testing.expect(setup.materials.division_fixed == null and setup.materials.multiplication_fixed == null);
    try std.testing.expect(!std.mem.eql(u8, &setup.root, &control.root));
    try std.testing.expect(!std.mem.eql(u8, &setup.cacheIdentity(), &control.cacheIdentity()));
    var trace = try C.Trace.initEthereum(a, &records, .{}, omitted, &setup.materials);
    defer trace.deinit();
    var control_trace = try C.Trace.initEthereum(a, &records, .{}, present, &control.materials);
    defer control_trace.deinit();
    var bundle = try C.proveTrace(a, &setup, omitted, &trace);
    defer bundle.deinit(a);
    var control_bundle = try C.proveTrace(a, &control, present, &control_trace);
    defer control_bundle.deinit(a);
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    const control_encoded = try wire.encodeProofBytesBinary(a, control_bundle.proof);
    defer a.free(control_encoded);
    const samples = bundle.proof.commitment_scheme_proof.sampled_values.items;
    const old_samples = control_bundle.proof.commitment_scheme_proof.sampled_values.items;
    try std.testing.expectEqual(@as(usize, air.arithmetic.division.layout.MAIN + air.arithmetic.multiplication.layout.MAIN), old_samples[1].len - samples[1].len);
    try std.testing.expectEqual(@as(usize, air.arithmetic.division.layout.INTERACTION + air.arithmetic.multiplication.layout.INTERACTION), old_samples[2].len - samples[2].len);
    try std.testing.expect(encoded.len < control_encoded.len);
    std.debug.print("Arithmetic count0 proof bytes present={d} omitted={d}, main columns removed={d}, inter removed={d}\n", .{ control_encoded.len, encoded.len, old_samples[1].len - samples[1].len, old_samples[2].len - samples[2].len });
    var receiver = try C.PreparedSetup.init(a, omitted);
    defer receiver.deinit();
    try receiver.verifyOwned(a, omitted, bundle.claims, try wire.decodeProofBytesBinary(a, encoded));
    var bad_claims = bundle.claims;
    bad_claims.division = Q.one();
    try std.testing.expectError(error.Rv64ServiceOmittedClaim, receiver.verifyOwned(a, omitted, bad_claims, try wire.decodeProofBytesBinary(a, encoded)));
    bad_claims = bundle.claims;
    bad_claims.multiplication = Q.one();
    bad_claims.multiplication_provider = Q.one().neg();
    try std.testing.expectError(error.Rv64ServiceOmittedClaim, receiver.verifyOwned(a, omitted, bad_claims, try wire.decodeProofBytesBinary(a, encoded)));
    var invalid = omitted;
    invalid.division_requests = 1;
    try std.testing.expectError(error.InvalidRv64ArithmeticRoster, invalid.validate());
    invalid = omitted;
    invalid.multiplication_log = 6;
    try std.testing.expectError(error.InvalidRv64ArithmeticRoster, invalid.validate());
    const artifact = std.process.getEnvVarOwned(a, "STWO_RV64_ARITH_NONE_ARTIFACT_DIR") catch null;
    defer if (artifact) |path| a.free(path);
    if (artifact) |path| {
        try std.fs.cwd().makePath(path);
        var directory = try std.fs.cwd().openDir(path, .{});
        defer directory.close();
        const json = try std.json.Stringify.valueAlloc(a, omitted, .{});
        defer a.free(json);
        const claims_json = try std.json.Stringify.valueAlloc(a, bundle.claims, .{});
        defer a.free(claims_json);
        const metrics = try std.json.Stringify.valueAlloc(a, .{ .present_bytes = control_encoded.len, .omitted_bytes = encoded.len, .main_columns_removed = old_samples[1].len - samples[1].len, .interaction_columns_removed = old_samples[2].len - samples[2].len, .cpu_main_columns = trace.cpu.plan.main_count + air.full.frame.width(omitted.execution_profile), .cpu_buses_retained = true }, .{});
        defer a.free(metrics);
        try directory.writeFile(.{ .sub_path = "public.json", .data = json });
        try directory.writeFile(.{ .sub_path = "claims.json", .data = claims_json });
        try directory.writeFile(.{ .sub_path = "metrics.json", .data = metrics });
        try directory.writeFile(.{ .sub_path = "proof.bin", .data = encoded });
        for ([_]struct { name: []const u8, column: usize }{ .{ .name = "bad-div-prefix.bin", .column = trace.cpu.interactionCount() + 4 }, .{ .name = "bad-mul-prefix.bin", .column = trace.cpu.interactionCount() + 20 } }) |opening| {
            var bad = try wire.decodeProofBytesBinary(a, encoded);
            defer bad.deinit(a);
            const values = bad.commitment_scheme_proof.sampled_values.items[2][opening.column];
            try std.testing.expectEqual(@as(usize, 2), values.len);
            values[1] = values[1].add(Q.one());
            const corrupt = try wire.encodeProofBytesBinary(a, bad);
            defer a.free(corrupt);
            try directory.writeFile(.{ .sub_path = opening.name, .data = corrupt });
        }
    }
}
test "omitted providers reject actual DIV and MUL even with colluding sparse advice" {
    var records: [3]rv.machine.Retirement = undefined;
    const present = try execute(&records);
    var control = try C.PreparedSetup.init(a, present);
    defer control.deinit();
    for ([_]bool{ false, true }) |mul| {
        var omitted = present;
        if (mul) {
            omitted.multiplication_roster = .none;
            omitted.multiplication_requests = 0;
        } else {
            omitted.division_roster = .none;
            omitted.division_requests = 0;
        }
        var setup = try C.PreparedSetup.init(a, omitted);
        defer setup.deinit();
        var trace = try C.Trace.initEthereum(a, &records, .{}, present, &control.materials);
        defer trace.deinit();
        if (mul) {
            trace.multiplication.?.deinit();
            trace.multiplication = null;
            a.free(trace.multiplication_indexed);
            trace.multiplication_indexed = &.{};
        } else {
            trace.division.?.deinit();
            trace.division = null;
            a.free(trace.indexed);
            trace.indexed = &.{};
        }
        try std.testing.expectError(error.ConstraintsNotSatisfied, C.proveTrace(a, &setup, omitted, &trace));
    }
}
