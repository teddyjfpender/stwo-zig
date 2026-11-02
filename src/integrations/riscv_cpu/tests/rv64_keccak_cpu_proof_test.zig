const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
const proof = @import("../rv64_keccak_cpu.zig");
const Cell = @import("../rv64_full_statement.zig").Cell;
const Q = @import("stwo_core").fields.qm31.QM31;
const a = std.testing.allocator;
// Two calls reuse a 200-byte state across a page boundary; ordinary SD/LD
// interleave with the service RAM network, DIV signed/W, AND and SRA arithmetic.
test "service CPU one PCS joins ECALL Keccak ROM DIV bytes and RAM clocks" {
    try run(.inverse_v1, .division_service_v2);
}
test "cyclic state service CPU one PCS and compact tape proof parity" {
    try run(.cyclic_v2, .division_service_v2);
}
test "MUL typed CPU one PCS joins all5 multiplication DIV Keccak RAM and shared bytes" {
    try run(.cyclic_v2, .division_multiplication_services_v3);
}
fn run(state_policy: air.state_policy.Policy, arithmetic_policy: air.arithmetic.division.policy.Policy) !void {
    const work = @import("stwo_prover_engine").work_pool;
    const workers = std.process.getEnvVarOwned(a, "STWO_RV64_KECCAK_CPU_WORKERS") catch null;
    defer if (workers) |text| a.free(text);
    var pool: work.WorkPool = .{};
    var owns_pool = false;
    defer if (owns_pool) pool.deinit();
    var binding: ?work.ScopedPoolBinding = null;
    defer if (binding) |*scope| scope.deinit();
    if (workers) |text| {
        try pool.initInPlaceWithOptions(.{ .worker_count = try std.fmt.parseInt(usize, text, 10), .stack_size = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024, .backing_allocator = a });
        owns_pool = true;
        binding = try work.ScopedPoolBinding.init(&pool);
    }
    const pc: u64 = 0x100001000;
    const ptr: u64 = 0xf123456780001ff8;
    const base_program = [_]u32{ 0x0220c1bb, 0x00353023, 0x00000073, 0x00053303, 0x00000073, 0x00053383, 0x002375b3, 0x40235633 };
    const mul_program = [_]u32{ 0x0220c1bb, 0x022086b3, 0x02209733, 0x0220b7b3, 0x0220a833, 0x0220893b, 0x00353023, 0x00000073, 0x00053303, 0x00000073, 0x00053383, 0x002375b3, 0x40235633 };
    const program: []const u32 = if (arithmetic_policy == .division_service_v2) &base_program else &mul_program;
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = pc, .size = program.len * 4, .permissions = .{ .read = true, .execute = true } });
    try memory.map(.{ .start = ptr, .size = 200, .permissions = .{ .read = true, .write = true } });
    for (program, 0..) |raw, i| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, raw, .little);
        try memory.initialize(pc + 4 * i, &bytes);
    }
    var cells: [25]Cell = undefined;
    for (&cells, 0..) |*cell, lane| {
        const value: u64 = @as(u64, @intCast(lane + 1)) *% 0x9e3779b97f4a7c15;
        cell.* = .{ .address = ptr + 8 * lane, .initial = value, .final = 0, .readable = true, .writable = true };
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .little);
        try memory.initialize(cell.address, &bytes);
    }
    var cpu = rv.machine.Cpu.init(pc, 0);
    cpu.regs[1] = if (arithmetic_policy == .division_multiplication_services_v3) 0x9234567880000001 else 0x1234567880000001;
    cpu.regs[2] = if (arithmetic_policy == .division_multiplication_services_v3) 0xfffffffffffffff4 else 2;
    cpu.regs[10] = ptr;
    cpu.regs[17] = rv.execution_profile.KECCAK_TAG;
    const initial = cpu.regs;
    var session = try rv.services.Session.init(a, cpu, &memory, .{});
    defer session.deinit();
    var record_storage: [13]rv.machine.Retirement = undefined;
    const records = record_storage[0..program.len];
    var calls: [2]rv.services.Call = undefined;
    var count: usize = 0;
    var reg_clocks: [32]u32 = @splat(0);
    var mem_clocks: [25]u32 = @splat(0);
    for (records, 0..) |*record, i| {
        var call: rv.services.Call = undefined;
        record.* = (try session.step(&call)) orelse blk: {
            calls[count] = call;
            count += 1;
            @memset(&mem_clocks, @intCast(4 * call.clock));
            break :blk call.retirement();
        };
        const decoded = try rv.execution_profile.decode(.keccak_service_v1, record.instruction);
        const effects = rv.execution_profile.effects(.keccak_service_v1, record.opcode);
        if (effects.reads_rs1 and decoded.rs1 != 0) reg_clocks[decoded.rs1] = @intCast(4 * i + 1);
        if (effects.reads_rs2 and decoded.rs2 != 0) reg_clocks[decoded.rs2] = @intCast(4 * i + 2);
        if (effects.writes_rd and decoded.rd != 0) reg_clocks[decoded.rd] = @intCast(4 * i + 3);
        if (record.memory) |event| mem_clocks[@intCast((event.address.toInt() - ptr) / 8)] = @intCast(4 * i + 4);
    }
    for (&cells) |*cell| cell.final = try memory.load(cell.address, 8);
    const public = proof.Public{ .arithmetic_policy = arithmetic_policy, .multiplication_requests = if (arithmetic_policy == .division_multiplication_services_v3) 5 else 0, .state_policy = state_policy, .statement = .{ .program = .{ .base = pc, .words = program }, .steps = @intCast(program.len), .initial_pc = pc, .final_pc = session.base.cpu.pc, .initial_registers = initial, .final_registers = session.base.cpu.regs, .cells = &cells, .register_clocks = reg_clocks, .memory_clocks = &mem_clocks, .opcodes = try air.program.opcode_policy.derive(.{ .base = pc, .words = program }, .keccak_service_v1) }, .division_requests = 1, .keccak_calls = 2, .bridge_log = 6 };
    var setup = try proof.PreparedSetup.init(a, public);
    defer setup.deinit();
    var unused = public;
    unused.division_requests = 0;
    unused.multiplication_requests = 0;
    unused.keccak_calls = 0;
    unused.first_call_id = 37;
    var empty_setup = try proof.PreparedSetup.init(a, unused);
    defer empty_setup.deinit();
    try std.testing.expectEqualSlices(u8, &setup.root, &empty_setup.root);
    try std.testing.expectEqualSlices(u8, &setup.cacheIdentity(), &empty_setup.cacheIdentity());
    try std.testing.checkAllAllocationFailures(a, initializeRelease, .{ records, &calls, public, &setup.materials });
    var trace = try proof.Trace.init(a, records, &calls, public, &setup.materials);
    defer trace.deinit();
    try std.testing.expectEqual(@as(u32, @intCast(4 * (calls[0].clock - 1))), trace.cpu.service_calls[0].previous_clocks[0]);
    try std.testing.expectEqual(@as(u32, @intCast(4 * (calls[1].clock - 1))), trace.cpu.service_calls[1].previous_clocks[0]);
    var tape = try rv.compact_tape.Tape.init(a, @intCast(program.len), pc, 1 << 40, .keccak_service_v1);
    defer tape.deinit();
    var service_at: usize = 0;
    for (records) |record| {
        if (record.opcode == .ECALL) {
            var call = calls[service_at];
            call.clock += tape.initial_clock;
            try tape.appendService(call);
            service_at += 1;
        } else {
            var global = record;
            global.clock += tape.initial_clock;
            try tape.append(global);
        }
    }
    var compact = try proof.Trace.initCompact(a, &tape, public, &setup.materials);
    defer compact.deinit();
    const state_count: usize = if (state_policy == .inverse_v1) 36 else 12;
    try std.testing.expectEqual(state_count, setup.materials.base.plan.stateInteractionCount());
    const legacy_interaction = 36 + 8 + air.range.cpu.interactionCount(&setup.materials.base.plan) + air.range.table_cpu.interactionCount(&setup.materials.base.plan, .byte_and) + air.range.table_cpu.interactionCount(&setup.materials.base.plan, .byte_shift);
    try std.testing.expectEqual(legacy_interaction - (36 - state_count), trace.cpu.interactionCount());
    try std.testing.expectEqualSlices(@import("stwo_core").fields.m31.M31, trace.cpu.main, compact.cpu.main);
    try std.testing.expectEqualSlices(@import("stwo_core").fields.m31.M31, trace.crypto.?.bridge.main, compact.crypto.?.bridge.main);
    try std.testing.expectEqualSlices(air.crypto.keccak.bridge.trace.Call, trace.cpu.service_calls, compact.cpu.service_calls);
    try std.testing.expectEqualSlices(u32, &trace.cpu.register_clocks, &compact.cpu.register_clocks);
    var bundle = try proof.proveTrace(a, &setup, public, &trace);
    defer bundle.deinit(a);
    if (arithmetic_policy == .division_multiplication_services_v3) {
        // Old D2 CPU constructor cannot silently admit a pruned MUL plan.
        const Full = @import("../rv64_full.zig");
        var channel = air.protocol.Channel{};
        const ch = Full.Support.challenges(&channel, &setup.materials.base);
        try std.testing.expectError(error.InvalidRv64FullPlan, Full.Support.SharedComponents.initWithServices(&setup.materials.base, public.statement, ch, bundle.claims.cpu, .{ .challenges = air.arithmetic.division.provider.Challenges.draw(&channel), .claim = Q.zero() }, .{ .challenges = air.crypto.keccak.bridge.equations.CallChallenges.draw(&channel), .claim = Q.zero(), .calls = public.keccak_calls, .first_call_id = public.first_call_id }));
        // Collude across CPU terminal register and typed provider output. Both
        // state and lookup claims agree, while real high-product math is false.
        var forged_storage: [13]rv.machine.Retirement = undefined;
        const forged = forged_storage[0..records.len];
        @memcpy(forged, records);
        forged[2].result = rv.Word.fromInt(forged[2].result.toInt() ^ 1);
        var forged_public = public;
        forged_public.statement.final_registers[14] ^= 1;
        var forged_trace = try proof.Trace.init(a, forged, &calls, forged_public, &setup.materials);
        defer forged_trace.deinit();
        try std.testing.expectError(error.ConstraintsNotSatisfied, proof.proveTrace(a, &setup, forged_public, &forged_trace));
    }

    const wire = @import("stwo_proof_wire");
    const state_count_for_mask = setup.materials.base.plan.stateInteractionCount();
    for (0..state_count_for_mask) |i| try std.testing.expectEqual(@as(usize, if (i >= state_count_for_mask - 4) 2 else 1), bundle.proof.commitment_scheme_proof.sampled_values.items[2][i].len);
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    var compact_bundle = try proof.proveTrace(a, &setup, public, &compact);
    defer compact_bundle.deinit(a);
    const compact_encoded = try wire.encodeProofBytesBinary(a, compact_bundle.proof);
    defer a.free(compact_encoded);
    try std.testing.expectEqualSlices(u8, encoded, compact_encoded);

    const artifact = std.process.getEnvVarOwned(a, if (arithmetic_policy == .division_multiplication_services_v3) "STWO_RV64_MUL_CPU_ARTIFACT_DIR" else if (state_policy == .inverse_v1) "STWO_RV64_KECCAK_CPU_ARTIFACT_DIR" else "STWO_RV64_KECCAK_CPU_CYCLIC_ARTIFACT_DIR") catch null;
    defer if (artifact) |path| a.free(path);
    if (artifact) |path| {
        try std.fs.cwd().makePath(path);
        var directory = try std.fs.cwd().openDir(path, .{});
        defer directory.close();
        const public_json = try std.json.Stringify.valueAlloc(a, public, .{});
        defer a.free(public_json);
        const claims_json = try std.json.Stringify.valueAlloc(a, bundle.claims, .{});
        defer a.free(claims_json);
        try directory.writeFile(.{ .sub_path = "public.json", .data = public_json });
        try directory.writeFile(.{ .sub_path = "claims.json", .data = claims_json });
        try directory.writeFile(.{ .sub_path = "proof.bin", .data = encoded });
        const counter_column = setup.materials.base.plan.main_count + air.full.frame.WIDTH;
        var wrong = try wire.decodeProofBytesBinary(a, encoded);
        defer wrong.deinit(a);
        try std.testing.expectEqual(@as(usize, 2), wrong.commitment_scheme_proof.sampled_values.items[1][counter_column].len);
        wrong.commitment_scheme_proof.sampled_values.items[1][counter_column][1] = wrong.commitment_scheme_proof.sampled_values.items[1][counter_column][1].add(Q.one());
        const corrupt = try wire.encodeProofBytesBinary(a, wrong);
        defer a.free(corrupt);
        try directory.writeFile(.{ .sub_path = "bad-count-prefix.bin", .data = corrupt });
        var state_wrong = try wire.decodeProofBytesBinary(a, encoded);
        defer state_wrong.deinit(a);
        const state_column = setup.materials.base.plan.stateInteractionCount() - 1;
        state_wrong.commitment_scheme_proof.sampled_values.items[2][state_column][1] = state_wrong.commitment_scheme_proof.sampled_values.items[2][state_column][1].add(Q.one());
        const state_corrupt = try wire.encodeProofBytesBinary(a, state_wrong);
        defer a.free(state_corrupt);
        try directory.writeFile(.{ .sub_path = "bad-state-prefix.bin", .data = state_corrupt });
        if (arithmetic_policy == .division_multiplication_services_v3) {
            const cpu_base_inter = trace.cpu.interactionCount();
            const provider_start = cpu_base_inter + 24 + 8 * setup.materials.base.providerCount() + air.arithmetic.division.layout.INTERACTION;
            const columns = [_]usize{ cpu_base_inter + 20, provider_start + air.arithmetic.multiplication.layout.INTERACTION - 1 };
            for (columns, 0..) |column, family| {
                var changed = try wire.decodeProofBytesBinary(a, encoded);
                defer changed.deinit(a);
                try std.testing.expectEqual(@as(usize, 2), changed.commitment_scheme_proof.sampled_values.items[2][column].len);
                changed.commitment_scheme_proof.sampled_values.items[2][column][1] = changed.commitment_scheme_proof.sampled_values.items[2][column][1].add(Q.one());
                const corrupt_mul = try wire.encodeProofBytesBinary(a, changed);
                defer a.free(corrupt_mul);
                try directory.writeFile(.{ .sub_path = if (family == 0) "bad-cpu-mul-prefix.bin" else "bad-mul-provider-prefix.bin", .data = corrupt_mul });
            }
        }
    }
    var receiver = try proof.PreparedSetup.init(a, public);
    defer receiver.deinit();
    try std.testing.expectEqualSlices(u8, &setup.root, &receiver.root);
    try receiver.verifyOwned(a, public, bundle.claims, try wire.decodeProofBytesBinary(a, encoded));
    var bad = bundle.claims;
    bad.header = bad.header.add(Q.one());
    try std.testing.expectError(error.Rv64ServiceGlobalClosure, receiver.verifyOwned(a, public, bad, try wire.decodeProofBytesBinary(a, encoded)));
    // A producer cannot hide a wrong header claim behind an equal/opposite
    // bridge claim: global closure passes, but both AIR components bind them.
    bad.bridge = bad.bridge.sub(Q.one());
    if (receiver.verifyOwned(a, public, bad, try wire.decodeProofBytesBinary(a, encoded))) |_| return error.AcceptedBalancedFalseHeader else |_| {}
    var altered_cells = cells;
    altered_cells[3].final ^= 1;
    var altered_public = public;
    altered_public.statement.cells = &altered_cells;
    if (receiver.verifyOwned(a, altered_public, bundle.claims, try wire.decodeProofBytesBinary(a, encoded))) |_| return error.AcceptedWrongServiceRamBoundary else |_| {}
}

fn initializeRelease(allocator: std.mem.Allocator, records: []const rv.machine.Retirement, calls: []const rv.services.Call, public: proof.Public, setup: *const proof.PreparedMaterials) !void {
    var trace = try proof.Trace.init(allocator, records, calls, public, setup);
    defer trace.deinit();
}
