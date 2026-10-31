//! Serialized receipt/receiver trust boundaries, independent of native receipts.
const std = @import("std");
const A = @import("../rv64_authenticated_execution.zig");
const Chain = @import("../rv64_ethereum_chain.zig");
const Receipt = @import("../rv64_ethereum_batch_receipt.zig");
const Request = @import("../rv64_ethereum_request.zig");
const rv = A.frontend.rv64;
const wire = @import("stwo_proof_wire");
const a = std.testing.allocator;
const pc: u64 = 4096;
const program = [_]u32{ 0x01100093, 0x00108093 };
fn publicFor(policy: *const A.R.policy.Policy) !A.Public {
    var final: [32]u64 = @splat(0);
    final[1] = 17;
    var clocks: [32]u32 = @splat(0);
    clocks[1] = 3;
    return .{ .cpu = .{ .execution_profile = .ethereum_services_v2, .arithmetic_policy = .division_multiplication_services_v3, .state_policy = .cyclic_v2, .division_roster = .none, .multiplication_roster = .none, .roster = .none, .division_requests = 0, .keccak_calls = 0, .statement = .{ .program = .{ .base = pc, .words = &program }, .steps = 1, .initial_pc = pc, .final_pc = pc + 4, .initial_registers = @splat(0), .final_registers = final, .register_clocks = clocks, .cells = &.{}, .memory_clocks = &.{}, .opcodes = try A.rv.program.opcode_policy.derive(.{ .base = pc, .words = &program }, .ethereum_services_v2) } }, .geometry = .chunk512, .before = @splat(0), .after = @splat(0), .policy_identity = policy.identity, .ram = null };
}
fn emptyClaims() A.Claims {
    const z = A.Q.zero();
    return .{ .cpu = .{ .cpu = .{ .state = z, .rom = z, .bytes = z, .bitwise = z, .shifts = z }, .division = z, .header = z, .permutation = z, .chi = z, .xor5 = z, .bridge = z, .bytes = z }, .ram = null };
}
test "serialized Ethereum receipt enforces schema empty program slot and strict typed JSON" {
    var config = Request.Config{ .elf = "", .input = "", .elf_sha256 = "", .input_sha256 = "", .expected_output = "", .symbols = std.mem.zeroes(rv.ethereum_contract.Symbols), .output_directory = "", .terminal_pc = 0 };
    try Request.validateBudget(config);
    config.workers = 33;
    try std.testing.expectError(error.InvalidEthereumProofBudget, Request.validateBudget(config));
    config.workers = 0;
    try Request.validateBudget(config);
    const automatic = try Request.effectiveWorkers(config);
    try std.testing.expect(automatic >= 1 and automatic <= 16);
    config.workers = 4;
    try std.testing.expectEqual(@as(usize, 4), try Request.effectiveWorkers(config));
    config.batch_steps = 1 << 22;
    try std.testing.expectError(error.InvalidEthereumProofBudget, Request.validateBudget(config));
    var policy = try A.R.policy.Policy.init(a, &.{.{ .first = pc, .last = pc + 7, .flags = 5 }});
    defer policy.deinit();
    const public = try publicFor(&policy);
    var authority = try A.Full.ProgramAuthority.init(a, public.cpu.statement.program, .ethereum_services_v2);
    defer authority.deinit();
    const receipt = Receipt.Receipt.create(0, 0, public, emptyClaims(), "proof bytes are separately pinned");
    const json = try std.json.Stringify.valueAlloc(a, receipt, .{});
    defer a.free(json);
    const decoded = try std.json.parseFromSlice(Receipt.Receipt, a, json, .{});
    defer decoded.deinit();
    const bound = try decoded.value.bound(&authority);
    try std.testing.expectEqualSlices(u32, &program, bound.cpu.statement.program.words);
    try std.testing.expectEqual(@as(u64, pc), bound.cpu.statement.program.base);
    var bad = decoded.value;
    bad.schema = "rv64-authenticated-ethereum-batch-v999";
    try std.testing.expectError(error.InvalidEthereumBatchReceipt, bad.bound(&authority));
    bad = decoded.value;
    bad.public.cpu.statement.program = .{ .base = pc, .words = &program };
    try std.testing.expectError(error.InvalidEthereumBatchReceipt, bad.bound(&authority));
    var other_profile = try A.Full.ProgramAuthority.init(a, public.cpu.statement.program, .ethereum_services_v1);
    defer other_profile.deinit();
    try std.testing.expectError(error.InvalidEthereumBatchReceipt, decoded.value.bound(&other_profile));
    for ([_][]const u8{ "\"unknown_authority\":true,", "\"schema\":\"duplicate\"," }) |prefix| {
        const malformed = try std.fmt.allocPrint(a, "{{{s}{s}", .{ prefix, json[1..] });
        defer a.free(malformed);
        if (std.json.parseFromSlice(Receipt.Receipt, a, malformed, .{})) |accepted| {
            accepted.deinit();
            return error.AcceptedMalformedReceipt;
        } else |_| {}
    }
    if (std.json.parseFromSlice(Receipt.Receipt, a, json[0 .. json.len - 1], .{})) |accepted| {
        accepted.deinit();
        return error.AcceptedTruncatedReceipt;
    } else |_| {}
    try std.testing.expectError(error.EthereumInputIdentityMismatch, Request.pin("altered", &receipt.proof_sha256));
    try Request.pin("proof bytes are separately pinned", &receipt.proof_sha256);
}

test "Ethereum cursor rejects out of order coverage root register PC and each service ID gap" {
    var policy = try A.R.policy.Policy.init(a, &.{.{ .first = pc, .last = pc + 7, .flags = 5 }});
    defer policy.deinit();
    const public = try publicFor(&policy);
    var cursor = Chain.Cursor{ .root = public.before, .pc = pc, .registers = @splat(0) };
    try cursor.check(public, 0, 0, 10);
    var canonical = public;
    canonical.cpu.state_policy = .cyclic_canonical_v3;
    try std.testing.expectError(error.InvalidEthereumBatchAdjacency, cursor.check(canonical, 0, 0, 10));
    var canonical_cursor = cursor;
    canonical_cursor.expected_state_policy = .cyclic_canonical_v3;
    try canonical_cursor.check(canonical, 0, 0, 10);
    try std.testing.expectError(error.InvalidEthereumBatchAdjacency, canonical_cursor.check(public, 0, 0, 10));
    try std.testing.expectError(error.InvalidEthereumBatchAdjacency, cursor.check(public, 1, 0, 10));
    try std.testing.expectError(error.InvalidEthereumBatchAdjacency, cursor.check(public, 0, 1, 10));
    try std.testing.expectError(error.InvalidEthereumBatchAdjacency, cursor.check(public, 0, 0, 0));
    for (0..3) |which| {
        var bad = public;
        switch (which) {
            0 => bad.before[0] = 1,
            1 => bad.cpu.statement.initial_registers[1] = 1,
            2 => bad.cpu.statement.initial_pc ^= 1 << 32,
            else => unreachable,
        }
        try std.testing.expectError(error.InvalidEthereumBatchAdjacency, cursor.check(bad, 0, 0, 10));
    }
    for (0..3) |which| {
        var bad = public;
        switch (which) {
            0 => bad.cpu.first_call_id = 2,
            1 => bad.cpu.secp.add.first_id = 2,
            2 => bad.cpu.secp.double.first_id = 2,
            else => unreachable,
        }
        try std.testing.expectError(error.InvalidEthereumServiceCoverage, cursor.check(bad, 0, 0, 10));
    }
    // Only a physical verifier authorizes this transition. The cursor stores no
    // producer receipt as proof authority and checks all next starting fields.
    try cursor.advanceVerified(public);
    try std.testing.expectEqual(@as(u64, 1), cursor.steps);
    try std.testing.expectEqual(@as(u32, 1), cursor.batches);
    try std.testing.expectError(error.InvalidEthereumBatchAdjacency, cursor.check(public, 0, 0, 10));
    var adjacent = public;
    adjacent.cpu.statement.initial_pc = public.cpu.statement.final_pc;
    adjacent.cpu.statement.initial_registers = public.cpu.statement.final_registers;
    adjacent.cpu.statement.final_pc += 4;
    adjacent.cpu.statement.final_registers[1] = 18;
    try cursor.check(adjacent, 1, 1, 10);
}

test "serialized physical receipt binds expected program authority instead of producer ROM" {
    var policy = try A.R.policy.Policy.init(a, &.{.{ .first = pc, .last = pc + 7, .flags = 5 }});
    defer policy.deinit();
    const public = try publicFor(&policy);
    var authority = try A.Full.ProgramAuthority.init(a, public.cpu.statement.program, .ethereum_services_v2);
    defer authority.deinit();
    var setup = try A.Prepared.initWithAuthority(a, public, &policy, &authority);
    defer setup.deinit();
    const record = rv.machine.Retirement{ .clock = 1, .pc = rv.Word.fromInt(pc), .next_pc = rv.Word.fromInt(pc + 4), .instruction = program[0], .opcode = .ADDI, .rs1 = 0, .rs2 = 0, .rd = 1, .immediate = rv.Word.fromInt(17), .lhs = rv.Word.fromInt(0), .rhs = rv.Word.fromInt(0), .previous_rd = rv.Word.fromInt(0), .result = rv.Word.fromInt(17), .writes_rd = true, .branch_taken = false, .memory = null };
    var full = try A.Full.Trace.initWithPrivateBoundary(a, &.{record}, .{}, public.cpu.statement, .{ .cells = &.{}, .memory_clocks = &.{} }, &setup.cpu.base.program, &setup.cpu.base.plan);
    var full_owned = true;
    defer if (full_owned) full.deinit();
    var trace = try A.CPU.Trace.fromCpu(a, full, public.cpu, &setup.cpu);
    full_owned = false;
    defer trace.deinit();
    var bundle = try A.proveTrace(a, &setup, public, &trace, null);
    defer bundle.deinit(a);
    const bytes = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(bytes);
    const receipt = Receipt.Receipt.create(0, 0, public, bundle.claims, bytes);
    const json = try std.json.Stringify.valueAlloc(a, receipt, .{});
    defer a.free(json);
    const parsed = try std.json.parseFromSlice(Receipt.Receipt, a, json, .{});
    defer parsed.deinit();
    try Request.pin(bytes, &parsed.value.proof_sha256);
    const expected = try parsed.value.bound(&authority);
    var receiver = try A.Prepared.initWithAuthority(a, expected, &policy, &authority);
    defer receiver.deinit();
    try receiver.verifyOwned(a, expected, parsed.value.claims, try wire.decodeProofBytesBinary(a, bytes));
    const changed = [_]u32{ program[0] ^ 0x00100000, program[1] };
    var wrong_authority = try A.Full.ProgramAuthority.init(a, .{ .base = pc, .words = &changed }, .ethereum_services_v2);
    defer wrong_authority.deinit();
    const wrong_expected = try parsed.value.bound(&wrong_authority);
    var wrong_receiver = try A.Prepared.initWithAuthority(a, wrong_expected, &policy, &wrong_authority);
    defer wrong_receiver.deinit();
    try std.testing.expectError(error.AuthenticatedExecutionFixedRootMismatch, wrong_receiver.verifyOwned(a, wrong_expected, parsed.value.claims, try wire.decodeProofBytesBinary(a, bytes)));
}

test "merged RAM BYTE mass rejects before first fixed allocation while each roster is admitted" {
    var policy = try A.R.policy.Policy.init(a, &.{.{ .first = pc, .last = pc + 7, .flags = 5 }});
    defer policy.deinit();
    var layout = (try publicFor(&policy)).layout();
    layout.cpu.statement.steps = (1 << 22) - 1;
    layout.cpu.roster = .paired;
    layout.cpu.bridge_log = 22;
    layout.cpu.multiplication_roster = .present;
    layout.cpu.multiplication_log = 22;
    layout.ram = .{ .hashes = 65536, .common_chunks = 32768, .edge_chunks = 32768, .nodes = 262144, .sides = 1 << 22, .edge_permits = 1 << 21 };
    const shape = try layout.ram.?.shapes(.chunk512);
    const ram_mass = try A.RAM.boundByteMass(shape);
    const prime = @import("stwo_core").fields.m31.Modulus;
    try std.testing.expect(ram_mass < prime);
    try std.testing.expect(try A.I.boundInternalMass(shape) < prime);
    const plan = try A.Full.planForStatementWithProfiles(layout.cpu.statement, layout.cpu.arithmetic_policy, layout.cpu.execution_profile);
    const base = (@as(u64, 1) << 22) * (plan.range_count + 40 + 96);
    var found = false;
    outer: for ([_]u32{ 20, 21, 22 }) |product_log| {
        for ([_]u32{ 18, 19, 20, 21, 22 }) |linear_log| {
            for ([_]u32{ 18, 19, 20, 21, 22 }) |bridge_log| {
                layout.cpu.secp.add = .{ .roster = .present, .calls = 0, .geometry = .{ .product_log = product_log, .linear_log = linear_log, .bridge_log = bridge_log } };
                const secp_mass = layout.cpu.secp.validate(.ethereum_services_v2, layout.cpu.statement.steps) catch continue;
                const cpu_mass = base + secp_mass.byte_queries;
                if (cpu_mass >= prime or cpu_mass + ram_mass < prime) continue;
                try layout.cpu.validate(); // No individual CPU/provider cap fails.
                var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
                try std.testing.expectError(error.AuthenticatedExecutionLookupMassExceeded, A.Prepared.initForLayout(failing.allocator(), layout, &policy, null));
                try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
                found = true;
                break :outer;
            }
        }
    }
    try std.testing.expect(found);
}
