const std = @import("std");
const native = @import("stwo_riscv_cpu_integration").rv64;
const wire = @import("stwo_proof_wire");

test "rv64 proof: authenticated arithmetic memory roundtrip verifies after witness destruction" {
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 512 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    const program = [_]u32{ 0x00108093, 0x00108093, 0x00113023, 0x00013183, 0x001181b3 };
    var initial: [32]u64 = @splat(0);
    initial[1] = 0x12345678ffffffff;
    initial[2] = 0x200004000;
    var final = initial;
    final[1] +%= 2;
    final[3] = final[1] +% final[1];
    const cells = [_]@import("stwo_riscv_frontend").rv64_air.statement.Cell{.{ .address = initial[2], .initial = 0xaabbccddeeff0011, .final = final[1] }};
    const statement = native.Statement{ .program_base = 0x100001000, .program = &program, .initial_pc = 0x100001000, .final_pc = 0x100001014, .initial_registers = initial, .final_registers = final, .memory = &cells, .steps = program.len };
    var timer = try std.time.Timer.start();
    var bundle = try native.prove(a, statement);
    defer bundle.deinit(a);
    const prove_ns = timer.lap();
    const prove_peak_bytes = budget.snapshot().peak_live_bytes;
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    const encoding_ns = timer.lap();
    var setup = try native.PreparedSetup.init(a, statement, bundle.metadata);
    defer setup.deinit();
    const setup_ns = timer.lap();
    const decoded = try wire.decodeProofBytesBinary(a, encoded);
    try setup.verifyOwned(a, statement, bundle.metadata, decoded);
    std.debug.print("RV64_STARK verified=true queries=70 pow_bits=26 bytes={d} fixed={d} main={d} interaction=36 rows=32 prove_ns={d} encode_ns={d} setup_ns={d} verify_ns={d} prove_peak_caller_bytes={d}\n", .{ encoded.len, setup.projection.fixed_count, setup.projection.main_count, prove_ns, encoding_ns, setup_ns, timer.read(), prove_peak_bytes });
    // Fresh deserialization and fresh transcript for each independently expected
    // statement. Cached preprocessing never authorizes changed public state.
    var changed = statement;
    changed.initial_registers[1] ^= 1;
    try rejected(&setup, changed, bundle.metadata, encoded);
    changed = statement;
    changed.final_registers[3] ^= 1;
    try rejected(&setup, changed, bundle.metadata, encoded);
    changed = statement;
    changed.final_pc += 4;
    try rejected(&setup, changed, bundle.metadata, encoded);
    var changed_cells = cells;
    changed_cells[0].address ^= @as(u64, 1) << 40;
    changed = statement;
    changed.memory = &changed_cells;
    try rejected(&setup, changed, bundle.metadata, encoded);
    changed_cells = cells;
    changed_cells[0].readable = false;
    try rejected(&setup, changed, bundle.metadata, encoded);
    var changed_metadata = bundle.metadata;
    changed_metadata.register_clocks[1] -= 1;
    try rejected(&setup, statement, changed_metadata, encoded);
    var changed_program = program;
    changed_program[0] ^= 1 << 20;
    changed = statement;
    changed.program = &changed_program;
    try rejected(&setup, changed, bundle.metadata, encoded);
    var sampled = try wire.decodeProofBytesBinary(a, encoded);
    sampled.commitment_scheme_proof.sampled_values.items[1][0][0] = sampled.commitment_scheme_proof.sampled_values.items[1][0][0].add(@import("stwo_core").fields.qm31.QM31.one());
    if (setup.verifyOwned(a, statement, bundle.metadata, sampled)) |_| return error.CorruptedOpeningAccepted else |_| {}
    var weak = try wire.decodeProofBytesBinary(a, encoded);
    weak.commitment_scheme_proof.config.pow_bits = 0;
    try std.testing.expectError(error.InvalidRv64ProofConfig, setup.verifyOwned(a, statement, bundle.metadata, weak));
    var root = try wire.decodeProofBytesBinary(a, encoded);
    root.commitment_scheme_proof.commitments.items[0][0] ^= 1;
    try std.testing.expectError(error.UntrustedRv64Preprocessing, setup.verifyOwned(a, statement, bundle.metadata, root));
    // Keep ownership valid while deleting/expanding proof-controlled shapes.
    for (0..4) |kind| {
        var malformed = try wire.decodeProofBytesBinary(a, encoded);
        if (kind == 0) {
            const columns = malformed.commitment_scheme_proof.sampled_values.items[1];
            const empty = try a.alloc([]@import("stwo_core").fields.qm31.QM31, 0);
            for (columns) |column| a.free(column);
            a.free(columns);
            malformed.commitment_scheme_proof.sampled_values.items[1] = empty;
        } else if (kind < 3) {
            const column = &malformed.commitment_scheme_proof.sampled_values.items[1][0];
            const replacement = try a.alloc(@import("stwo_core").fields.qm31.QM31, if (kind == 1) 0 else 2);
            @memset(replacement, @import("stwo_core").fields.qm31.QM31.zero());
            a.free(column.*);
            column.* = replacement;
        } else {
            const values = &malformed.commitment_scheme_proof.queried_values.items[1];
            const empty = try a.alloc([]@import("stwo_core").fields.m31.M31, 0);
            for (values.*) |column| a.free(column);
            a.free(values.*);
            values.* = empty;
        }
        try std.testing.expectError(error.InvalidRv64ProofShape, setup.verifyOwned(a, statement, bundle.metadata, malformed));
    }
    // Same immutable program/path setup, different initial/final state request.
    var second = statement;
    second.initial_registers[10] = 99;
    second.final_registers[10] = 99;
    var second_bundle = try native.prove(a, second);
    defer second_bundle.deinit(a);
    const second_encoded = try wire.encodeProofBytesBinary(a, second_bundle.proof);
    defer a.free(second_encoded);
    try setup.verifyOwned(a, second, second_bundle.metadata, try wire.decodeProofBytesBinary(a, second_encoded));
    try rejected(&setup, statement, second_bundle.metadata, second_encoded);
}

fn rejected(setup: *const native.PreparedSetup, statement: native.Statement, metadata: native.Metadata, encoded: []const u8) !void {
    const proof = try wire.decodeProofBytesBinary(std.testing.allocator, encoded);
    if (setup.verifyOwned(std.testing.allocator, statement, metadata, proof)) |_| return error.InvalidProofAccepted else |_| {}
}

test "rv64 proof: all 63 retiring instructions share one authenticated proof" {
    const rv = @import("stwo_riscv_frontend").rv64;
    const a = std.testing.allocator;
    const program = [_]u32{
        0x002081b3, 0x402081b3, 0x00108193, 0x002081bb, 0x402081bb, 0x0010819b,
        0x0020f1b3, 0x0020e1b3, 0x0020c1b3, 0x0020a1b3, 0x0020b1b3, 0x002091b3,
        0x0020d1b3, 0x4020d1b3, 0x002091bb, 0x0020d1bb, 0x4020d1bb, 0x022081b3,
        0x022091b3, 0x0220a1b3, 0x0220b1b3, 0x022081bb, 0x0220c1b3, 0x0220d1b3,
        0x0220e1b3, 0x0220f1b3, 0x0220c1bb, 0x0220d1bb, 0x0220e1bb, 0x0220f1bb,
        0x800001b7, 0x80000197, 0xfff0a193, 0xfff0b193, 0xfff0c193, 0xfff0e193,
        0xfff0f193, 0x03f09193, 0x03f0d193, 0x43f0d193, 0x01f0919b, 0x01f0d19b,
        0x41f0d19b, 0x00008183, 0x00009183, 0x0000a183, 0x0000b183, 0x0000c183,
        0x0000d183, 0x0000e183, 0x00208023, 0x00209023, 0x0020a023, 0x0020b023,
        0x00208263, 0x00209263, 0x0020c263, 0x0020d263, 0x0020e263, 0x0020f263,
        0x004001ef, 0x0000000f, 0x000201e7,
    };
    var covered: [65]bool = @splat(false);
    for (program) |word| covered[@intFromEnum((try rv.decode.Instruction.decode(word)).opcode)] = true;
    for (covered[0..63]) |present| try std.testing.expect(present);
    const base: u64 = 0x100001000;
    const address: u64 = 0x200004000;
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = base, .size = program.len * 4, .permissions = .{ .read = true, .execute = true } });
    for (program, 0..) |word, i| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word, .little);
        try memory.initialize(base + 4 * i, &bytes);
    }
    try memory.map(.{ .start = address, .size = 8, .permissions = .{ .read = true, .write = true } });
    var cpu = rv.machine.Cpu.init(base, 0);
    cpu.regs[1] = address;
    cpu.regs[2] = 0x8000000000000001;
    cpu.regs[4] = base + 4 * program.len;
    const initial = cpu.regs;
    for (program) |_| _ = try cpu.step(&memory);
    const cells = [_]@import("stwo_riscv_frontend").rv64_air.statement.Cell{.{ .address = address, .initial = 0, .final = memory.backing.load(address, 8).value }};
    const statement = native.Statement{ .program_base = base, .program = &program, .initial_pc = base, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .memory = &cells, .steps = program.len };
    var bundle = try native.prove(a, statement);
    defer bundle.deinit(a);
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    try native.verifyOwned(a, statement, bundle.metadata, try wire.decodeProofBytesBinary(a, encoded));
    std.debug.print("RV64_STARK all_opcodes=63 steps={d} verified=true bytes={d}\n", .{ program.len, encoded.len });
}

// Test-only adversarial prover uses the core diagnostic capture. Production APIs
// retain no switch for suppressing the OODS check or accepting failed proofs.
test "rv64 proof: fresh verifier rejects arithmetic-valid forged source custody" {
    const rv = @import("stwo_riscv_frontend").rv64_air;
    const a = std.testing.allocator;
    const program = [_]u32{0x00108093}; // ADDI x1,x1,1
    var initial: [32]u64 = @splat(0);
    initial[1] = 5;
    var final = initial;
    final[1] = 7; // Impossible: the untrusted source supplies 6 instead of 5.
    const expected = native.Statement{ .program_base = 0x100001000, .program = &program, .initial_pc = 0x100001000, .final_pc = 0x100001004, .initial_registers = initial, .final_registers = final, .memory = &.{}, .steps = 1 };
    var forged = expected;
    forged.initial_registers[1] = 6;
    var witness = try rv.witness.Witness.build(a, forged);
    defer witness.deinit();
    try rejectPrepared(expected, &witness);
}

fn rejectPrepared(expected: native.Statement, witness: *const @import("stwo_riscv_frontend").rv64_air.witness.Witness) !void {
    const rv = @import("stwo_riscv_frontend").rv64_air;
    const core = @import("stwo_core");
    const engine = @import("stwo_prover_engine");
    const B = @import("stwo_cpu_backend").CpuBackend;
    const P = rv.protocol;
    const a = std.testing.allocator;
    var trace = try rv.trace.Trace.init(a, expected, witness.metadata, witness.rows);
    defer trace.deinit();
    var channel = P.Channel{};
    try P.mix(&channel, expected, witness.metadata, trace.log_size);
    const Scheme = engine.pcs.CommitmentSchemeProver(B, P.Hasher, P.MerkleChannel);
    var scheme = try Scheme.init(a, P.config());
    var owned = true;
    errdefer if (owned) scheme.deinit(a);
    const fixed = try trace.columns(a, 0);
    defer a.free(fixed);
    const main = try trace.columns(a, 1);
    defer a.free(main);
    try scheme.commit(a, fixed, &channel);
    try scheme.commit(a, main, &channel);
    const challenges = rv.relations.Challenges.draw(&channel);
    const target = try rv.relations.expected(expected, witness.metadata, challenges);
    const actual = try trace.generateInteraction(challenges);
    try std.testing.expect(!target.eql(actual));
    const interaction = try trace.columns(a, 2);
    defer a.free(interaction);
    try scheme.commit(a, interaction, &channel);
    var component = try rv.component.Component.init(trace.log_size, trace.projection, challenges, target);
    const components = [_]engine.air.component_prover.ComponentProver{component.asProverComponent()};
    var diagnostic: ?@import("stwo_prover_api").ProveDiagnostic = null;
    var failed: ?core.proof.ExtendedStarkProof(P.Hasher) = null;
    owned = false;
    try std.testing.expectError(error.ConstraintsNotSatisfied, engine.prove.proveExWithExecutionDiagnosedRetainingFailure(B, P.Hasher, P.MerkleChannel, a, &components, &channel, scheme, false, null, null, null, &diagnostic, &failed));
    var captured = failed orelse return error.MissingUnverifiedAdversarialProof;
    defer captured.deinit(a);
    const encoded = try wire.encodeProofBytesBinary(a, captured.proof);
    defer a.free(encoded);
    const decoded = try wire.decodeProofBytesBinary(a, encoded);
    try std.testing.expectError(error.OodsNotMatching, native.verifyOwned(a, expected, witness.metadata, decoded));
    std.debug.print("RV64_STARK forged_state_custody_rejected=true fresh_decode=true\n", .{});
}

test "rv64 proof: arithmetic-valid RAM value and permission forgeries fail fresh verification" {
    const rv = @import("stwo_riscv_frontend").rv64_air;
    const a = std.testing.allocator;
    const address: u64 = 0x200004000;
    for ([_]u32{ 0x00013183, 0x00113023 }) |word| { // LD x3,0(x2); SD x1,0(x2)
        const program = [_]u32{word};
        var initial: [32]u64 = @splat(0);
        initial[1] = 5;
        initial[2] = address;
        var final = initial;
        const load = word == 0x00013183;
        if (load) final[3] = 6;
        const expected_cells = [_]rv.statement.Cell{.{ .address = address, .initial = 5, .final = 5, .writable = load }};
        const expected = native.Statement{ .program_base = 0x100001000, .program = &program, .initial_pc = 0x100001000, .final_pc = 0x100001004, .initial_registers = initial, .final_registers = final, .memory = &expected_cells, .steps = 1 };
        var forged_cells = expected_cells;
        if (load) {
            forged_cells[0].initial = 6;
            forged_cells[0].final = 6;
        } else forged_cells[0].writable = true;
        var forged = expected;
        forged.memory = &forged_cells;
        var witness = try rv.witness.Witness.build(a, forged);
        defer witness.deinit();
        try rejectPrepared(expected, &witness);
    }
}

test "rv64 proof: backward control flow and all-register alias custody verify" {
    const a = std.testing.allocator;
    const program = [_]u32{ 0xfff10113, 0xfe011ee3, 0x001080b3 };
    var initial: [32]u64 = @splat(0);
    initial[1] = 0x87654321ffffffff;
    initial[2] = 3;
    var final = initial;
    final[1] +%= final[1];
    final[2] = 0;
    const statement = native.Statement{ .program_base = 0x100001000, .program = &program, .initial_pc = 0x100001000, .final_pc = 0x10000100c, .initial_registers = initial, .final_registers = final, .memory = &.{}, .steps = 7 };
    var bundle = try native.prove(a, statement);
    defer bundle.deinit(a);
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    try native.verifyOwned(a, statement, bundle.metadata, try wire.decodeProofBytesBinary(a, encoded));
}

fn setupAllocationCase(a: std.mem.Allocator) !void {
    const program = [_]u32{0x00100093};
    const initial: [32]u64 = @splat(0);
    var final = initial;
    final[1] = 1;
    const statement = native.Statement{ .program_base = 0x100001000, .program = &program, .initial_pc = 0x100001000, .final_pc = 0x100001004, .initial_registers = initial, .final_registers = final, .memory = &.{}, .steps = 1 };
    var witness = try @import("stwo_riscv_frontend").rv64_air.witness.Witness.build(a, statement);
    defer witness.deinit();
    var setup = try native.PreparedSetup.init(a, statement, witness.metadata);
    defer setup.deinit();
}
test "rv64 proof: every immutable setup allocation failure releases ownership" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, setupAllocationCase, .{});
}

test "rv64 proof: full resource envelope verifies at both larger domain sizes" {
    const a = std.testing.allocator;
    const rv = @import("stwo_riscv_frontend").rv64_air;
    var program: [rv.statement.MAX_PROGRAM_WORDS]u32 = @splat(0x0000000f);
    @memset(program[program.len - rv.statement.MAX_STEPS ..], 0x00013003); // LD x0,0(x2).
    var registers: [32]u64 = @splat(0);
    registers[2] = std.math.maxInt(u64) - 7;
    var cells: [rv.statement.MAX_CELLS]rv.statement.Cell = undefined;
    for (&cells, 0..) |*cell, i| cell.* = .{ .address = 0x200004000 + 8 * i, .initial = i, .final = i, .writable = false };
    cells[cells.len - 1].address = registers[2];
    const base: u64 = 0x100001000;
    const initial_pc = base + 4 * (program.len - rv.statement.MAX_STEPS);
    for ([_]u32{ 128, rv.statement.MAX_STEPS }) |steps| {
        const statement = native.Statement{ .program_base = base, .program = &program, .initial_pc = initial_pc, .final_pc = initial_pc + 4 * steps, .initial_registers = registers, .final_registers = registers, .memory = &cells, .steps = steps };
        var bundle = try native.prove(a, statement);
        defer bundle.deinit(a);
        try std.testing.expectEqual(@as(u16, @intCast(4 * steps)), bundle.metadata.memory_clocks[cells.len - 1]);
        try std.testing.expectEqual(@as(u16, @intCast(4 * steps - 3)), bundle.metadata.register_clocks[2]);
        const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
        defer a.free(encoded);
        try native.verifyOwned(a, statement, bundle.metadata, try wire.decodeProofBytesBinary(a, encoded));
        std.debug.print("RV64_STARK boundary_steps={d} program_words=4096 cells=128 verified=true\n", .{steps});
    }
}

test "rv64 proof: highest program address wraps PC and highest RAM word loads into x0" {
    const a = std.testing.allocator;
    const Cell = @import("stwo_riscv_frontend").rv64_air.statement.Cell;
    for ([_]bool{ false, true }) |load| {
        const program = [_]u32{if (load) 0x00013003 else 0x0040006f};
        const base = if (load) @as(u64, 0x100001000) else std.math.maxInt(u64) - 3;
        var registers: [32]u64 = @splat(0);
        if (load) registers[2] = std.math.maxInt(u64) - 7;
        const cells = [_]Cell{.{ .address = std.math.maxInt(u64) - 7, .initial = std.math.maxInt(u64), .final = std.math.maxInt(u64), .writable = false }};
        const statement = native.Statement{ .program_base = base, .program = &program, .initial_pc = base, .final_pc = base +% 4, .initial_registers = registers, .final_registers = registers, .memory = if (load) &cells else &.{}, .steps = 1 };
        var bundle = try native.prove(a, statement);
        defer bundle.deinit(a);
        const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
        defer a.free(encoded);
        try native.verifyOwned(a, statement, bundle.metadata, try wire.decodeProofBytesBinary(a, encoded));
    }
}

test "rv64 proof: sparse immutable code admits distant PCs and data gaps" {
    const a = std.testing.allocator;
    const Cell = @import("stwo_riscv_frontend").rv64_air.statement.Cell;
    const program = [_]u32{ 0x0001006f, 0x00108093 };
    const addresses = [_]u64{ 0x100001000, 0x100011000 };
    var initial: [32]u64 = @splat(0);
    initial[1] = 3;
    var final = initial;
    final[1] = 4;
    const cells = [_]Cell{.{ .address = 0x100002000, .initial = 99, .final = 99, .writable = false }};
    const statement = native.Statement{ .program_base = addresses[0], .program = &program, .program_addresses = &addresses, .initial_pc = addresses[0], .final_pc = addresses[1] + 4, .initial_registers = initial, .final_registers = final, .memory = &cells, .steps = 2 };
    var bundle = try native.prove(a, statement);
    defer bundle.deinit(a);
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    try native.verifyOwned(a, statement, bundle.metadata, try wire.decodeProofBytesBinary(a, encoded));
    var changed = statement;
    var different = addresses;
    different[1] += 4;
    changed.program_addresses = &different;
    if (native.verifyOwned(a, changed, bundle.metadata, try wire.decodeProofBytesBinary(a, encoded))) |_| return error.SparseSubstitutionAccepted else |_| {}
    var overlap = cells;
    overlap[0].address = addresses[1];
    changed = statement;
    changed.memory = &overlap;
    try std.testing.expectError(error.Rv64ProgramMemoryOverlap, changed.validate());
    different = addresses;
    different[1] = different[0];
    changed = statement;
    changed.program_addresses = &different;
    try std.testing.expectError(error.InvalidRv64Program, changed.validate());
    different[1] = addresses[1] + 1;
    try std.testing.expectError(error.InvalidRv64Program, changed.validate());
    changed.program_addresses = addresses[0..1];
    try std.testing.expectError(error.InvalidRv64Program, changed.validate());
}
