//! CPU/SIMD adapter for the backend-generic SM83 proving path.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const pcs_core = @import("stwo_core").pcs;
const frontend = @import("stwo_sm83_frontend");
const sm83_prover = frontend.prover;
const environment_prover = frontend.environment_prover;
const machine_environment_prover =
    frontend.machine_environment_prover;
const machine_environment_verifier =
    frontend.machine_environment_verifier;
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;

pub const CpuProverEngine = sm83_prover.ProverEngineForBackend(CpuBackend);
pub const EnvironmentProverEngine =
    environment_prover.ProverEngineForBackend(CpuBackend);
pub const MachineEnvironmentProverEngine =
    machine_environment_prover.ProverEngineForBackend(CpuBackend);
pub const MachineEnvironmentVerifierEngine =
    machine_environment_verifier.ProverEngineForBackend(CpuBackend);
pub const ExecutionStatement = sm83_prover.ExecutionStatement;
pub const ProveOutput = sm83_prover.ProveOutput;
pub const EnvironmentExecutionStatement =
    environment_prover.ExecutionStatement;
pub const EnvironmentProveOutput = environment_prover.ProveOutput;
pub const MachineEnvironmentInput = machine_environment_prover.Input;
pub const MachineEnvironmentProveOutput =
    machine_environment_prover.ProveOutput;
pub const MachineEnvironmentExecutionStatement =
    machine_environment_verifier.ExecutionStatement;

comptime {
    sm83_prover.assertProverEngine(CpuProverEngine);
    environment_prover.assertProverEngine(EnvironmentProverEngine);
    machine_environment_prover.assertProverEngine(
        MachineEnvironmentProverEngine,
    );
    machine_environment_verifier.assertProverEngine(
        MachineEnvironmentVerifierEngine,
    );
}

pub fn proveExecution(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: frontend.Rom,
    initial_memory: frontend.MemoryImage,
    final_memory: frontend.MemoryImage,
    steps: []const frontend.StepTrace,
) !ProveOutput {
    return sm83_prover.proveExecutionWithEngine(
        CpuProverEngine,
        allocator,
        pcs_config,
        rom,
        initial_memory,
        final_memory,
        steps,
    );
}

pub fn proveMachineExecution(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: frontend.Rom,
    initial_memory: frontend.MemoryImage,
    final_memory: frontend.MemoryImage,
    steps: []const frontend.MachineStepResult,
) !ProveOutput {
    return sm83_prover.proveMachineExecutionWithEngine(
        CpuProverEngine,
        allocator,
        pcs_config,
        rom,
        initial_memory,
        final_memory,
        steps,
    );
}

pub fn verifyExecution(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: frontend.Rom,
    initial_memory: frontend.MemoryImage,
    final_memory: frontend.MemoryImage,
    statement: ExecutionStatement,
    proof: sm83_prover.Proof,
) !void {
    return sm83_prover.verifyExecutionWithEngine(
        CpuProverEngine,
        allocator,
        pcs_config,
        rom,
        initial_memory,
        final_memory,
        statement,
        proof,
    );
}

pub fn proveEnvironmentExecution(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: frontend.cartridge.Cartridge,
    initial_images: frontend.air.cartridge_memory_lookup.Images,
    final_images: frontend.air.cartridge_memory_lookup.Images,
    initial_mcycle: u32,
    initial_joypad: frontend.runner.joypad.State,
    initial_timer: frontend.runner.timer.Timer,
    actions: []const frontend.action_schedule.Action,
    observations: []const frontend.ram_observation.Region,
    intermediate_observations: []const frontend.air.intermediate_ram_observation_lookup.Sample,
    steps: []const frontend.CartridgeStepTrace,
) !EnvironmentProveOutput {
    return environment_prover.proveExecutionWithEngine(
        EnvironmentProverEngine,
        allocator,
        pcs_config,
        rom,
        initial_images,
        final_images,
        initial_mcycle,
        initial_joypad,
        initial_timer,
        actions,
        observations,
        intermediate_observations,
        steps,
    );
}

pub fn verifyEnvironmentExecution(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: frontend.cartridge.Cartridge,
    initial_images: frontend.air.cartridge_memory_lookup.Images,
    final_images: frontend.air.cartridge_memory_lookup.Images,
    actions: []const frontend.action_schedule.Action,
    observations: []const frontend.ram_observation.Region,
    intermediate_observations: []const frontend.air.intermediate_ram_observation_lookup.Sample,
    statement: EnvironmentExecutionStatement,
    proof: environment_prover.Proof,
) !void {
    return environment_prover.verifyExecutionWithEngine(
        EnvironmentProverEngine,
        allocator,
        pcs_config,
        rom,
        initial_images,
        final_images,
        actions,
        observations,
        intermediate_observations,
        statement,
        proof,
    );
}

pub fn proveMachineEnvironmentExecution(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    input: MachineEnvironmentInput,
    options: @import("stwo_prover_engine").engine.ProveOptions,
) !MachineEnvironmentProveOutput {
    return machine_environment_prover.proveExecutionWithEngine(
        MachineEnvironmentProverEngine,
        allocator,
        pcs_config,
        input,
        options,
    );
}

pub fn verifyMachineEnvironmentExecution(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: frontend.cartridge.Cartridge,
    initial_images: frontend.air.cartridge_memory_lookup.Images,
    final_images: frontend.air.cartridge_memory_lookup.Images,
    actions: []const frontend.action_schedule.Action,
    observations: []const frontend.ram_observation.Region,
    intermediate_observations: []const frontend.air.intermediate_ram_observation_lookup.Sample,
    statement: MachineEnvironmentExecutionStatement,
    proof: machine_environment_verifier.Proof,
) !void {
    return machine_environment_verifier.verifyExecutionWithEngine(
        MachineEnvironmentVerifierEngine,
        allocator,
        pcs_config,
        rom,
        initial_images,
        final_images,
        actions,
        observations,
        intermediate_observations,
        statement,
        proof,
    );
}

fn testConfig() !pcs_core.PcsConfig {
    return .{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
}

fn testSteps(allocator: std.mem.Allocator) ![16]frontend.StepTrace {
    var memory = try frontend.Memory.init(allocator);
    defer memory.deinit();
    for (0..16) |address| memory.write(@intCast(address), 0x80);
    var state = frontend.Cpu{ .a = 1, .b = 1 };
    var steps: [16]frontend.StepTrace = undefined;
    for (&steps) |*step_value| step_value.* = try frontend.step(&state, &memory);
    return steps;
}

fn indirectAddSteps(allocator: std.mem.Allocator) ![16]frontend.StepTrace {
    var memory = try frontend.Memory.init(allocator);
    defer memory.deinit();
    for (0..16) |address| memory.write(@intCast(address), 0x86);
    memory.write(0x8000, 2);
    var state = frontend.Cpu{ .a = 1, .h = 0x80 };
    var steps: [16]frontend.StepTrace = undefined;
    for (&steps) |*step_value| step_value.* = try frontend.step(&state, &memory);
    return steps;
}

fn indirectIncrementSteps(allocator: std.mem.Allocator) ![16]frontend.StepTrace {
    var memory = try frontend.Memory.init(allocator);
    defer memory.deinit();
    for (0..16) |address| memory.write(@intCast(address), 0x34);
    memory.write(0x8000, 0x0f);
    var state = frontend.Cpu{ .f = 0x10, .h = 0x80 };
    var steps: [16]frontend.StepTrace = undefined;
    for (&steps) |*step_value| step_value.* = try frontend.step(&state, &memory);
    return steps;
}

const test_rom_bytes = [_]u8{0x80} ** @import("stwo_sm83_frontend").rom.SIZE;
const test_memory_bytes =
    test_rom_bytes ++
    [_]u8{0} ** (frontend.memory.SIZE - frontend.rom.SIZE);

fn testRom() frontend.Rom {
    return frontend.Rom.init(&test_rom_bytes) catch unreachable;
}

fn testMemory() frontend.MemoryImage {
    return frontend.MemoryImage.init(&test_memory_bytes) catch unreachable;
}

test "SM83 execution CPU proof roundtrip verifies" {
    const config = try testConfig();
    const steps = try testSteps(std.testing.allocator);
    const output = try proveExecution(
        std.testing.allocator,
        config,
        testRom(),
        testMemory(),
        testMemory(),
        &steps,
    );
    try verifyExecution(
        std.testing.allocator,
        config,
        testRom(),
        testMemory(),
        testMemory(),
        output.statement,
        output.proof,
    );
}

test "SM83 CPU proof binds ADD A,(HL) ROM fetch and data-memory read" {
    const config = try testConfig();
    const steps = try indirectAddSteps(std.testing.allocator);
    var rom_bytes = test_rom_bytes;
    @memset(rom_bytes[0..16], 0x86);
    const rom = try frontend.Rom.init(&rom_bytes);
    var memory_bytes = test_memory_bytes;
    @memcpy(memory_bytes[0..frontend.rom.SIZE], &rom_bytes);
    memory_bytes[0x8000] = 2;
    const memory = try frontend.MemoryImage.init(&memory_bytes);
    const output = try proveExecution(
        std.testing.allocator,
        config,
        rom,
        memory,
        memory,
        &steps,
    );
    try verifyExecution(
        std.testing.allocator,
        config,
        rom,
        memory,
        memory,
        output.statement,
        output.proof,
    );
}

test "SM83 CPU proof binds ordered INC (HL) reads and writes" {
    const config = try testConfig();
    const steps = try indirectIncrementSteps(std.testing.allocator);
    var rom_bytes = test_rom_bytes;
    @memset(rom_bytes[0..16], 0x34);
    const rom = try frontend.Rom.init(&rom_bytes);
    var initial_bytes = test_memory_bytes;
    @memcpy(initial_bytes[0..frontend.rom.SIZE], &rom_bytes);
    initial_bytes[0x8000] = 0x0f;
    var final_bytes = initial_bytes;
    final_bytes[0x8000] = 0x1f;
    const initial_memory = try frontend.MemoryImage.init(&initial_bytes);
    const final_memory = try frontend.MemoryImage.init(&final_bytes);
    const output = try proveExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        &steps,
    );
    try verifyExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        output.statement,
        output.proof,
    );

    const mutation_output = try proveExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        &steps,
    );
    var mutated_statement = mutation_output.statement;
    mutated_statement.final.cpu.setFlag(
        .half_carry,
        !mutated_statement.final.cpu.flag(.half_carry),
    );
    if (verifyExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        mutated_statement,
        mutation_output.proof,
    )) {
        return error.ExpectedMutationRejection;
    } else |_| {}

    const memory_claim_proof = try proveExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        &steps,
    );
    var memory_statement = memory_claim_proof.statement;
    memory_statement.memory_lookup_claims.execution[0] =
        memory_statement.memory_lookup_claims.execution[0].add(QM31.one());
    memory_statement.memory_lookup_claims.boundary =
        memory_statement.memory_lookup_claims.boundary.sub(QM31.one());
    if (verifyExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        memory_statement,
        memory_claim_proof.proof,
    )) {
        return error.ExpectedMutationRejection;
    } else |_| {}
}

test "SM83 CPU prover rejects an inactive-vacuity mutation" {
    const config = try testConfig();
    const steps = try testSteps(std.testing.allocator);
    try std.testing.expectError(
        @import("stwo_prover_engine").prove.ProvingError.ConstraintsNotSatisfied,
        sm83_prover.testing.proveInactiveExecutionWithEngine(
            CpuProverEngine,
            std.testing.allocator,
            config,
            testRom(),
            testMemory(),
            testMemory(),
            &steps,
        ),
    );
}

test "SM83 CPU prover rejects state, opcode, and ROM multiplicity mutations" {
    const config = try testConfig();
    const steps = try testSteps(std.testing.allocator);
    try std.testing.expectError(
        @import("stwo_prover_engine").prove.ProvingError.ConstraintsNotSatisfied,
        sm83_prover.testing.proveDisconnectedStateWithEngine(
            CpuProverEngine,
            std.testing.allocator,
            config,
            testRom(),
            testMemory(),
            testMemory(),
            &steps,
        ),
    );
    try std.testing.expectError(
        @import("stwo_prover_engine").prove.ProvingError.ConstraintsNotSatisfied,
        sm83_prover.testing.proveForgedOpcodeWithEngine(
            CpuProverEngine,
            std.testing.allocator,
            config,
            testRom(),
            testMemory(),
            testMemory(),
            &steps,
        ),
    );
    try std.testing.expectError(
        @import("stwo_prover_engine").prove.ProvingError.ConstraintsNotSatisfied,
        sm83_prover.testing.proveForgedMultiplicityWithEngine(
            CpuProverEngine,
            std.testing.allocator,
            config,
            testRom(),
            testMemory(),
            testMemory(),
            &steps,
        ),
    );
}

test "SM83 CPU prover rejects data-memory witness mutations" {
    const config = try testConfig();
    const steps = try indirectAddSteps(std.testing.allocator);
    var rom_bytes = test_rom_bytes;
    @memset(rom_bytes[0..16], 0x86);
    const rom = try frontend.Rom.init(&rom_bytes);
    var memory_bytes = test_memory_bytes;
    @memcpy(memory_bytes[0..frontend.rom.SIZE], &rom_bytes);
    memory_bytes[0x8000] = 2;
    const memory = try frontend.MemoryImage.init(&memory_bytes);

    for ([_]sm83_prover.testing.MemoryWitnessMutation{
        .previous_value,
        .previous_clock,
        .next_value,
        .final_clock,
    }) |mutation| {
        try std.testing.expectError(
            @import("stwo_prover_engine").prove.ProvingError.ConstraintsNotSatisfied,
            sm83_prover.testing.proveForgedMemoryWithEngine(
                CpuProverEngine,
                std.testing.allocator,
                config,
                rom,
                memory,
                memory,
                &steps,
                mutation,
            ),
        );
    }
}

test "SM83 verifier rejects non-canonical preprocessing and public-state mutation" {
    const config = try testConfig();
    const steps = try testSteps(std.testing.allocator);
    const non_canonical_rom = try sm83_prover.testing.proveNonCanonicalRomWithEngine(
        CpuProverEngine,
        std.testing.allocator,
        config,
        testRom(),
        testMemory(),
        testMemory(),
        &steps,
    );
    try std.testing.expectError(
        error.InvalidPreprocessedCommitment,
        verifyExecution(
            std.testing.allocator,
            config,
            testRom(),
            testMemory(),
            testMemory(),
            non_canonical_rom.statement,
            non_canonical_rom.proof,
        ),
    );

    const non_canonical_memory =
        try sm83_prover.testing.proveNonCanonicalMemoryWithEngine(
            CpuProverEngine,
            std.testing.allocator,
            config,
            testRom(),
            testMemory(),
            testMemory(),
            &steps,
        );
    try std.testing.expectError(
        error.InvalidPreprocessedCommitment,
        verifyExecution(
            std.testing.allocator,
            config,
            testRom(),
            testMemory(),
            testMemory(),
            non_canonical_memory.statement,
            non_canonical_memory.proof,
        ),
    );

    const honest = try proveExecution(
        std.testing.allocator,
        config,
        testRom(),
        testMemory(),
        testMemory(),
        &steps,
    );
    var mutated_statement = honest.statement;
    mutated_statement.final.cpu.a +%= 1;
    if (verifyExecution(
        std.testing.allocator,
        config,
        testRom(),
        testMemory(),
        testMemory(),
        mutated_statement,
        honest.proof,
    )) {
        return error.ExpectedMutationRejection;
    } else |_| {}
}

test "SM83 verifier rejects raw ROM and balanced lookup-claim mutations" {
    const config = try testConfig();
    const steps = try testSteps(std.testing.allocator);
    const wrong_rom_proof = try proveExecution(
        std.testing.allocator,
        config,
        testRom(),
        testMemory(),
        testMemory(),
        &steps,
    );
    var wrong_rom_bytes = test_rom_bytes;
    wrong_rom_bytes[0] = 0x81;
    var wrong_memory_bytes = test_memory_bytes;
    @memcpy(
        wrong_memory_bytes[0..frontend.rom.SIZE],
        &wrong_rom_bytes,
    );
    const wrong_memory = try frontend.MemoryImage.init(&wrong_memory_bytes);
    try std.testing.expectError(
        error.RomDigestMismatch,
        verifyExecution(
            std.testing.allocator,
            config,
            try frontend.Rom.init(&wrong_rom_bytes),
            wrong_memory,
            wrong_memory,
            wrong_rom_proof.statement,
            wrong_rom_proof.proof,
        ),
    );

    const claim_proof = try proveExecution(
        std.testing.allocator,
        config,
        testRom(),
        testMemory(),
        testMemory(),
        &steps,
    );
    var statement = claim_proof.statement;
    statement.program_lookup_claims.execution[0] =
        statement.program_lookup_claims.execution[0].add(QM31.one());
    statement.program_lookup_claims.rom =
        statement.program_lookup_claims.rom.sub(QM31.one());
    if (verifyExecution(
        std.testing.allocator,
        config,
        testRom(),
        testMemory(),
        testMemory(),
        statement,
        claim_proof.proof,
    )) {
        return error.ExpectedMutationRejection;
    } else |_| {}
}

test "SM83 verifier rejects raw initial and final memory mutations" {
    const config = try testConfig();
    const steps = try testSteps(std.testing.allocator);

    const initial_proof = try proveExecution(
        std.testing.allocator,
        config,
        testRom(),
        testMemory(),
        testMemory(),
        &steps,
    );
    var initial_bytes = test_memory_bytes;
    initial_bytes[0x8000] = 1;
    try std.testing.expectError(
        error.InitialMemoryDigestMismatch,
        verifyExecution(
            std.testing.allocator,
            config,
            testRom(),
            try frontend.MemoryImage.init(&initial_bytes),
            testMemory(),
            initial_proof.statement,
            initial_proof.proof,
        ),
    );

    const final_proof = try proveExecution(
        std.testing.allocator,
        config,
        testRom(),
        testMemory(),
        testMemory(),
        &steps,
    );
    var final_bytes = test_memory_bytes;
    final_bytes[0x8000] = 1;
    try std.testing.expectError(
        error.FinalMemoryDigestMismatch,
        verifyExecution(
            std.testing.allocator,
            config,
            testRom(),
            testMemory(),
            try frontend.MemoryImage.init(&final_bytes),
            final_proof.statement,
            final_proof.proof,
        ),
    );
}

test "api signature: SM83 CPU integration selects the CPU backend" {
    try std.testing.expect(CpuProverEngine.Backend == CpuBackend);
    try std.testing.expect(
        EnvironmentProverEngine.Backend == CpuBackend,
    );
    try std.testing.expect(
        MachineEnvironmentVerifierEngine.Backend == CpuBackend,
    );
    try std.testing.expect(
        MachineEnvironmentProverEngine.Backend == CpuBackend,
    );
}

test {
    _ = @import("cartridge_test.zig");
    _ = @import("environment_test.zig");
    _ = @import("family_proofs_test.zig");
    _ = @import("machine_environment_test.zig");
    _ = @import("pokemon_battle_chain_proof.zig");
    _ = @import("pokemon_checkpoint_proof.zig");
    std.testing.refAllDecls(@This());
}
