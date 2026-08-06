//! Backend-instantiated H-007 proof exercises.
//!
//! This file deliberately has no package-local `test` declaration: the
//! backend-neutral frontend package does not import either concrete prover
//! backend. CPU and Metal product tests call `exerciseBackend` with their real
//! backend type; the CPU lane additionally calls `exerciseMutationNegatives`.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const orchestration = @import("../../prover/orchestration.zig");
const proof_types = @import("../../prover/types.zig");
const prover = @import("../../prover.zig");
const memory_state = @import("../../runner/memory_state.zig");
const runner = @import("../../runner/mod.zig");
const state_chain = @import("../../runner/state_chain.zig");
const trace_mod = @import("../../runner/trace.zig");
const compat = @import("typed_poseidon2_compat.zig");
const harness = @import("typed_poseidon2_proof_harness.zig");

pub const CANONICAL_PROGRAM_IDENTITY_DIGEST =
    harness.CANONICAL_PROGRAM_IDENTITY_DIGEST;

pub const TEST_CONFIG = pcs_core.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
    },
};

pub const ProveResult = struct {
    output: proof_types.ProveOutput,
    receipt: harness.Receipt,

    pub fn deinit(self: *ProveResult, allocator: std.mem.Allocator) void {
        self.output.deinit(allocator);
        self.* = undefined;
    }
};

pub fn proveWithPublicData(
    comptime Backend: type,
    allocator: std.mem.Allocator,
    config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    public_data: proof_types.PublicData,
    mutation: harness.Mutation,
) !ProveResult {
    const Engine = harness.CandidateEngine(Backend);
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    var context = try harness.Context.init(allocator, @typeName(Backend), mutation);
    defer context.deinit();
    var channel = harness.CandidateChannel{ .context = &context };
    var output = try orchestration.runRiscVWithEngineAndPublicDataUsingChannel(
        Engine,
        .prove,
        allocator,
        config,
        exec_trace,
        opt_chain,
        opt_memory,
        null,
        public_data,
        &channel,
        null,
        null,
    );
    errdefer output.deinit(allocator);
    try context.installOutputClaims(&output);
    const receipt = try context.receipt();
    try receipt.validate();
    return .{ .output = output, .receipt = receipt };
}

pub fn proveTraceOnly(
    comptime Backend: type,
    allocator: std.mem.Allocator,
    config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    mutation: harness.Mutation,
) !ProveResult {
    const Engine = harness.CandidateEngine(Backend);
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    var context = try harness.Context.init(allocator, @typeName(Backend), mutation);
    defer context.deinit();
    var channel = harness.CandidateChannel{ .context = &context };
    var output = try prover.proveRiscVTraceOnlyNoPublicIoUsingChannel(
        Engine,
        allocator,
        config,
        exec_trace,
        opt_chain,
        opt_memory,
        null,
        &channel,
    );
    errdefer output.deinit(allocator);
    try context.installOutputClaims(&output);
    const receipt = try context.receipt();
    try receipt.validate();
    return .{ .output = output, .receipt = receipt };
}

/// One real proof whose three Poseidon artifacts are typed-generated, followed
/// by verification through the unchanged production verifier. This fixture's
/// sparse-Merkle calls are narrow-only; the receipt exposes the exact mode
/// partition so callers cannot mistake this for wide/IO precompile coverage.
/// Backend admission (notably authenticated Metal AOT) remains caller-owned.
pub fn exerciseBackend(comptime Backend: type, allocator: std.mem.Allocator) !harness.Receipt {
    const ProverEngine = harness.CandidateEngine(Backend);
    const VerifierEngine = proof_types.ProverEngineForBackend(Backend);
    comptime {
        if (ProverEngine.Backend != Backend or VerifierEngine.Backend != Backend)
            @compileError("typed proof exercise changed backend identity");
    }
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    var result = try proveTraceOnly(
        Backend,
        allocator,
        TEST_CONFIG,
        &fixture.run.execution_trace,
        null,
        null,
        .none,
    );
    const receipt = result.receipt;
    defer result.output.deinitAfterProofMoved(allocator);
    try prover.verifyRiscVWithEngine(
        VerifierEngine,
        allocator,
        TEST_CONFIG,
        result.output.statement,
        result.output.proof,
        result.output.interaction_claim,
    );
    try receipt.validate();
    return receipt;
}

/// Generated-artifact negatives. Every mutation occurs after authentication
/// and legacy-window discovery, directly on the bytes/claim used by the proof.
pub fn exerciseMutationNegatives(comptime Backend: type, allocator: std.mem.Allocator) !void {
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const cases = [_]harness.Mutation{
        .{ .main_column = .{ .column = compat.TEMPORARY_START, .logical_row = 0 } },
        .{ .interaction_column = .{ .column = 0, .logical_row = 0 } },
        .{ .claim_sum = .{ .sum = 0 } },
    };
    for (cases) |mutation| {
        if (proveTraceOnly(
            Backend,
            allocator,
            TEST_CONFIG,
            &fixture.run.execution_trace,
            null,
            null,
            mutation,
        )) |produced| {
            var unexpected = produced;
            unexpected.deinit(allocator);
            return error.TestUnexpectedResult;
        } else |err| try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
    }
    if (proveTraceOnly(
        Backend,
        allocator,
        TEST_CONFIG,
        &fixture.run.execution_trace,
        null,
        null,
        .{ .main_column = .{
            .column = compat.N_MAIN_COLUMNS,
            .logical_row = 0,
        } },
    )) |produced| {
        var unexpected = produced;
        unexpected.deinit(allocator);
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.InvalidCandidateMutation, err);
}

const Fixture = struct {
    run: runner.RunResult,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const elf = runner.trace_dump.buildTestElf(5, .{
            0x00100093, // ADDI x1, x0, 1
            0x00100093,
            0x00100093,
            0x00100093,
            0x0000006f, // JAL x0, 0: completion sentinel
        });
        return .{ .run = try runner.run(allocator, &elf, 1000) };
    }

    fn deinit(self: *Fixture) void {
        self.run.deinit();
        self.* = undefined;
    }
};
