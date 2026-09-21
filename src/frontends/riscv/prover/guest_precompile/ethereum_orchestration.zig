//! End-to-end proving transaction for the combined Ethereum execution profile.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const prover_api = @import("stwo_prover_api");
const stage_profile = prover_api.stage_profile;
const work_pool = @import("stwo_prover_engine").work_pool;
const proof_admission = @import("../../air/guest_precompile/ethereum_proof_admission.zig");
const statement_mod = @import("../../air/guest_precompile/ethereum_statement.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const keccak_calls_mod = @import("../../runner/guest_precompile/keccakf_call_buffer.zig");
const keccak_rows_mod = @import("../../runner/guest_precompile/keccakf_v1.zig");
const recovery_calls_mod = @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig");
const recovery_rows_mod = @import("../../runner/guest_precompile/secp256k1_recover_v1.zig");
const memory_state = @import("../../runner/memory_state.zig");
const state_chain = @import("../../runner/state_chain.zig");
const trace_mod = @import("../../runner/trace.zig");
const commitment_witness = @import("../commitment_witness.zig");
const base_orchestration = @import("../orchestration.zig");
const proof_finalize = @import("../proof_finalize.zig");
const proof_workspace = @import("../proof_workspace.zig");
const statement_geometry = @import("../statement_geometry.zig");
const base_types = @import("../types.zig");
const ethereum_assembly = @import("ethereum_assembly.zig");
const ethereum_cancellation = @import("ethereum_cancellation.zig");
const ethereum_interaction = @import("ethereum_interaction.zig");
const ethereum_main = @import("ethereum_main.zig");
const ethereum_preprocessed = @import("ethereum_preprocessed.zig");
const ethereum_transcript = @import("ethereum_transcript.zig");
const ethereum_types = @import("ethereum_types.zig");
const ethereum_witness = @import("ethereum_witness.zig");

pub const ExecutionOptions = struct {
    /// One strict proof-scoped budget shared by every pool-aware producer and
    /// by quotient/FRI/opening work inside `Engine.prove`.
    cpu: prover_api.CpuCompositionExecutionRequest,
};

pub const sequential_execution = ExecutionOptions{ .cpu = .{
    .worker_count = 1,
    .host_byte_budget = std.math.maxInt(usize),
    .contention_policy = .strict,
} };

pub fn proveWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: base_types.PublicData,
) !ethereum_types.ProveOutputForEngine(Engine) {
    return proveWithEngineUsingExecution(
        Engine,
        allocator,
        pcs_config,
        exec_trace,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
        sequential_execution,
    );
}

pub fn proveWithEngineUsingExecution(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: base_types.PublicData,
    execution: ExecutionOptions,
) !ethereum_types.ProveOutputForEngine(Engine) {
    var channel = Engine.Channel{};
    return proveWithEngineUsingChannelAndExecution(
        Engine,
        allocator,
        pcs_config,
        exec_trace,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
        &channel,
        execution,
    );
}

pub fn proveWithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: base_types.PublicData,
    channel: *Engine.Channel,
) !ethereum_types.ProveOutputForEngine(Engine) {
    return proveWithEngineUsingChannelAndExecution(
        Engine,
        allocator,
        pcs_config,
        exec_trace,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
        channel,
        sequential_execution,
    );
}

pub fn proveWithEngineUsingChannelAndExecution(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: base_types.PublicData,
    channel: *Engine.Channel,
    execution: ExecutionOptions,
) !ethereum_types.ProveOutputForEngine(Engine) {
    comptime prover_api.assertProverEngine(Engine);
    if (execution.cpu.contention_policy != .strict)
        return error.NonStrictExecutionPolicy;
    var execution_pool: base_orchestration.ProofExecutionPool = .{};
    try execution_pool.initInPlace(allocator, execution.cpu);
    defer execution_pool.deinit();
    const workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);

    const external_count = try validateClockAuthority(
        exec_trace,
        keccak_calls.len(),
        keccak_rows.rows().len,
        recovery_calls.len(),
        recovery_rows.rows().len,
        public_data.clock,
    );
    var bound_public = public_data;
    try commitment_witness.bindCompletion(&bound_public, exec_trace.final_pc, opt_memory);

    var base_witness: commitment_witness.CommitmentWitness = undefined;
    {
        var stage = try stage_profile.StageScope.begin(
            recorder,
            "riscv_ethereum_commitment_witness",
            "Ethereum base commitment witness",
        );
        defer stage.end();
        base_witness = try commitment_witness.CommitmentWitness.buildExternalProfile(
            allocator,
            execution_profile.ExecutionProfile.rv32im_zkvm_ethereum_v1,
            .{ exec_trace.rows.items, keccak_rows.rows(), recovery_rows.rows() },
            opt_memory,
            bound_public.completion.?,
        );
    }
    defer base_witness.deinit(allocator);

    const geometry = try statement_geometry.buildExternalBase(
        allocator,
        workspace,
        exec_trace,
        &base_witness,
        opt_chain,
        bound_public,
        external_count,
    );
    var witness: ethereum_witness.Witness = undefined;
    {
        var stage = try stage_profile.StageScope.begin(
            recorder,
            "riscv_ethereum_extension_witness",
            "Ethereum extension witness",
        );
        defer stage.end();
        witness = try ethereum_witness.Witness.init(
            allocator,
            keccak_calls.records(),
            keccak_rows.rows(),
            recovery_calls.records(),
            recovery_rows.rows(),
            bound_public.clock,
        );
    }
    defer witness.deinit();
    const extension = try statement_mod.Statement.canonical(
        &workspace.statement,
        @intCast(keccak_calls.len()),
        @intCast(recovery_calls.len()),
        witness.shapes(),
    );
    try proof_admission.validate(&workspace.statement, &extension, .proof);

    pcs_config.mixInto(channel);
    workspace.statement.public_data.mixInto(channel);
    try extension.mixInto(&workspace.statement, channel);

    var scheme = try Engine.init(allocator, pcs_config);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);

    {
        var stage = try stage_profile.StageScope.begin(
            recorder,
            "riscv_ethereum_preprocessed_commit",
            "Ethereum preprocessed trace commit",
        );
        defer stage.end();
        const tree0 = try ethereum_preprocessed.generate(
            allocator,
            &workspace.statement,
            &extension,
        );
        var tree0_moved = false;
        errdefer if (!tree0_moved) freeColumns(allocator, tree0);
        tree0_moved = true;
        try Engine.commit(&scheme, allocator, tree0, recorder, channel);
    }

    var retained: @import("external_profile_tree.zig").MainRetained = undefined;
    {
        var stage = try stage_profile.StageScope.begin(
            recorder,
            "riscv_ethereum_main_commit",
            "Ethereum main trace commit",
        );
        defer stage.end();
        retained = try ethereum_main.commit(
            Engine,
            allocator,
            workspace,
            &scheme,
            channel,
            recorder,
            exec_trace,
            &base_witness,
            geometry,
            opt_chain,
            &witness,
            keccak_calls.records(),
            recovery_calls.records(),
        );
    }
    defer retained.deinit(allocator, workspace);

    const prefix = try ethereum_transcript.proveToRelations(
        allocator,
        channel,
        &workspace.statement,
    );
    const base_claim = try allocator.create(base_types.RiscVInteractionClaim);
    var claim_owned = true;
    defer if (claim_owned) allocator.destroy(base_claim);

    var serial_pool: work_pool.WorkPool = undefined;
    var serial_pool_live = false;
    defer if (serial_pool_live) serial_pool.deinit();
    const pool = execution_pool.get() orelse blk: {
        try serial_pool.initInPlaceWithOptions(.{ .worker_count = 1 });
        serial_pool_live = true;
        break :blk &serial_pool;
    };
    var extension_claim: ethereum_types.ExtensionClaim = undefined;
    {
        var stage = try stage_profile.StageScope.begin(
            recorder,
            "riscv_ethereum_interaction_commit",
            "Ethereum interaction trace commit",
        );
        defer stage.end();
        extension_claim = try ethereum_interaction.generateAndCommit(
            Engine,
            allocator,
            workspace,
            &scheme,
            channel,
            recorder,
            &base_witness,
            geometry,
            &retained.lookup_source,
            &prefix,
            &witness,
            pool,
            base_claim,
        );
    }
    try extension_claim.validate(&extension);
    try ethereum_cancellation.verifyDetailed(
        allocator,
        &workspace.statement,
        &prefix.relations,
        base_claim,
        &extension_claim,
    );

    const base_components = try proof_finalize.assemble(
        workspace,
        &prefix.relations.base,
        base_claim,
        workspace.statement.nMainColumns(),
        workspace.statement.nInteractionColumns(),
    );
    const assembly = try ethereum_assembly.Assembly(.prover).create(
        allocator,
        &workspace.statement,
        &extension,
        &prefix.relations,
        base_components,
        &extension_claim,
    );
    defer assembly.destroy(allocator);

    scheme_owned = false;
    var extended_proof: Engine.ExtendedProof = undefined;
    {
        var stage = try stage_profile.StageScope.begin(
            recorder,
            "riscv_ethereum_prove",
            "Ethereum composition, FRI, and openings",
        );
        defer stage.end();
        extended_proof = try Engine.prove(
            allocator,
            assembly.active(),
            channel,
            scheme,
            .{
                .recorder = recorder,
                .cpu_composition_execution = execution.cpu,
            },
        );
    }
    const proof = extended_proof.proof;
    extended_proof.aux.deinit(allocator);
    work_pool.recordProofPublicationForTest(execution_pool.get());
    claim_owned = false;
    return .{
        .statement = workspace.statement,
        .extension = extension,
        .proof = proof,
        .base_claim = base_claim,
        .extension_claim = extension_claim,
    };
}

fn validateClockAuthority(
    trace: *const trace_mod.Trace,
    keccak_calls: usize,
    keccak_rows: usize,
    recovery_calls: usize,
    recovery_rows: usize,
    public_clock: u32,
) !u32 {
    if (keccak_calls != keccak_rows or recovery_calls != recovery_rows)
        return base_types.ProverError.InvalidStatement;
    const external = std.math.add(usize, keccak_calls, recovery_calls) catch
        return base_types.ProverError.InvalidStatement;
    const total = std.math.add(usize, trace.step_count, external) catch
        return base_types.ProverError.InvalidStatement;
    if (std.math.cast(u32, total) != public_clock)
        return base_types.ProverError.InvalidStatement;
    trace.validateClockRange(0, public_clock, external) catch
        return base_types.ProverError.InvalidStatement;
    return std.math.cast(u32, external) orelse
        return base_types.ProverError.InvalidStatement;
}

fn freeColumns(
    allocator: std.mem.Allocator,
    columns: []@import("stwo_prover_engine").pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}
