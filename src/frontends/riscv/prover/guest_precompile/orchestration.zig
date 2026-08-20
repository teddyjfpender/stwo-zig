//! End-to-end proving transaction for the Poseidon2 extension profile.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const stage_profile = @import("stwo_prover_api").stage_profile;
const proof_transcript = @import("../../air/guest_precompile/proof_transcript.zig");
const guest_call_buffer = @import("../../runner/guest_precompile/call_buffer.zig");
const guest_runner = @import("../../runner/guest_precompile/poseidon2_v1.zig");
const memory_state = @import("../../runner/memory_state.zig");
const state_chain = @import("../../runner/state_chain.zig");
const trace_mod = @import("../../runner/trace.zig");
const commitment_witness = @import("../commitment_witness.zig");
const interaction_trace = @import("../interaction_trace.zig");
const interaction_witness_work = @import("../interaction_witness_work.zig");
const main_trace = @import("../main_trace.zig");
const preprocessed = @import("../preprocessed.zig");
const proof_workspace = @import("../proof_workspace.zig");
const poseidon_witness_work = @import("../poseidon_witness_work.zig");
const statement_geometry = @import("../statement_geometry.zig");
const base_types = @import("../types.zig");
const cancellation = @import("cancellation.zig");
const profile_finalize = @import("proof_finalize.zig");
const profile_types = @import("types.zig");

const CommitmentWitness = commitment_witness.CommitmentWitness;
const ProofWorkspace = proof_workspace.ProofWorkspace;

pub fn provePoseidon2WithEngineAndPublicData(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    calls: *const guest_call_buffer.Frozen,
    execution_rows: *const guest_runner.FrozenExecutionRows,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: base_types.PublicData,
) !profile_types.ProveOutput {
    var channel = Engine.Channel{};
    return provePoseidon2WithEngineAndPublicDataUsingChannel(
        Engine,
        allocator,
        pcs_config,
        exec_trace,
        calls,
        execution_rows,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
        &channel,
    );
}

/// Caller-owned-channel variant used by exact transcript and artifact tests.
pub fn provePoseidon2WithEngineAndPublicDataUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    calls: *const guest_call_buffer.Frozen,
    execution_rows: *const guest_runner.FrozenExecutionRows,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: base_types.PublicData,
    channel: *Engine.Channel,
) !profile_types.ProveOutput {
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    const workspace = try ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);

    var output: profile_types.ProveOutput = undefined;
    try proveStages(
        Engine,
        allocator,
        workspace,
        &output,
        pcs_config,
        exec_trace,
        calls,
        execution_rows,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
        channel,
    );
    return output;
}

fn proveStages(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    output: *profile_types.ProveOutput,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    calls: *const guest_call_buffer.Frozen,
    execution_rows: *const guest_runner.FrozenExecutionRows,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: base_types.PublicData,
    channel: *Engine.Channel,
) !void {
    const n_guest = std.math.cast(u32, calls.len()) orelse
        return base_types.ProverError.InvalidStatement;
    if (execution_rows.rows().len != calls.len())
        return base_types.ProverError.InvalidStatement;
    const total_steps = std.math.add(usize, exec_trace.step_count, calls.len()) catch
        return base_types.ProverError.InvalidStatement;
    if (total_steps == 0) return base_types.ProverError.EmptyTrace;
    const total_steps_u32 = std.math.cast(u32, total_steps) orelse
        return base_types.ProverError.InvalidStatement;
    if (total_steps_u32 != public_data.clock)
        return base_types.ProverError.InvalidStatement;

    var bound_public_data = public_data;
    try commitment_witness.bindCompletion(
        &bound_public_data,
        exec_trace.final_pc,
        opt_memory,
    );
    var poseidon_authority = try poseidon_witness_work.plan(recorder);
    var witness = if (poseidon_authority) |*authority|
        try CommitmentWitness.buildPoseidon2WithWorkReceipt(
            allocator,
            exec_trace,
            execution_rows,
            opt_memory,
            bound_public_data.completion.?,
            authority,
        )
    else
        try CommitmentWitness.buildPoseidon2(
            allocator,
            exec_trace,
            execution_rows,
            opt_memory,
            bound_public_data.completion.?,
        );
    defer witness.deinit(allocator);

    const geometry = try statement_geometry.buildPoseidon2(
        allocator,
        workspace,
        exec_trace,
        &witness,
        opt_chain,
        bound_public_data,
        n_guest,
        .proof,
    );
    try geometry.extension.validateConstruction(&workspace.statement, .{
        .custom_retirements = n_guest,
        .frozen_call_count = n_guest,
    });

    pcs_config.mixInto(channel);
    workspace.statement.public_data.mixInto(channel);
    try proof_transcript.mixProfileIdentity(
        channel,
        &workspace.statement,
        &geometry.extension,
        geometry.artifact,
    );

    var scheme = try Engine.init(allocator, pcs_config);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);

    try preprocessed.generateAndCommitPoseidon2(
        Engine,
        allocator,
        &workspace.statement,
        &geometry.extension,
        &scheme,
        channel,
        recorder,
    );

    var retained = try main_trace.generateAndCommitPoseidon2(
        Engine,
        allocator,
        workspace,
        &geometry.extension,
        calls,
        execution_rows,
        &scheme,
        channel,
        recorder,
        exec_trace,
        &witness,
        geometry.base,
        opt_chain,
    );
    defer retained.deinit(allocator, workspace);

    var interaction_work_authority = try interaction_witness_work.plan(recorder);
    const prefix = if (interaction_work_authority) |*authority|
        try proof_transcript.proveToRelationsWithWorkReceipt(
            allocator,
            channel,
            &workspace.statement,
            &geometry.extension,
            authority,
        )
    else
        try proof_transcript.proveToRelations(
            allocator,
            channel,
            &workspace.statement,
            &geometry.extension,
        );
    const claim = try profile_types.InteractionClaim.initBaseInto(
        allocator,
        &workspace.statement,
        &geometry.extension,
    );
    var claim_owned = true;
    defer if (claim_owned) claim.destroy(allocator);

    var guest_claim: interaction_trace.Poseidon2Claims = undefined;
    try interaction_trace.generateAndCommitPoseidon2(
        Engine,
        allocator,
        workspace,
        &geometry.extension,
        &retained.guest_relation_source,
        &scheme,
        channel,
        recorder,
        &witness,
        geometry.base,
        &retained.lookup_source,
        &prefix,
        &claim.base,
        &guest_claim,
    );
    try claim.finishCanonical(
        &workspace.statement,
        &geometry.extension,
        &guest_claim.caller,
        &guest_claim.provider,
    );
    try cancellation.verifyDetailed(
        allocator,
        &workspace.statement,
        &prefix.relations,
        &claim.base,
        claim.caller,
        claim.provider,
    );

    scheme_owned = false;
    const proof = try profile_finalize.prove(
        Engine,
        allocator,
        recorder,
        scheme,
        channel,
        workspace,
        &geometry.extension,
        &prefix.relations,
        &claim.base,
        claim.caller,
        claim.provider,
    );
    claim_owned = false;
    output.* = .{
        .proof = proof,
        .statement = workspace.statement,
        .extension = geometry.extension,
        .artifact = geometry.artifact,
        .interaction_claim = claim,
    };
}
