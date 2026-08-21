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
const proof_phase_meter = @import("../proof_phase_meter.zig");
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
    return provePoseidon2WithEngineAndPublicDataUsingChannelWithPhaseMeter(
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
        channel,
        null,
    );
}

/// Caller-owned-channel profile proof with the exact five-region witness
/// partition used by the base production prover.
pub fn provePoseidon2WithEngineAndPublicDataUsingChannelAndPhaseMeter(
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
    phase_meter: *proof_phase_meter.Meter,
) !profile_types.ProveOutput {
    return provePoseidon2WithEngineAndPublicDataUsingChannelWithPhaseMeter(
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
        channel,
        phase_meter,
    );
}

fn provePoseidon2WithEngineAndPublicDataUsingChannelWithPhaseMeter(
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
    phase_meter: ?*proof_phase_meter.Meter,
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
        phase_meter,
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
    phase_meter: ?*proof_phase_meter.Meter,
) !void {
    const n_guest = try validateExecutionClockAuthority(
        exec_trace,
        calls.len(),
        execution_rows.rows().len,
        public_data.clock,
    );

    var bound_public_data = public_data;
    try commitment_witness.bindCompletion(
        &bound_public_data,
        exec_trace.final_pc,
        opt_memory,
    );
    var witness_region: ?proof_phase_meter.WitnessRegion =
        if (phase_meter) |meter| try meter.begin() else null;
    errdefer if (witness_region) |*region| region.abort();
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
    if (witness_region) |*region| try region.finish();

    var geometry_region: ?proof_phase_meter.WitnessRegion =
        if (phase_meter) |meter| try meter.begin() else null;
    errdefer if (geometry_region) |*region| region.abort();
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
    if (geometry_region) |*region| try region.finish();
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

    try preprocessed.generateAndCommitPoseidon2WithPhaseMeter(
        Engine,
        allocator,
        &workspace.statement,
        &geometry.extension,
        &scheme,
        channel,
        recorder,
        phase_meter,
    );

    var retained = try main_trace.generateAndCommitPoseidon2WithPhaseMeter(
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
        phase_meter,
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
    try interaction_trace.generateAndCommitPoseidon2WithPhaseMeter(
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
        phase_meter,
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
    if (phase_meter) |meter| try meter.requireComplete();
    claim_owned = false;
    output.* = .{
        .proof = proof,
        .statement = workspace.statement,
        .extension = geometry.extension,
        .artifact = geometry.artifact,
        .interaction_claim = claim,
    };
}

/// Fail-closed producer admission for the profile clock omitted from the core
/// rows. Kept separate so boundary mutations are tested without constructing
/// an expensive proof.
fn validateExecutionClockAuthority(
    exec_trace: *const trace_mod.Trace,
    call_count: usize,
    execution_row_count: usize,
    public_clock: u32,
) !u32 {
    const n_guest = std.math.cast(u32, call_count) orelse
        return base_types.ProverError.InvalidStatement;
    if (execution_row_count != call_count)
        return base_types.ProverError.InvalidStatement;
    const total_steps = std.math.add(usize, exec_trace.step_count, call_count) catch
        return base_types.ProverError.InvalidStatement;
    if (total_steps == 0) return base_types.ProverError.EmptyTrace;
    const total_steps_u32 = std.math.cast(u32, total_steps) orelse
        return base_types.ProverError.InvalidStatement;
    if (total_steps_u32 != public_clock)
        return base_types.ProverError.InvalidStatement;
    exec_trace.validateClockRange(0, public_clock, call_count) catch
        return base_types.ProverError.InvalidStatement;
    return n_guest;
}

test "guest prover rejects a shape-valid nonzero clock origin before witness work" {
    var canonical = trace_mod.Trace.init(std.testing.allocator);
    defer canonical.deinit();
    try canonical.bindExtractedClockRange(0, 1, 1);
    try std.testing.expectEqual(
        @as(u32, 1),
        try validateExecutionClockAuthority(&canonical, 1, 1, 1),
    );

    var shifted = trace_mod.Trace.init(std.testing.allocator);
    defer shifted.deinit();
    try shifted.bindExtractedClockRange(1, 2, 1);
    try std.testing.expectError(
        error.InvalidStatement,
        validateExecutionClockAuthority(&shifted, 1, 1, 1),
    );
    try std.testing.expectError(
        error.InvalidStatement,
        validateExecutionClockAuthority(&canonical, 1, 0, 1),
    );
}
