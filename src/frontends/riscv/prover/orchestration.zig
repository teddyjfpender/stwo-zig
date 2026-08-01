//! RISC-V STARK proving orchestration.
//!
//! Proves execution of a RISC-V RV32IM program by:
//! 1. Running the program (ELF) to produce an execution trace
//! 2. Splitting the trace by opcode family
//! 3. Creating per-family components, each at its own log_size
//! 4. Committing and proving via the stwo STARK backend
//! 5. Verification of the produced proof
//!
//! ## Architecture
//!
//! Instead of one monolithic component with all trace rows, the trace is split
//! by opcode family. Each active family gets its own component with its own
//! `log_size = ceil(log2(count))`. This gives smaller FFTs per-component and
//! better cache behavior.
//!
//! ## Stages
//!
//! `proveStages` owns nothing but sequencing. Each stage lives in the module
//! named after the artefact it owns, and the order below is protocol order --
//! a transcript is a total order over these calls, so moving one is a different
//! proof even when every witness value is identical:
//!
//! | stage | module |
//! |-------|--------|
//! | commitment witness (memory, program, Merkle, Poseidon2) | `commitment_witness.zig` |
//! | statement and shard geometry | `statement_geometry.zig` |
//! | tree 0: preprocessed columns | `preprocessed.zig` |
//! | tree 1: main trace | `main_trace.zig` |
//! | claim phase and tree 2: interactions | `interaction_trace.zig` |
//! | components and proof assembly | `proof_finalize.zig` |
//!
//! ## Storage
//!
//! Every protocol-capacity-sized value -- statement, opcode column buffers,
//! interaction scratch, prover components borrowed by `core` -- lives in one
//! heap `ProofWorkspace` per proof (see `proof_workspace.zig`). `proveStages`
//! returns `!void` and publishes through an out-pointer so the large proof
//! output costs one frame slot at the boundary instead of one per
//! error-propagation site inside the stages.
//!
//! ## Usage
//! ```zig
//! const result = try proveRiscVWithEngineAndPublicData(
//!     Engine, allocator, config, &exec_trace, &state_chain, &rw_memory, null, public_data,
//! );
//! try verifyRiscVWithEngine(Engine, allocator, config, result.statement, result.proof, result.interaction_claim);
//! ```

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const prover_engine = @import("stwo_prover_engine").engine;
const stage_profile = @import("stwo_prover_api").stage_profile;
const relation_challenges = @import("../air/relation_challenges.zig");
const trace_mod = @import("../runner/trace.zig");
const memory_state = @import("../runner/memory_state.zig");
const state_chain = @import("../runner/state_chain.zig");
const commitment_witness = @import("commitment_witness.zig");
const interaction_trace = @import("interaction_trace.zig");
const main_trace = @import("main_trace.zig");
const preprocessed_trace = @import("preprocessed.zig");
const proof_finalize = @import("proof_finalize.zig");
const proof_workspace = @import("proof_workspace.zig");
const relation_diagnostic = @import("relation_diagnostic.zig");
const statement_geometry = @import("statement_geometry.zig");
const statement_validation = @import("statement_validation.zig");
const test_trace_dump = @import("test_trace_dump.zig");
const test_witness_hook = @import("test_witness_hook.zig");
const types = @import("types.zig");

const CommitmentWitness = commitment_witness.CommitmentWitness;
const Geometry = statement_geometry.Geometry;
const ProofWorkspace = proof_workspace.ProofWorkspace;
const PublicData = types.PublicData;
const ProverError = types.ProverError;
const RiscVInteractionClaim = types.RiscVInteractionClaim;
const RiscVStatement = types.RiscVStatement;
const RunMode = types.RunMode;
const RunOutput = types.RunOutput;

pub const TestWitnessMutation = test_witness_hook.Mutation;
pub const TestTraceDump = test_trace_dump.Capture;

pub fn runRiscVWithEngineAndPublicData(
    comptime Engine: type,
    comptime mode: RunMode,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: PublicData,
) !RunOutput(mode) {
    var channel = Engine.Channel{};
    return runRiscVWithEngineAndPublicDataUsingChannel(
        Engine,
        mode,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
        &channel,
        null,
        null,
    );
}

/// Runs the production proving transaction against a caller-owned channel.
///
/// The ordinary entrypoint above instantiates `Engine.Channel` directly. This
/// substitution point lets conformance tests observe the exact production
/// transcript without replaying statement or commitment events.
///
/// Owns the per-proof workspace: one allocation, released on every exit path.
/// The returned output copies workspace-resident results so it outlives
/// `destroy`; the boxed interaction claim is **transferred** to the caller.
pub fn runRiscVWithEngineAndPublicDataUsingChannel(
    comptime Engine: type,
    comptime mode: RunMode,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: PublicData,
    channel: *Engine.Channel,
    test_mutation: ?TestWitnessMutation,
    test_dump: ?*TestTraceDump,
) !RunOutput(mode) {
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    const workspace = try ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);

    var output: RunOutput(mode) = undefined;
    try proveStages(
        Engine,
        mode,
        workspace,
        &output,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
        channel,
        test_mutation,
        test_dump,
    );
    return output;
}

/// Executes every proving stage against workspace-resident storage. `!void` and
/// the out-pointer are deliberate: see the module note on frame slots.
///
/// The `defer`s here, and not inside the stages, are the ones whose buffers are
/// still borrowed by a *later* stage: composition reads the interaction scratch,
/// and `Engine.prove` reads the components that borrow it, so nothing acquired
/// for Tree 2 may be released before proving returns.
fn proveStages(
    comptime Engine: type,
    comptime mode: RunMode,
    workspace: *ProofWorkspace,
    output: *RunOutput(mode),
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: PublicData,
    channel: *Engine.Channel,
    test_mutation: ?TestWitnessMutation,
    test_dump: ?*TestTraceDump,
) !void {
    if (exec_trace.step_count == 0) return ProverError.EmptyTrace;

    var derived = try derive(mode, allocator, workspace, exec_trace, opt_chain, opt_memory, public_data);
    defer derived.witness.deinit(allocator);
    const witness = &derived.witness;
    const geometry = derived.geometry;
    const statement = &workspace.statement;

    // Security geometry is part of the RISC-V Fiat–Shamir statement. This
    // prevents a proof under one profile from sharing a transcript prefix with
    // another profile even when every execution field is identical.
    pcs_config.mixInto(channel);
    statement.public_data.mixInto(channel);

    var scheme = try Engine.init(allocator, pcs_config);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);

    var retained_tree0: ?relation_diagnostic.RetainedTree = null;
    defer if (retained_tree0) |*tree| tree.deinit(allocator);
    var retained_tree1: ?relation_diagnostic.RetainedTree = null;
    defer if (retained_tree1) |*tree| tree.deinit(allocator);

    try preprocessed_trace.generateAndCommit(
        Engine,
        mode,
        allocator,
        statement,
        &scheme,
        channel,
        recorder,
        test_mutation,
        &retained_tree0,
    );

    var retained = try main_trace.generateAndCommit(
        Engine,
        mode,
        allocator,
        workspace,
        &scheme,
        channel,
        recorder,
        exec_trace,
        witness,
        geometry,
        opt_chain,
        test_mutation,
        test_dump,
        &retained_tree1,
    );
    defer retained.deinit(allocator, workspace);

    if (comptime mode == .prove) logProofGeometry(statement, geometry, witness.poseidonCalls().len);

    const transcript_prefix = try interaction_trace.drawChallenges(Engine, mode, allocator, channel, statement);

    const interaction_claim = try allocator.create(RiscVInteractionClaim);
    var interaction_claim_owned = true;
    defer if (interaction_claim_owned) allocator.destroy(interaction_claim);

    try interaction_trace.generateAndCommit(
        Engine,
        allocator,
        workspace,
        &scheme,
        channel,
        recorder,
        witness,
        geometry,
        &retained.lookup_source,
        &transcript_prefix,
        interaction_claim,
    );

    // Exported here and not at the commit point because this is the first
    // instant at which all four exported artefacts coexist: the opcode buffers
    // Tree 1 was copied from, the challenges Tree 2 was built under, and the
    // claims Tree 2 produced. The run continues to a real proof afterwards.
    if (test_dump) |dump| try dump.record(
        statement,
        &transcript_prefix.relations,
        interaction_claim,
    );

    if (comptime mode == .relation_diagnostic) {
        output.* = try buildDiagnostic(
            Engine,
            allocator,
            statement,
            &scheme,
            &retained_tree0.?,
            &retained_tree1.?,
            transcript_prefix.relations,
            interaction_claim,
        );
        return;
    }

    scheme_owned = false;
    const proof = try proof_finalize.prove(
        Engine,
        allocator,
        recorder,
        scheme,
        channel,
        workspace,
        &transcript_prefix.relations,
        interaction_claim,
        statement.nOpcodeMainColumns() + statement.nInfraColumns(),
        statement.nInteractionColumns(),
    );
    interaction_claim_owned = false;
    output.* = .{
        .statement = statement.*,
        .proof = proof,
        .interaction_claim = interaction_claim,
    };
}

/// Everything the proof is derived from, before the transcript opens.
const Derived = struct {
    witness: CommitmentWitness,
    geometry: Geometry,
};

/// Derives the commitment witness and admits the statement it implies.
///
/// Nothing here touches the channel. That is the point of the boundary: the
/// whole derivation is a function of the execution alone, so a statement the
/// witness does not support is rejected before a single transcript event has
/// been mixed, and a rejected run leaves the caller's channel untouched.
///
/// The witness is **transferred** to the caller, which releases it once every
/// stage that takes views into it has finished.
fn derive(
    comptime mode: RunMode,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    public_data: PublicData,
) !Derived {
    var bound_public_data = public_data;
    try commitment_witness.bindCompletion(&bound_public_data, exec_trace.final_pc, opt_memory);

    var witness = try CommitmentWitness.build(
        allocator,
        exec_trace,
        opt_memory,
        bound_public_data.completion.?,
    );
    errdefer witness.deinit(allocator);

    // The two policies are one-to-one with the run modes; `statement_validation`
    // owns whatever difference they carry.
    const policy: statement_validation.AdmissionPolicy = switch (mode) {
        .prove => .proof,
        .relation_diagnostic => .relation_diagnostic,
    };
    const geometry = try statement_geometry.build(
        allocator,
        workspace,
        exec_trace,
        &witness,
        opt_chain,
        bound_public_data,
        policy,
    );
    return .{ .witness = witness, .geometry = geometry };
}

/// CP-11 relation evidence over the three roots this run committed.
///
/// The tree-shape guard is not defensive: `relation_diagnostic` indexes the
/// roots positionally, so a scheme that committed a different number of trees
/// would silently attribute one tree's root to another.
fn buildDiagnostic(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    statement: *const RiscVStatement,
    scheme: *const Engine.Scheme,
    tree0: *const relation_diagnostic.RetainedTree,
    tree1: *const relation_diagnostic.RetainedTree,
    relations: relation_challenges.Relations,
    claim: *const RiscVInteractionClaim,
) !types.RelationDiagnostic {
    if (scheme.trees.items.len != 3) return error.InvalidTreeShape;
    return relation_diagnostic.build(allocator, statement, tree0, tree1, .{
        scheme.trees.items[0].root(),
        scheme.trees.items[1].root(),
        scheme.trees.items[2].root(),
    }, relations, claim);
}

/// Column counts of the committed trees, once per proving run.
fn logProofGeometry(
    statement: *const RiscVStatement,
    geometry: Geometry,
    n_poseidon_calls: usize,
) void {
    const n_opcode_main = statement.nOpcodeMainColumns();
    const n_infra_main = statement.nInfraColumns();
    std.log.info("Columns: opcode={d} infra={d} total tree1={d} interaction={d}", .{
        n_opcode_main,
        n_infra_main,
        n_opcode_main + n_infra_main,
        statement.nInteractionColumns(),
    });
    std.log.info("Poseidon2 Merkle: {d} exact sparse-node calls, poseidon_log_size={d}, merkle_log_size={d}", .{
        n_poseidon_calls,
        geometry.poseidon_log_size,
        geometry.merkle_log_size,
    });
}
