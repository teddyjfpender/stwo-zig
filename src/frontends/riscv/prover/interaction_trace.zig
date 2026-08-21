//! The claim phase and Tree 2: LogUp interaction columns.
//!
//! ## Why the claim phase lives here
//!
//! `drawChallenges` is the only place a relation challenge may be drawn. It sits
//! in this module because the challenges and the columns they parameterise must
//! not be separable: every interaction column below is a function of the exact
//! `Relations` value drawn from the transcript position immediately after the
//! Tree-1 root. A second draw site, even one that produced the same value, would
//! be a second definition of the Fiat-Shamir position.
//!
//! ## Ordering
//!
//! Interaction columns are appended in the *same* declaration order Tree 1 used
//! -- opcode shards, then program, RW-memory shards, Merkle, Poseidon2, clock
//! update, lookup tables -- because `proof_finalize` walks one shared offset
//! cursor over both trees. The per-component claim written into
//! `interaction_claim` is indexed by that component's registry position, not by
//! the order it was generated in, which is why the memory and lookup-table
//! stages re-derive `infra_index` rather than counting.
//!
//! ## Ownership
//!
//! The generated `ColumnEvaluation` array is **transferred** to the commitment
//! scheme at the commit point and released here on every path that does not
//! reach it. Generator results transfer their column buffers into that array;
//! only the fixed-size claims are copied into `RiscVInteractionClaim`. No
//! duplicate interaction masks remain in `ProofWorkspace`: composition later
//! borrows the committed Tree-2 values from the scheme.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const work_pool = @import("stwo_prover_engine").work_pool;
const prover_api = @import("stwo_prover_api");
const stage_profile = @import("stwo_prover_api").stage_profile;
const clock_update_interaction = @import("../air/clock_update_interaction.zig");
const component_order = @import("../air/component_order.zig");
const guest_interaction = @import("../air/guest_precompile/interaction.zig");
const guest_components = @import("../air/guest_precompile/component_registry.zig");
const guest_main_trace = @import("../air/guest_precompile/main_trace.zig");
const guest_proof_transcript = @import("../air/guest_precompile/proof_transcript.zig");
const guest_relations = @import("../air/guest_precompile/relation_challenges.zig");
const guest_statement = @import("../air/guest_precompile/statement.zig");
const lookup_table_interaction = @import("../air/lookups/tables/interaction.zig");
const lookup_table_schema = @import("../air/lookups/tables/schema.zig");
const lookup_physical_v2 = @import("../air/lang/lookup_physical_manifest_v2.zig");
const opcode_entries = @import("../air/lookups/opcode_entries.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const BaseScalar = @import("../air/lookups/base_scalar.zig").Scalar;
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_interaction = @import("../air/program/interaction.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const proof_transcript = @import("../proof_transcript.zig");
const trace_mod = @import("../runner/trace.zig");
const commitment_witness = @import("commitment_witness.zig");
const lookup_sources = @import("lookup_sources.zig");
const interaction_production = @import("interaction_trace_plan_execution_production.zig");
const interaction_witness_work = @import("interaction_witness_work.zig");
const proof_phase_meter = @import("proof_phase_meter.zig");
const proof_workspace = @import("proof_workspace.zig");
const statement_geometry = @import("statement_geometry.zig");
const statement_mod = @import("../air/statement.zig");
const test_witness_hook = @import("test_witness_hook.zig");
const tree2_main_source = @import("tree2_main_source.zig");
const types = @import("types.zig");

const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const CommitmentWitness = commitment_witness.CommitmentWitness;
const Geometry = statement_geometry.Geometry;
const ProofWorkspace = proof_workspace.ProofWorkspace;
const Relations = relation_challenges.Relations;
const RiscVInteractionClaim = types.RiscVInteractionClaim;
const RunMode = types.RunMode;
const OpcodeBaseEntries = opcode_entries.Entries(BaseScalar);

/// Draws the relation challenges that parameterise Tree 2.
///
/// In `.prove` the draw is preceded by the canonical main claim, the shard
/// manifest and the interaction proof of work, so the challenges are bound to
/// the committed main trace. `.relation_diagnostic` deliberately draws from a
/// *fresh* channel instead: the diagnostic compares relation sums across runs,
/// which requires challenges that do not depend on the witness under study.
///
/// The result is returned by value so the caller owns the storage the generated
/// components will borrow a pointer to for the rest of the proof.
pub fn drawChallenges(
    comptime Engine: type,
    comptime mode: RunMode,
    allocator: std.mem.Allocator,
    channel: *Engine.Channel,
    statement: *const types.RiscVStatement,
    recorder: ?*stage_profile.Recorder,
) !proof_transcript.ProverRelations {
    if (comptime mode == .prove) {
        var work_authority = try interaction_witness_work.plan(recorder);
        if (work_authority) |*authority| {
            return proof_transcript.proveToRelationsWithWorkReceipt(
                allocator,
                channel,
                statement,
                authority,
            );
        }
        return proof_transcript.proveToRelations(allocator, channel, statement);
    }
    var diagnostic_channel = Engine.Channel{};
    return .{
        .interaction_pow = 0,
        .relations = try Relations.draw(allocator, &diagnostic_channel),
    };
}

/// Generates every Tree-2 column, mixes the interaction claim, and commits.
///
/// `claim` is written in place by the caller's allocation: the boxed claim
/// outlives this proof, so allocating it at the boundary that transfers it keeps
/// its ownership visible in one function. `prefix` is **borrowed** and must
/// outlive proving -- the prover components hold `&prefix.relations`.
pub fn generateAndCommit(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    main_source: *const tree2_main_source.Source,
    prefix: *const proof_transcript.ProverRelations,
    claim: *RiscVInteractionClaim,
    test_mutation: ?test_witness_hook.Mutation,
    phase_meter: ?*proof_phase_meter.Meter,
) !void {
    if (prefix.challenge_work_receipt != null) {
        return generateAndCommitSequentialProfiled(
            Engine,
            allocator,
            workspace,
            scheme,
            channel,
            recorder,
            witness,
            geometry,
            main_source,
            prefix,
            claim,
            test_mutation,
            phase_meter,
            null,
        );
    }
    return generateAndCommitInternal(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        witness,
        geometry,
        main_source,
        prefix,
        claim,
        test_mutation,
        phase_meter,
        null,
    );
}

/// Append-only Tree-2 construction for an authenticated selected statement.
/// It deliberately has no execution-policy parameter yet: the first complete
/// proof uses the allocation-safe sequential generator, while V1 retains its
/// existing parallel selection without a branch.
pub fn generateAndCommitAuthenticatedLookupV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    main_source: *const tree2_main_source.Source,
    prefix: *const proof_transcript.ProverRelations,
    claim: *RiscVInteractionClaim,
    phase_meter: ?*proof_phase_meter.Meter,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated_statement: *const lookup_physical_v2.AuthenticatedStatement,
) !void {
    try authenticated_statement.validateAgainst(&workspace.statement, manifest);
    if (prefix.challenge_work_receipt != null) {
        return generateAndCommitSequentialProfiled(
            Engine,
            allocator,
            workspace,
            scheme,
            channel,
            recorder,
            witness,
            geometry,
            main_source,
            prefix,
            claim,
            null,
            phase_meter,
            .{
                .manifest = manifest,
                .statement = authenticated_statement,
            },
        );
    }
    return generateAndCommitInternal(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        witness,
        geometry,
        main_source,
        prefix,
        claim,
        null,
        phase_meter,
        .{
            .manifest = manifest,
            .statement = authenticated_statement,
        },
    );
}

pub const LookupV2Admission = struct {
    manifest: *const lookup_physical_v2.Manifest,
    statement: *const lookup_physical_v2.AuthenticatedStatement,
};

fn generateAndCommitSequentialProfiled(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    main_source: *const tree2_main_source.Source,
    prefix: *const proof_transcript.ProverRelations,
    claim: *RiscVInteractionClaim,
    test_mutation: ?test_witness_hook.Mutation,
    phase_meter: ?*proof_phase_meter.Meter,
    lookup_v2: ?LookupV2Admission,
) !void {
    // Parallel predecessor generators have distinct chunk/offset schedules;
    // prepared execution below receipts them exactly. The allocation-safe
    // sequential route fails closed rather than mislabelling a global-pool
    // substitution.
    if (work_pool.getGlobalPool() != null)
        return error.UnsupportedProfiledSequentialInteractionExecution;

    const authority = interaction_witness_work.Authority.init();
    const binding = interaction_witness_work.baseSessionDigest(
        prefix.interaction_pow,
        &prefix.relations,
    );
    var completed = interaction_witness_work.Shard{};
    try completed.observe(
        &authority,
        .base,
        binding,
        prefix.challenge_work_receipt.?,
    );

    try generateAndCommitInternal(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        witness,
        geometry,
        main_source,
        prefix,
        claim,
        test_mutation,
        phase_meter,
        lookup_v2,
    );
    const counts = try sequentialBaseWorkCounts(
        &workspace.statement,
        witness,
        geometry,
        if (lookup_v2) |authenticated| authenticated.manifest else null,
    );
    try completed.observe(
        &authority,
        .base,
        binding,
        try interaction_witness_work.completeInteraction(
            &authority,
            .base_interaction_trace,
            .base,
            binding,
            counts,
        ),
    );
    const receipt = try interaction_witness_work.seal(
        &authority,
        .base,
        binding,
        completed,
    );
    try interaction_witness_work.publish(recorder, receipt);
}

fn generateAndCommitInternal(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    main_source: *const tree2_main_source.Source,
    prefix: *const proof_transcript.ProverRelations,
    claim: *RiscVInteractionClaim,
    test_mutation: ?test_witness_hook.Mutation,
    phase_meter: ?*proof_phase_meter.Meter,
    lookup_v2: ?LookupV2Admission,
) !void {
    const statement = &workspace.statement;
    try main_source.validate(statement);
    claim.initZeroInto();
    claim.n_components = statement.n_components;
    claim.n_infra = statement.n_infra;
    claim.interaction_pow = prefix.interaction_pow;

    const relations = &prefix.relations;
    const n_interaction = if (lookup_v2) |authenticated|
        try authenticated.statement.totalInteractionColumns(
            statement,
            authenticated.manifest,
        )
    else
        statement.nInteractionColumns();

    var stage = try stage_profile.StageScope.begin(recorder, "riscv_interaction_commit", "RISC-V interaction trace generation and commit");
    defer stage.end();

    var materialization_region: ?proof_phase_meter.WitnessRegion =
        if (phase_meter) |meter| try meter.begin() else null;
    errdefer if (materialization_region) |*region| region.abort();

    var columns = try Columns.init(allocator, n_interaction);
    defer columns.deinit(allocator);

    try generateBase(
        allocator,
        workspace,
        &columns,
        recorder,
        witness,
        geometry,
        main_source,
        relations,
        claim,
        lookup_v2,
        .ambient,
    );
    std.debug.assert(columns.filled == n_interaction);
    if (test_mutation) |mutation| {
        try test_witness_hook.applyInteraction(
            allocator,
            statement.*,
            columns.values,
            mutation,
        );
    }

    if (materialization_region) |*region| try region.finish();
    if (lookup_v2) |authenticated| {
        try authenticated.statement.mixInteractionClaim(
            channel,
            statement,
            authenticated.manifest,
            claim,
        );
    } else {
        try proof_transcript.mixInteractionClaim(channel, statement, claim);
    }
    columns.moved = true;
    try Engine.commit(scheme, allocator, columns.values, recorder, channel);
}

/// Selects the predecessor or the explicitly requested bounded Tree-2 epoch.
/// A null request enters `generateAndCommit` directly, preserving its generator
/// selection, allocation order, and commitment path. The requested path
/// prepares all destinations and scratch before acquiring its finite pool.
pub fn generateAndCommitWithExecution(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    main_source: *const tree2_main_source.Source,
    prefix: *const proof_transcript.ProverRelations,
    claim: *RiscVInteractionClaim,
    test_mutation: ?test_witness_hook.Mutation,
    execution_request: ?prover_api.CpuCompositionExecutionRequest,
    pool: ?*work_pool.WorkPool,
    phase_meter: ?*proof_phase_meter.Meter,
) !void {
    const request = execution_request orelse return generateAndCommit(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        witness,
        geometry,
        main_source,
        prefix,
        claim,
        test_mutation,
        phase_meter,
    );

    const statement = &workspace.statement;
    if (request.worker_count > 1 and pool == null) return error.WorkPoolRequired;
    try work_pool.observeProofPoolStageForTest(.tree2, pool);
    try main_source.validate(statement);
    claim.initZeroInto();
    claim.n_components = statement.n_components;
    claim.n_infra = statement.n_infra;
    claim.interaction_pow = prefix.interaction_pow;

    var stage = try stage_profile.StageScope.begin(
        recorder,
        "riscv_interaction_commit",
        "RISC-V interaction trace generation and commit",
    );
    defer stage.end();

    var materialization_region: ?proof_phase_meter.WitnessRegion =
        if (phase_meter) |meter| try meter.begin() else null;
    errdefer if (materialization_region) |*region| region.abort();

    const prepared_inputs = interaction_production.Inputs{
        .witness = witness,
        .geometry = geometry,
        .main_source = main_source.*,
        .relations = &prefix.relations,
        .claim = claim,
    };
    const pool_capacity = if (pool) |active_pool| active_pool.workerCount() else 1;
    const worker_stack_bytes = if (pool) |active_pool|
        active_pool.stackSize()
    else
        work_pool.WORKER_STACK_SIZE;
    const challenge_work = prefix.challenge_work_receipt;
    const work_authority = interaction_witness_work.Authority.init();
    const work_binding = interaction_witness_work.baseSessionDigest(
        prefix.interaction_pow,
        &prefix.relations,
    );
    var prepared = if (challenge_work) |challenge_receipt|
        try interaction_production.Prepared.prepareWithWorkReceipt(
            allocator,
            statement,
            prepared_inputs,
            request,
            pool_capacity,
            worker_stack_bytes,
            .{
                .authority = work_authority,
                .session_digest = work_binding,
                .challenge_receipt = challenge_receipt,
            },
        )
    else
        try interaction_production.Prepared.prepare(
            allocator,
            statement,
            prepared_inputs,
            request,
            pool_capacity,
            worker_stack_bytes,
        );
    defer prepared.deinit();
    _ = try prepared.execute(pool);
    if (test_mutation) |mutation| {
        try test_witness_hook.applyInteraction(
            allocator,
            statement.*,
            try prepared.borrowPublishedColumnsForTest(),
            mutation,
        );
    }

    if (materialization_region) |*region| try region.finish();
    try proof_transcript.mixInteractionClaim(channel, statement, claim);
    const work_receipt = if (challenge_work != null)
        try prepared.interactionWorkReceipt()
    else
        null;
    const columns = try prepared.takeColumns();
    // The engine consumes descriptors and payloads on both success and error;
    // the prepared owner is disarmed immediately before this call.
    try Engine.commit(scheme, allocator, columns, recorder, channel);
    if (work_receipt) |receipt|
        try interaction_witness_work.publish(recorder, receipt);
}

/// Detailed extension recurrence claims. The two transcript-visible component
/// sums are recomputed from these arrays by `guest_statement.InteractionClaim`.
pub const Poseidon2Claims = struct {
    caller: [guest_interaction.caller_batch_count]QM31,
    provider: [guest_interaction.provider_batch_count]QM31,

    pub fn canonical(self: *const Poseidon2Claims) guest_interaction.Claims {
        return .{ .caller = self.caller, .provider = self.provider };
    }
};

pub fn generateAndCommitPoseidon2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    extension: *const guest_statement.ExtensionStatement,
    relation_source: *const guest_main_trace.RelationSource,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    lookup_source: *const lookup_sources.Result,
    prefix: *const guest_proof_transcript.ProverRelations,
    base_claim: *RiscVInteractionClaim,
    guest_claim: *Poseidon2Claims,
) !void {
    return generateAndCommitPoseidon2WithPhaseMeter(
        Engine,
        allocator,
        workspace,
        extension,
        relation_source,
        scheme,
        channel,
        recorder,
        witness,
        geometry,
        lookup_source,
        prefix,
        base_claim,
        guest_claim,
        null,
    );
}

/// Profile Tree 2 with the same materialization boundary used by the base
/// prover. Commitment work is deliberately outside the witness region.
pub fn generateAndCommitPoseidon2WithPhaseMeter(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    extension: *const guest_statement.ExtensionStatement,
    relation_source: *const guest_main_trace.RelationSource,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    lookup_source: *const lookup_sources.Result,
    prefix: *const guest_proof_transcript.ProverRelations,
    base_claim: *RiscVInteractionClaim,
    guest_claim: *Poseidon2Claims,
    phase_meter: ?*proof_phase_meter.Meter,
) !void {
    const base_receipt = prefix.base_challenge_work_receipt;
    const guest_receipt = prefix.guest_challenge_work_receipt;
    if (base_receipt == null and guest_receipt == null) {
        return generateAndCommitPoseidon2Unprofiled(
            Engine,
            allocator,
            workspace,
            extension,
            relation_source,
            scheme,
            channel,
            recorder,
            witness,
            geometry,
            lookup_source,
            prefix.interaction_pow,
            &prefix.relations,
            base_claim,
            guest_claim,
            phase_meter,
            .ambient,
        );
    }
    if (base_receipt == null or guest_receipt == null)
        return error.IncompleteInteractionChallengeWork;
    return generateAndCommitPoseidon2Profiled(
        Engine,
        allocator,
        workspace,
        extension,
        relation_source,
        scheme,
        channel,
        recorder,
        witness,
        geometry,
        lookup_source,
        prefix,
        base_claim,
        guest_claim,
        phase_meter,
    );
}

fn generateAndCommitPoseidon2Unprofiled(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    extension: *const guest_statement.ExtensionStatement,
    relation_source: *const guest_main_trace.RelationSource,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    lookup_source: *const lookup_sources.Result,
    interaction_pow: u64,
    relations: *const guest_relations.Poseidon2V1Relations,
    base_claim: *RiscVInteractionClaim,
    guest_claim: *Poseidon2Claims,
    phase_meter: ?*proof_phase_meter.Meter,
    base_execution_policy: BaseExecutionPolicy,
) !void {
    const statement = &workspace.statement;
    try extension.validate(statement);
    const main_source = tree2_main_source.Source.fromLegacy(workspace, lookup_source);
    try main_source.validate(statement);
    base_claim.initZeroInto();
    base_claim.n_components = statement.n_components;
    base_claim.n_infra = statement.n_infra;
    base_claim.interaction_pow = interaction_pow;

    const n_base_interaction = statement.nInteractionColumns();
    const n_interaction = std.math.add(
        usize,
        n_base_interaction,
        guest_interaction.total_column_count,
    ) catch return error.InvalidTraceShape;
    var stage = try stage_profile.StageScope.begin(
        recorder,
        "riscv_guest_interaction_commit",
        "RISC-V guest interaction trace generation and commit",
    );
    defer stage.end();
    var materialization_region: ?proof_phase_meter.WitnessRegion =
        if (phase_meter) |meter| try meter.begin() else null;
    errdefer if (materialization_region) |*region| region.abort();
    var columns = try Columns.init(allocator, n_interaction);
    defer columns.deinit(allocator);

    try generateBase(
        allocator,
        workspace,
        &columns,
        recorder,
        witness,
        geometry,
        &main_source,
        &relations.base,
        base_claim,
        null,
        base_execution_policy,
    );
    if (columns.filled != n_base_interaction) return error.InvalidTraceShape;
    var destinations = try columns.reserveGuest(
        allocator,
        extension.components[0].log_size,
    );
    const generated = try guest_interaction.generateFromRelationSourceInto(
        allocator,
        statement,
        extension,
        relation_source,
        relations,
        &destinations,
    );
    guest_claim.* = .{ .caller = generated.caller, .provider = generated.provider };
    try generated.verifyGuestCancellation();
    if (columns.filled != n_interaction) return error.InvalidTraceShape;

    const canonical_base = try allocator.create(statement_mod.CanonicalInteractionClaim);
    defer allocator.destroy(canonical_base);
    canonical_base.* = try base_claim.canonical(statement);
    const extended_claim = guest_statement.InteractionClaim.init(
        canonical_base.view(),
        generated.callerTotal(),
        generated.providerTotal(),
        extension,
    );
    try guest_proof_transcript.mixInteractionClaim(
        channel,
        statement,
        extension,
        &extended_claim,
        .{
            .base = base_claim,
            .caller = &guest_claim.caller,
            .provider = &guest_claim.provider,
        },
    );

    if (materialization_region) |*region| try region.finish();
    columns.moved = true;
    try Engine.commit(scheme, allocator, columns.values, recorder, channel);
}

fn generateAndCommitPoseidon2Profiled(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    extension: *const guest_statement.ExtensionStatement,
    relation_source: *const guest_main_trace.RelationSource,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    lookup_source: *const lookup_sources.Result,
    prefix: *const guest_proof_transcript.ProverRelations,
    base_claim: *RiscVInteractionClaim,
    guest_claim: *Poseidon2Claims,
    phase_meter: ?*proof_phase_meter.Meter,
) !void {
    // Tree 2 explicitly ignores the ambient pool so its real execution matches
    // the sequential work receipt. Later quotient stages retain pool access.

    const authority = interaction_witness_work.Authority.init();
    const binding = interaction_witness_work.guestSessionDigest(
        prefix.interaction_pow,
        &prefix.relations,
    );
    var completed = interaction_witness_work.Shard{};
    try completed.observe(
        &authority,
        .poseidon2_guest,
        binding,
        prefix.base_challenge_work_receipt.?,
    );
    try completed.observe(
        &authority,
        .poseidon2_guest,
        binding,
        prefix.guest_challenge_work_receipt.?,
    );

    // Completion publication is deliberately after the real Tree-2 commit.
    // Any allocation, denominator, cancellation, claim, or commit failure
    // therefore leaves the aggregate site incomplete.
    try generateAndCommitPoseidon2Unprofiled(
        Engine,
        allocator,
        workspace,
        extension,
        relation_source,
        scheme,
        channel,
        recorder,
        witness,
        geometry,
        lookup_source,
        prefix.interaction_pow,
        &prefix.relations,
        base_claim,
        guest_claim,
        phase_meter,
        GUEST_PROFILED_TREE2_EXECUTION_POLICY,
    );

    try GUEST_PROFILED_TREE2_EXECUTION_POLICY.requireSequentialReceipt();
    const base_counts = try sequentialBaseWorkCounts(
        &workspace.statement,
        witness,
        geometry,
        null,
    );
    try completed.observe(
        &authority,
        .poseidon2_guest,
        binding,
        try interaction_witness_work.completeInteraction(
            &authority,
            .base_interaction_trace,
            .poseidon2_guest,
            binding,
            base_counts,
        ),
    );
    const guest_counts = try guestInteractionWorkCounts(extension.counts.n_guest);
    try completed.observe(
        &authority,
        .poseidon2_guest,
        binding,
        try interaction_witness_work.completeInteraction(
            &authority,
            .guest_interaction_trace,
            .poseidon2_guest,
            binding,
            guest_counts,
        ),
    );
    const receipt = try interaction_witness_work.seal(
        &authority,
        .poseidon2_guest,
        binding,
        completed,
    );
    try interaction_witness_work.publish(recorder, receipt);
}

const generation_mod = @import("interaction_trace_generation.zig");
pub const BaseExecutionPolicy = generation_mod.BaseExecutionPolicy;
pub const GUEST_PROFILED_TREE2_EXECUTION_POLICY: BaseExecutionPolicy = .sequential;
const generation = generation_mod.Ops(@This());
const generateBase = generation.generateBase;
const sequentialBaseWorkCounts = generation.sequentialBaseWorkCounts;
const guestInteractionWorkCounts = generation.guestInteractionWorkCounts;
const Columns = generation.Columns;
