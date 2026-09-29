//! Complete backend-neutral official Cairo proving transaction.
//!
//! The current entrypoint remains profile-gated by an authenticated AIR bundle.
//! Component presence and row geometry are derived from the live input.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const adapter = @import("../adapter/mod.zig");
const cairo_air = @import("../air/mod.zig");
const claim_generator = @import("../claim_generator.zig");
const preprocessed = @import("../preprocessed/mod.zig");
const statement = @import("../statement/mod.zig");
const statement_bootstrap = @import("../statement_bootstrap.zig");
const witness = @import("../witness/mod.zig");
const proving_air = @import("air/mod.zig");
const base_trace = @import("base_trace.zig");
const feed_geometry_oracle = @import("feed_geometry_oracle.zig");
const interaction_trace = @import("interaction_trace.zig");
const trace_arena = @import("trace_arena.zig");
const trace_commit = @import("trace_commit.zig");
const preprocessed_commit = @import("preprocessed_commit.zig");
const transcript = @import("transcript.zig");
const geometry = @import("../witness/resident_geometry.zig");
pub const leaf_lane = @import("leaf_lane.zig");

const QM31 = core.fields.qm31.QM31;
const VerifierComponent = core.air.components.Component;
const ComponentProver = prover.air.component_prover.ComponentProver;

pub const official_pcs_config = core.pcs.PcsConfig{
    .pow_bits = 26,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 70,
        .fold_step = 1,
    },
    .lifting_log_size = 0,
};

/// Execution storage only; both opening methods evaluate the same committed
/// polynomials at the same transcript points and preserve proof bytes.
pub const SampledEvaluationStorage = enum { retained_coefficients, committed_columns, compact_polynomials, compact_preprocessed };

pub const Fixture = struct {
    input: *const adapter.ProverInput,
    programs: *const witness.bundle.Bundle,
    generated_executor: ?witness.generated_executor.Executor = null,
    interaction_executor: ?witness.interaction_executor.Executor = null,
    topology: witness.feed_topology.Loaded,
    fixed: *const witness.fixed_table_bundle.Bundle,
    relations: *const witness.relation_bundle.Bundle,
    air_templates: *const cairo_air.template_library.Library,
    /// Optional whole-stage device composition evaluator. Supplied by the Metal
    /// product and absent on the CPU product, which keeps the CPU lane the
    /// byte-parity reference by construction.
    composition_device: ?proving_air.device_stage.Device = null,
    native_composition: ?proving_air.native_evaluator.Executor = null,
    sampled_evaluation: SampledEvaluationStorage = .retained_coefficients,
};

pub fn Result(comptime Engine: type) type {
    return struct {
        allocator: std.mem.Allocator,
        proof: Engine.ExtendedProof,
        statement: statement_bootstrap.OwnedStatementBootstrap,
        composition: witness.composition_bundle.Bundle,
        claimed_sums: []QM31,
        interaction_pow: u64,
        preprocessed_variant: preprocessed.trace.Variant,
        channel_salt: u32 = 0,
        proof_owned: bool = true,

        pub fn deinit(self: *@This()) void {
            if (self.proof_owned) self.proof.deinit(self.allocator);
            self.statement.deinit();
            self.composition.deinit();
            self.allocator.free(self.claimed_sums);
            self.* = undefined;
        }
    };
}

pub fn proveFixture(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    fixture: Fixture,
    variant: preprocessed.trace.Variant,
) !Result(Engine) {
    return proveFixtureWithRecorder(
        Engine,
        allocator,
        fixture,
        variant,
        null,
    );
}

pub fn proveFixtureWithRecorder(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    fixture: Fixture,
    variant: preprocessed.trace.Variant,
    recorder: ?*prover.stage_profile.Recorder,
) !Result(Engine) {
    return proveFixtureForLane(Engine, allocator, fixture, variant, recorder, null);
}

/// The one Cairo proving transaction. `lane == null` is the official lane
/// (stwo-cairo 82f2125, `official_pcs_config`); a `leaf_lane.Lane` selects the
/// `proving_5a7c5ed` leaf protocol and requires `Engine.MerkleChannel` to be a
/// channel profile. The step order is upstream `prove_cairo_common`'s for both.
pub fn proveFixtureForLane(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    fixture: Fixture,
    variant: preprocessed.trace.Variant,
    recorder: ?*prover.stage_profile.Recorder,
    lane: ?leaf_lane.Lane,
) !Result(Engine) {
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    if (lane) |leaf| {
        if (comptime core.protocol_revision.Revision.of(Engine.MerkleChannel) != .proving_5a7c5ed)
            return error.LeafLaneRequiresChannelProfile;
        if (leaf.variant != variant) return error.PreprocessedVariantMismatch;
        // Compact storage prunes or drops what the post-commit lift reads.
        switch (fixture.sampled_evaluation) {
            .retained_coefficients, .committed_columns => {},
            .compact_polynomials, .compact_preprocessed => return error.UnsupportedLeafLaneStorage,
        }
    }
    const claim_options = claim_generator.Options{
        .preprocessed_variant = claimVariant(variant),
        .memory_id_to_big_components = if (lane) |leaf| leaf.memory_id_to_big_components else null,
    };
    var target = blk: {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "preprocessed_plan",
            "Preprocessed plan",
        );
        defer stage.end();
        break :blk try preprocessed.trace.Spec.init(allocator, variant);
    };
    defer target.deinit();
    const preprocessed_logs = try target.logs(allocator);
    defer allocator.free(preprocessed_logs);

    const preprocessed_binding = preprocessed.product_cache.Binding{
        .variant = variant,
        .spec_digest = preprocessed.product_cache.specDigest(target),
        .pcs_digest = if (lane) |leaf|
            preprocessed.product_cache.pcsDigestRevision(leaf.fri_config)
        else
            preprocessed.product_cache.pcsDigest(official_pcs_config),
    };

    var pedersen: preprocessed.pedersen_table.Table = undefined;
    var pedersen_initialized = false;
    defer if (pedersen_initialized) pedersen.deinit();
    {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "preprocessed_table_build",
            "Preprocessed table build",
        );
        defer stage.end();
        const binding = preprocessed_binding;
        switch (variant) {
            .canonical_without_pedersen => {},
            .canonical => {
                pedersen = try preprocessed.product_cache.pedersenTable(
                    allocator,
                    .standard,
                    binding,
                    recorder,
                );
                pedersen_initialized = true;
            },
            .canonical_small => {
                pedersen = try preprocessed.product_cache.pedersenTable(
                    allocator,
                    .small,
                    binding,
                    recorder,
                );
                pedersen_initialized = true;
            },
        }
    }

    var channel = Engine.Channel{};
    transcript.mixChannelSalt(&channel, if (lane) |leaf| leaf.channel_salt else 0);
    // `Revision.proving_5a7c5ed.mixConfig` is exactly the FRI config's mix;
    // the lifting heights, unknown until the claim exists, are never mixed.
    if (lane) |leaf| leaf.fri_config.mixInto(&channel) else official_pcs_config.mixInto(&channel);
    var scheme = try Engine.init(
        allocator,
        if (lane) |leaf| core.protocol_revision.Revision.friLegacyView(leaf.fri_config) else official_pcs_config,
    );
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);
    switch (fixture.sampled_evaluation) {
        .committed_columns => scheme.setCoefficientRetentionPolicy(.never),
        .retained_coefficients => {},
        .compact_polynomials, .compact_preprocessed => scheme.setCompactPolynomialStorage(18),
    }

    var preprocessed_worker = preprocessed_commit.Worker(Engine).init(
        allocator,
        &target,
        if (pedersen_initialized) &pedersen else null,
        preprocessed_binding,
        &scheme,
        &channel,
        recorder,
    );
    defer preprocessed_worker.deinit();
    // The leaf lane's preprocessed height depends on the trace, so its tree
    // is committed only after the claim fixes the heights (`finish`).
    if (lane == null) preprocessed_worker.start(recorder);

    // Backends that bind one contiguous resident source arena get their base
    // trace planned and allocated *before* component execution, so every
    // generated and implicit column is written at its final offset and nothing
    // is repacked afterwards. Every other backend keeps today's fragmented
    // allocation exactly as it is: the branch is comptime.
    const arena_capable = comptime @hasDecl(Engine, "Backend") and
        @hasDecl(Engine.Backend, "adopts_source_trace_arena") and
        Engine.Backend.adopts_source_trace_arena;

    var planned_geometry: ?claim_generator.OwnedClaimGeometry = null;
    // The arena-planned base trace borrows this geometry (`borrowed_geometry`),
    // so the transaction frees it on every exit, after `base` (declared later).
    defer if (planned_geometry) |*owned| owned.deinit();
    var planned_composition: ?witness.composition_bundle.Bundle = null;
    errdefer if (planned_composition) |*owned| owned.deinit();
    var arena: ?trace_arena.Arena = null;
    errdefer if (arena) |*owned| owned.deinit();
    // True once `feed_geometry_oracle` has written at least one *predicted* log
    // size into the planned claim. It is the precondition for treating a
    // plan-versus-witness geometry disagreement as recoverable rather than as a
    // soundness abort: without a prediction the planned claim is exactly what
    // `deriveFromProverInput` produced, and a disagreement there is a real bug.
    var oracle_predicted = false;
    // Compact host streams interpolate arena subcolumns in place and transfer
    // their shared owner once; the ordinary resident path adopts it directly.
    if (arena_capable) {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "base_trace_arena_plan",
            "Base trace arena plan",
        );
        defer stage.end();
        // Structural admission, and the reason it is not a hard requirement:
        // a claim derived before witness execution still carries *deferred*
        // per-component log sizes for every feed-dependent component
        // (`claim_generator.LogSize.deferred`, resolved by
        // `resolveFeedGeometry`, "the witness-to-statement handoff"). The AIR
        // template binder refuses a deferred log size outright
        // (`air/template_binding.zig:42`, `:104`), so a claim with any deferred
        // component cannot be laid out before execution.
        //
        // `feed_geometry_oracle` closes that gap for the components whose row
        // counts the authenticated feed topology fully determines from the
        // adapted prover input; anything it cannot determine exactly it refuses,
        // and then this block falls back rather than fails, so the product keeps
        // its unchanged fragmented path.
        var claim = claim_generator.deriveFromProverInput(
            allocator,
            fixture.input,
            claim_options,
        ) catch null;
        if (claim) |*live| {
            if (live.deferredCount() != 0) {
                var oracle_stage = try prover.stage_profile.StageScope.begin(
                    recorder,
                    "base_trace_geometry_oracle",
                    "Pre-execution feed geometry resolution",
                );
                defer oracle_stage.end();
                if (feed_geometry_oracle.resolveInPlace(
                    allocator,
                    live,
                    claim_generator.ExecutionResources.fromProverInput(fixture.input),
                    fixture.topology,
                )) |outcome| {
                    oracle_predicted = outcome.resolved != 0;
                } else |_| {}
            }
        }
        var instantiated: ?witness.composition_bundle.Bundle = null;
        if (claim) |*live| {
            if (live.deferredCount() == 0) {
                instantiated = fixture.air_templates.instantiate(
                    allocator,
                    live,
                    variant,
                    fixture.input.builtin_segments,
                ) catch null;
            }
        }
        if (instantiated == null) {
            if (claim) |*live| live.deinit();
            claim = null;
        }
        if (if (instantiated) |ready|
            trace_arena.tryPrepare(allocator, ready.components)
        else
            null) |ready|
        {
            planned_geometry = claim;
            planned_composition = instantiated;
            arena = ready;
            // Telemetry, not control flow: the stage name records the decision
            // so an arena-engaged run is distinguishable from a fallback run in
            // `--stage-profile-out` without a debug build.
            var engaged = try prover.stage_profile.StageScope.begin(
                recorder,
                "base_trace_arena_engaged",
                "Base trace arena engaged",
            );
            engaged.end();
        } else {
            if (instantiated) |*owned| owned.deinit();
            if (claim) |*owned| owned.deinit();
            var fell_back = try prover.stage_profile.StageScope.begin(
                recorder,
                "base_trace_arena_fallback",
                "Base trace arena fallback",
            );
            fell_back.end();
        }
    }

    var base = blk: {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "base_trace_build",
            "Base trace build",
        );
        defer stage.end();
        const pedersen_deductions: ?witness.deductions.PedersenTable =
            if (pedersen_initialized) .{
                .window_bits = pedersen.window.bits(),
                .points = pedersen.points,
            } else null;
        // The planned attempt. The witness-to-statement handoff is the earliest
        // point at which the deferred path's own row counts exist, and it is
        // inside this call: `live_graph.executeComponent` computes each
        // component's padded row count and `validateClaimGeometry` compares it
        // against the planned claim. A predicted log size that disagrees is
        // therefore caught before any commitment exists — but too late to avoid
        // the work, so the recovery is to discard the plan and rebuild on the
        // deferred path, which is byte-for-byte the unplanned product path.
        //
        // Declining the arena for the proof is the *only* consequence: the proof
        // completes with correct bytes. Fail-closed abort is kept for the case
        // this cannot explain — no prediction was made, i.e. the deferred path
        // and the committed claim disagree by themselves.
        if (arena) |*ready| {
            if (base_trace.buildInto(
                allocator,
                fixture.input,
                fixture.programs,
                fixture.generated_executor,
                fixture.interaction_executor,
                fixture.topology,
                fixture.fixed,
                claim_options,
                pedersen_deductions,
                recorder,
                .{ .geometry = &planned_geometry.?, .arena = ready },
            )) |planned_base| {
                break :blk planned_base;
            } else |err| {
                if (!oracle_predicted or !isPlannedGeometryDisagreement(err))
                    return err;
                if (arena) |*owned| owned.deinit();
                arena = null;
                if (planned_composition) |*owned| owned.deinit();
                planned_composition = null;
                if (planned_geometry) |*owned| owned.deinit();
                planned_geometry = null;
                // A distinct decline reason, and deliberately not the plan-time
                // `base_trace_arena_fallback`: that one means the claim was never
                // resolvable, this one means it resolved to the wrong answer.
                var declined = try prover.stage_profile.StageScope.begin(
                    recorder,
                    "base_trace_arena_geometry_declined",
                    "Base trace arena declined: predicted geometry disagreed",
                );
                declined.end();
            }
        }
        break :blk try base_trace.buildInto(
            allocator,
            fixture.input,
            fixture.programs,
            fixture.generated_executor,
            fixture.interaction_executor,
            fixture.topology,
            fixture.fixed,
            claim_options,
            pedersen_deductions,
            recorder,
            null,
        );
    };
    defer base.deinit();
    prover.measurement.process_usage.reportStage("cairo.base_trace_complete");
    var composition = blk: {
        if (planned_composition) |ready| {
            planned_composition = null;
            break :blk ready;
        }
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "air_template_instantiation",
            "AIR template instantiation",
        );
        defer stage.end();
        break :blk try fixture.air_templates.instantiate(
            allocator,
            &base.geometry,
            variant,
            fixture.input.builtin_segments,
        );
    };
    errdefer composition.deinit();
    try validateComposition(&composition, base.geometry);

    var flat = try base.geometry.flatten();
    defer flat.deinit();
    var owned_statement = try statement_bootstrap.init(allocator, .{
        .channel_salt = if (lane) |leaf| leaf.channel_salt else 0,
        // Ordinal 2 is statement metadata; the transaction mixes the config
        // itself. On the leaf lane its eight words with lifting 0 are exactly
        // the two felts `FriConfig::mix_into` mixes.
        .pcs = if (lane) |leaf| .{
            .pow_bits = leaf.fri_config.pow_bits,
            .log_blowup_factor = leaf.fri_config.log_blowup_factor,
            .n_queries = leaf.fri_config.n_queries,
            .log_last_layer_degree_bound = leaf.fri_config.log_last_layer_degree_bound,
            .fold_step = leaf.fri_config.fold_step,
            .lifting_log_size = 0,
        } else .{
            .pow_bits = official_pcs_config.pow_bits,
            .log_blowup_factor = official_pcs_config.fri_config.log_blowup_factor,
            .n_queries = @intCast(official_pcs_config.fri_config.n_queries),
            .log_last_layer_degree_bound = official_pcs_config.fri_config.log_last_layer_degree_bound,
            .fold_step = official_pcs_config.fri_config.fold_step,
            .lifting_log_size = official_pcs_config.lifting_log_size,
        },
        .component_enable_bits = flat.component_enable_bits,
        .component_log_sizes = flat.component_log_sizes,
        .prover_input = fixture.input,
    });
    errdefer owned_statement.deinit();

    if (lane) |leaf| {
        // `LiftingSizePolicy::AtLeastPreprocessed`: the heights follow the
        // claim, padding components included, and precede every commitment.
        var max_claim_log_size: u32 = 0;
        for (base.geometry.components) |component| switch (component.log_size) {
            .known => |log_size| max_claim_log_size = @max(max_claim_log_size, log_size),
            .deferred => return error.InvalidCompositionGeometry,
        };
        if (comptime @hasDecl(Engine.Scheme, "setRevisionConfig"))
            try scheme.setRevisionConfig(try leaf.pcsConfig(max_claim_log_size))
        else
            return error.LeafLaneRequiresChannelProfile;
    }
    try preprocessed_worker.finish(recorder);
    // The fixed-data tree keeps its own compact representation. After the
    // worker joins, future witness trees can retain ordinary committed columns.
    if (fixture.sampled_evaluation == .compact_preprocessed) {
        scheme.compact_polynomial_storage = false;
        scheme.setCoefficientRetentionPolicy(.never);
    }
    prover.measurement.process_usage.reportStage("cairo.preprocessed_complete");
    try transcript.mixClaim(Engine.MerkleChannel, allocator, &channel, &owned_statement);

    {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "main_trace_commit",
            "Main trace commit",
        );
        defer stage.end();
        try trace_commit.commit(Engine, &scheme, allocator, &base, &arena, recorder, &channel, .{
            .id = "main_trace_commit_arena_bound",
            .label = "Main trace commit bound to the base trace arena",
        });
        try Engine.flushPendingCommit(&scheme, allocator, &channel);
    }

    prover.measurement.process_usage.reportStage("cairo.main_commit_complete");
    const interaction_pow =
        transcript.grindInteraction(&channel);
    const lookup = try transcript.drawLookupElements(
        allocator,
        &channel,
    );

    var interaction_arena: ?trace_arena.Arena = null;
    defer if (interaction_arena) |*owned| owned.deinit();
    // Compact host streams interpolate arena subcolumns in place and transfer
    // their shared owner once; the ordinary resident path adopts it directly.
    if (arena_capable) {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "interaction_trace_arena_plan",
            "Interaction trace arena plan",
        );
        defer stage.end();
        if (trace_arena.planInteraction(allocator, composition.components)) |layout| {
            if (std.posix.getenv("STWO_CAIRO_PROFILE_ARENAS") != null)
                std.debug.print("cairo_interaction_arena admitted=true bytes={} columns={}\n", .{
                    layout.base_words * @sizeOf(core.fields.m31.M31), layout.offsets.len,
                });
            interaction_arena = try trace_arena.allocateUninitialized(allocator, layout);
        } else |err| {
            if (std.posix.getenv("STWO_CAIRO_PROFILE_ARENAS") != null)
                std.debug.print("cairo_interaction_arena admitted=false reason={s}\n", .{@errorName(err)});
        }
    }
    var interaction = blk: {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "interaction_trace_build",
            "Interaction trace build",
        );
        defer stage.end();
        break :blk try interaction_trace.build(
            allocator,
            fixture.input,
            fixture.topology,
            fixture.fixed,
            fixture.relations,
            &base,
            lookup.z,
            lookup.alpha,
            if (pedersen_initialized) &pedersen else null,
            fixture.interaction_executor,
            recorder,
            if (interaction_arena) |*ready| ready else null,
        );
    };
    defer interaction.deinit();
    base.releaseWitnessFeeds();
    prover.measurement.process_usage.reportStage("cairo.interaction_build_complete");
    const public_sum = try statement.public_logup.sum(
        allocator,
        fixture.input,
        lookup.z,
        lookup.alpha,
    );
    if (!public_sum.add(interaction.component_sum).eql(QM31.zero()))
        return error.InvalidGlobalLookupSum;
    transcript.mixInteractionClaim(
        &channel,
        interaction.claimed_sums,
    );
    {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "interaction_trace_commit",
            "Interaction trace commit",
        );
        defer stage.end();
        try trace_commit.commit(Engine, &scheme, allocator, &interaction, &interaction_arena, recorder, &channel, .{
            .id = "interaction_trace_commit_arena_bound",
            .label = "Interaction commitment adopts its coordinate arena",
        });
        try Engine.flushPendingCommit(&scheme, allocator, &channel);
    }

    prover.measurement.process_usage.reportStage("cairo.interaction_commit_complete");
    // The components' OODS bound (`resident_geometry.validateMaximumDegreeLog`
    // expects it plus one). On the leaf lane it is upstream `prove_ex`'s
    // `max_log_degree_bound`, the committed trace height minus the blowup,
    // which lifting raises above the composition's evaluation domain.
    const component_bound_log_size: u32 = if (lane != null)
        try revisionComponentBound(Engine, &scheme)
    else
        composition.max_evaluation_log_size;
    const runtime_components = try allocator.alloc(
        proving_air.component.Component,
        composition.components.len,
    );
    defer allocator.free(runtime_components);
    const components = try allocator.alloc(
        ComponentProver,
        runtime_components.len,
    );
    defer allocator.free(components);
    for (
        composition.components,
        runtime_components,
        components,
        interaction.claimed_sums,
    ) |*captured, *runtime, *component, claimed_sum| {
        runtime.* = proving_air.component.Component.init(
            allocator,
            captured,
            preprocessed_logs,
            component_bound_log_size,
            lookup.z,
            lookup.alpha,
            claimed_sum,
        );
        runtime.native_executor = fixture.native_composition;
        runtime.recorder = if (fixture.native_composition != null) recorder else null;
        component.* = runtime.asProverComponent();
    }

    // The device composition stage is opened here, after the bundle exists and
    // before `Engine.prove`, so that admission is a pre-stage decision with a
    // whole-stage host fallback available. `bound` stays null on refusal.
    var bound: ?proving_air.device_stage.Bound = null;
    defer if (bound) |*owned| {
        owned.close();
        recordDeviceCompositionCounts(recorder, owned.counts) catch {};
    };
    if (fixture.composition_device) |device| {
        var admit = try prover.stage_profile.StageScope.begin(
            recorder,
            "composition_device_admission",
            "Device composition admission",
        );
        var committed_logs = try scheme.columnLogSizes(allocator);
        defer committed_logs.deinitDeep(allocator);
        const opened = device.open(
            device.context,
            allocator,
            composition.components,
            committed_logs.items,
        ) catch null;
        admit.end();
        if (opened) |session| {
            bound = .{
                .allocator = allocator,
                .components = runtime_components,
                .captured = composition.components,
                .session = session,
                .recorder = recorder,
            };
        } else {
            var declined = try prover.stage_profile.StageScope.begin(
                recorder,
                "composition_device_declined",
                "Device composition declined; host stage",
            );
            declined.end();
        }
    }

    scheme_owned = false;
    const proof = try Engine.prove(
        allocator,
        components,
        &channel,
        scheme,
        .{
            .recorder = recorder,
            .composition_stage = if (bound) |*ready| ready.asStage() else null,
            .include_all_preprocessed_columns = lane != null,
        },
    );
    prover.measurement.process_usage.reportStage("cairo.proof_complete");
    return .{
        .allocator = allocator,
        .proof = proof,
        .statement = owned_statement,
        .composition = composition,
        .claimed_sums = interaction.takeClaimedSums(),
        .interaction_pow = interaction_pow,
        .preprocessed_variant = variant,
        .channel_salt = if (lane) |leaf| leaf.channel_salt else 0,
    };
}

/// Replays the official Cairo transcript and consumes the in-memory proof.
///
/// Callers that need proof bytes must serialize them before this function.
/// Success means the Zig AIR, PCS, FRI, interaction PoW, and public LogUp
/// statement have all accepted the proof.
pub fn verifyAndConsume(
    comptime Engine: type,
    input: *const adapter.ProverInput,
    result: *Result(Engine),
) !void {
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    if (!result.proof_owned) return error.ProofAlreadyConsumed;
    // The core verifier implements the existing lane's heights only; a leaf
    // lane proof is accepted by upstream `verify_cairo_ex` (R10c oracle).
    if (result.proof.proof.commitment_scheme_proof.revision_config != null)
        return error.UnsupportedRevisionVerification;
    const allocator = result.allocator;
    const composition = &result.composition;
    const stark_proof = &result.proof.proof;
    if (stark_proof.commitment_scheme_proof.commitments.items.len != 4)
        return error.InvalidProofShape;
    if (!std.meta.eql(
        stark_proof.commitment_scheme_proof.config,
        official_pcs_config,
    )) return error.InvalidProtocolConfiguration;
    if (composition.components.len != result.claimed_sums.len)
        return error.InvalidComponentShape;

    var preprocessed_spec = try preprocessed.trace.Spec.init(
        allocator,
        result.preprocessed_variant,
    );
    defer preprocessed_spec.deinit();
    const preprocessed_logs = try preprocessed_spec.logs(allocator);
    defer allocator.free(preprocessed_logs);
    const base_logs = try componentTreeLogs(allocator, composition, 1);
    defer allocator.free(base_logs);
    const interaction_logs = try componentTreeLogs(allocator, composition, 2);
    defer allocator.free(interaction_logs);

    var channel = Engine.Channel{};
    transcript.mixChannelSalt(&channel, 0);
    official_pcs_config.mixInto(&channel);
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(
        Engine.Hasher,
        Engine.MerkleChannel,
    ).init(allocator, official_pcs_config);
    defer scheme.deinit(allocator);

    const commitments = stark_proof.commitment_scheme_proof.commitments.items;
    try scheme.commit(allocator, commitments[0], preprocessed_logs, &channel);
    try transcript.mixClaim(
        Engine.MerkleChannel,
        allocator,
        &channel,
        &result.statement,
    );
    try scheme.commit(allocator, commitments[1], base_logs, &channel);
    if (!channel.verifyPowNonce(
        transcript.interaction_pow_bits,
        result.interaction_pow,
    )) return error.ProofOfWork;
    channel.mixU64(result.interaction_pow);
    const lookup = try transcript.drawLookupElements(
        allocator,
        &channel,
    );

    var global_sum = try statement.public_logup.sum(
        allocator,
        input,
        lookup.z,
        lookup.alpha,
    );
    for (result.claimed_sums) |claimed_sum|
        global_sum = global_sum.add(claimed_sum);
    if (!global_sum.eql(QM31.zero())) return error.InvalidGlobalLookupSum;
    transcript.mixInteractionClaim(
        &channel,
        result.claimed_sums,
    );
    try scheme.commit(
        allocator,
        commitments[2],
        interaction_logs,
        &channel,
    );

    const runtime_components = try allocator.alloc(
        proving_air.component.Component,
        composition.components.len,
    );
    defer allocator.free(runtime_components);
    const verifier_components = try allocator.alloc(
        VerifierComponent,
        runtime_components.len,
    );
    defer allocator.free(verifier_components);
    for (
        composition.components,
        runtime_components,
        verifier_components,
        result.claimed_sums,
    ) |*captured, *runtime, *component, claimed_sum| {
        runtime.* = proving_air.component.Component.init(
            allocator,
            captured,
            preprocessed_logs,
            composition.max_evaluation_log_size,
            lookup.z,
            lookup.alpha,
            claimed_sum,
        );
        component.* = runtime.asVerifierComponent();
    }

    result.proof.aux.deinit(allocator);
    const proof = result.proof.proof;
    result.proof_owned = false;
    try core.verifier.verify(
        Engine.Hasher,
        Engine.MerkleChannel,
        allocator,
        verifier_components,
        &channel,
        &scheme,
        proof,
    );
}

fn revisionComponentBound(comptime Engine: type, scheme: *const Engine.Scheme) !u32 {
    if (comptime @hasField(Engine.Scheme, "revision_config")) {
        const config = scheme.revision_config orelse return error.MissingRevisionConfig;
        return config.trace_lifting_log_size - config.fri_config.log_blowup_factor + 1;
    } else return error.LeafLaneRequiresChannelProfile;
}

/// Publishes the stage's coverage as three zero-duration marker scopes, which
/// is how every other decision in this transaction is made observable in
/// `--stage-profile-out` without a debug build.
fn recordDeviceCompositionCounts(
    recorder: ?*prover.stage_profile.Recorder,
    counts: proving_air.device_stage.Counts,
) !void {
    const markers = [_]struct { usize, []const u8, []const u8 }{
        .{ counts.device_components, "composition_device_components", "Components evaluated on device" },
        .{ counts.host_components, "composition_device_host_components", "Components evaluated on host inside the device stage" },
        .{ counts.device_fallbacks, "composition_device_fallbacks", "Device evaluations that fell back to the host" },
    };
    for (markers) |marker| {
        var index: usize = 0;
        while (index < marker[0]) : (index += 1) {
            var scope = try prover.stage_profile.StageScope.begin(
                recorder,
                marker[1],
                marker[2],
            );
            scope.end();
        }
    }
}

fn componentTreeLogs(
    allocator: std.mem.Allocator,
    composition: *const witness.composition_bundle.Bundle,
    tree: u32,
) ![]u32 {
    var column_count: usize = 0;
    for (composition.components) |component| {
        const span = try geometry.componentSpan(
            component,
            tree,
        );
        if (span.start != column_count) return error.InvalidComponentShape;
        column_count = span.end;
    }
    const logs = try allocator.alloc(u32, column_count);
    errdefer allocator.free(logs);
    for (composition.components) |component| {
        const span = try geometry.componentSpan(
            component,
            tree,
        );
        @memset(logs[span.start..span.end], component.trace_log_size);
    }
    return logs;
}

/// The two ways a pre-execution geometry plan can be contradicted by the
/// executed witness: the claim's predicted log size differs from the component's
/// padded row count (`live_graph.validateClaimGeometry`), or the arena's planned
/// width or extent for a component differs from what was produced
/// (`base_trace.Collector.capture`). Every other error keeps aborting.
pub fn isPlannedGeometryDisagreement(err: anyerror) bool {
    return err == witness.live_graph.Error.ClaimGeometryMismatch or
        err == trace_arena.Error.ArenaPlanMismatch;
}

fn validateComposition(
    composition: *const witness.composition_bundle.Bundle,
    live: claim_generator.OwnedClaimGeometry,
) !void {
    if (composition.components.len != live.components.len)
        return error.InvalidCompositionGeometry;
    for (composition.components, live.components) |component, actual| {
        const log_size = switch (actual.log_size) {
            .known => |value| value,
            .deferred => return error.InvalidCompositionGeometry,
        };
        if (component.instance != actual.instance or
            !compositionLabelMatches(component.label, actual) or
            component.trace_log_size != log_size)
            return error.InvalidCompositionGeometry;
    }
}

fn compositionLabelMatches(
    label: []const u8,
    component: claim_generator.ComponentGeometry,
) bool {
    if (!std.mem.eql(u8, component.name, "memory_id_to_big"))
        return std.mem.eql(u8, label, component.name);
    var buffer: [64]u8 = undefined;
    const expected = std.fmt.bufPrint(
        &buffer,
        "memory_id_to_big[{}]",
        .{component.instance},
    ) catch return false;
    return std.mem.eql(u8, label, expected);
}

fn claimVariant(
    variant: preprocessed.trace.Variant,
) claim_generator.PreprocessedVariant {
    return switch (variant) {
        .canonical => .canonical,
        .canonical_without_pedersen => .canonical_without_pedersen,
        .canonical_small => .canonical_small,
    };
}

test "official Cairo transaction configuration is upstream-compatible" {
    try std.testing.expectEqual(@as(u32, 26), official_pcs_config.pow_bits);
    try std.testing.expectEqual(
        @as(u32, 1),
        official_pcs_config.fri_config.log_blowup_factor,
    );
    try std.testing.expectEqual(
        @as(usize, 70),
        official_pcs_config.fri_config.n_queries,
    );
    try std.testing.expectEqual(
        @as(u32, 24),
        transcript.interaction_pow_bits,
    );
    try std.testing.expectEqual(@as(?u32, 0), official_pcs_config.lifting_log_size);
}
