const std = @import("std");
pub const stwo = @import("stwo");
const arena = stwo.backends.metal.arena_plan;
const metal_runtime = stwo.backends.metal.runtime;
const adapted_input = stwo.frontends.cairo.adapter.adapted_input;
const cairo_adapter = stwo.frontends.cairo.adapter;
const cairo_proof_plan = stwo.frontends.cairo.proof_plan;
const cairo_statement_bootstrap = stwo.frontends.cairo.statement_bootstrap;
const staged_arena_planner = stwo.frontends.cairo.staged_arena_planner;
const arena_binding_mod = stwo.integrations.cairo_metal.arena_binding;
const runtime_decommit_geometry = stwo.integrations.cairo_metal.runtime_decommit_geometry;
const schedule_addressing = @import("schedule_addressing.zig");
const schedule_coverage = @import("schedule_coverage.zig");
const arena_diagnostics = @import("diagnostics.zig");
const transcript_fixture = @import("transcript_fixture.zig");
const canonical_protocol_support = @import("canonical_protocol.zig");

const buildMerkleCommitCoverage = schedule_coverage.buildMerkleCommitCoverage;
const buildMerkleParentSources = schedule_coverage.buildMerkleParentSources;
const buildPreprocessedSources = schedule_coverage.buildPreprocessedSources;
const buildRetainedSources = schedule_coverage.buildRetainedSources;
const logPurposeLayout = arena_diagnostics.logPurposeLayout;
const CompositionCoverage = schedule_coverage.CompositionCoverage;
const FixedTableCoverage = schedule_coverage.FixedTableCoverage;
const RelationCoverage = schedule_coverage.RelationCoverage;
const TranscriptReferenceFixture = transcript_fixture.TranscriptReferenceFixture;
const validateCompositionCoverage = schedule_coverage.validateCompositionCoverage;
const validateEcOpCoverage = schedule_coverage.validateEcOpCoverage;
const validateFixedTableCoverage = schedule_coverage.validateFixedTableCoverage;
const validateNarrowAddressedBindings = schedule_addressing.validateNarrowAddressedBindings;
const validateRelationCoverage = schedule_coverage.validateRelationCoverage;

const canonical_protocol = canonical_protocol_support.canonical_protocol;

const host_geometry_mod = @import("host_geometry.zig");
const prepared_geometry_mod = @import("prepared_geometry_cache.zig");
const prepared_state_mod = @import("prepared_state_cache.zig");
const timing_mod = @import("timing.zig");
const execution_metrics_mod = @import("execution_metrics.zig");
const metal_execution = @import("metal_execution.zig");
const report = @import("report.zig");
const logical_plan_mod = @import("logical_plan.zig");

pub const PreparedStateKey = host_geometry_mod.PreparedStateKey;
pub const PreparedHostGeometry = host_geometry_mod.PreparedHostGeometry;
pub const PreparedStateTelemetry = timing_mod.PreparedStateTelemetry;
pub const PreparedStateCache = prepared_state_mod.PreparedStateCache;

const logicalPlanHash = prepared_geometry_mod.logicalPlanHash;
const PreparedGeometryHandle = prepared_geometry_mod.PreparedGeometryHandle;
const RunnerPhaseTiming = timing_mod.RunnerPhaseTiming;
const RecipePreparationTiming = timing_mod.RecipePreparationTiming;
const CanonicalFullProofPlanMode = timing_mod.CanonicalFullProofPlanMode;
const ExecutionMetrics = execution_metrics_mod.ExecutionMetrics;

const PreparedStateRequest = struct { cache: *PreparedStateCache, key: PreparedStateKey };

fn writeFailure(
    writer: *std.Io.Writer,
    err: anyerror,
    logical: usize,
    components: usize,
    budget: u64,
) !void {
    const result = .{ .fits = false, .failure = @errorName(err), .logical_buffers = logical, .component_subepochs = components, .budget_bytes = budget };
    try std.json.Stringify.value(result, .{ .whitespace = .indent_2 }, writer);
    try writer.writeByte('\n');
}

pub fn runOne(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    external_runtime: ?*metal_runtime.Runtime,
    prepared_state_request: ?PreparedStateRequest,
    prepared_host_geometry: ?*const PreparedHostGeometry,
    report_writer: *std.Io.Writer,
) !void {
    var runner_wall_timer = try std.time.Timer.start();
    var runner_phase_timing = RunnerPhaseTiming{};
    var recipe_preparation_timing = RecipePreparationTiming{};
    if (args.len < 3 or args.len > 8) {
        std.debug.print("usage: metal-arena-plan <arena_preflight.json> <budget-gib> [witness-programs.bin] [multiplicity-feeds.bin] [relation-templates.bin] [fixed-tables.bin] [composition.bin]\n", .{});
        return error.InvalidArguments;
    }
    const budget_gib = try std.fmt.parseFloat(f64, args[2]);
    const budget_bytes: u64 = @intFromFloat(budget_gib * 1024.0 * 1024.0 * 1024.0);
    var owned_host_geometry: ?*PreparedHostGeometry = null;
    defer if (owned_host_geometry) |geometry| geometry.deinit();
    const host_geometry = prepared_host_geometry orelse blk: {
        owned_host_geometry = try PreparedHostGeometry.init(allocator, args);
        runner_phase_timing.schedule_read_and_hash_wall_s =
            owned_host_geometry.?.preparation_timing.schedule_read_and_hash_wall_s;
        runner_phase_timing.schedule_json_parse_wall_s =
            owned_host_geometry.?.preparation_timing.schedule_json_parse_wall_s;
        runner_phase_timing.bundle_read_and_validate_wall_s =
            owned_host_geometry.?.preparation_timing.bundle_read_wall_s;
        break :blk owned_host_geometry.?;
    };
    const input_sha256 = host_geometry.schedule_sha256;
    const schedule = host_geometry.schedule();
    const compacted_consumer_rows = host_geometry.compactedConsumerRows();
    const schedule_coverage_started_ns = runner_wall_timer.read();
    const retained_sources = try buildRetainedSources(allocator, schedule);
    defer allocator.free(retained_sources);
    const preprocessed_coverage = try buildPreprocessedSources(allocator, schedule);
    defer allocator.free(preprocessed_coverage.sources);
    const merkle_parent_coverage = try buildMerkleParentSources(allocator, schedule);
    defer allocator.free(merkle_parent_coverage.sources);
    const merkle_commit_coverage = try buildMerkleCommitCoverage(allocator, schedule);
    defer allocator.free(merkle_commit_coverage.bottoms);
    const ec_op_coverage = try validateEcOpCoverage(schedule);
    RunnerPhaseTiming.addInterval(
        &runner_phase_timing.schedule_liveness_analysis_wall_s,
        &runner_wall_timer,
        schedule_coverage_started_ns,
    );
    const bundle_read_started_ns = runner_wall_timer.read();
    const witness_bundle = host_geometry.witness_bundle;
    const witness_recipe_requirements = if (witness_bundle) |bundle|
        arena_binding_mod.WitnessRecipeRequirements.fromBundle(bundle)
    else
        arena_binding_mod.WitnessRecipeRequirements{};
    const feed_bundle = host_geometry.feed_bundle;
    const relation_bundle = host_geometry.relation_bundle;
    const relation_coverage: ?RelationCoverage = if (relation_bundle) |bundle|
        try validateRelationCoverage(allocator, schedule, bundle)
    else
        null;
    const fixed_table_bundle = host_geometry.fixed_table_bundle;
    var fixed_table_destinations = std.StringHashMap(void).init(allocator);
    defer fixed_table_destinations.deinit();
    const fixed_table_coverage: ?FixedTableCoverage = if (fixed_table_bundle) |bundle|
        try validateFixedTableCoverage(schedule, bundle, &fixed_table_destinations)
    else
        null;
    const composition_bundle = host_geometry.composition_bundle;
    RunnerPhaseTiming.addInterval(
        &runner_phase_timing.bundle_read_and_validate_wall_s,
        &runner_wall_timer,
        bundle_read_started_ns,
    );
    const adapted_input_started_ns = runner_wall_timer.read();
    var prover_input: ?cairo_adapter.ProverInput = if (std.process.getEnvVarOwned(allocator, "STWO_ZIG_SN2_POPULATE_INPUT")) |input_path| blk: {
        defer allocator.free(input_path);
        break :blk try adapted_input.readFile(allocator, input_path);
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (prover_input) |*adapted| adapted.deinit(allocator);
    RunnerPhaseTiming.addInterval(
        &runner_phase_timing.input_materialization_wall_s,
        &runner_wall_timer,
        adapted_input_started_ns,
    );
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_BASE_EVAL_DIGESTS")) {
        const prover_input_sha256 = try std.process.getEnvVarOwned(allocator, "STWO_ZIG_SN2_INPUT_SHA256");
        defer allocator.free(prover_input_sha256);
        if (prover_input_sha256.len != 64) return error.InvalidInputDigest;
        std.debug.print("base_eval_digest_input sha256={s}\n", .{prover_input_sha256});
    }
    const reference_read_started_ns = runner_wall_timer.read();
    const transcript_reference_path = std.process.getEnvVarOwned(
        allocator,
        "STWO_ZIG_SN2_TRANSCRIPT_REFERENCE",
    ) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (transcript_reference_path) |path| allocator.free(path);
    var transcript_reference: ?TranscriptReferenceFixture = if (transcript_reference_path) |path|
        try TranscriptReferenceFixture.read(allocator, path)
    else
        null;
    defer if (transcript_reference) |*fixture| fixture.deinit();
    RunnerPhaseTiming.addInterval(
        &runner_phase_timing.bundle_read_and_validate_wall_s,
        &runner_wall_timer,
        reference_read_started_ns,
    );
    const statement_plan_started_ns = runner_wall_timer.read();
    var statement_bootstrap: ?cairo_statement_bootstrap.OwnedStatementBootstrap = null;
    if (composition_bundle) |*composition| {
        if (prover_input) |*adapted| {
            statement_bootstrap = try cairo_statement_bootstrap.initFromCompositionSchedule(
                allocator,
                .{
                    .channel_salt = canonical_protocol.channel_salt,
                    .pcs = .{
                        .pow_bits = canonical_protocol.query_pow_bits,
                        .log_blowup_factor = canonical_protocol.log_blowup_factor,
                        .n_queries = canonical_protocol.n_queries,
                        .log_last_layer_degree_bound = canonical_protocol.fri_log_last_layer_degree_bound,
                        .fold_step = canonical_protocol.fri_fold_step,
                        .lifting_log_size = canonical_protocol.fri_lifting,
                    },
                    .composition = composition,
                    .prover_input = adapted,
                },
            );
        }
    }
    defer if (statement_bootstrap) |*statement| statement.deinit();
    if (composition_bundle) |*composition| {
        if (prover_input) |*adapted| {
            if (std.process.getEnvVarOwned(
                allocator,
                "STWO_ZIG_SN2_COMPACT_STATEMENT_OUTPUT",
            )) |statement_output_path| {
                defer allocator.free(statement_output_path);
                const compact_statement = try cairo_statement_bootstrap.encodeCompactStatementV1(
                    allocator,
                    composition,
                    adapted,
                );
                defer allocator.free(compact_statement);
                const statement_file = try std.fs.createFileAbsolute(
                    statement_output_path,
                    .{ .exclusive = true },
                );
                defer statement_file.close();
                try statement_file.writeAll(compact_statement);
                try statement_file.sync();
            } else |err| switch (err) {
                error.EnvironmentVariableNotFound => {},
                else => return err,
            }
        }
    }
    var proof_plan: ?cairo_proof_plan.CairoProofPlan = if (witness_bundle != null)
        try cairo_proof_plan.CairoProofPlan.fromWitnessSchedule(
            allocator,
            schedule,
            compacted_consumer_rows,
            witness_bundle.?,
            if (prover_input) |*adapted| adapted else null,
        )
    else
        null;
    defer if (proof_plan) |*value| value.deinit();
    var staged_planner: ?staged_arena_planner.StagedArenaPlanner = if (proof_plan) |*value|
        try staged_arena_planner.StagedArenaPlanner.init(allocator, value)
    else
        null;
    defer if (staged_planner) |*value| value.deinit();
    const composition_coverage: ?CompositionCoverage = if (composition_bundle) |bundle|
        try validateCompositionCoverage(schedule, bundle)
    else
        null;
    RunnerPhaseTiming.addInterval(
        &runner_phase_timing.statement_and_proof_plan_wall_s,
        &runner_wall_timer,
        statement_plan_started_ns,
    );
    const schedule_liveness_started_ns = runner_wall_timer.read();
    var logical_plan = try logical_plan_mod.build(.{
        .allocator = allocator,
        .schedule = schedule,
        .feed_bundle = feed_bundle,
        .proof_plan = if (proof_plan) |*value| value else null,
        .staged_planner = if (staged_planner) |*value| value else null,
        .relation_coverage = relation_coverage,
        .witness_bundle = witness_bundle,
        .fixed_table_destinations = &fixed_table_destinations,
        .retained_sources = retained_sources,
        .preprocessed_coverage = preprocessed_coverage,
        .merkle_parent_coverage = merkle_parent_coverage,
        .merkle_commit_coverage = merkle_commit_coverage,
        .composition_coverage = composition_coverage,
    });
    defer logical_plan.deinit(allocator);
    const logical = logical_plan.logical;

    RunnerPhaseTiming.addInterval(
        &runner_phase_timing.schedule_liveness_analysis_wall_s,
        &runner_wall_timer,
        schedule_liveness_started_ns,
    );
    const arena_plan_started_ns = runner_wall_timer.read();
    const execute_proof = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_PROOF");
    const execute_decommit = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_DECOMMIT") or execute_proof;
    const execute_fri = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_FRI") or execute_decommit;
    const execute_quotient = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_QUOTIENT") or execute_fri;
    const execute_composition = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_COMPOSITION") or execute_quotient;
    const projection_tick: ?u16 = if (!std.process.hasEnvVarConstant("STWO_ZIG_SN2_PREPARE_METAL") or execute_composition)
        null
    else if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_RELATIONS"))
        4 * 65
    else
        2 * 65;
    const canonical_full_proof_plan = prepared_state_request != null and (CanonicalFullProofPlanMode{
        .execute_proof = execute_proof,
        .no_projection = projection_tick == null,
        .prepare_metal = std.process.hasEnvVarConstant("STWO_ZIG_SN2_PREPARE_METAL"),
        .execute_preprocessed = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_PREPROCESSED"),
        .execute_witness = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_WITNESS"),
        .execute_base_interpolation = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_BASE_INTERPOLATION"),
        .execute_commitments = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_COMMITMENTS"),
        .execute_relations = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_RELATIONS"),
        .execute_oods = std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_OODS"),
        .verify_proof = std.process.hasEnvVarConstant("STWO_ZIG_SN2_VERIFY_PROOF"),
    }).eligible();
    const logical_plan_hash = logicalPlanHash(logical);
    const cached_full_plan: ?PreparedGeometryHandle = if (canonical_full_proof_plan)
        try prepared_state_request.?.cache.findCanonicalPlan(
            prepared_state_request.?.key,
            logical_plan_hash,
        )
    else
        null;
    const arena_plan_cache_hit = cached_full_plan != null;
    var owned_full_plan: ?arena.Plan = null;
    var full_plan_ownership_transferred = false;
    defer if (!full_plan_ownership_transferred) {
        if (owned_full_plan) |*owned| owned.deinit();
    };
    if (cached_full_plan == null) {
        owned_full_plan = arena.build(allocator, logical, budget_bytes) catch |err| {
            try writeFailure(report_writer, err, schedule.len, logical_plan.component_count, budget_bytes);
            return;
        };
    }
    const full_plan = if (cached_full_plan) |cached| cached.plan.* else owned_full_plan.?;
    if (full_plan.bindings.len != logical.len) return error.PreparedStatePlanIdentityMismatch;
    var projected_plan: ?arena.Plan = if (projection_tick) |last_tick|
        try arena.projectThroughTick(allocator, logical, full_plan, last_tick, budget_bytes)
    else
        null;
    defer if (projected_plan) |*projected| projected.deinit();
    const plan = if (projected_plan) |projected| projected else full_plan;
    try validateNarrowAddressedBindings(schedule, plan);
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_PROTOCOL_LAYOUT")) {
        inline for ([_][]const u8{
            "PreprocessedCoefficients",
            "BaseCoefficients",
            "InteractionCoefficients",
            "RelationAlphaPowers",
            "RelationZ",
            "RelationClaimedSum",
            "CompositionCoefficients",
            "CompositionDescriptors",
            "CompositionLdeTile",
            "CompositionAccumulators",
            "CompositionRandomCoefficientPowers",
            "CompositionExtParams",
            "CommitLdeTile",
            "MerkleLeafState",
            "MerkleLayerScratch",
            "QuotientTile",
            "InverseTwiddles",
            "FriRetainedEvaluation",
            "FriFoldingChallenge",
            "FriMerkleLayer",
            "FriPing",
            "FriPong",
            "FriFinalCoefficients",
            "FriFinalDegreeError",
            "DecommitUniqueQueries",
            "DecommitMappedQueries",
            "DecommitWalkQueries",
            "DecommitWalkScratch",
            "DecommitExpandedPositions",
            "DecommitSparseIndices",
            "DecommitSparseHashes",
            "DecommitCounts",
            "DecommitValues",
            "DecommitAssembly",
            "DecommitTraceLdeTile",
            "DecommitTraceEvaluationPointers",
            "DecommitTraceRetainedPointers",
            "DecommitFriCoordinatePointers",
            "DecommitFriRetainedPointers",
            "ProofBytes",
            "TranscriptState",
            "TranscriptInput",
            "TranscriptOutput",
        }) |wanted_purpose| try logPurposeLayout(schedule, plan, wanted_purpose);
    }
    var decommit_geometry: ?runtime_decommit_geometry.OwnedProofDecommitGeometry = if (composition_bundle) |bundle|
        try runtime_decommit_geometry.OwnedProofDecommitGeometry.init(
            allocator,
            schedule,
            plan,
            bundle,
        )
    else
        null;
    defer if (decommit_geometry) |*geometry| geometry.deinit();
    var proof_bindings: ?arena_binding_mod.PreparedProofBindings = if (composition_bundle != null)
        try arena_binding_mod.PreparedProofBindings.init(
            allocator,
            schedule,
            plan,
            composition_bundle.?,
            relation_bundle orelse return error.MissingRelationBundle,
            decommit_geometry.?.geometry(),
        )
    else
        null;
    defer if (proof_bindings) |*bindings| bindings.deinit();
    RunnerPhaseTiming.addInterval(
        &runner_phase_timing.arena_plan_and_bindings_wall_s,
        &runner_wall_timer,
        arena_plan_started_ns,
    );
    const fri_root_count = if (proof_bindings) |bindings| bindings.decommit_fri_trees.len else 0;
    var execution_metrics = try ExecutionMetrics.init(
        allocator,
        fri_root_count,
        transcript_reference != null,
    );
    defer execution_metrics.deinit(allocator);
    const requested_commit_tree_count = if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_COMMITMENTS")) blk: {
        const tree_count = if (std.process.getEnvVarOwned(allocator, "STWO_ZIG_SN2_COMMIT_TREE_COUNT")) |value| value_blk: {
            defer allocator.free(value);
            break :value_blk try std.fmt.parseInt(usize, value, 10);
        } else |err| switch (err) {
            error.EnvironmentVariableNotFound => 1,
            else => return err,
        };
        if (tree_count == 0 or tree_count > 4) return error.InvalidCommitmentTreeCount;
        break :blk tree_count;
    } else 0;
    try metal_execution.execute(.{
        .allocator = allocator,
        .args = args,
        .proof_bindings = if (proof_bindings) |*value| value else null,
        .schedule = schedule,
        .plan = plan,
        .external_runtime = external_runtime,
        .fixed_table_bundle = fixed_table_bundle,
        .composition_bundle = composition_bundle,
        .relation_bundle = relation_bundle,
        .feed_bundle = feed_bundle,
        .witness_bundle = witness_bundle,
        .witness_recipe_requirements = witness_recipe_requirements,
        .prover_input = if (prover_input) |*value| value else null,
        .prepared_state_request = prepared_state_request,
        .logical_plan_hash = logical_plan_hash,
        .canonical_full_proof_plan = canonical_full_proof_plan,
        .cached_full_plan = cached_full_plan,
        .owned_full_plan = &owned_full_plan,
        .full_plan_ownership_transferred = &full_plan_ownership_transferred,
        .arena_plan_cache_hit = arena_plan_cache_hit,
        .runner_wall_timer = &runner_wall_timer,
        .runner_phase_timing = &runner_phase_timing,
        .recipe_preparation_timing = &recipe_preparation_timing,
        .execute_composition = execute_composition,
        .execute_quotient = execute_quotient,
        .execute_fri = execute_fri,
        .execute_decommit = execute_decommit,
        .execute_proof = execute_proof,
        .proof_plan = if (proof_plan) |*value| value else null,
        .statement_bootstrap = if (statement_bootstrap) |*value| value else null,
        .transcript_reference_path = transcript_reference_path,
        .transcript_reference = transcript_reference,
        .requested_commit_tree_count = requested_commit_tree_count,
    }, &execution_metrics);
    try report.write(.{
        .allocator = allocator,
        .missing_components = logical_plan.missing_components,
        .missing_lookup_components = logical_plan.missing_lookup_components,
        .plan = plan,
        .schedule = schedule,
        .runner_wall_timer = &runner_wall_timer,
        .runner_phase_timing = &runner_phase_timing,
        .recipe_preparation_timing = &recipe_preparation_timing,
        .args = args,
        .input_sha256 = input_sha256,
        .canonical_protocol = canonical_protocol,
        .component_count = logical_plan.component_count,
        .witness_bundle = witness_bundle,
        .feed_bundle = feed_bundle,
        .native_destination_count = logical_plan.native_destination_count,
        .relation_bundle = relation_bundle,
        .relation_coverage = relation_coverage,
        .fixed_table_bundle = fixed_table_bundle,
        .fixed_table_coverage = fixed_table_coverage,
        .ec_op_coverage = ec_op_coverage,
        .composition_bundle = composition_bundle,
        .composition_coverage = composition_coverage,
        .proof_bindings = if (proof_bindings) |*value| value else null,
        .proof_plan = if (proof_plan) |*value| value else null,
        .arena_plan_cache_hit = arena_plan_cache_hit,
        .native_recipe_buffers = logical_plan.native_recipe_buffers,
        .native_recipe_bytes = logical_plan.native_recipe_bytes,
        .zero_recipe_buffers = logical_plan.zero_recipe_buffers,
        .zero_recipe_bytes = logical_plan.zero_recipe_bytes,
        .witness_recipe_buffers = logical_plan.witness_recipe_buffers,
        .witness_recipe_bytes = logical_plan.witness_recipe_bytes,
        .witness_missing_buffers = logical_plan.witness_missing_buffers,
        .bound_recipe_buffers = logical_plan.bound_recipe_buffers,
        .bound_recipe_bytes = logical_plan.bound_recipe_bytes,
        .circle_recipe_buffers = logical_plan.circle_recipe_buffers,
        .circle_recipe_bytes = logical_plan.circle_recipe_bytes,
        .preprocessed_recipe_buffers = logical_plan.preprocessed_recipe_buffers,
        .preprocessed_recipe_bytes = logical_plan.preprocessed_recipe_bytes,
        .merkle_parent_coverage = merkle_parent_coverage,
        .merkle_commit_coverage = merkle_commit_coverage,
        .peak_tick = logical_plan.peak_tick,
        .diagnostic_peak_logical_bytes = logical_plan.diagnostic_peak_logical_bytes,
        .diagnostic_base_peak_bytes = logical_plan.diagnostic_base_peak_bytes,
        .diagnostic_base_peak_tick = logical_plan.diagnostic_base_peak_tick,
        .diagnostic_interaction_peak_bytes = logical_plan.diagnostic_interaction_peak_bytes,
        .diagnostic_interaction_peak_tick = logical_plan.diagnostic_interaction_peak_tick,
        .interaction_peak_purposes = logical_plan.interaction_peak_purposes,
        .base_peak_purposes = logical_plan.base_peak_purposes,
        .peak_purposes = logical_plan.peak_purposes,
        .budget_bytes = budget_bytes,
        .budget_gib = budget_gib,
        .report_writer = report_writer,
    }, &execution_metrics);
}
