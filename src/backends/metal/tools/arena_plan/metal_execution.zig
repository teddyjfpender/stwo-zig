const std = @import("std");
const stwo = @import("stwo");
const arena = stwo.backends.metal.arena_plan;
const metal_runtime = stwo.backends.metal.runtime;
const protocol_recipes = stwo.backends.metal.protocol_recipes;
const blake2_merkle = stwo.core.vcs_lifted.blake2_merkle;
const arena_binding_mod = stwo.integrations.cairo_metal.arena_binding;
const cairo_memory_trace = stwo.integrations.cairo_metal.memory_trace;
const diagnostics = @import("diagnostics.zig");
const timing = @import("timing.zig");
const PreparedStateAcquire = @import("prepared_state_cache.zig").PreparedStateAcquire;
const ExecutionMetrics = @import("execution_metrics.zig").ExecutionMetrics;
const base_execution = @import("base_execution.zig");
const interaction_execution = @import("interaction_execution.zig");
const protocol_execution = @import("protocol_execution.zig");

const logComponentPurposeLayout = diagnostics.logComponentPurposeLayout;
const logPurposeLayout = diagnostics.logPurposeLayout;
const RunnerPhaseTiming = timing.RunnerPhaseTiming;

fn requireResidentPreprocessedCoefficients(composition_requested: bool, populated: bool) !void {
    if (composition_requested and !populated) return error.MissingPreprocessedCoefficients;
}

pub fn execute(ctx: anytype, execution_metrics: *ExecutionMetrics) !void {
    const allocator = ctx.allocator;
    const args = ctx.args;
    const proof_bindings = ctx.proof_bindings;
    const schedule = ctx.schedule;
    const plan = ctx.plan;
    const external_runtime = ctx.external_runtime;
    const fixed_table_bundle = ctx.fixed_table_bundle;
    const composition_bundle = ctx.composition_bundle;
    const relation_bundle = ctx.relation_bundle;
    const feed_bundle = ctx.feed_bundle;
    const witness_bundle = ctx.witness_bundle;
    const witness_recipe_requirements = ctx.witness_recipe_requirements;
    const prover_input = ctx.prover_input;
    const prepared_state_request = ctx.prepared_state_request;
    const logical_plan_hash = ctx.logical_plan_hash;
    const canonical_full_proof_plan = ctx.canonical_full_proof_plan;
    const cached_full_plan = ctx.cached_full_plan;
    const owned_full_plan = ctx.owned_full_plan;
    const full_plan_ownership_transferred = ctx.full_plan_ownership_transferred;
    const arena_plan_cache_hit = ctx.arena_plan_cache_hit;
    const runner_wall_timer = ctx.runner_wall_timer;
    const runner_phase_timing = ctx.runner_phase_timing;
    const recipe_preparation_timing = ctx.recipe_preparation_timing;
    const execute_composition = ctx.execute_composition;
    const execute_quotient = ctx.execute_quotient;
    const execute_fri = ctx.execute_fri;
    const execute_decommit = ctx.execute_decommit;
    const execute_proof = ctx.execute_proof;
    const proof_plan = ctx.proof_plan;
    const statement_bootstrap = ctx.statement_bootstrap;
    const transcript_reference_path = ctx.transcript_reference_path;
    const transcript_reference = ctx.transcript_reference;
    const requested_commit_tree_count = ctx.requested_commit_tree_count;

    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_PREPARE_METAL")) {
        const bindings = if (proof_bindings) |value| value else return error.MissingPreparedProofBindings;
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("resident_plan bytes={} peak_live_bytes={}\n", .{ plan.total_bytes, plan.peak_live_bytes });
        var owned_metal: ?metal_runtime.Runtime = if (external_runtime == null)
            try metal_runtime.Runtime.initFull()
        else
            null;
        defer if (owned_metal) |*value| value.deinit();
        const metal = external_runtime orelse &owned_metal.?;
        const restored_preprocessed_path = std.process.getEnvVarOwned(
            allocator,
            "STWO_ZIG_SN2_RESTORE_PREPROCESSED_EVALUATIONS",
        ) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (restored_preprocessed_path) |path| allocator.free(path);
        const staged_preprocessed_path = std.process.getEnvVarOwned(
            allocator,
            "STWO_ZIG_SN2_PREPROCESSED_EVALUATIONS_OUTPUT",
        ) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (staged_preprocessed_path) |path| allocator.free(path);
        if (restored_preprocessed_path != null and staged_preprocessed_path != null)
            return error.ConflictingPreprocessedPaths;
        const restoring_tree0 = restored_preprocessed_path != null;
        const staged_tree0 = !restoring_tree0 and requested_commit_tree_count > 0 and
            std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_PREPROCESSED") and
            std.process.hasEnvVarConstant("STWO_ZIG_SN2_PREPROCESSED_COEFFS");
        const preprocessed_spill_path = restored_preprocessed_path orelse
            staged_preprocessed_path orelse
            "/tmp/stwo-zig-sn2-preprocessed-evaluations.spill";
        const tree0_merkle_path = try std.fmt.allocPrint(allocator, "{s}.tree0-merkle", .{preprocessed_spill_path});
        defer allocator.free(tree0_merkle_path);
        if (staged_tree0) {
            for ([_][]const u8{ preprocessed_spill_path, tree0_merkle_path }) |output_path| {
                if (std.fs.accessAbsolute(output_path, .{})) |_| {
                    return error.PreprocessedOutputAlreadyExists;
                } else |err| switch (err) {
                    error.FileNotFound => {},
                    else => return err,
                }
            }
        }
        var staged_tree0_root: ?[32]u8 = null;
        if (restoring_tree0) {
            const root_hex = try std.process.getEnvVarOwned(allocator, "STWO_ZIG_SN2_TREE0_ROOT_HEX");
            defer allocator.free(root_hex);
            if (root_hex.len != 64) return error.InvalidCommitmentRoot;
            var root: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&root, root_hex) catch return error.InvalidCommitmentRoot;
            staged_tree0_root = root;
            execution_metrics.commitment_roots[0] = root;
            execution_metrics.populated_preprocessed_coefficients = fixed_table_bundle.?.preprocessed_identities.len;
        }
        if (staged_tree0) {
            var tree0_arena = try arena.ResidentArena.initWithExtra(metal, plan, bindings.commitmentScratchBytes(0));
            defer tree0_arena.deinit();
            const coefficients_path = try std.process.getEnvVarOwned(allocator, "STWO_ZIG_SN2_PREPROCESSED_COEFFS");
            defer allocator.free(coefficients_path);
            try arena_binding_mod.populatePreprocessedCoefficients(
                allocator,
                &tree0_arena,
                schedule,
                plan,
                fixed_table_bundle.?,
                coefficients_path,
            );
            execution_metrics.populated_preprocessed_coefficients = fixed_table_bundle.?.preprocessed_identities.len;
            try bindings.populateCommitmentTwiddles(allocator, &tree0_arena, plan, 0);
            const committed = try bindings.executeCommitment(
                metal,
                &tree0_arena,
                schedule,
                plan,
                0,
                blake2_merkle.Blake2sPlainMerkleHasher.leafSeed(),
                blake2_merkle.Blake2sPlainMerkleHasher.nodeSeed(),
            );
            execution_metrics.commitment_gpu_ms += committed.gpu_ms;
            execution_metrics.commitment_lde_gpu_ms += committed.lde_gpu_ms;
            execution_metrics.commitment_leaf_gpu_ms += committed.leaf_gpu_ms;
            execution_metrics.commitment_parent_gpu_ms += committed.parent_gpu_ms;
            try arena_binding_mod.spillRetainedMerkleLayers(
                allocator,
                &tree0_arena,
                schedule,
                plan,
                0,
                tree0_merkle_path,
            );
            var root: [32]u8 = undefined;
            @memcpy(&root, (try tree0_arena.bytes(committed.root))[0..32]);
            staged_tree0_root = root;
            execution_metrics.commitment_roots[0] = root;
            execution_metrics.preprocessed_gpu_ms += try arena_binding_mod.evaluatePreprocessedCoefficients(
                allocator,
                metal,
                &tree0_arena,
                schedule,
                plan,
                bindings.commitmentTwiddleStorage(plan, 0),
            );
            try arena_binding_mod.spillPreprocessedEvaluations(
                allocator,
                &tree0_arena,
                schedule,
                plan,
                preprocessed_spill_path,
            );
        }
        const resident_bytes = plan.total_bytes;
        execution_metrics.resident_arena_bytes = resident_bytes;
        var local_resident_arena: ?arena.ResidentArena = null;
        defer if (local_resident_arena) |*resident| resident.deinit();
        const resident_acquire_started_ns = runner_wall_timer.read();
        const resident_acquire = if (prepared_state_request) |request|
            try request.cache.begin(
                metal,
                request.key,
                logical_plan_hash,
                plan,
                canonical_full_proof_plan,
                cached_full_plan,
                if (canonical_full_proof_plan and !arena_plan_cache_hit) .{
                    .owner = owned_full_plan,
                    .transferred = full_plan_ownership_transferred,
                } else null,
            )
        else blk: {
            local_resident_arena = try arena.ResidentArena.initByteLength(metal, resident_bytes);
            break :blk PreparedStateAcquire{
                .resident_arena = &local_resident_arena.?,
                .cache_hit = false,
            };
        };
        RunnerPhaseTiming.addInterval(
            &runner_phase_timing.resident_acquire_reset_restore_wall_s,
            runner_wall_timer,
            resident_acquire_started_ns,
        );
        const resident_arena = resident_acquire.resident_arena;
        execution_metrics.prepared_state_cache_hit = resident_acquire.cache_hit;
        if (prepared_state_request) |request| {
            const telemetry = request.cache.requestTelemetry();
            execution_metrics.prepared_state_snapshot_bytes = telemetry.snapshot_bytes;
            execution_metrics.prepared_state_clear_bytes = telemetry.clear_bytes;
            execution_metrics.prepared_state_restore_gpu_ms = telemetry.restore_gpu_ms;
        }
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ARENA_LAYOUT")) {
            try logPurposeLayout(schedule, plan, "ForwardTwiddles");
            try logPurposeLayout(schedule, plan, "PreprocessedEvaluations");
            try logPurposeLayout(schedule, plan, "RuntimeMultiplicity");
            try logPurposeLayout(schedule, plan, "FixedMultiplicity");
            try logPurposeLayout(schedule, plan, "CommitLdeTile");
            try logPurposeLayout(schedule, plan, "MerkleLeafState");
            try logPurposeLayout(schedule, plan, "MerkleLayerScratch");
            try logPurposeLayout(schedule, plan, "TranscriptState");
            try logPurposeLayout(schedule, plan, "TranscriptInput");
            try logPurposeLayout(schedule, plan, "TranscriptOutput");
            try logPurposeLayout(schedule, plan, "ExecutionTablePointers");
            try logPurposeLayout(schedule, plan, "ExecutionTableStrides");
            try logPurposeLayout(schedule, plan, "FixedTableSourcePointers");
            try logComponentPurposeLayout(schedule, plan, "WitnessInput", "partial_ec_mul_generic");
            try logComponentPurposeLayout(schedule, plan, "BaseTrace", "ec_op_builtin");
            try logComponentPurposeLayout(schedule, plan, "BaseCoefficients", "blake_g");
            try logComponentPurposeLayout(schedule, plan, "InteractionTrace", "blake_g");
            try logComponentPurposeLayout(schedule, plan, "InteractionCoefficients", "blake_g");
            try logComponentPurposeLayout(schedule, plan, "BaseTrace", "add_opcode");
            try logComponentPurposeLayout(schedule, plan, "BaseCoefficients", "add_opcode");
            try logComponentPurposeLayout(schedule, plan, "BaseTrace", "add_opcode_small");
            try logComponentPurposeLayout(schedule, plan, "LookupInputs", "add_opcode_small");
            try logComponentPurposeLayout(schedule, plan, "SubcomponentInputs", "add_opcode_small");
            try logComponentPurposeLayout(schedule, plan, "WitnessInput", "add_opcode_small");
            try logComponentPurposeLayout(schedule, plan, "WitnessOutputPointers", "add_opcode_small");
            try logComponentPurposeLayout(schedule, plan, "WitnessInputPointers", "add_opcode_small");
            try logComponentPurposeLayout(schedule, plan, "WitnessMultiplicityPointers", "add_opcode_small");
        }
        const memory_trace_started_ns = runner_wall_timer.read();
        var memory_trace: ?cairo_memory_trace.CairoMemoryTrace = if (prover_input != null)
            try cairo_memory_trace.CairoMemoryTrace.init(allocator, schedule, plan, fixed_table_bundle.?)
        else
            null;
        defer if (memory_trace) |*trace| trace.deinit();
        RunnerPhaseTiming.addInterval(
            &runner_phase_timing.input_materialization_wall_s,
            runner_wall_timer,
            memory_trace_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=memory_trace done\n", .{});
        const coefficient_restore_started_ns = runner_wall_timer.read();
        if (std.process.getEnvVarOwned(allocator, "STWO_ZIG_SN2_PREPROCESSED_COEFFS")) |coefficients_path| {
            defer allocator.free(coefficients_path);
            if (!execution_metrics.prepared_state_cache_hit) {
                if (restoring_tree0) {
                    const loaded = try arena_binding_mod.populateUnreconstructedPreprocessedCoefficients(
                        allocator,
                        resident_arena,
                        schedule,
                        plan,
                        fixed_table_bundle.?,
                        coefficients_path,
                    );
                    execution_metrics.preprocessed_coefficients_loaded_bytes = loaded.loaded_bytes;
                    execution_metrics.preprocessed_coefficients_reconstructed_bytes = loaded.reconstructed_bytes;
                } else {
                    try arena_binding_mod.populatePreprocessedCoefficients(
                        allocator,
                        resident_arena,
                        schedule,
                        plan,
                        fixed_table_bundle.?,
                        coefficients_path,
                    );
                    for (bindings.preprocessed_coefficients) |binding|
                        execution_metrics.preprocessed_coefficients_loaded_bytes += binding.size_bytes;
                }
            }
            execution_metrics.populated_preprocessed_coefficients = fixed_table_bundle.?.preprocessed_identities.len;
            execution_metrics.resident_preprocessed_coefficients = true;
        } else |err| switch (err) {
            error.EnvironmentVariableNotFound => {},
            else => return err,
        }
        RunnerPhaseTiming.addInterval(
            &runner_phase_timing.immutable_host_restore_wall_s,
            runner_wall_timer,
            coefficient_restore_started_ns,
        );
        try requireResidentPreprocessedCoefficients(execute_composition, execution_metrics.resident_preprocessed_coefficients);
        if (requested_commit_tree_count > 0 and !staged_tree0 and !restoring_tree0) {
            if (execution_metrics.populated_preprocessed_coefficients == 0) return error.CommitmentInputsNotExecuted;
            try bindings.populateCommitmentTwiddles(allocator, resident_arena, plan, 0);
            const committed = try bindings.executeCommitment(
                metal,
                resident_arena,
                schedule,
                plan,
                0,
                blake2_merkle.Blake2sPlainMerkleHasher.leafSeed(),
                blake2_merkle.Blake2sPlainMerkleHasher.nodeSeed(),
            );
            execution_metrics.commitment_gpu_ms += committed.gpu_ms;
            execution_metrics.commitment_lde_gpu_ms += committed.lde_gpu_ms;
            execution_metrics.commitment_leaf_gpu_ms += committed.leaf_gpu_ms;
            execution_metrics.commitment_parent_gpu_ms += committed.parent_gpu_ms;
            var root: [32]u8 = undefined;
            @memcpy(&root, (try resident_arena.bytes(committed.root))[0..32]);
            execution_metrics.commitment_roots[0] = root;
        }
        const input_population_started_ns = runner_wall_timer.read();
        if (prover_input) |adapted| {
            execution_metrics.execution_table_split_gpu_ms = try arena_binding_mod.populateExecutionTables(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                adapted,
            );
            execution_metrics.populated_direct_witness_lanes = try arena_binding_mod.populateCasmWitnessInputs(
                allocator,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                adapted,
            );
            execution_metrics.populated_direct_witness_lanes += try arena_binding_mod.populateBuiltinSeedWitnessInputs(
                allocator,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                adapted,
            );
        }
        RunnerPhaseTiming.addInterval(
            &runner_phase_timing.input_materialization_wall_s,
            runner_wall_timer,
            input_population_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=inputs done\n", .{});
        const fixed_recipe_started_ns = runner_wall_timer.read();
        var local_fixed_tables: ?protocol_recipes.FixedTableBatchRecipe = null;
        defer if (local_fixed_tables) |*recipe| recipe.deinit();
        const fixed_tables = if (prepared_state_request) |request| fixed_blk: {
            if (canonical_full_proof_plan) {
                if (execution_metrics.prepared_state_cache_hit) {
                    execution_metrics.fixed_table_recipe_cache_hit = true;
                    break :fixed_blk try request.cache.borrowFixedTables();
                }
                local_fixed_tables = try arena_binding_mod.prepareFixedTableBatch(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    fixed_table_bundle.?,
                );
                break :fixed_blk try request.cache.installFixedTables(&local_fixed_tables);
            }
            local_fixed_tables = try arena_binding_mod.prepareFixedTableBatch(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                fixed_table_bundle.?,
            );
            break :fixed_blk &local_fixed_tables.?;
        } else fixed_blk: {
            local_fixed_tables = try arena_binding_mod.prepareFixedTableBatch(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                fixed_table_bundle.?,
            );
            break :fixed_blk &local_fixed_tables.?;
        };
        RunnerPhaseTiming.addInterval(
            &runner_phase_timing.recipe_preparation_wall_s,
            runner_wall_timer,
            fixed_recipe_started_ns,
        );
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.fixed_tables_wall_s,
            runner_wall_timer,
            fixed_recipe_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=fixed_tables done\n", .{});
        const feed_recipe_started_ns = runner_wall_timer.read();
        var local_multiplicity_feeds: ?arena_binding_mod.MultiplicityFeedBatch = null;
        defer if (local_multiplicity_feeds) |*recipe| recipe.deinit();
        const multiplicity_feeds = if (prepared_state_request) |request| feed_blk: {
            if (canonical_full_proof_plan) {
                if (execution_metrics.prepared_state_cache_hit) {
                    execution_metrics.multiplicity_feed_recipe_cache_hit = true;
                    break :feed_blk try request.cache.borrowMultiplicityFeeds();
                }
                local_multiplicity_feeds = try arena_binding_mod.prepareMultiplicityFeedBatch(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    feed_bundle.?,
                );
                break :feed_blk try request.cache.installMultiplicityFeeds(&local_multiplicity_feeds);
            }
            local_multiplicity_feeds = try arena_binding_mod.prepareMultiplicityFeedBatch(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                feed_bundle.?,
            );
            break :feed_blk &local_multiplicity_feeds.?;
        } else feed_blk: {
            local_multiplicity_feeds = try arena_binding_mod.prepareMultiplicityFeedBatch(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                feed_bundle.?,
            );
            break :feed_blk &local_multiplicity_feeds.?;
        };
        RunnerPhaseTiming.addInterval(
            &runner_phase_timing.recipe_preparation_wall_s,
            runner_wall_timer,
            feed_recipe_started_ns,
        );
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.multiplicity_feeds_wall_s,
            runner_wall_timer,
            feed_recipe_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=multiplicity_feeds done\n", .{});
        const immutable_restore_started_ns = runner_wall_timer.read();
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_PREPROCESSED")) {
            if (execution_metrics.populated_preprocessed_coefficients == 0) return error.MissingPreprocessedCoefficients;
            if (execution_metrics.prepared_state_cache_hit) {
                // The arena was zeroed and the validated immutable snapshot was
                // restored before any request-specific input was populated.
            } else if (staged_tree0 or restoring_tree0) {
                try arena_binding_mod.restorePreprocessedEvaluations(
                    allocator,
                    resident_arena,
                    schedule,
                    plan,
                    preprocessed_spill_path,
                );
                try arena_binding_mod.populateNamedInverseTwiddles(
                    allocator,
                    resident_arena,
                    schedule,
                    plan,
                    "PreprocessedInverseTwiddles",
                );
                execution_metrics.preprocessed_gpu_ms += try arena_binding_mod.interpolateAvailablePreprocessedColumns(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                );
                try arena_binding_mod.restoreRetainedMerkleLayers(
                    allocator,
                    resident_arena,
                    schedule,
                    plan,
                    0,
                    tree0_merkle_path,
                );
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) {
                    if (memory_trace) |trace| {
                        try trace.populateRc99Lut(resident_arena);
                        std.debug.print("restored RC9_9 preprocessed table validated\n", .{});
                    }
                }
            } else {
                if (requested_commit_tree_count == 0)
                    try bindings.populateCommitmentTwiddles(allocator, resident_arena, plan, 0);
                execution_metrics.preprocessed_gpu_ms += try arena_binding_mod.evaluatePreprocessedCoefficients(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    bindings.commitmentTwiddleStorage(plan, 0),
                );
            }
        }
        var base_inverse_twiddles_prepared = execution_metrics.prepared_state_cache_hit and canonical_full_proof_plan;
        if (prepared_state_request) |request| {
            if (!execution_metrics.prepared_state_cache_hit and canonical_full_proof_plan) {
                try bindings.populateCommitmentInverseTwiddles(allocator, resident_arena, plan, 1);
                base_inverse_twiddles_prepared = true;
            }
            if (!execution_metrics.prepared_state_cache_hit) try request.cache.capture(metal, schedule, plan);
            const telemetry = request.cache.requestTelemetry();
            execution_metrics.prepared_state_snapshot_bytes = telemetry.snapshot_bytes;
            execution_metrics.prepared_state_capture_gpu_ms = telemetry.capture_gpu_ms;
        }
        RunnerPhaseTiming.addInterval(
            &runner_phase_timing.immutable_host_restore_wall_s,
            runner_wall_timer,
            immutable_restore_started_ns,
        );
        const remaining_recipe_started_ns = runner_wall_timer.read();
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=aot_witness begin\n", .{});
        var local_witness: ?protocol_recipes.AotWitnessBatchRecipe = null;
        defer if (local_witness) |*recipe| recipe.deinit();
        const base_aot_witness_started_ns = runner_wall_timer.read();
        const witness = if (prepared_state_request) |request| witness_blk: {
            if (canonical_full_proof_plan) {
                if (execution_metrics.prepared_state_cache_hit) {
                    execution_metrics.base_aot_witness_cache_hit = true;
                    break :witness_blk try request.cache.borrowBaseAotWitness();
                }
                local_witness = try arena_binding_mod.prepareAotWitnessBatch(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    witness_bundle.?,
                    fixed_table_bundle.?,
                );
                break :witness_blk try request.cache.installBaseAotWitness(&local_witness);
            }
            local_witness = try arena_binding_mod.prepareAotWitnessBatch(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                fixed_table_bundle.?,
            );
            break :witness_blk &local_witness.?;
        } else witness_blk: {
            local_witness = try arena_binding_mod.prepareAotWitnessBatch(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                fixed_table_bundle.?,
            );
            break :witness_blk &local_witness.?;
        };
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.base_aot_witness_acquire_wall_s,
            runner_wall_timer,
            base_aot_witness_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=aot_witness done\n", .{});
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=compact_verify begin\n", .{});
        const compact_verify_started_ns = runner_wall_timer.read();
        var local_compact_verify: ?protocol_recipes.CompactRecipe = null;
        defer if (local_compact_verify) |*recipe| recipe.deinit();
        const compact_verify: ?*protocol_recipes.CompactRecipe = if (!witness_recipe_requirements.verify_instruction)
            null
        else if (prepared_state_request) |request| compact_blk: {
            if (canonical_full_proof_plan) {
                if (execution_metrics.prepared_state_cache_hit) {
                    execution_metrics.compact_verify_recipe_cache_hit = true;
                    break :compact_blk try request.cache.borrowCompact(.verify_instruction);
                }
                local_compact_verify = try arena_binding_mod.prepareCompactWitnessInput(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    witness_bundle.?,
                    "verify_instruction",
                );
                break :compact_blk try request.cache.installCompact(.verify_instruction, &local_compact_verify);
            }
            local_compact_verify = try arena_binding_mod.prepareCompactWitnessInput(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                "verify_instruction",
            );
            break :compact_blk &local_compact_verify.?;
        } else compact_blk: {
            local_compact_verify = try arena_binding_mod.prepareCompactWitnessInput(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                "verify_instruction",
            );
            break :compact_blk &local_compact_verify.?;
        };
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.compact_verify_wall_s,
            runner_wall_timer,
            compact_verify_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=compact_verify done\n", .{});
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=compact_pedersen begin\n", .{});
        const compact_pedersen_started_ns = runner_wall_timer.read();
        var local_compact_pedersen: ?protocol_recipes.CompactRecipe = null;
        defer if (local_compact_pedersen) |*recipe| recipe.deinit();
        const compact_pedersen: ?*protocol_recipes.CompactRecipe = if (!witness_recipe_requirements.pedersen)
            null
        else if (prepared_state_request) |request| compact_blk: {
            if (canonical_full_proof_plan) {
                if (execution_metrics.prepared_state_cache_hit) {
                    execution_metrics.compact_pedersen_recipe_cache_hit = true;
                    break :compact_blk try request.cache.borrowCompact(.pedersen);
                }
                local_compact_pedersen = try arena_binding_mod.prepareCompactWitnessInput(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    witness_bundle.?,
                    "pedersen_aggregator_window_bits_18",
                );
                break :compact_blk try request.cache.installCompact(.pedersen, &local_compact_pedersen);
            }
            local_compact_pedersen = try arena_binding_mod.prepareCompactWitnessInput(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                "pedersen_aggregator_window_bits_18",
            );
            break :compact_blk &local_compact_pedersen.?;
        } else compact_blk: {
            local_compact_pedersen = try arena_binding_mod.prepareCompactWitnessInput(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                "pedersen_aggregator_window_bits_18",
            );
            break :compact_blk &local_compact_pedersen.?;
        };
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.compact_pedersen_wall_s,
            runner_wall_timer,
            compact_pedersen_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=compact_pedersen done\n", .{});
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=compact_poseidon begin\n", .{});
        const compact_poseidon_started_ns = runner_wall_timer.read();
        var local_compact_poseidon: ?protocol_recipes.CompactRecipe = null;
        defer if (local_compact_poseidon) |*recipe| recipe.deinit();
        const compact_poseidon: ?*protocol_recipes.CompactRecipe = if (!witness_recipe_requirements.poseidon)
            null
        else if (prepared_state_request) |request| compact_blk: {
            if (canonical_full_proof_plan) {
                if (execution_metrics.prepared_state_cache_hit) {
                    execution_metrics.compact_poseidon_recipe_cache_hit = true;
                    break :compact_blk try request.cache.borrowCompact(.poseidon);
                }
                local_compact_poseidon = try arena_binding_mod.prepareCompactWitnessInput(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    witness_bundle.?,
                    "poseidon_aggregator",
                );
                break :compact_blk try request.cache.installCompact(.poseidon, &local_compact_poseidon);
            }
            local_compact_poseidon = try arena_binding_mod.prepareCompactWitnessInput(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                "poseidon_aggregator",
            );
            break :compact_blk &local_compact_poseidon.?;
        } else compact_blk: {
            local_compact_poseidon = try arena_binding_mod.prepareCompactWitnessInput(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                "poseidon_aggregator",
            );
            break :compact_blk &local_compact_poseidon.?;
        };
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.compact_poseidon_wall_s,
            runner_wall_timer,
            compact_poseidon_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=compact_poseidon done\n", .{});
        try base_execution.execute(.{
            .allocator = allocator,
            .metal = metal,
            .resident_arena = resident_arena,
            .schedule = schedule,
            .plan = plan,
            .prover_input = if (prover_input) |value| value else null,
            .witness_recipe_requirements = witness_recipe_requirements,
            .bindings = bindings,
            .proof_plan = if (proof_plan) |value| value else null,
            .witness_bundle = witness_bundle,
            .fixed_table_bundle = fixed_table_bundle,
            .prepared_state_request = prepared_state_request,
            .canonical_full_proof_plan = canonical_full_proof_plan,
            .base_inverse_twiddles_prepared = base_inverse_twiddles_prepared,
            .runner_wall_timer = runner_wall_timer,
            .runner_phase_timing = runner_phase_timing,
            .recipe_preparation_timing = recipe_preparation_timing,
            .remaining_recipe_started_ns = remaining_recipe_started_ns,
            .execute_proof = execute_proof,
            .witness = witness,
            .compact_verify = compact_verify,
            .compact_pedersen = compact_pedersen,
            .compact_poseidon = compact_poseidon,
            .multiplicity_feeds = multiplicity_feeds,
            .memory_trace = if (memory_trace) |*value| value else null,
            .requested_commit_tree_count = requested_commit_tree_count,
            .staged_tree0_root = staged_tree0_root,
        }, execution_metrics);
        const transcript_recipe_started_ns = runner_wall_timer.read();
        var transcript = try bindings.prepareTranscript(metal, resident_arena);
        defer transcript.deinit();
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.transcript_wall_s,
            runner_wall_timer,
            transcript_recipe_started_ns,
        );
        try interaction_execution.execute(.{
            .allocator = allocator,
            .metal = metal,
            .resident_arena = resident_arena,
            .schedule = schedule,
            .plan = plan,
            .requested_commit_tree_count = requested_commit_tree_count,
            .prover_input = if (prover_input) |value| value else null,
            .bindings = bindings,
            .witness_recipe_requirements = witness_recipe_requirements,
            .prepared_state_request = prepared_state_request,
            .canonical_full_proof_plan = canonical_full_proof_plan,
            .witness_bundle = witness_bundle,
            .fixed_table_bundle = fixed_table_bundle,
            .relation_bundle = relation_bundle,
            .runner_wall_timer = runner_wall_timer,
            .recipe_preparation_timing = recipe_preparation_timing,
            .transcript = &transcript,
            .statement_bootstrap = if (statement_bootstrap) |value| value else null,
            .transcript_reference_path = transcript_reference_path,
            .transcript_reference = transcript_reference,
            .proof_plan = if (proof_plan) |value| value else null,
            .compact_verify = compact_verify,
            .compact_pedersen = compact_pedersen,
            .compact_poseidon = compact_poseidon,
            .memory_trace = if (memory_trace) |*value| value else null,
            .fixed_tables = fixed_tables,
        }, execution_metrics);
        try protocol_execution.execute(.{
            .allocator = allocator,
            .args = args,
            .metal = metal,
            .resident_arena = resident_arena,
            .schedule = schedule,
            .plan = plan,
            .bindings = bindings,
            .composition_bundle = composition_bundle,
            .execute_composition = execute_composition,
            .execute_quotient = execute_quotient,
            .execute_fri = execute_fri,
            .execute_decommit = execute_decommit,
            .execute_proof = execute_proof,
            .requested_commit_tree_count = requested_commit_tree_count,
            .transcript = &transcript,
            .transcript_reference = transcript_reference,
            .runner_wall_timer = runner_wall_timer,
            .recipe_preparation_timing = recipe_preparation_timing,
            .prover_input = if (prover_input) |value| value else null,
        }, execution_metrics);
    }
}
