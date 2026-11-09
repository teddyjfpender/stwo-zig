const std = @import("std");
const stwo = @import("stwo");
const protocol_recipes = stwo.backends.metal.protocol_recipes;
const blake2_merkle = stwo.core.vcs_lifted.blake2_merkle;
const arena_binding_mod = stwo.integrations.cairo_metal.arena_binding;
const diagnostics = @import("diagnostics.zig");
const timing = @import("timing.zig");
const ExecutionMetrics = @import("execution_metrics.zig").ExecutionMetrics;

const logAddOpcodeCoefficientDigests = diagnostics.logAddOpcodeCoefficientDigests;
const logPurposeDigests = diagnostics.logPurposeDigests;
const dumpAddOpcodeCoefficients = diagnostics.dumpAddOpcodeCoefficients;
const RunnerPhaseTiming = timing.RunnerPhaseTiming;
const nanosecondsToSeconds = timing.nanosecondsToSeconds;

pub fn execute(ctx: anytype, execution_metrics: *ExecutionMetrics) !void {
    const allocator = ctx.allocator;
    const metal = ctx.metal;
    const resident_arena = ctx.resident_arena;
    const schedule = ctx.schedule;
    const plan = ctx.plan;
    const prover_input = ctx.prover_input;
    const witness_recipe_requirements = ctx.witness_recipe_requirements;
    const bindings = ctx.bindings;
    const proof_plan = ctx.proof_plan;
    const witness_bundle = ctx.witness_bundle;
    const fixed_table_bundle = ctx.fixed_table_bundle;
    const prepared_state_request = ctx.prepared_state_request;
    const canonical_full_proof_plan = ctx.canonical_full_proof_plan;
    const base_inverse_twiddles_prepared = ctx.base_inverse_twiddles_prepared;
    const runner_wall_timer = ctx.runner_wall_timer;
    const runner_phase_timing = ctx.runner_phase_timing;
    const recipe_preparation_timing = ctx.recipe_preparation_timing;
    const remaining_recipe_started_ns = ctx.remaining_recipe_started_ns;
    const execute_proof = ctx.execute_proof;
    const witness = ctx.witness;
    const compact_verify = ctx.compact_verify;
    const compact_pedersen = ctx.compact_pedersen;
    const compact_poseidon = ctx.compact_poseidon;
    const multiplicity_feeds = ctx.multiplicity_feeds;
    const memory_trace = ctx.memory_trace;
    const requested_commit_tree_count = ctx.requested_commit_tree_count;
    const staged_tree0_root = ctx.staged_tree0_root;

    if (prover_input) |adapted| {
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=ec_op_base begin\n", .{});
        const ec_op_base_started_ns = runner_wall_timer.read();
        var ec_op: ?protocol_recipes.EcOpRecipe = if (witness_recipe_requirements.ec_op)
            try arena_binding_mod.prepareEcOpWitness(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                adapted,
                .base,
            )
        else
            null;
        defer if (ec_op) |*recipe| recipe.deinit();
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.ec_op_base_wall_s,
            runner_wall_timer,
            ec_op_base_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("prepare stage=ec_op_base done\n", .{});
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_WITNESS")) {
            if (!std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_BASE_INTERPOLATION"))
                return error.MissingBaseInterpolation;
            if (!base_inverse_twiddles_prepared)
                try bindings.populateCommitmentInverseTwiddles(allocator, resident_arena, plan, 1);
            const recorded_base_interpolation_started_ns = runner_wall_timer.read();
            var local_recorded_interpolation: ?arena_binding_mod.RecordedBaseInterpolationBatch = null;
            defer if (local_recorded_interpolation) |*recipe| recipe.deinit();
            const recorded_interpolation = if (prepared_state_request) |request| recorded_blk: {
                if (canonical_full_proof_plan) {
                    if (execution_metrics.prepared_state_cache_hit) {
                        execution_metrics.recorded_base_interpolation_cache_hit = true;
                        break :recorded_blk try request.cache.borrowRecordedBaseInterpolation();
                    }
                    local_recorded_interpolation = try arena_binding_mod.prepareRecordedBaseInterpolation(
                        allocator,
                        metal,
                        resident_arena,
                        schedule,
                        plan,
                        proof_plan.?,
                        bindings.commitmentTwiddleStorage(plan, 1),
                    );
                    break :recorded_blk try request.cache.installRecordedBaseInterpolation(
                        &local_recorded_interpolation,
                    );
                }
                local_recorded_interpolation = try arena_binding_mod.prepareRecordedBaseInterpolation(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    proof_plan.?,
                    bindings.commitmentTwiddleStorage(plan, 1),
                );
                break :recorded_blk &local_recorded_interpolation.?;
            } else recorded_blk: {
                local_recorded_interpolation = try arena_binding_mod.prepareRecordedBaseInterpolation(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    proof_plan.?,
                    bindings.commitmentTwiddleStorage(plan, 1),
                );
                break :recorded_blk &local_recorded_interpolation.?;
            };
            RunnerPhaseTiming.addInterval(
                &recipe_preparation_timing.recorded_base_interpolation_wall_s,
                runner_wall_timer,
                recorded_base_interpolation_started_ns,
            );
            const native_base_interpolation_started_ns = runner_wall_timer.read();
            var local_native_interpolation: ?arena_binding_mod.NativeBaseInterpolationBatch = null;
            defer if (local_native_interpolation) |*recipe| recipe.deinit();
            const native_interpolation = if (prepared_state_request) |request| native_blk: {
                if (canonical_full_proof_plan) {
                    if (execution_metrics.prepared_state_cache_hit) {
                        execution_metrics.native_base_interpolation_cache_hit = true;
                        break :native_blk try request.cache.borrowNativeBaseInterpolation();
                    }
                    local_native_interpolation = try arena_binding_mod.prepareNativeBaseInterpolation(
                        allocator,
                        metal,
                        resident_arena,
                        schedule,
                        plan,
                        fixed_table_bundle.?,
                        bindings.commitmentTwiddleStorage(plan, 1),
                    );
                    break :native_blk try request.cache.installNativeBaseInterpolation(
                        &local_native_interpolation,
                    );
                }
                local_native_interpolation = try arena_binding_mod.prepareNativeBaseInterpolation(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    fixed_table_bundle.?,
                    bindings.commitmentTwiddleStorage(plan, 1),
                );
                break :native_blk &local_native_interpolation.?;
            } else native_blk: {
                local_native_interpolation = try arena_binding_mod.prepareNativeBaseInterpolation(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    fixed_table_bundle.?,
                    bindings.commitmentTwiddleStorage(plan, 1),
                );
                break :native_blk &local_native_interpolation.?;
            };
            RunnerPhaseTiming.addInterval(
                &recipe_preparation_timing.native_base_interpolation_wall_s,
                runner_wall_timer,
                native_base_interpolation_started_ns,
            );
            try arena_binding_mod.clearFixedMultiplicities(allocator, metal, resident_arena, schedule, plan);
            if (execute_proof) {
                const prove_started_ns = runner_wall_timer.read();
                runner_phase_timing.recipe_preparation_wall_s +=
                    nanosecondsToSeconds(prove_started_ns - remaining_recipe_started_ns);
                execution_metrics.prove_started_wall_s = nanosecondsToSeconds(prove_started_ns);
                execution_metrics.prove_timer = try std.time.Timer.start();
            }
            const recorded = try arena_binding_mod.executeScheduledWitnessGraph(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                proof_plan.?,
                witness_bundle.?,
                witness,
                .{
                    .compact_verify = compact_verify,
                    .compact_pedersen = compact_pedersen,
                    .compact_poseidon = compact_poseidon,
                    .ec_op = if (ec_op) |*recipe| recipe else null,
                },
                recorded_interpolation,
                multiplicity_feeds,
            );
            execution_metrics.executed_witness_programs = recorded.executed_programs;
            execution_metrics.witness_graph_gpu_ms = recorded.writer_gpu_ms + recorded.input_gpu_ms;
            execution_metrics.multiplicity_feed_gpu_ms = recorded.feed_gpu_ms;
            execution_metrics.base_interpolation_gpu_ms = recorded.interpolation_gpu_ms;
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) std.debug.print(
                "recorded_witness writer_gpu_ms={d:.6} input_gpu_ms={d:.6} feed_gpu_ms={d:.6} interpolation_gpu_ms={d:.6} programs={}\n",
                .{
                    recorded.writer_gpu_ms,
                    recorded.input_gpu_ms,
                    recorded.feed_gpu_ms,
                    recorded.interpolation_gpu_ms,
                    recorded.executed_programs,
                },
            );
            if (!std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_PREPROCESSED"))
                return error.MissingPreprocessedEvaluations;
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS"))
                try logAddOpcodeCoefficientDigests(resident_arena, schedule, plan, "recorded_graph");
            const trace = if (memory_trace) |value| value else return error.MissingMemoryTrace;
            try trace.populateRc99Lut(resident_arena);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("base stage=rc99_lut done\n", .{});
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS"))
                try logAddOpcodeCoefficientDigests(resident_arena, schedule, plan, "rc99_lut");
            execution_metrics.memory_public_seed_gpu_ms = try trace.seedPublicMemory(metal, resident_arena, adapted);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("base stage=public_memory done\n", .{});
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS"))
                try logAddOpcodeCoefficientDigests(resident_arena, schedule, plan, "public_memory");
            execution_metrics.memory_trace_gpu_ms = try trace.executeAddress(metal, resident_arena, adapted);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("base stage=memory_address done\n", .{});
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_BASE_EVAL_DIGESTS"))
                try arena_binding_mod.logComponentBaseEvalDigests(
                    resident_arena,
                    schedule,
                    plan,
                    "memory_address_to_id",
                );
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS"))
                try logAddOpcodeCoefficientDigests(resident_arena, schedule, plan, "memory_address");
            execution_metrics.base_interpolation_gpu_ms += try native_interpolation.interpolateMemoryAddress();
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("base stage=memory_address_ifft done\n", .{});
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS"))
                try logAddOpcodeCoefficientDigests(resident_arena, schedule, plan, "memory_address_ifft");
            const memory_values = try trace.executeValues(metal, resident_arena);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("base stage=memory_values done\n", .{});
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS"))
                try logAddOpcodeCoefficientDigests(resident_arena, schedule, plan, "memory_values");
            execution_metrics.memory_trace_gpu_ms += memory_values.trace_gpu_ms;
            execution_metrics.memory_rc99_gpu_ms = memory_values.rc99_gpu_ms;
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_BASE_EVAL_DIGESTS"))
                try arena_binding_mod.logComponentBaseEvalDigests(
                    resident_arena,
                    schedule,
                    plan,
                    "memory_id_to_big",
                );
            execution_metrics.base_interpolation_gpu_ms += try native_interpolation.interpolateMemoryValues();
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("base stage=memory_values_ifft done\n", .{});
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS"))
                try logAddOpcodeCoefficientDigests(resident_arena, schedule, plan, "memory_values_ifft");
            execution_metrics.base_interpolation_gpu_ms += try native_interpolation.executeFixed(schedule, plan);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("base stage=fixed_ifft done\n", .{});
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS"))
                try logAddOpcodeCoefficientDigests(resident_arena, schedule, plan, "fixed_ifft");
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_DUMP_ADD_OPCODE_COEFFICIENTS"))
                try dumpAddOpcodeCoefficients(resident_arena, schedule, plan);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_BASE_DIGESTS"))
                try logPurposeDigests(resident_arena, schedule, plan, "BaseCoefficients");
        }
    }
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_BASE_INTERPOLATION")) {
        if (execution_metrics.executed_witness_programs != witness_bundle.?.entries.len) return error.WitnessGraphNotExecuted;
        if (execution_metrics.base_interpolation_gpu_ms == 0) return error.MissingBaseInterpolation;
    }
    if (requested_commit_tree_count > 1) {
        if (execution_metrics.base_interpolation_gpu_ms == 0) return error.CommitmentInputsNotExecuted;
        try bindings.populateCommitmentTwiddles(allocator, resident_arena, plan, 1);
        const committed = try bindings.executeCommitment(
            metal,
            resident_arena,
            schedule,
            plan,
            1,
            blake2_merkle.Blake2sPlainMerkleHasher.leafSeed(),
            blake2_merkle.Blake2sPlainMerkleHasher.nodeSeed(),
        );
        execution_metrics.commitment_gpu_ms += committed.gpu_ms;
        execution_metrics.commitment_lde_gpu_ms += committed.lde_gpu_ms;
        execution_metrics.commitment_leaf_gpu_ms += committed.leaf_gpu_ms;
        execution_metrics.commitment_parent_gpu_ms += committed.parent_gpu_ms;
        var root: [32]u8 = undefined;
        @memcpy(&root, (try resident_arena.bytes(committed.root))[0..32]);
        execution_metrics.commitment_roots[1] = root;
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("base tree1_root={x}\n", .{root});
    }
    if (staged_tree0_root) |root|
        try bindings.restoreCommitmentRoot(resident_arena, schedule, plan, 0, root);
}
