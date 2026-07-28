const std = @import("std");
const stwo = @import("stwo");
const protocol_recipes = stwo.backends.metal.protocol_recipes;
const blake2_merkle = stwo.core.vcs_lifted.blake2_merkle;
const arena_binding_mod = stwo.integrations.cairo_metal.arena_binding;
const RunnerPhaseTiming = @import("timing.zig").RunnerPhaseTiming;
const ExecutionMetrics = @import("execution_metrics.zig").ExecutionMetrics;

pub fn execute(ctx: anytype, execution_metrics: *ExecutionMetrics) !void {
    const allocator = ctx.allocator;
    const metal = ctx.metal;
    const resident_arena = ctx.resident_arena;
    const schedule = ctx.schedule;
    const plan = ctx.plan;
    const requested_commit_tree_count = ctx.requested_commit_tree_count;
    const prover_input = ctx.prover_input;
    const bindings = ctx.bindings;
    const witness_recipe_requirements = ctx.witness_recipe_requirements;
    const prepared_state_request = ctx.prepared_state_request;
    const canonical_full_proof_plan = ctx.canonical_full_proof_plan;
    const witness_bundle = ctx.witness_bundle;
    const fixed_table_bundle = ctx.fixed_table_bundle;
    const relation_bundle = ctx.relation_bundle;
    const runner_wall_timer = ctx.runner_wall_timer;
    const recipe_preparation_timing = ctx.recipe_preparation_timing;
    const transcript = ctx.transcript;
    const statement_bootstrap = ctx.statement_bootstrap;
    const transcript_reference_path = ctx.transcript_reference_path;
    const transcript_reference = ctx.transcript_reference;
    const proof_plan = ctx.proof_plan;
    const compact_verify = ctx.compact_verify;
    const compact_pedersen = ctx.compact_pedersen;
    const compact_poseidon = ctx.compact_poseidon;
    const memory_trace = ctx.memory_trace;
    const fixed_tables = ctx.fixed_tables;

    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_RELATIONS")) {
        if (requested_commit_tree_count < 3 or execution_metrics.commitment_roots[0] == null or execution_metrics.commitment_roots[1] == null)
            return error.CommitmentInputsNotExecuted;
        const adapted = if (prover_input) |value| value else return error.MissingAdaptedInput;
        try bindings.populateCommitmentInverseTwiddles(allocator, resident_arena, plan, 2);
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("interaction_prepare stage=witness begin\n", .{});
        var local_interaction_witness: ?protocol_recipes.AotWitnessBatchRecipe = null;
        defer if (local_interaction_witness) |*recipe| recipe.deinit();
        const interaction_aot_witness_started_ns = runner_wall_timer.read();
        const interaction_witness = if (prepared_state_request) |request| interaction_blk: {
            if (canonical_full_proof_plan) {
                if (execution_metrics.prepared_state_cache_hit) {
                    execution_metrics.interaction_aot_witness_cache_hit = true;
                    break :interaction_blk try request.cache.borrowInteractionAotWitness();
                }
                local_interaction_witness = try arena_binding_mod.prepareAotInteractionBatch(
                    allocator,
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    witness_bundle.?,
                    fixed_table_bundle.?,
                );
                break :interaction_blk try request.cache.installInteractionAotWitness(
                    &local_interaction_witness,
                );
            }
            local_interaction_witness = try arena_binding_mod.prepareAotInteractionBatch(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                fixed_table_bundle.?,
            );
            break :interaction_blk &local_interaction_witness.?;
        } else interaction_blk: {
            local_interaction_witness = try arena_binding_mod.prepareAotInteractionBatch(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                witness_bundle.?,
                fixed_table_bundle.?,
            );
            break :interaction_blk &local_interaction_witness.?;
        };
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.interaction_aot_witness_wall_s,
            runner_wall_timer,
            interaction_aot_witness_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("interaction_prepare stage=witness done\n", .{});
        const ec_op_interaction_started_ns = runner_wall_timer.read();
        var ec_lookup: ?protocol_recipes.EcOpRecipe = if (witness_recipe_requirements.ec_op)
            try arena_binding_mod.prepareEcOpWitness(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                adapted,
                .lookup,
            )
        else
            null;
        defer if (ec_lookup) |*recipe| recipe.deinit();
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.ec_op_interaction_wall_s,
            runner_wall_timer,
            ec_op_interaction_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("interaction_prepare stage=ec_lookup done\n", .{});
        const relation_components_started_ns = runner_wall_timer.read();
        var relations = try bindings.prepareRelationComponents(
            allocator,
            metal,
            resident_arena,
            schedule,
            plan,
            relation_bundle.?,
            witness_bundle.?,
            bindings.commitmentTwiddleStorage(plan, 2),
        );
        defer relations.deinit();
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.relation_components_wall_s,
            runner_wall_timer,
            relation_components_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("interaction_prepare stage=relations done\n", .{});
        const interaction_native_interpolation_started_ns = runner_wall_timer.read();
        var interaction_native = try arena_binding_mod.prepareNativeBaseInterpolation(
            allocator,
            metal,
            resident_arena,
            schedule,
            plan,
            fixed_table_bundle.?,
            bindings.commitmentTwiddleStorage(plan, 2),
        );
        defer interaction_native.deinit();
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.interaction_native_interpolation_wall_s,
            runner_wall_timer,
            interaction_native_interpolation_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("interaction_prepare stage=native done\n", .{});
        if (statement_bootstrap) |statement| {
            try statement.populateTranscriptRecipeInputs(transcript);
            execution_metrics.statement_self_derived = true;
            if (transcript_reference_path) |reference_path|
                try arena_binding_mod.validateTranscriptBootstrap(
                    allocator,
                    resident_arena,
                    schedule,
                    plan,
                    reference_path,
                    .{ .validate_commitment_roots = true },
                );
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print(
                    "interaction_prepare stage=statement_bootstrap source=self_derived parity={s}\n",
                    .{if (transcript_reference_path != null) "exact" else "unchecked"},
                );
        } else if (transcript_reference_path) |reference_path| {
            try arena_binding_mod.restoreTranscriptBootstrap(
                allocator,
                resident_arena,
                schedule,
                plan,
                reference_path,
            );
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("interaction_prepare stage=transcript_reference_bootstrap fallback=true\n", .{});
        } else {
            if (std.process.getEnvVarOwned(allocator, "STWO_ZIG_SN2_TRANSCRIPT_BOOTSTRAP")) |bootstrap_path| {
                defer allocator.free(bootstrap_path);
                execution_metrics.legacy_transcript_bootstrap_used = true;
                execution_metrics.parity_fixture_used = true;
                try arena_binding_mod.restoreTranscriptBootstrap(
                    allocator,
                    resident_arena,
                    schedule,
                    plan,
                    bootstrap_path,
                );
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print("interaction_prepare stage=transcript_bootstrap done\n", .{});
            } else |err| switch (err) {
                error.EnvironmentVariableNotFound => {},
                else => return err,
            }
        }
        try transcript.initialize();
        try transcript.bootstrapThroughBase();
        const interaction_pow = if (transcript_reference) |fixture| blk: {
            try transcript.interactionPowAndLookupNonce(fixture.interaction_nonce);
            try transcript.expectOutputWords(1, &fixture.expected_output_1);
            break :blk fixture.interaction_nonce;
        } else try transcript.interactionPowAndLookup();
        execution_metrics.interaction_pow_nonce = interaction_pow;
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("transcript interaction_pow={d}\n", .{interaction_pow});
        try bindings.materializeRelationChallenges(resident_arena);
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_RESTORE_REFERENCE_RELATION_CHALLENGES"))
            try bindings.restoreRelationChallenges(
                resident_arena,
                .{ 23353985, 545987341, 122919781, 2037762338 },
                .{ 738082848, 31333331, 241479621, 1778656766 },
            );
        const recorded = try arena_binding_mod.executeScheduledInteractionGraph(
            allocator,
            metal,
            resident_arena,
            schedule,
            plan,
            proof_plan.?,
            witness_bundle.?,
            adapted,
            interaction_witness,
            .{
                .compact_verify = compact_verify,
                .compact_pedersen = compact_pedersen,
                .compact_poseidon = compact_poseidon,
                .ec_op = if (ec_lookup) |*recipe| recipe else null,
            },
            &relations,
        );
        execution_metrics.interaction_witness_gpu_ms += recorded.writer_gpu_ms + recorded.input_gpu_ms;
        execution_metrics.relation_gpu_ms += recorded.relation_gpu_ms;
        execution_metrics.interaction_interpolation_gpu_ms += recorded.interpolation_gpu_ms;
        var executed_relations = recorded.executed_relations;

        // Native relation components follow the recorded proof DAG in the
        // staged tick order. Each source is rebuilt, related, and IFFT'd
        // before the next component can reuse its trace allocation.
        for (relations.operations) |operation| {
            if (proof_plan.?.componentIndex(operation.component) != null or
                std.mem.eql(u8, operation.component, "ec_op_builtin")) continue;
            if (std.mem.eql(u8, operation.component, "memory_address_to_id")) {
                const trace = if (memory_trace) |value| value else return error.MissingMemoryTrace;
                execution_metrics.interaction_witness_gpu_ms += try trace.executeAddress(metal, resident_arena, adapted);
            } else if (std.mem.eql(u8, operation.component, "memory_id_to_big")) {
                const trace = if (memory_trace) |value| value else return error.MissingMemoryTrace;
                execution_metrics.interaction_witness_gpu_ms += try trace.executeValueTraces(metal, resident_arena);
            } else {
                const fixed_entry = fixed_table_bundle.?.find(operation.component) orelse return error.MissingFixedTable;
                var needs_lookup = false;
                var needs_base = false;
                const relation_component = relation_bundle.?.find(operation.component) orelse return error.MissingRelation;
                for (relation_component.traces) |trace| {
                    needs_lookup = needs_lookup or trace.layout == .lookup_words;
                    needs_base = needs_base or trace.layout != .lookup_words;
                }
                if (needs_lookup) {
                    const fixed_index = try arena_binding_mod.fixedLookupIndex(
                        schedule,
                        plan,
                        fixed_table_bundle.?,
                        operation.component,
                    ) orelse return error.MissingFixedTable;
                    const before = fixed_tables.accumulated_gpu_ms;
                    try fixed_tables.executeIndex(fixed_index);
                    execution_metrics.interaction_witness_gpu_ms += fixed_tables.accumulated_gpu_ms - before;
                }
                if (needs_base)
                    execution_metrics.interaction_witness_gpu_ms += try interaction_native.materializeFixed(fixed_entry.component);
            }
            const native = try relations.executeComponent(operation.component);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_INTERACTION_EVAL_DIGESTS"))
                try arena_binding_mod.logComponentInteractionDigests(
                    allocator,
                    resident_arena,
                    schedule,
                    plan,
                    operation.component,
                );
            execution_metrics.relation_gpu_ms += native.relation_gpu_ms;
            execution_metrics.interaction_interpolation_gpu_ms += native.interpolation_gpu_ms;
            executed_relations += 1;
        }
        if (executed_relations != relations.operations.len) return error.RelationGraphNotExecuted;
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_TRACE_COLUMN_613"))
            try arena_binding_mod.logLogicalBindingDigest(
                resident_arena,
                plan,
                1737,
                "after_all_relations",
            );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_RELATION_DIAGNOSTICS"))
            try bindings.logRelationDiagnostics(resident_arena, relations);
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPAIR_COLUMN_613_LDE")) {
            const file = try std.fs.createFileAbsolute("/tmp/sn2-column613-before-publish.u32le", .{});
            defer file.close();
            try file.writeAll(try resident_arena.bytes(plan.binding(1737) catch return error.MissingBinding));
        }
        try bindings.publishInteractionClaim(resident_arena, schedule, plan);
        if (transcript_reference) |fixture|
            try transcript.expectInputWords(22, fixture.input_22);
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPAIR_COLUMN_613_LDE")) {
            const file = try std.fs.createFileAbsolute("/tmp/sn2-column613-after-publish.u32le", .{});
            defer file.close();
            try file.writeAll(try resident_arena.bytes(plan.binding(1737) catch return error.MissingBinding));
        }
        try bindings.populateCommitmentTwiddles(allocator, resident_arena, plan, 2);
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPAIR_COLUMN_613_LDE")) {
            const file = try std.fs.createFileAbsolute("/tmp/sn2-column613-pre-commit-source.u32le", .{});
            defer file.close();
            try file.writeAll(try resident_arena.bytes(plan.binding(1737) catch return error.MissingBinding));
        }
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_INTERACTION_COEFF_DIGESTS"))
            try arena_binding_mod.logInteractionCoefficientDigests(
                resident_arena,
                schedule,
                plan,
                "before_commit",
            );
        const committed = try bindings.executeCommitment(
            metal,
            resident_arena,
            schedule,
            plan,
            2,
            blake2_merkle.Blake2sPlainMerkleHasher.leafSeed(),
            blake2_merkle.Blake2sPlainMerkleHasher.nodeSeed(),
        );
        execution_metrics.commitment_gpu_ms += committed.gpu_ms;
        execution_metrics.commitment_lde_gpu_ms += committed.lde_gpu_ms;
        execution_metrics.commitment_leaf_gpu_ms += committed.leaf_gpu_ms;
        execution_metrics.commitment_parent_gpu_ms += committed.parent_gpu_ms;
        var root: [32]u8 = undefined;
        @memcpy(&root, (try resident_arena.bytes(committed.root))[0..32]);
        execution_metrics.commitment_roots[2] = root;
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("interaction tree2_root={x}\n", .{root});
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("interaction stage=tree2_commit done\n", .{});
        if (transcript_reference) |fixture|
            try transcript.expectInputWords(22, fixture.input_22);
        if (transcript_reference) |fixture|
            try transcript.expectInputWords(23, &fixture.input_23);
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPLAY_TRANSCRIPT_AFTER_TREE2")) {
            const fixture = transcript_reference orelse return error.MissingTranscriptReference;
            try transcript.initialize();
            try transcript.bootstrapThroughBase();
            try transcript.interactionPowAndLookupNonce(fixture.interaction_nonce);
            try transcript.expectOutputWords(1, &fixture.expected_output_1);
        }
        try transcript.interactionAndComposition();
        if (transcript_reference) |fixture|
            try transcript.expectOutputWords(2, &fixture.expected_output_2);
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("interaction stage=transcript done\n", .{});
        execution_metrics.transcript_gpu_ms = transcript.accumulated_gpu_ms;
        execution_metrics.interaction_pow_wall_s = transcript.interaction_pow.wallSeconds();
        execution_metrics.interaction_pow_mode = transcript.interaction_pow.modeName();
        execution_metrics.interaction_pow_invocations = transcript.interaction_pow.invocations;
        if (execution_metrics.interaction_pow_invocations != 0)
            execution_metrics.interaction_pow_bits = transcript.interaction_pow.pow_bits;
    }
}
