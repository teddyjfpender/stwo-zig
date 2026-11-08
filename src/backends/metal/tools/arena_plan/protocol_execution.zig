const std = @import("std");
const stwo = @import("stwo");
const arena = stwo.backends.metal.arena_plan;
const metal_runtime = stwo.backends.metal.runtime;
const blake2_hash = stwo.core.vcs.blake2_hash;
const blake2_merkle = stwo.core.vcs_lifted.blake2_merkle;
const proof_bundle = stwo.frontends.cairo.witness.proof_bundle;
const resident_verifier = stwo.frontends.cairo.witness.resident_verifier;
const arena_binding_mod = stwo.integrations.cairo_metal.arena_binding;
const cairo_oods = stwo.integrations.cairo_metal.oods;
const cairo_quotient_inputs = stwo.integrations.cairo_metal.quotient_inputs;
const cairo_quotient_reference = stwo.integrations.cairo_metal.quotient_reference;
const proof_layout = @import("proof_layout.zig");
const timing = @import("timing.zig");
const runtimeVerifierGeometry = @import("host_geometry.zig").runtimeVerifierGeometry;
const ExecutionMetrics = @import("execution_metrics.zig").ExecutionMetrics;

const bindingDegreeLogs = proof_layout.bindingDegreeLogs;
const transcriptInputBinding = proof_layout.transcriptInputBinding;
const RunnerPhaseTiming = timing.RunnerPhaseTiming;
const nanosecondsToSeconds = timing.nanosecondsToSeconds;

pub fn execute(ctx: anytype, execution_metrics: *ExecutionMetrics) !void {
    const allocator = ctx.allocator;
    const args = ctx.args;
    const metal = ctx.metal;
    const resident_arena = ctx.resident_arena;
    const schedule = ctx.schedule;
    const plan = ctx.plan;
    const bindings = ctx.bindings;
    const composition_bundle = ctx.composition_bundle;
    const execute_composition = ctx.execute_composition;
    const execute_quotient = ctx.execute_quotient;
    const execute_fri = ctx.execute_fri;
    const execute_decommit = ctx.execute_decommit;
    const execute_proof = ctx.execute_proof;
    const requested_commit_tree_count = ctx.requested_commit_tree_count;
    const transcript = ctx.transcript;
    const transcript_reference = ctx.transcript_reference;
    const runner_wall_timer = ctx.runner_wall_timer;
    const recipe_preparation_timing = ctx.recipe_preparation_timing;
    const prover_input = ctx.prover_input;

    const prepare_full_protocol = !std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_WITNESS");
    if (prepare_full_protocol or execute_composition) {
        const composition_path = args[7];
        if (!std.mem.endsWith(u8, composition_path, ".bin")) return error.InvalidCompositionPath;
        try arena_binding_mod.populateNamedInverseTwiddles(
            allocator,
            resident_arena,
            schedule,
            plan,
            "InverseTwiddles",
        );
        const composition_metallib = try std.fmt.allocPrint(
            allocator,
            "{s}.metallib",
            .{composition_path[0 .. composition_path.len - ".bin".len]},
        );
        defer allocator.free(composition_metallib);
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("composition_prepare begin\n", .{});
        const composition_recipe_started_ns = runner_wall_timer.read();
        var composition = try bindings.prepareComposition(
            allocator,
            metal,
            resident_arena,
            composition_bundle.?,
            composition_metallib,
        );
        defer composition.deinit();
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.composition_wall_s,
            runner_wall_timer,
            composition_recipe_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("composition_prepare done\n", .{});
        if (execute_composition) {
            if (requested_commit_tree_count < 4 or execution_metrics.commitment_roots[2] == null)
                return error.CommitmentInputsNotExecuted;
            if (!composition.isComplete() and
                (execute_quotient or std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_OODS")))
                return error.PartialCompositionCannotContinue;
            try composition.execute();
            execution_metrics.composition_gpu_ms = composition.accumulated_gpu_ms;
            if (composition.isComplete()) {
                try bindings.populateCommitmentTwiddles(allocator, resident_arena, plan, 3);
                const committed = try bindings.executeCommitment(
                    metal,
                    resident_arena,
                    schedule,
                    plan,
                    3,
                    blake2_merkle.Blake2sPlainMerkleHasher.leafSeed(),
                    blake2_merkle.Blake2sPlainMerkleHasher.nodeSeed(),
                );
                execution_metrics.commitment_gpu_ms += committed.gpu_ms;
                execution_metrics.commitment_lde_gpu_ms += committed.lde_gpu_ms;
                execution_metrics.commitment_leaf_gpu_ms += committed.leaf_gpu_ms;
                execution_metrics.commitment_parent_gpu_ms += committed.parent_gpu_ms;
                var root: [32]u8 = undefined;
                @memcpy(&root, (try resident_arena.bytes(committed.root))[0..32]);
                execution_metrics.commitment_roots[3] = root;
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print("composition tree3_root={x}\n", .{root});
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print("composition stage=tree3_commit done\n", .{});
                try transcript.compositionAndOods();
                if (transcript_reference) |fixture|
                    try transcript.expectOutputWords(3, &fixture.expected_output_3);
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print("composition stage=transcript done\n", .{});
            } else if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) {
                std.debug.print("composition stage=partial_front done\n", .{});
            }
            if (composition.isComplete() and std.process.hasEnvVarConstant("STWO_ZIG_SN2_EXECUTE_OODS")) {
                var oods_input: ?arena.Binding = null;
                for (bindings.transcript_inputs) |transcript_input| if (transcript_input.ordinal == 25) {
                    oods_input = transcript_input.binding;
                    break;
                };
                const oods = try cairo_oods.populate(
                    allocator,
                    metal,
                    resident_arena,
                    composition_bundle.?,
                    bindings.preprocessed_coefficients,
                    bindings.canonical_base_coefficients,
                    bindings.canonical_interaction_coefficients,
                    bindings.composition_coefficients,
                    try transcript.output(3),
                    oods_input orelse return error.MissingTranscriptInput,
                );
                if (transcript_reference) |fixture|
                    try transcript.expectInputWords(25, fixture.input_25);
                try transcript.oodsAndQuotient();
                if (transcript_reference) |fixture|
                    try transcript.expectOutputWords(4, &fixture.expected_output_4);
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print(
                        "oods stage=evaluate samples={} columns={} wall_ms={d:.3} gpu_ms={d:.3} parity={s}\n",
                        .{
                            oods.sample_count,
                            oods.column_count,
                            oods.wall_ms,
                            oods.gpu_ms,
                            if (transcript_reference != null) "exact" else "unchecked",
                        },
                    );
            } else if (composition.isComplete() and execute_quotient) {
                const fixture = transcript_reference orelse return error.MissingTranscriptReference;
                try transcript.loadInputWords(25, fixture.input_25);
                try transcript.oodsAndQuotient();
                try transcript.expectOutputWords(4, &fixture.expected_output_4);
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print(
                        "oods stage=reference_transcript samples={} parity=exact fixture_only=true\n",
                        .{fixture.input_25.len / 4},
                    );
            }
            if (composition.isComplete()) execution_metrics.transcript_gpu_ms = transcript.accumulated_gpu_ms;
        }
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("quotient_prepare begin\n", .{});
        const quotient_recipe_started_ns = runner_wall_timer.read();
        var quotient = try bindings.prepareQuotient(allocator, metal, resident_arena);
        defer quotient.deinit();
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.quotient_wall_s,
            runner_wall_timer,
            quotient_recipe_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("quotient_prepare done\n", .{});
        if (execute_quotient) {
            const quotient_reference_path = std.process.getEnvVarOwned(
                allocator,
                "STWO_ZIG_SN2_QUOTIENT_REFERENCE",
            ) catch |err| switch (err) {
                error.EnvironmentVariableNotFound => null,
                else => return err,
            };
            defer if (quotient_reference_path) |path| allocator.free(path);
            if (quotient_reference_path != null) execution_metrics.parity_fixture_used = true;
            const quotient_inputs = try cairo_quotient_inputs.populate(
                allocator,
                metal,
                resident_arena,
                composition_bundle.?,
                bindings.preprocessed_coefficients,
                bindings.canonical_base_coefficients,
                bindings.canonical_interaction_coefficients,
                bindings.composition_coefficients,
                try transcript.output(3),
                try transcript.output(4),
                try transcriptInputBinding(bindings, 25),
                bindings.quotient_partials,
                bindings.quotient_sample_points,
                bindings.quotient_first_linear_terms,
                bindings.forward_twiddles,
            );
            const reference: ?cairo_quotient_reference.ReferenceValidation = if (quotient_reference_path) |path|
                try cairo_quotient_reference.validateReferenceFixture(
                    allocator,
                    resident_arena,
                    composition_bundle.?,
                    bindings.quotient_partials,
                    bindings.quotient_sample_points,
                    bindings.quotient_first_linear_terms,
                    bindings.quotient_subdomain_values,
                    bindings.quotient_tile,
                    path,
                )
            else
                null;
            // Quotient input materialization reuses the epoch-local arena
            // aggressively. Restore the split-domain protocol constant at
            // its final consumption boundary so no transient input kernel
            // can clobber it before the IFFT.
            try arena_binding_mod.populateQuotientInverseTwiddles(
                allocator,
                resident_arena,
                schedule,
                plan,
            );
            try quotient.execute();
            execution_metrics.quotient_gpu_ms = quotient.accumulated_gpu_ms;
            execution_metrics.quotient_executed = true;
            if (reference) |expected| {
                const actual_digest = blake2_hash.Blake2sHasher.hash(
                    try resident_arena.bytes(bindings.quotient_tile),
                );
                if (!std.mem.eql(u8, &actual_digest, &expected.quotient_digest)) {
                    std.debug.print(
                        "quotient stage=final_digest mismatch expected={x} actual={x}\n",
                        .{ expected.quotient_digest, actual_digest },
                    );
                    return error.QuotientParityMismatch;
                }
                execution_metrics.quotient_reference_parity = true;
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print(
                        "quotient stage=inputs wall_ms={d:.3} gpu_ms={d:.3} samples={} columns={} scanned_words={} reference_bytes={} parity=exact\n" ++
                            "quotient stage=execute gpu_ms={d:.3} blake2s={x} parity=exact\n",
                        .{
                            quotient_inputs.wall_ms,
                            quotient_inputs.gpu_ms,
                            quotient_inputs.sample_count,
                            quotient_inputs.column_count,
                            quotient_inputs.source_words_scanned,
                            expected.payload_bytes,
                            execution_metrics.quotient_gpu_ms,
                            actual_digest,
                        },
                    );
            } else if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) {
                std.debug.print(
                    "quotient stage=inputs wall_ms={d:.3} gpu_ms={d:.3} samples={} columns={} scanned_words={} parity=unchecked\n" ++
                        "quotient stage=execute gpu_ms={d:.3} parity=unchecked\n",
                    .{
                        quotient_inputs.wall_ms,
                        quotient_inputs.gpu_ms,
                        quotient_inputs.sample_count,
                        quotient_inputs.column_count,
                        quotient_inputs.source_words_scanned,
                        execution_metrics.quotient_gpu_ms,
                    },
                );
            }
        }
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("fri_prepare begin\n", .{});
        // Composition and quotient may reuse the sparse arena range that
        // holds this protocol constant. Restore it at the FRI boundary
        // without perturbing the established arena placement.
        try arena_binding_mod.populateNamedInverseTwiddles(
            allocator,
            resident_arena,
            schedule,
            plan,
            "InverseTwiddles",
        );
        const fri_recipe_started_ns = runner_wall_timer.read();
        var fri = try bindings.prepareFri(
            metal,
            resident_arena,
            blake2_merkle.Blake2sPlainMerkleHasher.leafSeed(),
            blake2_merkle.Blake2sPlainMerkleHasher.nodeSeed(),
        );
        defer fri.deinit();
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.fri_wall_s,
            runner_wall_timer,
            fri_recipe_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("fri_prepare done\n", .{});
        if (execute_fri) {
            if (!execution_metrics.quotient_executed) return error.QuotientRequired;
            if (transcript_reference) |fixture| {
                if (fixture.fri_inputs.len != bindings.decommit_fri_trees.len)
                    return error.InvalidTranscriptReference;
            }
            for (0..bindings.decommit_fri_trees.len) |round| {
                const root_binding = try fri.commitTree(round);
                var root: [32]u8 = undefined;
                @memcpy(&root, (try resident_arena.bytes(root_binding))[0..32]);
                execution_metrics.fri_roots[round] = root;
                try transcript.friLayer(@intCast(round), root_binding, bindings.fri_challenges[round]);
                if (transcript_reference) |fixture|
                    try transcript.expectInputWords(
                        @intCast(65536 + round * 4),
                        &fixture.fri_inputs[round],
                    );
                try fri.foldRound(round);
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print("fri round={} root={x}\n", .{ round, root });
            }
            try fri.finalize();
            execution_metrics.fri_final_degree_valid = true;
            try transcript.lastLayer(bindings.fri_final_coefficients);
            if (transcript_reference) |fixture|
                try transcript.expectInputWords(30, &fixture.input_30);
            execution_metrics.fri_gpu_ms = fri.accumulated_gpu_ms;
            execution_metrics.transcript_gpu_ms = transcript.accumulated_gpu_ms;
            execution_metrics.fri_executed = true;
            execution_metrics.fri_reference_parity = transcript_reference != null;
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print(
                    "fri stage=execute gpu_ms={d:.3} roots={} final_degree=valid parity={s}\n",
                    .{ execution_metrics.fri_gpu_ms, bindings.decommit_fri_trees.len, if (execution_metrics.fri_reference_parity) "exact" else "unchecked" },
                );
        }
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("decommit_prepare begin\n", .{});
        const decommit_queries_started_ns = runner_wall_timer.read();
        var decommit_queries = try bindings.prepareDecommitQueries(metal, resident_arena);
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.decommit_queries_wall_s,
            runner_wall_timer,
            decommit_queries_started_ns,
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("decommit_prepare done\n", .{});
        if (execute_decommit) {
            if (!execution_metrics.fri_executed or !execution_metrics.fri_final_degree_valid) return error.FriRequired;
            const nonce = if (transcript_reference) |fixture| blk: {
                try transcript.queryPowAndPositionsNonce(fixture.query_nonce);
                try transcript.expectInputWords(31, &fixture.input_31);
                break :blk fixture.query_nonce;
            } else try transcript.queryPowAndPositions();
            execution_metrics.query_pow_nonce = nonce;
            execution_metrics.query_pow_wall_s = transcript.query_pow.wallSeconds();
            execution_metrics.query_pow_mode = transcript.query_pow.modeName();
            execution_metrics.query_pow_invocations = transcript.query_pow.invocations;
            if (execution_metrics.query_pow_invocations != 0)
                execution_metrics.query_pow_bits = transcript.query_pow.pow_bits;
            execution_metrics.decommit_lde_gpu_ms = try bindings.executeDecommit(
                allocator,
                metal,
                resident_arena,
                schedule,
                plan,
                &decommit_queries,
                blake2_merkle.Blake2sPlainMerkleHasher.leafSeed(),
                blake2_merkle.Blake2sPlainMerkleHasher.nodeSeed(),
            );
            execution_metrics.decommit_gpu_ms = decommit_queries.accumulated_gpu_ms;
            execution_metrics.transcript_gpu_ms = transcript.accumulated_gpu_ms;
            execution_metrics.decommit_executed = true;
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print(
                    "decommit stage=execute query_nonce={} lde_gpu_ms={d:.3} gpu_ms={d:.3} parity={s}\n",
                    .{
                        nonce,
                        execution_metrics.decommit_lde_gpu_ms,
                        execution_metrics.decommit_gpu_ms,
                        if (transcript_reference != null) "exact" else "unchecked",
                    },
                );
        }
        const proof_assembly_started_ns = runner_wall_timer.read();
        var assembly = try bindings.prepareProofAssembly(allocator, metal, resident_arena);
        defer assembly.deinit();
        RunnerPhaseTiming.addInterval(
            &recipe_preparation_timing.proof_assembly_wall_s,
            runner_wall_timer,
            proof_assembly_started_ns,
        );
        if (execute_proof) {
            if (!execution_metrics.decommit_executed) return error.DecommitmentRequired;
            try assembly.execute();
            execution_metrics.proof_assembly_gpu_ms = assembly.accumulated_gpu_ms;
            const proof_words = try assembly.words();
            const interaction_claim_words = std.math.cast(
                usize,
                (try transcriptInputBinding(bindings, 22)).size_bytes / 4,
            ) orelse return error.InvalidProofLayout;
            const sampled_value_words = std.math.cast(
                usize,
                (try transcriptInputBinding(bindings, 25)).size_bytes / 4,
            ) orelse return error.InvalidProofLayout;
            const decommitment_capacity_words = std.math.cast(
                usize,
                bindings.decommit_assembly.size_bytes / 4,
            ) orelse return error.InvalidProofLayout;
            const layout = try proof_bundle.Layout.init(
                interaction_claim_words,
                sampled_value_words,
                bindings.decommit_fri_trees.len,
                std.math.cast(usize, (try transcriptInputBinding(bindings, 30)).size_bytes / 4) orelse
                    return error.InvalidProofLayout,
                decommitment_capacity_words,
            );
            var decoded = try proof_bundle.ProofBundle.decode(allocator, proof_words, layout);
            defer decoded.deinit(allocator);
            execution_metrics.proof_bundle_valid = true;
            execution_metrics.proof_layout = .{
                .interaction_claim_words = interaction_claim_words,
                .sampled_value_words = sampled_value_words,
                .decommitment_capacity_words = decommitment_capacity_words,
            };
            const proof_output_path = try std.process.getEnvVarOwned(
                allocator,
                "STWO_ZIG_SN2_PROOF_OUTPUT",
            );
            defer allocator.free(proof_output_path);
            const proof_file = try std.fs.createFileAbsolute(proof_output_path, .{ .exclusive = true });
            defer proof_file.close();
            try proof_file.writeAll(std.mem.sliceAsBytes(proof_words));
            execution_metrics.proof_output_bytes = proof_words.len * 4;
            execution_metrics.proof_assembled = true;
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_VERIFY_PROOF")) {
                const verify_ordinals = [_]u32{ 1, 2, 3, 10, 11, 12, 13, 14, 15, 16, 20 };
                var verify_inputs: [verify_ordinals.len]resident_verifier.TranscriptInput = undefined;
                var verifier_config_words: ?[]const u32 = null;
                for (verify_ordinals, &verify_inputs) |ordinal, *verify_input| {
                    const binding = try transcriptInputBinding(bindings, ordinal);
                    const bytes: []align(4) u8 = @alignCast(try resident_arena.bytes(binding));
                    verify_input.* = .{ .ordinal = ordinal, .words = std.mem.bytesAsSlice(u32, bytes) };
                    if (ordinal == 2) verifier_config_words = verify_input.words;
                }
                const preprocessed_logs = try bindingDegreeLogs(allocator, bindings.preprocessed_coefficients);
                defer allocator.free(preprocessed_logs);
                const base_logs = try bindingDegreeLogs(allocator, bindings.canonical_base_coefficients);
                defer allocator.free(base_logs);
                const interaction_logs = try bindingDegreeLogs(allocator, bindings.canonical_interaction_coefficients);
                defer allocator.free(interaction_logs);
                const verifier_geometry = try runtimeVerifierGeometry(
                    verifier_config_words orelse return error.MissingTranscriptInput,
                    composition_bundle.?,
                );
                try resident_verifier.verifyRuntime(allocator, .{
                    .bundle = decoded,
                    .composition = composition_bundle.?,
                    .tree_logs = .{ preprocessed_logs, base_logs, interaction_logs },
                    .transcript_inputs = &verify_inputs,
                    .statement = if (prover_input) |p| p else return error.MissingAdaptedInput,
                }, verifier_geometry);
                execution_metrics.proof_verified = true;
                const prove_elapsed_ns = if (execution_metrics.prove_timer) |*timer|
                    timer.read()
                else
                    return error.MissingProveTimer;
                execution_metrics.prove_wall_s = @as(f64, @floatFromInt(prove_elapsed_ns)) /
                    @as(f64, @floatFromInt(std.time.ns_per_s));
                execution_metrics.proof_verified_wall_s = nanosecondsToSeconds(runner_wall_timer.read());
            }
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print(
                    "proof stage=assemble gpu_ms={d:.3} bytes={} bundle_valid=true verified={s}\n",
                    .{ execution_metrics.proof_assembly_gpu_ms, execution_metrics.proof_output_bytes, if (execution_metrics.proof_verified) "true" else "false" },
                );
        }
        execution_metrics.resident_prepare_gate = "passed_full_arena_and_protocol_plans";
    } else {
        execution_metrics.resident_prepare_gate = "passed_requested_protocol_prefix";
    }
}
