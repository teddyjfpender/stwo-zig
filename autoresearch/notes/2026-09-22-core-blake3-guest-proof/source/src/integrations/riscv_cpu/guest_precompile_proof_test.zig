//! End-to-end CPU proof for the advertised Poseidon2 execution profile.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const prover_api = @import("stwo_prover_api");
const work_pool = @import("stwo_prover_engine").work_pool;
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const prover = frontend.prover_mod;
const public_data_mod = frontend.air.public_data;
const runner = frontend.runner;
const LegacyEngine = prover.ProverEngineForBackend(CpuBackend);

const test_config = pcs_core.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
};

test "Poseidon2 profile proves one guest call and independently verifies on CPU" {
    try proveAndVerify(LegacyEngine, true, false);
}

test "Poseidon2 profile proves its canonical zero-call extension geometry" {
    try proveAndVerify(LegacyEngine, false, false);
}

test "P-003 combined Poseidon2 producer publishes main-witness work" {
    try proveAndVerify(LegacyEngine, true, true);
}

fn proveAndVerify(comptime Engine: type, include_call: bool, capture_work: bool) !void {
    const allocator = std.testing.allocator;
    var pool: work_pool.WorkPool = undefined;
    var pool_live = false;
    defer if (pool_live) pool.deinit();
    var pool_binding: work_pool.ScopedPoolBinding = undefined;
    var pool_bound = false;
    defer if (pool_bound) pool_binding.deinit();
    if (capture_work) {
        try pool.initInPlaceWithOptions(.{
            .worker_count = 2,
            .stack_size = frontend.air.guest_precompile.provider_component
                .prepared_row_stack_bytes,
        });
        pool_live = true;
        pool_binding = try work_pool.ScopedPoolBinding.init(&pool);
        pool_bound = true;
    }
    var recorder = prover_api.stage_profile.Recorder.initWithOptions(
        allocator,
        "test",
        "riscv-poseidon2-main-witness",
        .{ .capture_work = capture_work },
    );
    defer recorder.deinit();
    const elf = frontend.testing.guest_precompile_test_elf.build(include_call, .self_loop);
    var run = try runner.runPoseidon2Extension(allocator, &elf, 16);
    defer run.deinit();
    try std.testing.expectEqual(.self_loop, run.base.completion_reason);
    try std.testing.expectEqual(@as(usize, @intFromBool(include_call)), run.calls.len());
    try std.testing.expectEqual(
        run.calls.len(),
        run.execution_rows.rows().len,
    );

    const input_words = try public_data_mod.packInputWords(allocator, run.base.input);
    defer allocator.free(input_words);
    const output_words = try allocator.alloc(
        public_data_mod.OutputWord,
        run.base.output_words.len,
    );
    defer allocator.free(output_words);
    for (output_words, run.base.output_words) |*destination, source| {
        destination.* = .{
            .addr = source.addr,
            .value = source.value,
            .clock = source.clock,
        };
    }
    const public_data = public_data_mod.PublicData{
        .initial_pc = run.base.initial_pc,
        .final_pc = run.base.final_pc,
        .clock = @intCast(run.base.step_count),
        .initial_regs = run.base.initial_regs,
        .final_regs = run.base.final_regs,
        .reg_last_clock = run.base.state_chain_tracker.reg_last_clk,
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = try public_data_mod.completionFromRun(run.base),
        .io_entries = .{
            .input_start = run.base.input_start,
            .input_len = @intCast(run.base.input.len),
            .input_words = input_words,
            .output_len = run.base.output_len,
            .output_len_addr = run.base.output_len_addr,
            .output_data_addr = run.base.output_data_addr,
            .output_words = output_words,
        },
    };

    var output = try prover.provePoseidon2WithEngineAndPublicData(
        Engine,
        allocator,
        test_config,
        &run.base.execution_trace,
        &run.calls,
        &run.execution_rows,
        &run.base.state_chain_tracker,
        &run.base.rw_memory,
        if (capture_work) &recorder else null,
        public_data,
    );
    var proof_moved = false;
    defer if (proof_moved)
        output.deinitAfterProofMoved(allocator)
    else
        output.deinit(allocator);

    try output.interaction_claim.validate(&output.statement, &output.extension);
    try std.testing.expectEqual(
        @as(u32, @intFromBool(include_call)),
        output.extension.counts.n_guest,
    );
    try std.testing.expectEqual(@as(u32, 3), output.statement.total_steps);
    try std.testing.expectEqual(
        @as(usize, 4),
        output.proof.commitment_scheme_proof.commitments.items.len,
    );
    if (capture_work) {
        const work = recorder.workCaptureRecorder() orelse unreachable;
        inline for (.{
            prover_api.work_profile.Site.main_witness_field,
            prover_api.work_profile.Site.sparse_memory_and_guest_poseidon_witness,
            prover_api.work_profile.Site.relation_challenges_and_interaction_traces,
            prover_api.work_profile.Site.fri_protocol,
        }) |site| {
            const site_index = @intFromEnum(site);
            try std.testing.expectEqual(@as(u64, 1), work.planned_sites[site_index]);
            try std.testing.expectEqual(@as(u64, 1), work.completed_sites[site_index]);
        }
        const snapshot = try recorder.workSnapshot();
        try snapshot.validate();
    }

    if (comptime Engine.Hasher == @import("stwo_core").proof_suites.Blake3.Hasher) {
        const codec = prover.guest_precompile.proof_artifact.Blake3;
        const encoded = try codec.encodeAlloc(allocator, .{ .pcs_config = test_config, .statement = &output.statement, .extension = &output.extension, .artifact = output.artifact, .interaction_claim = output.interaction_claim, .proof = &output.proof });
        defer allocator.free(encoded);
        var decoded = try codec.decodeAllocForConfig(allocator, encoded, test_config, .{});
        defer decoded.deinitAfterProofMoved(allocator);
        try prover.verifyPoseidon2WithEngine(Engine, allocator, test_config, decoded.statement, decoded.extension, decoded.artifact, decoded.proof, decoded.interaction_claim);
    }
    if (comptime Engine.Hasher == @import("stwo_core").proof_suites.Blake2s.Hasher) {
        const legacy = prover.guest_precompile.proof_artifact;
        const codec = legacy.Blake3;
        const encoded = try legacy.encodeAlloc(allocator, .{ .pcs_config = test_config, .statement = &output.statement, .extension = &output.extension, .artifact = output.artifact, .interaction_claim = output.interaction_claim, .proof = &output.proof });
        defer allocator.free(encoded);
        // A forged header can pass structural admission, but cannot change the
        // proof's commitment/transcript suite or authenticated preprocessed root.
        std.mem.writeInt(u16, encoded[codec.HeaderOffset.version..][0..2], codec.format_version, .little);
        std.mem.writeInt(u16, encoded[codec.HeaderOffset.hasher..][0..2], codec.blake3_merkle_hasher_v1, .little);
        var decoded = try codec.decodeAllocForConfig(allocator, encoded, test_config, .{});
        defer decoded.deinitAfterProofMoved(allocator);
        const suite = @import("stwo_core").proof_suites.Blake3;
        const Blake3Engine = @import("stwo_prover_engine").engine.ProverEngine(CpuBackend, suite.Hasher, suite.MerkleChannel, suite.Channel);
        try std.testing.expectError(error.InvalidPreprocessedCommitment, prover.verifyPoseidon2WithEngine(Blake3Engine, allocator, test_config, decoded.statement, decoded.extension, decoded.artifact, decoded.proof, decoded.interaction_claim));
    }
    proof_moved = true;
    try prover.verifyPoseidon2WithEngine(
        Engine,
        allocator,
        test_config,
        output.statement,
        output.extension,
        output.artifact,
        output.proof,
        output.interaction_claim,
    );
}

test "BLAKE3 core suite proves guest precompile and verifies its v5 artifact" {
    const suite = @import("stwo_core").proof_suites.Blake3;
    const Engine = @import("stwo_prover_engine").engine.ProverEngine(CpuBackend, suite.Hasher, suite.MerkleChannel, suite.Channel);
    try proveAndVerify(Engine, true, false);
}
