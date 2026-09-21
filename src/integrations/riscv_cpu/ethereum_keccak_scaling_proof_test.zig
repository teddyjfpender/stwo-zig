//! Small complete VM diagnostic for the measured Keccak composition cost.
//! Development PCS only; no recursive/omitted-route test-root import.

const std = @import("std");
const builtin = @import("builtin");
const core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const stage_profile = @import("stwo_prover_api").stage_profile;
const prover = frontend.prover_mod;
const public_data_mod = frontend.air.public_data;
const artifact = prover.guest_precompile.ethereum_proof_artifact;
const fixture = frontend.testing.guest_precompile_test_elf;
const TrackedAllocator = @import("recursive_common_ethereum_incremental_leaf_genuine_runtime_v4.zig").TrackedSmpAllocatorV4;
const Engine = prover.ProverEngineForBackend(CpuBackend);

// These parameters deliberately do not select a production security profile.
const development_config = core.pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
};

test "complete RV Keccak one call serializes destroys producer and freshly verifies" {
    try run(1);
}

test "complete RV Keccak four calls serialize destroy producer and freshly verify" {
    try run(4);
}

test "complete RV Keccak sixteen calls serialize destroy producer and freshly verify" {
    try run(16);
}

const Published = struct {
    bytes: []u8,
    sha256: [32]u8,
    execution_ns: u64,
    prove_ns: u64,
    encode_ns: u64,
};

fn run(call_count: usize) !void {
    const allocator = std.testing.allocator;
    var total = try std.time.Timer.start();
    var producer: TrackedAllocator = .{};
    defer producer.requireEmpty() catch @panic("Keccak producer leaked");
    const published = try produce(producer.allocator(), allocator, call_count);
    defer allocator.free(published.bytes);
    // produce() has released the runner, public IO, recorder and original proof.
    // Only bytes and scalar diagnostics cross into this verifier transaction.
    try producer.requireEmpty();
    var actual_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(published.bytes, &actual_sha256, .{});
    try std.testing.expectEqualSlices(u8, &published.sha256, &actual_sha256);

    var verifier: TrackedAllocator = .{};
    defer verifier.requireEmpty() catch @panic("Keccak verifier leaked");
    var verify_timer = try std.time.Timer.start();
    try freshlyVerify(verifier.allocator(), published.bytes, call_count);
    const verify_ns = verify_timer.read();
    try verifier.requireEmpty();
    std.debug.print(
        "RISCV_KECCAK_LIFECYCLE calls={d} workers=1 profile=development queries=3 pow_bits=0 execution_ns={d} prove_ns={d} encode_ns={d} fresh_decode_verify_ns={d} total_ns={d} artifact_bytes={d} producer_peak_bytes={d} verifier_peak_bytes={d} producer_live_bytes=0 verifier_live_bytes=0\n",
        .{ call_count, published.execution_ns, published.prove_ns, published.encode_ns, verify_ns, total.read(), published.bytes.len, producer.peakBytes(), verifier.peakBytes() },
    );
}

fn produce(allocator: std.mem.Allocator, publication_allocator: std.mem.Allocator, call_count: usize) !Published {
    const elf = switch (call_count) {
        1 => try allocator.dupe(u8, &fixture.buildEthereumKeccakCalls(1)),
        4 => try allocator.dupe(u8, &fixture.buildEthereumKeccakCalls(4)),
        16 => try allocator.dupe(u8, &fixture.buildEthereumKeccakCalls(16)),
        else => return error.UnsupportedKeccakFixtureSize,
    };
    defer allocator.free(elf);
    var execution_timer = try std.time.Timer.start();
    var execution = try frontend.runner.runEthereumExtension(allocator, elf, call_count + 3);
    defer execution.deinit();
    const execution_ns = execution_timer.read();
    try std.testing.expectEqual(frontend.runner.CompletionReason.self_loop, execution.base.completion_reason);
    try std.testing.expectEqual(call_count + 2, execution.base.step_count);
    try std.testing.expectEqual(call_count, execution.keccakf_calls.len());
    try std.testing.expectEqual(@as(usize, 0), execution.signer_recovery_calls.len());

    const input_words = try public_data_mod.packInputWords(allocator, execution.base.input);
    defer allocator.free(input_words);
    const output_words = try allocator.alloc(public_data_mod.OutputWord, execution.base.output_words.len);
    defer allocator.free(output_words);
    for (output_words, execution.base.output_words) |*destination, source| {
        destination.* = .{ .addr = source.addr, .value = source.value, .clock = source.clock };
    }
    const public_data = public_data_mod.PublicData{
        .initial_pc = execution.base.initial_pc,
        .final_pc = execution.base.final_pc,
        .clock = @intCast(execution.base.step_count),
        .initial_regs = execution.base.initial_regs,
        .final_regs = execution.base.final_regs,
        .reg_last_clock = execution.base.state_chain_tracker.reg_last_clk,
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = try public_data_mod.completionFromRun(execution.base),
        .io_entries = .{
            .input_start = execution.base.input_start,
            .input_len = @intCast(execution.base.input.len),
            .input_words = input_words,
            .output_len = execution.base.output_len,
            .output_len_addr = execution.base.output_len_addr,
            .output_data_addr = execution.base.output_data_addr,
            .output_words = output_words,
        },
    };
    var recorder = stage_profile.Recorder.initWithOptions(allocator, @tagName(builtin.mode), "riscv-keccak-scaling", .{ .capture_tasks = false });
    defer recorder.deinit();
    var proof_timer = try std.time.Timer.start();
    var output = try prover.proveEthereumWithEngineUsingExecution(
        Engine,
        allocator,
        development_config,
        &execution.base.execution_trace,
        &execution.keccakf_calls,
        &execution.keccakf_execution_rows,
        &execution.signer_recovery_calls,
        &execution.signer_recovery_execution_rows,
        &execution.base.state_chain_tracker,
        &execution.base.rw_memory,
        &recorder,
        public_data,
        .{ .cpu = .{ .worker_count = 1, .host_byte_budget = std.math.maxInt(usize), .contention_policy = .strict } },
    );
    defer output.deinit(allocator);
    const prove_ns = proof_timer.read();
    try output.extension.validate(&output.statement);
    try output.extension_claim.validate(&output.extension);
    try std.testing.expectEqual(@as(u32, @intCast(call_count)), output.extension.counts.keccak_calls);
    try std.testing.expectEqual(@as(u32, 0), output.extension.counts.signer_calls);
    const keccak = output.extension.components[0];
    std.debug.print("RISCV_KECCAK_SHAPE calls={d} log_size={d} rows={d} preprocessed_columns={d} main_columns={d} interaction_columns={d}\n", .{
        call_count, keccak.log_size, keccak.n_rows, keccak.preprocessed_columns, keccak.main_columns, keccak.interaction_columns,
    });
    var profile = try recorder.snapshot(allocator);
    defer profile.deinit(allocator);
    printStages(call_count, profile.stages, 0);

    var encode_timer = try std.time.Timer.start();
    const bytes = try artifact.encodeAlloc(publication_allocator, .{
        .pcs_config = development_config,
        .statement = &output.statement,
        .extension = &output.extension,
        .base_claim = output.base_claim,
        .extension_claim = &output.extension_claim,
        .proof = &output.proof,
    });
    var sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &sha256, .{});
    return .{ .bytes = bytes, .sha256 = sha256, .execution_ns = execution_ns, .prove_ns = prove_ns, .encode_ns = encode_timer.read() };
}

fn freshlyVerify(allocator: std.mem.Allocator, bytes: []const u8, call_count: usize) !void {
    var decoded = try artifact.decodeAllocForConfig(allocator, bytes, development_config, .{});
    var moved = false;
    defer if (moved) decoded.deinitAfterProofMoved(allocator) else decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u32, @intCast(call_count)), decoded.extension.counts.keccak_calls);
    try std.testing.expectEqual(@as(u32, 0), decoded.extension.counts.signer_calls);
    try std.testing.expectEqual(@as(u32, @intCast(call_count)), decoded.extension.counts.external_retirements);
    try std.testing.expectEqual(@as(usize, 14), decoded.extension.components.len);
    moved = true; // The production verifier consumes the proof on all paths.
    try prover.verifyEthereumWithEngine(Engine, allocator, development_config, decoded.statement, decoded.extension, decoded.proof, decoded.base_claim, &decoded.extension_claim);
}

fn printStages(call_count: usize, stages: []const stage_profile.StageNode, depth: usize) void {
    for (stages) |stage| {
        std.debug.print("RISCV_KECCAK_STAGE calls={d} depth={d} id={s} seconds={d:.9}\n", .{ call_count, depth, stage.id, stage.seconds });
        if (stage.children) |children| printStages(call_count, children, depth + 1);
    }
}
