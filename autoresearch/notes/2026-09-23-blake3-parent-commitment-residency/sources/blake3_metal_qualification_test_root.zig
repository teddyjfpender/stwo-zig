//! Explicit device qualification of full-width Ethereum commitments and artifacts.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Metal = @import("stwo_metal_backend").MetalCommitBackend;
const suite = core.proof_suites.Blake3;
const Engine = engine.engine.ProverEngine(Metal, suite.Hasher, suite.MerkleChannel, suite.Channel);
const api = @import("prover/blake3_ethereum_proof.zig");
test "Metal full-width BLAKE3 Ethereum canonical leaf independently verifies on CPU" {
    try checked(false);
}
test "Metal full-width BLAKE3 Ethereum canonical recursive parent independently verifies on CPU" {
    try checked(true);
}
fn checked(comptime recurse: bool) !void {
    check(recurse) catch |err| {
        std.debug.print("BLAKE3_ETHEREUM_METAL_FAILED recursive={any} error={s}\n", .{ recurse, @errorName(err) });
        return err;
    };
}
fn check(comptime recurse: bool) !void {
    const a = std.testing.allocator;
    const mode = try std.process.getEnvVarOwned(a, "STWO_BLAKE3_CSP_RUNTIME");
    defer a.free(mode);
    try @import("blake3_runtime").initialize(Engine, a, mode);
    defer Metal.shutdown() catch unreachable;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    var binding_alive = true;
    defer if (binding_alive) binding.deinit();
    const elf = @import("runner/guest_precompile/test_elf.zig").buildEthereumWithCompletion(.self_loop);
    var session = try @import("runner/mod.zig").EthereumExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment = try session.startSegment(100);
    defer segment.deinit();
    var owner = try @import("prover/blake3_ethereum_witness.zig").Owner.initSegment(a, &segment);
    var owner_alive = true;
    defer if (owner_alive) owner.deinit();
    const config = @import("recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG;
    const cpu = try api.ForBackend(Cpu).PreparedVerifier.init(a, &owner.native.statement, owner.statement, try owner.admission(), config);
    defer cpu.deinit();
    const gpu = try api.ForBackend(Metal).PreparedVerifier.init(a, &owner.native.statement, owner.statement, try owner.admission(), config);
    defer gpu.deinit();
    try std.testing.expectEqualSlices(u8, &cpu.root, &gpu.root);
    try std.testing.expectEqualSlices(u8, &cpu.id, &gpu.id);
    const before = try Engine.telemetrySnapshot();
    var proved = try api.ForBackend(Metal).prove(a, &owner, gpu, cpu.id, &pool);
    var proof_alive = true;
    defer if (proof_alive) proved.proof.deinit(a);
    const raw = try api.codec.encode(a, &proved.proof, cpu, cpu.id);
    defer a.free(raw);
    proved.proof.deinit(a);
    proof_alive = false;
    owner.deinit();
    owner_alive = false;
    const received = try api.codec.decode(a, raw, cpu, cpu.id);
    var captured = try api.ForBackend(Cpu).verifyCaptureOwned(a, received, cpu, cpu.id);
    defer captured.deinit();
    try captured.validate(cpu, cpu.id);
    try std.testing.expectEqualSlices(u8, &proved.transcript_digest, &captured.final_channel.digestBytes());
    try std.testing.expectEqual(@as(usize, 70), captured.proof.queries.raw.len);
    const delta = (try Engine.telemetrySnapshot()).delta(before);
    try delta.requireMetalDispatch();
    std.debug.print("BLAKE3_ETHEREUM_METAL verified_on_cpu=true preprocessing_equal=true signer=1 keccak=1 queries=70 pow_bits=26 artifact_bytes={d} dispatches={d} fallbacks={d} runtime={s} witness_released=true\n", .{ raw.len, delta.counters.metalDispatchTotal(), delta.counters.cpuFallbackTotal(), mode });
    if (recurse) {
        binding.deinit();
        binding_alive = false;
        try checkParent(a, cpu, &captured, cpu.id, &pool);
    }
}

fn checkParent(a: std.mem.Allocator, admitted: anytype, captured: anytype, expected: [32]u8, pool: *engine.work_pool.WorkPool) !void {
    const parent = @import("recursion/blake3_execution_parent_proof.zig");
    std.debug.print("BLAKE3_ETHEREUM_METAL_PARENT_STAGE stage=prepare_start\n", .{});
    var prepared = parent.preparation.prepare(a, admitted, captured, expected, 2) catch |err| {
        std.debug.print("BLAKE3_ETHEREUM_METAL_PARENT_STAGE stage=prepare_failed error={s}\n", .{@errorName(err)});
        return err;
    };
    var prepared_alive = true;
    defer if (prepared_alive) prepared.deinit();
    std.debug.print("BLAKE3_ETHEREUM_METAL_PARENT_STAGE stage=prepared retained_bytes={d}\n", .{try prepared.rows.retainedBytes()});
    const key = try parent.ForBackend(Cpu).deriveKeyWithProfileAndPool(a, &prepared, .csp_q70_pow26, pool);
    const parent_id = try key.identity();
    const admission = try parent.protocol.Admission.init(key, parent_id);
    std.debug.print("BLAKE3_ETHEREUM_METAL_PARENT_STAGE stage=key_admitted\n", .{});
    const Worker = parent.pipeline.ForBackend(Metal).Worker;
    const worker = try Worker.init(a, &prepared.rows, admission, .{ .worker_count = 4, .host_byte_limit = 36 * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 });
    std.debug.print("BLAKE3_ETHEREUM_METAL_PARENT_STAGE stage=worker_ready\n", .{});
    var worker_alive = true;
    defer if (worker_alive) worker.deinit();
    // Require device work in proving itself, excluding preprocessing setup.
    const before = try Engine.telemetrySnapshot();
    var proof = worker.prove(&prepared.rows) catch |err| {
        const failed_usage = worker.budget.snapshot();
        if (worker.workspace.core_diagnostic) |diagnostic| {
            std.debug.print("BLAKE3_PARENT_CORE_FAILURE phase={s} composition_subphase={s} cause={s}\n", .{ @tagName(diagnostic.phase), if (diagnostic.composition_subphase) |subphase| @tagName(subphase) else "none", @errorName(diagnostic.cause) });
        }
        std.debug.print("BLAKE3_PARENT_WORKER_FAILURE phase={s} error={s} peak_bytes={d} limit_bytes={d}\n", .{ @tagName(worker.workspace.phase), @errorName(err), failed_usage.peak_live_bytes, failed_usage.limit });
        return err;
    };
    defer proof.deinit();
    const usage = worker.budget.snapshot();
    const delta = (try Engine.telemetrySnapshot()).delta(before);
    try delta.requireMetalDispatch();
    worker.deinit();
    worker_alive = false;
    prepared.deinit();
    prepared_alive = false;
    const bytes = try parent.codec.encode(a, &proof, &admission);
    defer a.free(bytes);
    var decoded = try parent.codec.decode(a, bytes, &admission);
    defer decoded.deinit();
    var verified = try parent.verify(&decoded, &admission);
    defer verified.deinit();
    try verified.validate(&admission, parent_id);
    try std.testing.expectEqual(@as(usize, 70), verified.capture.queries.raw.len);
    std.debug.print("BLAKE3_ETHEREUM_METAL_PARENT verified_on_cpu=true queries=70 pow_bits=26 artifact_bytes={d} worker_peak_bytes={d} dispatches={d} fallbacks={d} worker_and_rows_released=true\n", .{ bytes.len, usage.peak_live_bytes, delta.counters.metalDispatchTotal(), delta.counters.cpuFallbackTotal() });
}
