//! Full-width base execution transaction. The serialized artifact is freshly
//! verified after witness destruction before it can be published.
const std = @import("std");
const stwo = @import("stwo");
const prover = stwo.frontends.riscv.prover_mod;
const runner = stwo.frontends.riscv.runner;
const artifact = prover.blake3_execution_artifact;
pub const Timing = struct {
    execution_ns: u64,
    witness_ns: u64,
    admission_ns: u64,
    proving_ns: u64,
    artifact_encoding_ns: u64,
    fresh_verification_ns: u64,
    total_ns: u64,
};
pub const DeviceCounts = struct { dispatches: u64 = 0, cpu_fallbacks: u64 = 0 };
pub const Result = struct {
    public: prover.blake3_verified_public,
    device: DeviceCounts,
    artifact: artifact.Encoded,
    transcript: [32]u8,
    steps: usize,
    timing: Timing,
    pub fn deinit(self: *Result, a: std.mem.Allocator) void {
        a.free(self.artifact.bytes);
        self.* = undefined;
    }
};
pub fn execute(comptime Engine: type, comptime metal: bool, comptime profile: stwo.frontends.riscv.isa.execution_profile.ExecutionProfile, a: std.mem.Allocator, elf: []const u8, input: []const u8, config: stwo.core.pcs.PcsConfig, budget: ?*@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget) !Result {
    const ethereum = profile == .rv32im_zkvm_ethereum_v1;
    const extended = profile != .rv32im_zkvm_v1;
    const Backend = Engine.Backend;
    const Artifact = prover.blake3_profile_artifact.ForExecutionProfile(profile);
    const Api = if (ethereum) prover.blake3_ethereum_proof.ForBackend(Backend) else if (extended) prover.blake3_poseidon_proof.ForBackend(Backend) else prover.blake3_execution.ForBackend(Backend);
    var timer = try std.time.Timer.start();
    try runner.elf_loader.validateReleaseAbiForProfile(elf, profile);
    var run = if (ethereum) try runner.runEthereumExtensionWithInput(a, elf, input, prover.MAX_EXECUTION_STEPS) else if (extended) try runner.runPoseidon2ExtensionWithInput(a, elf, input, prover.MAX_EXECUTION_STEPS) else try runner.runWithInput(a, elf, input, prover.MAX_EXECUTION_STEPS);
    var run_alive = true;
    defer if (run_alive) run.deinit();
    const base_run = if (extended) &run.base else &run;
    try prover.admitRunForProving(base_run);
    const steps = base_run.step_count;
    const execution_end = timer.read();
    var owner = if (ethereum) try prover.blake3_ethereum_witness.Owner.initCompactRun(a, &run) else if (extended) try prover.blake3_poseidon_witness.Owner.initCompactRun(a, &run) else try prover.blake3_segment_execution.Owner.initCompactRun(a, &run);
    var owner_alive = true;
    defer if (owner_alive) owner.deinit();
    run.deinit();
    run_alive = false;
    const witness_end = timer.read();
    if (budget) |limit| {
        const measured = limit.snapshot();
        std.debug.print("full-width witness: steps={d} hash_counts={any} hash_logs={any} live={d} peak={d}\n", .{ steps, owner.hashes.counts, owner.hashes.logs, measured.live_bytes, measured.peak_live_bytes });
    }
    const admission = try owner.admission();
    if (budget != null) std.debug.print("full-width shared-path geometry [program, initial, final]: {any}\n", .{try prover.blake3_commitment_sharing.measure(a, admission)});
    const prepared = if (extended)
        try Api.PreparedVerifier.initCompact(a, &owner.native.statement, owner.statement, admission, config, owner.native.compact_ranges.?.plan)
    else
        try Api.PreparedVerifier.initCompact(a, &owner.native.statement, admission, config, owner.native.compact_ranges.?.plan);
    var prepared_alive = true;
    defer if (prepared_alive) prepared.deinit();
    const admission_end = timer.read();
    if (budget) |limit| {
        const measured = limit.snapshot();
        std.debug.print("full-width admission: live={d} peak={d}\n", .{ measured.live_bytes, measured.peak_live_bytes });
    }
    const telemetry_before = if (metal) try Engine.telemetrySnapshot() else {};
    var result = if (extended)
        try Api.prove(a, &owner, prepared, prepared.id, @import("stwo_prover_engine").work_pool.getGlobalPool() orelse return error.ProofPoolUnavailable)
    else
        try Api.proveCompact(a, owner.native, owner.hashes, admission, config);
    var proof_alive = true;
    defer if (proof_alive) result.proof.deinit(a);
    const proving_end = timer.read();
    var device: DeviceCounts = .{};
    if (metal) {
        const delta = (try Engine.telemetrySnapshot()).delta(telemetry_before);
        try delta.requireMetalDispatch();
        device = .{ .dispatches = delta.counters.metalDispatchTotal(), .cpu_fallbacks = delta.counters.cpuFallbackTotal() };
    }
    const encoded = try Artifact.encode(a, &result.proof, prepared, elf, input, .{});
    prepared.deinit();
    prepared_alive = false;
    errdefer a.free(encoded.bytes);
    result.proof.deinit(a);
    proof_alive = false;
    owner.deinit();
    owner_alive = false;
    const artifact_end = timer.read();
    const verified = try Artifact.ForBackend(@import("stwo_cpu_backend").CpuBackend).verifyPublic(a, encoded.bytes, encoded.statement_id, config, elf, input, .{});
    const transcript = verified.transcript;
    if (!std.mem.eql(u8, &transcript, &result.transcript_digest)) return error.TranscriptStateDigestMismatch;
    const end = timer.read();
    return .{ .public = verified, .device = device, .artifact = .{ .bytes = encoded.bytes, .statement_id = encoded.statement_id }, .transcript = transcript, .steps = steps, .timing = .{
        .execution_ns = execution_end,
        .witness_ns = witness_end - execution_end,
        .admission_ns = admission_end - witness_end,
        .proving_ns = proving_end - admission_end,
        .artifact_encoding_ns = artifact_end - proving_end,
        .fresh_verification_ns = end - artifact_end,
        .total_ns = end,
    } };
}
