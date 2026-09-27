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
pub fn execute(comptime Engine: type, comptime metal: bool, comptime ethereum: bool, a: std.mem.Allocator, elf: []const u8, input: []const u8, config: stwo.core.pcs.PcsConfig) !Result {
    const Backend = Engine.Backend;
    const Artifact = if (ethereum) prover.blake3_ethereum_artifact else prover.blake3_execution_artifact;
    const Api = if (ethereum) prover.blake3_ethereum_proof.ForBackend(Backend) else prover.blake3_execution.ForBackend(Backend);
    var timer = try std.time.Timer.start();
    try runner.elf_loader.validateReleaseAbiForProfile(elf, if (ethereum) .rv32im_zkvm_ethereum_v1 else .rv32im_zkvm_v1);
    var run = if (ethereum) try runner.runEthereumExtensionWithInput(a, elf, input, prover.MAX_EXECUTION_STEPS) else try runner.runWithInput(a, elf, input, prover.MAX_EXECUTION_STEPS);
    var run_alive = true;
    defer if (run_alive) run.deinit();
    const base_run = if (ethereum) &run.base else &run;
    try prover.admitRunForProving(base_run);
    const steps = base_run.step_count;
    const execution_end = timer.read();
    var owner = if (ethereum) try prover.blake3_ethereum_witness.Owner.initRun(a, &run) else try prover.blake3_segment_execution.Owner.initRun(a, &run);
    var owner_alive = true;
    defer if (owner_alive) owner.deinit();
    run.deinit();
    run_alive = false;
    const witness_end = timer.read();
    const admission = try owner.admission();
    const prepared = if (ethereum)
        try Api.PreparedVerifier.init(a, &owner.native.statement, owner.statement, admission, config)
    else
        try Api.PreparedVerifier.init(a, &owner.native.statement, admission, config);
    var prepared_alive = true;
    defer if (prepared_alive) prepared.deinit();
    const admission_end = timer.read();
    const telemetry_before = if (metal) try Engine.telemetrySnapshot() else {};
    var result = if (ethereum)
        try Api.prove(a, &owner, prepared, prepared.id, @import("stwo_prover_engine").work_pool.getGlobalPool() orelse return error.ProofPoolUnavailable)
    else
        try Api.prove(a, owner.native, owner.hashes, admission, config);
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
