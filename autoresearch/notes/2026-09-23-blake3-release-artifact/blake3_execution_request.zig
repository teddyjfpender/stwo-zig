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
    proving_ns: u64,
    artifact_encoding_ns: u64,
    fresh_verification_ns: u64,
    total_ns: u64,
};
pub const DeviceCounts = struct { dispatches: u64 = 0, cpu_fallbacks: u64 = 0 };
pub const Result = struct {
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
pub fn execute(comptime Engine: type, comptime metal: bool, a: std.mem.Allocator, elf: []const u8, input: []const u8, config: stwo.core.pcs.PcsConfig) !Result {
    const Backend = Engine.Backend;
    const Api = prover.blake3_execution.ForBackend(Backend);
    var timer = try std.time.Timer.start();
    try runner.elf_loader.validateReleaseAbi(elf);
    var run = try runner.runWithInput(a, elf, input, prover.MAX_EXECUTION_STEPS);
    var run_alive = true;
    defer if (run_alive) run.deinit();
    try prover.admitRunForProving(&run);
    const steps = run.step_count;
    const execution_end = timer.read();
    var owner = try prover.blake3_segment_execution.Owner.initRun(a, &run);
    var owner_alive = true;
    defer if (owner_alive) owner.deinit();
    run.deinit();
    run_alive = false;
    const witness_end = timer.read();
    const admission = try owner.admission();
    const telemetry_before = if (metal) try Engine.telemetrySnapshot() else {};
    var result = try Api.prove(a, owner.native, owner.hashes, admission, config);
    var proof_alive = true;
    defer if (proof_alive) result.proof.deinit(a);
    const proving_end = timer.read();
    var device: DeviceCounts = .{};
    if (metal) {
        const delta = (try Engine.telemetrySnapshot()).delta(telemetry_before);
        try delta.requireMetalDispatch();
        device = .{ .dispatches = delta.counters.metalDispatchTotal(), .cpu_fallbacks = delta.counters.cpuFallbackTotal() };
    }
    const encoded = blk: {
        const prepared = try Api.PreparedVerifier.init(a, &owner.native.statement, admission, config);
        defer prepared.deinit();
        break :blk try artifact.encode(a, &result.proof, prepared, elf, input, .{});
    };
    errdefer a.free(encoded.bytes);
    result.proof.deinit(a);
    proof_alive = false;
    owner.deinit();
    owner_alive = false;
    const artifact_end = timer.read();
    const transcript = try artifact.ForBackend(Backend).verify(a, encoded.bytes, encoded.statement_id, config, elf, input, .{});
    if (!std.mem.eql(u8, &transcript, &result.transcript_digest)) return error.TranscriptStateDigestMismatch;
    const end = timer.read();
    return .{ .device = device, .artifact = encoded, .transcript = transcript, .steps = steps, .timing = .{
        .execution_ns = execution_end,
        .witness_ns = witness_end - execution_end,
        .proving_ns = proving_end - witness_end,
        .artifact_encoding_ns = artifact_end - proving_end,
        .fresh_verification_ns = end - artifact_end,
        .total_ns = end,
    } };
}
