//! Experimental CSP workload runner: real RV32IM execution, secure proof and CPU verification.
//! This is separate from the release-gated CSP product registry.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const prover = frontend.prover_mod;
const bend = @import("stwo_bend_backend");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const B = bend.BendBackendWithHost(.{ .executable = @import("config").executable, .threads = @import("config").bend_threads, .workers = @import("config").bend_workers, .shadow_check = @import("config").shadow_check, .persistent = true, .cache_bytes = 64 * 1024 * 1024 }, Cpu);
const pd = frontend.air.public_data;
const postcard = @import("postcard");

pub fn main() !void {
    const a = std.heap.page_allocator;
    defer bend.runtime.shutdown();
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 5) return error.ExpectedBackendElfInputProofPath;
    if (std.mem.eql(u8, args[1], "bend")) return run(B, "bend", a, args);
    if (std.mem.eql(u8, args[1], "cpu")) return run(Cpu, "cpu", a, args);
    return error.InvalidBackend;
}
fn run(comptime Backend: type, comptime name: []const u8, a: std.mem.Allocator, args: []const []const u8) !void {
    const Engine = prover.ProverEngineForBackend(Backend);
    const CpuEngine = prover.ProverEngineForBackend(Cpu);
    const elf = try std.fs.cwd().readFileAlloc(a, args[2], 32 * 1024 * 1024);
    defer a.free(elf);
    const input = try std.fs.cwd().readFileAlloc(a, args[3], 32 * 1024 * 1024);
    defer a.free(input);
    var timer = try std.time.Timer.start();
    var result = try frontend.runner.runWithInput(a, elf, input, 10_000_000);
    defer result.deinit();
    try prover.admitRunForProving(&result);
    const execution_ns = timer.lap();
    const input_words = try pd.packInputWords(a, result.input);
    defer a.free(input_words);
    const output_words = try a.alloc(pd.OutputWord, result.output_words.len);
    defer a.free(output_words);
    for (result.output_words, output_words) |word, *out| out.* = .{ .addr = word.addr, .value = word.value, .clock = word.clock };
    const public_data = prover.PublicData{
        .initial_pc = result.initial_pc,
        .final_pc = result.final_pc,
        .clock = @intCast(result.step_count),
        .initial_regs = result.initial_regs,
        .final_regs = result.final_regs,
        .reg_last_clock = result.state_chain_tracker.reg_last_clk,
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = try pd.completionFromRun(result),
        .io_entries = .{ .input_start = result.input_start, .input_len = @intCast(result.input.len), .input_words = input_words, .output_len = result.output_len, .output_len_addr = result.output_len_addr, .output_data_addr = result.output_data_addr, .output_words = output_words },
    };
    var channel = Engine.Channel{};
    var output = try prover.proveRiscVWithEngineAndPublicDataUsingChannel(Engine, a, prover.SECURE_PCS_CONFIG, &result.execution_trace, &result.state_chain_tracker, &result.rw_memory, null, public_data, &channel);
    defer output.deinitAfterProofMoved(a);
    var owned = true;
    defer if (owned) output.proof.deinit(a);
    const proving_ns = timer.lap();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    try postcard.serializeProof(prover.Hasher, bytes.writer(a), output.proof);
    const serialization_ns = timer.lap();
    // Verify the Bend proof through the ordinary CPU engine, never a Bend verifier.
    var verifier_channel = CpuEngine.Channel{};
    owned = false;
    try prover.verifyRiscVWithEngineUsingChannel(CpuEngine, a, prover.SECURE_PCS_CONFIG, output.statement, output.proof, output.interaction_claim, &verifier_channel);
    const verification_ns = timer.lap();
    if (!std.mem.eql(u8, &channel.digestBytes(), &verifier_channel.digestBytes()) or channel.n_draws != verifier_channel.n_draws) return error.TranscriptMismatch;
    try std.fs.cwd().writeFile(.{ .sub_path = args[4], .data = bytes.items });
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes.items, &digest, .{});
    const hash = std.fmt.bytesToHex(digest, .lower);
    const report = try std.json.Stringify.valueAlloc(a, .{
        .backend = name,
        .parallelism = .{
            .zig_workers = if (@import("stwo_prover_engine").work_pool.getGlobalPool()) |pool| pool.workerCount() else 1,
            .bend_processes = if (Backend == Cpu) @as(u8, 0) else @import("config").bend_workers,
            .bend_threads_per_process = if (Backend == Cpu) @as(u8, 0) else @import("config").bend_threads,
        },
        .verified_by = "cpu",
        .bend_shadow_check = Backend != Cpu and @import("config").shadow_check,
        .secure_pcs = prover.SECURE_PCS_CONFIG,
        .cycles = result.step_count,
        .execution_ns = execution_ns,
        .proving_with_witness_ns = proving_ns,
        .compute_ns = execution_ns + proving_ns,
        .serialization_ns = serialization_ns,
        .verification_ns = verification_ns,
        .proof_bytes = bytes.items.len,
        .proof_sha256 = hash[0..],
        .bend = bend.runtime.snapshot(),
        .public_values = .{ .schema = "riscv-public-values-diagnostic-v1", .public_data = .{ .io_entries = public_data.io_entries } },
        .host_services = "Merkle, composition evaluation, interaction generation, batch inversion, transcript and verifier",
    }, .{});
    defer a.free(report);
    try std.fs.File.stdout().writeAll(report);
    try std.fs.File.stdout().writeAll("\n");
}
