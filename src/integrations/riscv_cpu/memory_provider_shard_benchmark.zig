//! Explicit high-memory command boundary for one research log18 provider proof.
//!
//! Merely building this executable runs nothing.  Execution requires the exact
//! opt-in flag below; the build step intentionally installs it without adding
//! a run artifact.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const riscv_cpu = @import("stwo_riscv_cpu_integration");
const core = @import("stwo_core");
const shard_planner = @import("stwo_prover_engine").pcs.residency_shard_plan;

const harness = frontend.testing.narrow_memory_provider_proof_harness;
const authority = frontend.testing.narrow_memory_provider_shard_authority;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const poseidon2 = frontend.air.memory_commitment.poseidon2;
const retained = riscv_cpu.ethereum_poseidon_provider_hpc_benchmark_v1;
const raw_pair = riscv_cpu.ethereum_poseidon_provider_raw_pair_benchmark_v1;
const raw_batch = riscv_cpu.ethereum_poseidon_provider_raw_batch_benchmark_v2;
const topology_sweep = riscv_cpu.ethereum_poseidon_provider_topology_sweep_v1;
const retention_sweep = riscv_cpu.ethereum_poseidon_provider_retention_sweep_v1;
const retained_batch = riscv_cpu.ethereum_poseidon_provider_retained_batch_v3;

pub const benchmark_log_size: u32 = 18;
pub const benchmark_call_count: usize = @as(usize, 1) << benchmark_log_size;
pub const execute_flag = "--run-research-log18";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len >= 2 and std.mem.eql(u8, args[1], retained.execute_flag)) {
        try retained.run(allocator, args[2..]);
        return;
    }
    if (args.len >= 2 and std.mem.eql(u8, args[1], raw_pair.execute_flag)) {
        try raw_pair.run(allocator, args[2..]);
        return;
    }
    if (args.len >= 2 and std.mem.eql(u8, args[1], raw_batch.execute_flag)) {
        try raw_batch.run(allocator, args[2..]);
        return;
    }
    if (args.len >= 2 and std.mem.eql(u8, args[1], topology_sweep.execute_flag)) {
        try topology_sweep.run(allocator, args[2..]);
        return;
    }
    if (args.len >= 2 and std.mem.eql(u8, args[1], retention_sweep.execute_flag)) {
        try retention_sweep.run(allocator, args[2..]);
        return;
    }
    if (args.len >= 2 and std.mem.eql(u8, args[1], retained_batch.execute_flag)) {
        try retained_batch.run(allocator, args[2..]);
        return;
    }
    if (args.len != 2 or !std.mem.eql(u8, args[1], execute_flag)) {
        std.debug.print(
            "research-only; no proof launched. Explicit execution: {s} {s}\n",
            .{ args[0], execute_flag },
        );
        return error.ExplicitResearchRunFlagRequired;
    }

    const config = core.pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try core.fri.FriConfig.init(0, 1, 3),
    };
    const calls = try allocator.alloc(poseidon2_air.Call, benchmark_call_count);
    defer allocator.free(calls);
    for (calls, 0..) |*call, index| {
        const left: u32 = @intCast(index + 1);
        const right: u32 = @intCast(index + 2);
        call.* = poseidon2_air.Call.narrowWithOutput(
            left,
            right,
            poseidon2.hashPair(left, right),
        );
    }
    var plan = try authority.ProviderShardPlanV1.create(
        allocator,
        [_]u8{0x18} ** 32,
        calls,
        shard_planner.Request{
            .logical_row_count = benchmark_call_count,
            .column_count = authority.main_column_count,
            .min_shard_log_size = benchmark_log_size,
            .max_shard_log_size = benchmark_log_size,
            .log_blowup_factor = config.fri_config.log_blowup_factor,
            .retention_policy = .never,
            .host_byte_budget = 16 * 1024 * 1024 * 1024,
            .reserved_host_bytes = 4 * 1024 * 1024 * 1024,
            .requested_parallel_shards = 1,
        },
    );
    defer plan.deinit(allocator);

    var prove_timer = try std.time.Timer.start();
    var output = try harness.proveShard(
        riscv_cpu.CpuProverEngine,
        allocator,
        config,
        &plan,
        calls,
        0,
        .never,
        null,
    );
    const prove_ns = prove_timer.read();
    var proof_owned = true;
    defer if (proof_owned) output.proof.deinit(allocator);
    const proof_size_estimate = output.proof.sizeEstimate();

    var verify_timer = try std.time.Timer.start();
    proof_owned = false;
    try harness.verifyShard(
        riscv_cpu.CpuProverEngine,
        allocator,
        config,
        &plan,
        calls,
        output.statement,
        output.proof,
    );
    const verify_ns = verify_timer.read();
    try output.owner_telemetry.validate();
    std.debug.print(
        "RESEARCH_ONLY production=false log={d} calls={d} proof_size_estimate={d} " ++
            "prove_ns={d} verify_ns={d} retained_coefficients={d}\n",
        .{
            benchmark_log_size,
            benchmark_call_count,
            proof_size_estimate,
            prove_ns,
            verify_ns,
            output.owner_telemetry.retained_coefficient_columns,
        },
    );
}

comptime {
    if (!harness.RESEARCH_ONLY or harness.ACTIVATES_PRODUCTION_PROOF)
        @compileError("log18 command must remain research-only");
}
