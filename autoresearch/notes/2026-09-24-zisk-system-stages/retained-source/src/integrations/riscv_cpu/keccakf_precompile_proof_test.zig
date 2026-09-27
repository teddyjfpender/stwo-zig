//! CPU instantiation of the backend-generic typed Keccak-f proof harness.

const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const proof_harness = @import("keccakf_proof_harness");

const Engine = frontend.prover_mod.ProverEngineForBackend(CpuBackend);

test "Keccak-f typed shard and lookup tables prove and independently verify" {
    _ = try proof_harness.run(Engine, std.heap.smp_allocator);
}

test "Keccak-f BLAKE3 canonical system benchmark" {
    const core = @import("stwo_core");
    const suite = core.proof_suites.Blake3;
    const Blake3Engine = @import("stwo_prover_engine").engine.ProverEngine(
        CpuBackend,
        suite.Hasher,
        suite.MerkleChannel,
        suite.Channel,
    );
    const pools = @import("stwo_prover_engine").work_pool;
    const workers = blk: {
        const raw = std.process.getEnvVarOwned(std.heap.page_allocator, "STWO_RISCV_SYSTEM_BENCH_WORKERS") catch break :blk @as(usize, 16);
        defer std.heap.page_allocator.free(raw);
        break :blk try std.fmt.parseInt(usize, raw, 10);
    };
    var pool: pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = std.heap.smp_allocator });
    defer pool.deinit();
    var binding = try pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    std.debug.print("Keccak-f BLAKE3 system profile: queries=70 pow=26 workers={d}\n", .{pool.workerCount()});
    _ = try proof_harness.runWithConfig(Blake3Engine, std.heap.smp_allocator, .{
        .pow_bits = 26,
        .fri_config = try core.fri.FriConfig.init(0, 1, 70),
    });
}
