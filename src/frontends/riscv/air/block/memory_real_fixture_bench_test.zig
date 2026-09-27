//! Isolated CPU qualification of the actual three-segment fixture's sorted
//! memory rows. This is not a complete block proof: execution and initial
//! providers are not yet closed against this separately proved component.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const runner = @import("../../runner/mod.zig");
const replay_mod = @import("../../prover/block_memory_replay.zig");
const instance = @import("memory_instance.zig");
const trace_mod = @import("memory_component_trace.zig");
const proof_mod = @import("../../prover/block_memory_proof_v2.zig");
const manifest = @import("../../prover/block_commitment_manifest.zig");
const source_seal = @import("../../prover/block_memory_source_seal_v2.zig");

const fixture = "autoresearch/notes/2026-09-24-ethereum-block-delivery/exact-three-segment-v1/";
const assets = "autoresearch/notes/2026-09-24-recursive-memory/";
const expected_rows: u64 = 51_929;

test "real three-segment sorted memory proves q70 pow26 and fresh verifies" {
    const backing = std.testing.allocator;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(backing, 8 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    const elf = try std.fs.cwd().readFileAlloc(a, assets ++ "eth-auth-stwo-expanded.elf", 32 * 1024 * 1024);
    defer a.free(elf);
    const input = try std.fs.cwd().readFileAlloc(a, assets ++ "fixtures/batch-1.input", 64 * 1024 * 1024);
    defer a.free(input);
    const oracle = try std.fs.cwd().readFileAlloc(a, assets ++ "fixtures/batch-1.expected", 1024 * 1024);
    defer a.free(oracle);
    const schedule_bytes = try std.fs.cwd().readFileAlloc(a, fixture ++ "schedule.json", 1024);
    defer a.free(schedule_bytes);
    var schedule = try std.json.parseFromSlice([]u32, a, schedule_bytes, .{});
    defer schedule.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 7000, 7000, 7635 }, schedule.value);

    var timer = try std.time.Timer.start();
    var session = try runner.EthereumExecutionSession.init(a, elf, .{
        .input = input,
        .strict_completion = true,
        .stop_on_halt_flag = true,
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var current = try session.startSegment(schedule.value[0]);
    var current_live = true;
    defer if (current_live) current.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var replay = try replay_mod.Replay.initFromSnapshot(a, tmp.dir, current.base.entry_cpu.regs, &current.base.rw_memory, 1 << 18);
    defer replay.deinit();
    for (schedule.value, 0..) |cycles, index| {
        try std.testing.expectEqual(@as(u64, cycles), current.base.cycle_count);
        try std.testing.expectEqual(@as(u32, @intCast(index)), current.base.segment_index);
        if (index + 1 == schedule.value.len) {
            try std.testing.expect(current.base.isComplete());
            try std.testing.expectEqualSlices(u8, oracle, current.base.output orelse return error.MissingOutput);
        }
        try replay.appendResult(&current.base);
        const next = current.base.continuation;
        current.deinit();
        current_live = false;
        if (index + 1 < schedule.value.len) {
            current = try session.resumeSegment(next orelse return error.MissingContinuation, schedule.value[index + 1]);
            current_live = true;
        }
    }
    var sorted = try replay.finish();
    defer sorted.deinit();
    var partitioner = try instance.Partitioner.init(&sorted, expected_rows, 1 << 16);
    var trace = (try trace_mod.Trace.nextFromPartitioner(a, &partitioner, 16)).?;
    defer trace.deinit();
    try std.testing.expect((try trace_mod.Trace.nextFromPartitioner(a, &partitioner, 16)) == null);
    try std.testing.expectEqual(@as(u32, @intCast(expected_rows)), trace.claim.rows);
    const replay_ns = timer.lap();

    const api = proof_mod.ForBackend(@import("stwo_cpu_backend").CpuBackend);
    const config = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.FriConfig.init(0, 1, 70) };
    var first_round = try api.commitFirstRound(a, &trace, config);
    defer first_round.deinit(a);
    const first_round_ns = timer.lap();
    const sealed = try source_seal.SourceSeal.initWithMemoryCount(
        manifest.Sealed{ .digest = @splat(37), .instance_count = 3 },
        0,
        @splat(41),
        1,
    );
    const proof = try api.proveExperimental(a, &first_round, &trace, sealed, 0, first_round.roots);
    const prove_ns = timer.lap();
    var counter = ProofByteCounter{};
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &counter, proof.stark);
    const receipt = try api.verifyExperimentalOwned(a, proof, trace.claim, sealed, 0, first_round.roots, config);
    const verify_ns = timer.lap();
    try std.testing.expectEqual(@as(u32, 0), receipt.relation.instance_index);
    std.debug.print(
        "BLOCK_MEMORY_REAL_FIXTURE rows={d} log_size={d} replay_ns={d} first_round_ns={d} prove_ns={d} verify_ns={d} proof_bytes={d} tracked_peak_bytes={d}\n",
        .{ expected_rows, trace.claim.log_size, replay_ns, first_round_ns, prove_ns, verify_ns, counter.bytes_written, budget.snapshot().peak_live_bytes },
    );
}

const ProofByteCounter = struct {
    bytes_written: usize = 0,
    pub fn writeAll(self: *ProofByteCounter, bytes: []const u8) !void {
        self.bytes_written += bytes.len;
    }
    pub fn writeByte(self: *ProofByteCounter, _: u8) !void {
        self.bytes_written += 1;
    }
};
