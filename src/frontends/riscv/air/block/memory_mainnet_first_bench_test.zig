//! Isolated first sorted-memory proof from the frozen 218-segment SHA
//! block fixture. The shared range table, execution bus, and initial-source
//! providers are intentionally outside this one-instance measurement.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const runner = @import("../../runner/mod.zig");
const replay_mod = @import("../../prover/block_memory_replay.zig");
const instance = @import("memory_instance.zig");
const trace_mod = @import("memory_component_trace.zig");
const proof_mod = @import("../../prover/block_memory_shared_instance_proof_v2.zig");
const counter_mod = @import("../lookups/tables/counter.zig");
const manifest = @import("../../prover/block_commitment_manifest.zig");
const source_seal = @import("../../prover/block_memory_source_seal_v2.zig");

const fixture = "autoresearch/notes/2026-09-24-ethereum-block-delivery/";
const expected_events: u64 = 356_303_914;
const Loaded = struct { trace: trace_mod.Trace, replay_ns: u64, segments: u32 };

fn loadFirst(a: std.mem.Allocator, instance_capacity: u32, log_size: u32) !Loaded {
    const elf = try std.fs.cwd().readFileAlloc(a, fixture ++ "ethereum-block-sha-default-v3.elf", 32 * 1024 * 1024);
    defer a.free(elf);
    const input = try std.fs.cwd().readFileAlloc(a, fixture ++ "fixture/stwo-runner-input-evm-hints.bin", 64 * 1024 * 1024);
    defer a.free(input);
    const oracle = try std.fs.cwd().readFileAlloc(a, fixture ++ "fixture/expected-output.bin", 1024 * 1024);
    defer a.free(oracle);
    const schedule_bytes = try std.fs.cwd().readFileAlloc(a, fixture ++ "exact-schedule-proposal-v1/schedule.json", 16 * 1024);
    defer a.free(schedule_bytes);
    var schedule = try std.json.parseFromSlice([]u32, a, schedule_bytes, .{});
    defer schedule.deinit();
    if (schedule.value.len != 218) return error.MainnetFixtureScheduleChanged;

    var timer = try std.time.Timer.start();
    var session = try runner.EthereumShaExecutionSession.init(a, elf, .{
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
        if (current.base.cycle_count != cycles or current.base.segment_index != index)
            return error.MainnetFixtureExecutionMismatch;
        if (index + 1 == schedule.value.len) {
            if (!current.base.isComplete() or !std.mem.eql(u8, oracle, current.base.output orelse return error.MissingOutput))
                return error.MainnetFixtureOutputMismatch;
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
    var partitioner = try instance.Partitioner.init(&sorted, expected_events, instance_capacity);
    const trace = (try trace_mod.Trace.nextFromPartitioner(a, &partitioner, log_size)) orelse return error.EmptyMainnetMemoryRoster;
    if (trace.claim.rows != instance_capacity or trace.claim.log_size != log_size or trace.claim.first_row != 0 or trace.claim.total_rows != expected_events)
        return error.MainnetMemoryRosterMismatch;
    return .{ .trace = trace, .replay_ns = timer.lap(), .segments = @intCast(schedule.value.len) };
}

test "mainnet first log20 sorted-memory request proves q70 pow26 and fresh verifies" {
    try benchFirst(20, 48);
}

test "mainnet first log21 sorted-memory request proves q70 pow26 and fresh verifies" {
    try benchFirst(21, 32);
}

test "mainnet first log22 sorted-memory request proves q70 pow26 and fresh verifies" {
    try benchFirst(22, 32);
}

fn benchFirst(log_size: u32, limit_gib: usize) !void {
    const backing = std.testing.allocator;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(backing, limit_gib * 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    const instance_capacity: u32 = @as(u32, 1) << @intCast(log_size);
    var loaded = try loadFirst(a, instance_capacity, log_size);
    defer loaded.trace.deinit();
    var timer = try std.time.Timer.start();
    const api = proof_mod.ForBackend(@import("stwo_cpu_backend").CpuBackend);
    const config = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.FriConfig.init(0, 1, 70) };
    var counter = try counter_mod.Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    var roots_only_counter = try counter_mod.Counter.init(a, .range_check_8_8);
    defer roots_only_counter.deinit(a);
    const roots_only = try api.commitFirstRoundRootsOnly(a, &loaded.trace, &roots_only_counter, 0, config);
    const roots_only_ns = timer.lap();
    const roots_only_peak_bytes = budget.snapshot().peak_live_bytes;
    var first = try api.commitFirstRound(a, &loaded.trace, &counter, 0, config);
    defer first.deinit(a);
    const first_round_ns = timer.lap();
    const first_round_peak_bytes = budget.snapshot().peak_live_bytes;
    try std.testing.expectEqualDeep(roots_only.roots, first.roots);
    try std.testing.expectEqualDeep(roots_only.snapshot, first.snapshot);
    try std.testing.expectEqualDeep(@import("memory_range_interaction_v2.zig").counterSnapshot(&roots_only_counter), @import("memory_range_interaction_v2.zig").counterSnapshot(&counter));
    // This is a one-instance isolated benchmark. Its source seal is coherent
    // for fresh verifier parity, but is not a complete bound block roster.
    const capacity_u64: u64 = instance_capacity;
    const memory_instances: u32 = @intCast((expected_events + capacity_u64 - 1) / capacity_u64);
    const sealed = try source_seal.SourceSeal.initWithMemoryCount(
        manifest.Sealed{ .digest = @splat(37), .instance_count = loaded.segments },
        0,
        @splat(41),
        memory_instances,
    );
    const proof = try api.prove(a, &first, &loaded.trace, sealed, 0, first.roots);
    const prove_ns = timer.lap();
    var counter_bytes = ProofByteCounter{};
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &counter_bytes, proof.stark);
    const verified = try api.verifyOwned(a, proof, loaded.trace.claim, sealed, 0, first.roots, config);
    const verify_ns = timer.lap();
    try std.testing.expectEqual(@as(u32, 0), verified.memory.relation.instance_index);
    std.debug.print(
        "BLOCK_MEMORY_MAINNET_SIZE rows={d} log_size={d} instances={d} replay_ns={d} roots_only_ns={d} roots_only_peak_bytes={d} first_round_ns={d} first_round_peak_bytes={d} prove_ns={d} verify_ns={d} proof_bytes={d} tracked_peak_bytes={d} limit_bytes={d}\n",
        .{ loaded.trace.claim.rows, loaded.trace.claim.log_size, memory_instances, loaded.replay_ns, roots_only_ns, roots_only_peak_bytes, first_round_ns, first_round_peak_bytes, prove_ns, verify_ns, counter_bytes.bytes_written, budget.snapshot().peak_live_bytes, budget.snapshot().limit },
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
