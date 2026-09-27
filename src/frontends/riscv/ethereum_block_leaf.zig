//! Real full-validator segment qualification, before whole-block aggregation.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("runner/mod.zig");
const Owner = @import("prover/blake3_ethereum_witness.zig").Owner;
const proof_mod = @import("prover/blake3_ethereum_proof.zig");
const Api = proof_mod.ForBackend(Cpu);
pub fn main() !void {
    const backing = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(backing);
    defer std.process.argsFree(backing, args);
    if (args.len < 6 or args.len > 9) return error.ExpectedElfInputStepsProofReport;
    const target = if (args.len >= 7) try std.fmt.parseInt(u32, args[6], 10) else 0;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(backing, 48 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    const elf = try std.fs.cwd().readFileAlloc(a, args[1], 32 * 1024 * 1024);
    defer a.free(elf);
    const input = try std.fs.cwd().readFileAlloc(a, args[2], 64 * 1024 * 1024);
    defer a.free(input);
    const steps = try std.fmt.parseInt(u32, args[3], 10);
    if (steps == 0 or steps > 1 << 22) return error.InvalidSegmentBudget;
    const stride = if (args.len >= 8) try std.fmt.parseInt(u32, args[7], 10) else steps;
    if (stride == 0 or stride > 1 << 22) return error.InvalidSegmentBudget;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 16, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    var binding_alive = true;
    defer if (binding_alive) binding.deinit();
    var timer = try std.time.Timer.start();
    var session = try runner.EthereumExecutionSession.init(a, elf, .{
        .input = input,
        .stop_on_halt_flag = true,
        .strict_completion = true,
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var segment = try session.startSegment(if (target == 0) steps else stride);
    var segment_alive = true;
    defer if (segment_alive) segment.deinit();
    for (0..target) |index| {
        const continuation = segment.base.continuation orelse return error.SegmentIndexBeyondCompletion;
        segment.deinit();
        segment_alive = false;
        segment = try session.resumeSegment(continuation, if (index + 1 == target) steps else stride);
        segment_alive = true;
    }
    const execution_ns = timer.read();
    std.debug.print("BLOCK_LEAF phase=execution cycles={d}\n", .{segment.base.cycle_count});
    var owner = try Owner.initCompactSegment(a, &segment);
    defer owner.deinit();
    const witness_ns = timer.read() - execution_ns;
    std.debug.print("BLOCK_LEAF phase=witness programs={d} boundaries={d} hash_logs={any} peak_bytes={d}\n", .{ owner.plan.programs.len, owner.plan.memories.len, owner.hashes.logs, budget.snapshot().peak_live_bytes });
    const config = @import("recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG;
    const key = try Api.PreparedVerifier.initCompact(a, &owner.native.statement, owner.statement, try owner.admission(), config, owner.native.compact_ranges.?.plan);
    defer key.deinit();
    const prove_start = timer.read();
    var proved = try Api.prove(a, &owner, key, key.id, &pool);
    defer proved.proof.deinit(a);
    const prove_ns = timer.read() - prove_start;
    const bytes = try proof_mod.codec.encode(a, &proved.proof, key, key.id);
    defer a.free(bytes);
    const decoded = try proof_mod.codec.decode(a, bytes, key, key.id);
    var verified = try Api.verifyCaptureOwned(a, decoded, key, key.id);
    defer verified.deinit();
    try verified.validate(key, key.id);
    if (args.len == 9) {
        if (!std.mem.eql(u8, args[8], "recursive")) return error.InvalidQualificationMode;
        const parent_proof = try std.fmt.allocPrint(a, "{s}.parent", .{args[4]});
        defer a.free(parent_proof);
        const parent_report = try std.fmt.allocPrint(a, "{s}.parent", .{args[5]});
        defer a.free(parent_report);
        binding.deinit();
        binding_alive = false;
        try @import("prover/blake3_recursive_capture_qualification.zig").run(a, key, &verified, key.id, &pool, parent_proof, parent_report);
    }

    const report = try std.json.Stringify.valueAlloc(a, .{
        .segment_verified = true,
        .block_verified = false,
        .keccak_calls = segment.keccakf_calls.len(),
        .recovery_calls = segment.signer_recovery_calls.len(),
        .segment_index = target,
        .warmup_segment_cycles = stride,
        .global_first_cycle = segment.base.global_first_cycle,
        .queries = 70,
        .pow_bits = 26,
        .cycles = segment.base.cycle_count,
        .execution_ns = execution_ns,
        .witness_ns = witness_ns,
        .prove_ns = prove_ns,
        .total_ns = timer.read(),
        .peak_bytes = budget.snapshot().peak_live_bytes,
        .programs = owner.plan.programs.len,
        .memory_boundaries = owner.plan.memories.len,
        .hash_logs = owner.hashes.logs,
        .proof_bytes = bytes.len,
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try writeNew(args[4], bytes);
    try writeNew(args[5], report);
}
fn writeNew(name: []const u8, bytes: []const u8) !void {
    var file = try std.fs.cwd().createFile(name, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(bytes);
    try file.sync();
}
