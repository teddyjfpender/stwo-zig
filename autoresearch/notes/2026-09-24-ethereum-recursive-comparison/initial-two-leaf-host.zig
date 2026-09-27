//! Two real Ethereum segments, full-memory custody and an independently verified root.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("runner/mod.zig");
const Owner = @import("prover/blake3_ethereum_witness.zig").Owner;
const Api = @import("prover/blake3_ethereum_proof.zig").ForBackend(Cpu);
const Pipeline = @import("prover/blake3_segment_parent.zig").ForEthereumBackend(Cpu);
const parent = @import("recursion/blake3_execution_parent_proof.zig");
const span = @import("recursion/span_statement_blake3.zig");
const segment_statement = @import("prover/blake3_segment_statement.zig");
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 7) return error.ExpectedElfInputExpectedProofReportMode;
    const elf = try std.fs.cwd().readFileAlloc(a, args[1], 16 * 1024 * 1024);
    defer a.free(elf);
    const input = try std.fs.cwd().readFileAlloc(a, args[2], 4096);
    defer a.free(input);
    const expected_output = try std.fs.cwd().readFileAlloc(a, args[3], 72);
    defer a.free(expected_output);
    var preflight = try runner.EthereumExecutionSession.init(a, elf, .{ .input = input, .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    var pre = try preflight.startSegment(10000000);
    if (pre.base.continuation != null) return error.GuestStepLimit;
    if (!std.mem.eql(u8, pre.base.output orelse return error.MissingOutput, expected_output)) return error.OutputMismatch;
    const cycles = pre.base.cycle_count;
    const keccak = pre.keccakf_calls.len();
    const recoveries = pre.signer_recovery_calls.len();
    std.debug.print("ETH_AUTH_EXECUTION cycles={d} keccak={d} recoveries={d} output={s}\n", .{ cycles, keccak, recoveries, std.fmt.bytesToHex(expected_output[0..72].*, .lower) });
    pre.deinit();
    preflight.deinit();
    if (std.mem.eql(u8, args[6], "execute")) return;
    const profile: parent.protocol.Profile = .csp_q70_pow26;
    const config = profile.config();
    var timer = try std.time.Timer.start();
    const pool_mod = @import("stwo_prover_engine").work_pool;
    var pool: pool_mod.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try pool_mod.ScopedPoolBinding.init(&pool);
    var binding_alive = true;
    defer if (binding_alive) binding.deinit();
    var session = try runner.EthereumExecutionSession.init(a, elf, .{ .input = input, .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var first = try session.startSegment(@intCast(cycles / 2));
    defer first.deinit();
    var second = try session.resumeSegment(first.base.continuation orelse return error.MissingContinuation, 10000000);
    defer second.deinit();
    if (second.base.continuation != null) return error.GuestStepLimit;
    if (!std.mem.eql(u8, second.base.output orelse return error.MissingOutput, expected_output)) return error.OutputMismatch;
    const execution_ns = timer.read();
    var left = try Owner.initCompactSegment(a, &first);
    var left_alive = true;
    defer if (left_alive) left.deinit();
    var right = try Owner.initCompactSegment(a, &second);
    var right_alive = true;
    defer if (right_alive) right.deinit();
    try std.testing.expectEqualDeep(left.memory.program.root, right.memory.program.root);
    const first_boundary = try segment_statement.boundary(a, &first.base);
    const second_boundary = try segment_statement.boundary(a, &second.base);
    try std.testing.expectEqualDeep(first_boundary.exit, second_boundary.entry);
    const job = try segment_statement.initJob(a, config, &first.base, &second.base, &left.native.statement.public_data, &right.native.statement.public_data);
    const statements = [2]span.SpanStatement{
        try segment_statement.leaf(a, job, &first.base),
        try segment_statement.leaf(a, job, &second.base),
    };
    const lkey = try Api.PreparedVerifier.initCompact(a, &left.native.statement, left.statement, try left.admission(), config, left.native.compact_ranges.?.plan);
    defer lkey.deinit();
    const rkey = try Api.PreparedVerifier.initCompact(a, &right.native.statement, right.statement, try right.admission(), config, right.native.compact_ranges.?.plan);
    defer rkey.deinit();
    const witness_admission_ns = timer.read() - execution_ns;
    const fold_start_ns = timer.read();
    left_alive = false;
    right_alive = false;
    var fold = try Pipeline.preparePairOwnedWithPool(a, .{ &left, &right }, .{ lkey, rkey }, .{ lkey.id, rkey.id }, statements, 2, &pool);
    var fold_alive = true;
    defer if (fold_alive) fold.deinit();
    const leaf_and_recursion_preparation_ns = timer.read() - fold_start_ns;
    binding.deinit();
    binding_alive = false;
    const retained = try fold.prepared.rows.retainedBytes();
    const statement = fold.statement;
    _ = try span.RootStatement.init(statement);
    std.debug.print("BLAKE3_ETHEREUM_SEGMENTS_PREPARED segments=2 cycles={d} retained_bytes={d}\n", .{ statement.body.executed.cycle_count, retained });
    const key = try parent.ForBackend(Cpu).deriveKeyWithProfileAndPool(a, &fold.prepared, profile, &pool);
    const expected = try key.identity();
    const admission = try parent.protocol.Admission.init(key, expected);
    const Worker = parent.pipeline.ForBackend(Cpu).Worker;
    const worker = try Worker.init(a, &fold.prepared.rows, admission, .{ .worker_count = 4, .host_byte_limit = @as(usize, if (profile == .csp_q70_pow26) 48 else 24) * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 });
    var worker_alive = true;
    defer if (worker_alive) worker.deinit();
    const parent_start_ns = timer.read();
    var proof = worker.prove(&fold.prepared.rows) catch |err| {
        const failed_usage = worker.budget.snapshot();
        if (worker.workspace.core_diagnostic) |diagnostic| {
            std.debug.print("BLAKE3_PARENT_CORE_FAILURE phase={s} composition_subphase={s} cause={s}\n", .{ @tagName(diagnostic.phase), if (diagnostic.composition_subphase) |subphase| @tagName(subphase) else "none", @errorName(diagnostic.cause) });
        }
        std.debug.print("BLAKE3_PARENT_WORKER_FAILURE phase={s} error={s} peak_bytes={d} limit_bytes={d}\n", .{ @tagName(worker.workspace.phase), @errorName(err), failed_usage.peak_live_bytes, failed_usage.limit });
        return err;
    };
    defer proof.deinit();
    const parent_proving_ns = timer.read() - parent_start_ns;
    const usage = worker.budget.snapshot();
    worker.deinit();
    worker_alive = false;
    fold.deinit();
    fold_alive = false;
    const bytes = try parent.codec.encode(a, &proof, &admission);
    defer a.free(bytes);
    try std.fs.cwd().writeFile(.{ .sub_path = args[4], .data = bytes });
    const verification_start_ns = timer.read();
    var decoded = try parent.codec.decode(a, bytes, &admission);
    defer decoded.deinit();
    var verified = try parent.tree.Node.verifyOwned(&decoded, admission, expected, statement);
    defer verified.deinit();
    _ = try verified.root();
    try std.testing.expectEqual(@as(usize, config.fri_config.n_queries), verified.verified.capture.queries.raw.len);
    const final_verification_ns = timer.read() - verification_start_ns;
    const total_ns = timer.read();
    const report = try std.json.Stringify.valueAlloc(a, .{
        .verified = true,
        .recursive = true,
        .queries = 70,
        .pow_bits = 26,
        .cycles = cycles,
        .keccak_calls = keccak,
        .recovery_calls = recoveries,
        .segments = 2,
        .execution_ns = execution_ns,
        .witness_admission_ns = witness_admission_ns,
        .leaf_and_recursion_preparation_ns = leaf_and_recursion_preparation_ns,
        .parent_proving_ns = parent_proving_ns,
        .final_verification_ns = final_verification_ns,
        .total_ns = total_ns,
        .proof_bytes = bytes.len,
        .worker_peak_bytes = usage.peak_live_bytes,
        .output = std.fmt.bytesToHex(expected_output[0..72].*, .lower),
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try std.fs.cwd().writeFile(.{ .sub_path = args[5], .data = report });
    std.debug.print("ETH_AUTH_RECURSIVE {s}\n", .{report});
}
