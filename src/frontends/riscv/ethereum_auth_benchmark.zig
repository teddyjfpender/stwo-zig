//! Complete accelerated Ethereum-authentication guest and native recursive wrapper.
//! Research harness; shared execution/proving APIs own all proof semantics.
const std = @import("std");
const memoryStage = @import("stwo_prover_engine").measurement.process_usage.reportStage;
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
    const input = try std.fs.cwd().readFileAlloc(a, args[2], 16384);
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
    try pool.initInPlaceWithOptions(.{ .worker_count = 16, .backing_allocator = a });
    defer pool.deinit();
    var binding = try pool_mod.ScopedPoolBinding.init(&pool);
    var binding_alive = true;
    defer if (binding_alive) binding.deinit();
    var session = try runner.EthereumExecutionSession.init(a, elf, .{ .input = input, .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var first = try session.startSegment(10000000);
    defer first.deinit();
    if (first.base.continuation != null) return error.GuestStepLimit;
    if (!std.mem.eql(u8, first.base.output orelse return error.MissingOutput, expected_output)) return error.OutputMismatch;
    const execution_ns = timer.read();
    memoryStage("auth.execution_complete");
    var owner = try Owner.initCompactSegment(a, &first);
    var owner_alive = true;
    defer if (owner_alive) owner.deinit();
    const job = try segment_statement.initJob(a, config, &first.base, &first.base, &owner.native.statement.public_data, &owner.native.statement.public_data);
    const statement = try segment_statement.leaf(a, job, &first.base);
    _ = try span.RootStatement.init(statement);
    const leaf_key = try Api.PreparedVerifier.initCompact(a, &owner.native.statement, owner.statement, try owner.admission(), config, owner.native.compact_ranges.?.plan);
    var leaf_key_alive = true;
    defer if (leaf_key_alive) leaf_key.deinit();
    const witness_admission_ns = timer.read() - execution_ns;
    memoryStage("auth.leaf_admission");
    const fold_start_ns = timer.read();
    var prepared = try Pipeline.prepareWithPool(a, &owner, leaf_key, leaf_key.id, statement, 2, &pool);
    var prepared_alive = true;
    defer if (prepared_alive) prepared.deinit();
    owner.deinit();
    owner_alive = false;
    memoryStage("auth.parent_prepared");
    leaf_key.deinit();
    leaf_key_alive = false;
    const leaf_and_recursion_preparation_ns = timer.read() - fold_start_ns;
    binding.deinit();
    binding_alive = false;
    const partition_start_ns = timer.read();
    try prepared.rows.partitionHashRows();
    const hash_partition_ns = timer.read() - partition_start_ns;
    const retained = try prepared.rows.retainedBytes();
    memoryStage("auth.partitioned");
    const storage = @import("recursion/air/blake3_parent_row_storage.zig");
    const Geometry = struct { index: usize, name: []const u8, main_columns: usize, main_rows: usize, fixed_rows: usize, fixed_columns: usize, retained_bytes: usize };
    var geometry: [storage.Airs.len]Geometry = undefined;
    inline for (storage.Airs, 0..) |Air, i| {
        var main_bytes: usize = 0;
        var main_rows: usize = 0;
        for (prepared.rows.main[i]) |column| {
            main_bytes += column.values.len * 4;
            main_rows = @max(main_rows, column.values.len);
        }
        geometry[i] = .{ .index = i, .name = @typeName(Air), .main_columns = prepared.rows.main[i].len, .main_rows = main_rows, .fixed_rows = prepared.rows.fixed[i].len, .fixed_columns = @sizeOf(storage.FixedRow(Air)) / 4, .retained_bytes = main_bytes + prepared.rows.fixed[i].len * @sizeOf(storage.FixedRow(Air)) + prepared.rows.main[i].len * @sizeOf(@import("stwo_prover_engine").pcs.ColumnEvaluation) };
    }
    if (std.mem.eql(u8, args[6], "prepare")) {
        const diagnostic = try std.json.Stringify.valueAlloc(a, .{ .preparation_only = true, .retained_bytes = retained, .geometry = geometry, .output = std.fmt.bytesToHex(expected_output[0..72].*, .lower) }, .{ .whitespace = .indent_2 });
        defer a.free(diagnostic);
        try std.fs.cwd().writeFile(.{ .sub_path = args[5], .data = diagnostic });
        return;
    }
    _ = try span.RootStatement.init(statement);
    std.debug.print("BLAKE3_ETHEREUM_SEGMENTS_PREPARED segments=1 cycles={d} retained_bytes={d}\n", .{ statement.body.executed.cycle_count, retained });
    const key = try parent.ForBackend(Cpu).deriveKeyWithProfileAndPool(a, &prepared, profile, &pool);
    const expected = try key.identity();
    memoryStage("auth.parent_key_derived");
    const admission = try parent.protocol.Admission.init(key, expected);
    const Worker = parent.pipeline.ForBackend(Cpu).Worker;
    const worker = try Worker.init(a, &prepared.rows, admission, .{ .worker_count = 16, .host_byte_limit = @as(usize, if (profile == .csp_q70_pow26) 48 else 24) * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 });
    var worker_alive = true;
    memoryStage("auth.parent_worker_created");
    defer if (worker_alive) worker.deinit();
    const parent_start_ns = timer.read();
    var proof = worker.proveConsuming(&prepared.rows) catch |err| {
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
    prepared.deinit();
    prepared_alive = false;
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
        .segments = 1,
        .execution_ns = execution_ns,
        .witness_admission_ns = witness_admission_ns,
        .leaf_and_recursion_preparation_ns = leaf_and_recursion_preparation_ns,
        .parent_proving_ns = parent_proving_ns,
        .hash_partition_ns = hash_partition_ns,
        .final_verification_ns = final_verification_ns,
        .total_ns = total_ns,
        .proof_bytes = bytes.len,
        .worker_peak_bytes = usage.peak_live_bytes,
        .preparation_retained_bytes = retained,
        .geometry = geometry,
        .output = std.fmt.bytesToHex(expected_output[0..72].*, .lower),
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try std.fs.cwd().writeFile(.{ .sub_path = args[5], .data = report });
    std.debug.print("ETH_AUTH_RECURSIVE {s}\n", .{report});
}
