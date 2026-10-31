//! Reprove one retained batch against an independently accepted COMPLETE chain.
//! Replay establishes witness data only; the prior chain establishes authority.
//! Prefix replay and baseline acceptance are excluded from the batch benchmark.
const std = @import("std");
const A = @import("rv64_authenticated_execution.zig");
const rv = A.frontend.rv64;
const Request = @import("rv64_ethereum_request.zig");
const Native = @import("rv64_ethereum_batch.zig");
const Receipt = @import("rv64_ethereum_batch_receipt.zig");
const Receiver = @import("rv64_ethereum_verify_chain.zig");
const Chain = @import("rv64_ethereum_chain.zig");
const BatchProof = @import("rv64_ethereum_prove_batch.zig");
const Recycler = @import("rv64_large_block_recycler.zig").LargeBlockRecycler;
var recycler = Recycler.init(std.heap.smp_allocator, 16 * 1024 * 1024 * 1024);
// Large column buffers are recycled across batch proofs (see the recycler).
const a: std.mem.Allocator = .{ .ptr = &recycler, .vtable = &Recycler.vtable };

pub fn main() !void {
    defer recycler.deinit();
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 4) return error.ExpectedConfigBaselineDirectoryAndBatchIndex;
    const raw = try std.fs.cwd().readFileAlloc(a, args[1], 16384);
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(Request.Config, a, raw, .{});
    defer parsed.deinit();
    const config = parsed.value;
    const target = try std.fmt.parseInt(u32, args[3], 10);
    try Request.validateBudget(config);
    const work = @import("stwo_prover_engine").work_pool;
    var pool: work.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = try Request.effectiveWorkers(config), .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try work.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var baseline_config = config;
    baseline_config.output_directory = args[2];
    var timer = try std.time.Timer.start();
    // No producer-provided root, summary flag or key can substitute for this.
    const accepted = try Receiver.verify(a, baseline_config, true);
    const baseline_receiver_ns = timer.lap();
    if (target >= accepted.batches) return error.InvalidEthereumReproveTarget;
    var baseline = try std.fs.cwd().openDir(args[2], .{});
    defer baseline.close();
    const meta_name = try std.fmt.allocPrint(a, "batch-{d:0>6}.json", .{target});
    defer a.free(meta_name);
    const metadata = try baseline.readFileAlloc(a, meta_name, 128 * 1024);
    defer a.free(metadata);
    const receipt = try std.json.parseFromSlice(Receipt.Receipt, a, metadata, .{});
    defer receipt.deinit();
    var request = try Request.Request.init(a, config);
    defer request.deinit();
    const expected = try receipt.value.bound(&request.authority);
    var session = try rv.ethereum_services.Session.initWithProfile(a, rv.machine.Cpu.init(request.loaded.info.entry, config.symbols.stack_top), &request.loaded.memory, .{ .max_retirements = config.max_steps }, .ethereum_services_v2);
    defer session.deinit();
    const cpu = &session.keccak.base.cpu;
    while (cpu.retired < receipt.value.first_step) {
        var event: rv.ethereum_services.Event = undefined;
        _ = try session.step(&event);
    }
    var observed_cache = try A.R.values.Cache.fromMemory(a, .chunk512, &request.loaded.memory);
    var owns_cache = true;
    defer if (owns_cache) observed_cache.deinit();
    const calls = [_]u64{ session.keccak.calls, session.add_calls, session.double_calls };
    var cursor = Chain.Cursor{ .root = observed_cache.root(), .pc = cpu.pc, .registers = cpu.regs, .steps = cpu.retired, .batches = target, .calls = calls, .expected_state_policy = config.state_policy };
    try cursor.check(expected, receipt.value.index, receipt.value.first_step, config.max_steps);
    request.initial_cache.deinit();
    request.initial_cache = observed_cache;
    owns_cache = false;
    const replay_ns = timer.lap();
    try std.fs.cwd().makePath(config.output_directory);
    var directory = try std.fs.cwd().openDir(config.output_directory, .{});
    defer directory.close();
    // Exclusive creation also prevents accidental publication into the control.
    const request_json = try std.json.Stringify.valueAlloc(a, config, .{ .whitespace = .indent_2 });
    defer a.free(request_json);
    try Receipt.writeExclusive(directory, "request.json", request_json);
    var tape = try rv.compact_tape.Tape.init(a, expected.cpu.statement.steps, cpu.pc, cpu.retired, .ethereum_services_v2);
    defer tape.deinit();
    var capture = try rv.boundary_capture.Capture.init(a, cpu.retired, expected.cpu.statement.steps, 1 << 24);
    defer capture.deinit();
    const ids = [_]u32{ @intCast(calls[0] + 1), @intCast(calls[1] + 1), @intCast(calls[2] + 1) };
    var batch = try Native.Batch.init(&request.authority, &tape, &capture, cpu.regs, ids);
    batch.state_policy = config.state_policy;
    timer.reset();
    while (tape.len < tape.storage.len) try Native.captureNext(&session, &tape, &capture, &batch);
    const metrics = try BatchProof.prove(a, &request, config, &tape, &capture, &batch, cpu, &cursor, directory, timer.read());
    const proof_name = try std.fmt.allocPrint(a, "batch-{d:0>6}.proof", .{target});
    defer a.free(proof_name);
    const control = try baseline.readFileAlloc(a, proof_name, 128 * 1024 * 1024);
    defer a.free(control);
    const candidate = try directory.readFileAlloc(a, proof_name, 128 * 1024 * 1024);
    defer a.free(candidate);
    // A performance-only replacement must reproduce the complete transcript,
    // claims and physical proof, not merely the final guest output.
    if (!std.mem.eql(u8, candidate, control)) return error.EthereumReproveProofBytesDiffer;
    const result = .{ .schema = "rv64-ethereum-retained-batch-reprove-v1", .baseline_complete_chain_verified = accepted.full_block_proof_verified, .full_block_reproved = false, .target_batch = target, .proof_bytes_equal = true, .proof_sha256 = std.fmt.bytesToHex(Request.sha(candidate), .lower), .baseline_receiver_ns = baseline_receiver_ns, .native_prefix_replay_ns = replay_ns, .metrics = metrics };
    const json = try std.json.Stringify.valueAlloc(a, result, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try Receipt.writeExclusive(directory, "reprove.json", json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
