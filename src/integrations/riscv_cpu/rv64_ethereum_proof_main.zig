//! Pinned Ethereum execution prover and independent serialized-chain receiver.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const Request = @import("rv64_ethereum_request.zig");
const Native = @import("rv64_ethereum_batch.zig");
const BatchProof = @import("rv64_ethereum_prove_batch.zig");
const Chain = @import("rv64_ethereum_chain.zig");
const Receipt = @import("rv64_ethereum_batch_receipt.zig");
const Terminal = @import("rv64_ram_terminal.zig");
const base = std.heap.smp_allocator;
pub fn main() !void {
    const args = try std.process.argsAlloc(base);
    defer std.process.argsFree(base, args);
    if (args.len != 3) return error.ExpectedModeAndEthereumProofConfig;
    const raw = try std.fs.cwd().readFileAlloc(base, args[2], 16384);
    defer base.free(raw);
    const parsed = try std.json.parseFromSlice(Request.Config, base, raw, .{});
    defer parsed.deinit();
    const config = parsed.value;
    try Request.validateBudget(config);
    var diagnostic = @import("rv64_oom_diagnostic.zig").Diagnostic{ .child = base };
    const a = if (config.diagnose_allocations) diagnostic.allocator() else base;
    const work = @import("stwo_prover_engine").work_pool;
    var pool: work.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = try Request.effectiveWorkers(config), .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try work.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    if (std.mem.eql(u8, args[1], "verify") or std.mem.eql(u8, args[1], "verify-prefix")) return emit(a, try @import("rv64_ethereum_verify_chain.zig").verify(a, config, std.mem.eql(u8, args[1], "verify")));
    const is_resume = std.mem.eql(u8, args[1], "resume");
    if (!is_resume and !std.mem.eql(u8, args[1], "prove")) return error.InvalidEthereumProofMode;
    return prove(a, config, is_resume);
}
fn prove(a: std.mem.Allocator, config: Request.Config, is_resume: bool) !void {
    var total = try std.time.Timer.start();
    var request = try Request.Request.init(a, config);
    defer request.deinit();
    const initial_root = request.initial_cache.root();
    const immutable_setup_ns = total.read();
    try std.fs.cwd().makePath(config.output_directory);
    var directory = try std.fs.cwd().openDir(config.output_directory, .{});
    defer directory.close();
    const request_json = try std.json.Stringify.valueAlloc(a, config, .{ .whitespace = .indent_2 });
    defer a.free(request_json);
    if (!is_resume) try Receipt.writeExclusive(directory, "request.json", request_json);
    var reports = if (is_resume) try directory.openFile("batches.jsonl", .{ .mode = .write_only }) else try directory.createFile("batches.jsonl", .{ .exclusive = true });
    if (is_resume) try reports.seekFromEnd(0);
    defer reports.close();
    var session = try rv.ethereum_services.Session.initWithProfile(a, rv.machine.Cpu.init(request.loaded.info.entry, config.symbols.stack_top), &request.loaded.memory, .{ .max_retirements = config.max_steps }, .ethereum_services_v2);
    defer session.deinit();
    const cpu = &session.keccak.base.cpu;
    var resume_timer = try std.time.Timer.start();
    const restored = if (is_resume) try @import("rv64_ethereum_resume.zig").restore(a, &request, config, &session) else null;
    const resume_ns = if (is_resume) resume_timer.read() else 0;
    var cursor = if (restored) |value| value.cursor else Chain.Cursor{ .root = initial_root, .pc = cpu.pc, .registers = cpu.regs, .expected_state_policy = config.state_policy };
    var tape = try rv.compact_tape.Tape.init(a, config.batch_steps, cpu.pc, cpu.retired, .ethereum_services_v2);
    defer tape.deinit();
    var capture = try rv.boundary_capture.Capture.init(a, cpu.retired, config.batch_steps, 1 << 24);
    defer capture.deinit();
    var completed = false;
    var proof_bytes: u64 = if (restored) |value| value.proof_bytes else 0;
    while (!completed and (config.max_batches == 0 or cursor.batches < config.max_batches)) {
        const ids = [_]u32{ @intCast(cursor.calls[0] + 1), @intCast(cursor.calls[1] + 1), @intCast(cursor.calls[2] + 1) };
        var batch = try Native.Batch.init(&request.authority, &tape, &capture, cpu.regs, ids);
        batch.state_policy = config.state_policy;
        var timer = try std.time.Timer.start();
        while (tape.len < tape.storage.len) {
            try Native.captureNext(&session, &tape, &capture, &batch);
            if (cpu.pc == config.terminal_pc) {
                if (try request.loaded.memory.load(config.symbols.halt_flag, 4) != 1 or try request.loaded.memory.load(config.symbols.output_len, 4) != 43) return error.InvalidEthereumCompletion;
                for (request.expected_output, 0..) |byte, index| if (try request.loaded.memory.load(config.symbols.output_data + index, 1) != byte) return error.EthereumOutputMismatch;
                completed = true;
                break;
            }
        }
        const metrics = try BatchProof.prove(a, &request, config, &tape, &capture, &batch, cpu, &cursor, directory, timer.read());
        const line = try std.json.Stringify.valueAlloc(a, metrics, .{});
        defer a.free(line);
        try reports.writeAll(line);
        try reports.writeAll("\n");
        try reports.sync();
        try Receipt.checkpoint(a, directory, cursor);
        proof_bytes += metrics.proof_bytes;
        std.debug.print("RV64 verified batch {d}: {d} steps, prove {d:.3}s, verify {d:.3}s, {d} proof bytes\n", .{ metrics.index, metrics.instructions, @as(f64, @floatFromInt(metrics.prove_ns)) / 1e9, @as(f64, @floatFromInt(metrics.verify_ns)) / 1e9, metrics.proof_bytes });
    }
    var terminal_ns: u64 = 0;
    if (completed) {
        const public = Terminal.Statement{ .geometry = .chunk512, .root = cursor.root, .policy = &request.policy, .halt_flag = config.symbols.halt_flag, .output = request.expected_output };
        var timer = try std.time.Timer.start();
        const bytes = try Terminal.prove(a, public, &request.initial_cache, &request.loaded.memory);
        defer a.free(bytes);
        try Terminal.verify(a, public, bytes);
        try Receipt.writeExclusive(directory, "terminal.proof", bytes);
        terminal_ns = timer.read();
        proof_bytes += bytes.len;
    }
    const summary = .{ .schema = "rv64-ethereum-authenticated-execution-v1", .completed = completed, .full_block_proof_verified = false, .fresh_process_receiver_required = true, .verified_batches = cursor.batches, .instructions = cursor.steps, .calls = cursor.calls, .initial_root = initial_root, .final_root = cursor.root, .initial_pc = request.loaded.info.entry, .final_pc = cursor.pc, .elf_sha256 = config.elf_sha256, .input_sha256 = config.input_sha256, .proof_bytes = proof_bytes, .immutable_setup_ns = immutable_setup_ns, .terminal_ns = terminal_ns, .total_ns = total.read(), .recursive_aggregation = false, .resumed = is_resume, .resume_ns = resume_ns, .workers = try Request.effectiveWorkers(config) };
    const json = try std.json.Stringify.valueAlloc(a, summary, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try Receipt.replaceSummary(directory, json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
fn emit(a: std.mem.Allocator, value: @import("rv64_ethereum_verify_chain.zig").Result) !void {
    const json = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
