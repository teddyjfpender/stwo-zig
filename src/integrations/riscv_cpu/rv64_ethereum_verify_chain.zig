//! Fresh process receiver: reconstruct expected ELF/input/policy/initial root,
//! verify every batch and adjacency, then optionally the terminal certificate.
const std = @import("std");
const A = @import("rv64_authenticated_execution.zig");
const Request = @import("rv64_ethereum_request.zig");
const Receipt = @import("rv64_ethereum_batch_receipt.zig");
const Chain = @import("rv64_ethereum_chain.zig");
const Terminal = @import("rv64_ram_terminal.zig");
const VerifierCache = @import("rv64_execution_verifier_cache.zig");
pub const Result = struct { status: []const u8, full_block_proof_verified: bool, batches: u32, instructions: u64, calls: [3]u64, final_root: A.R.values.Digest, final_pc: u64, final_registers: [32]u64, setup_ns: u64, verify_ns: u64, proof_bytes: u64, verifier_cache: VerifierCache.Stats };
/// Borrowed independently derived authority. No native image/cache is needed
/// by the canonical receiver body; this context must outlive verification.
pub const ExpectedContext = struct {
    authority: *const A.Full.ProgramAuthority,
    policy: *const A.R.policy.Policy,
    initial_root: A.R.values.Digest,
    initial_pc: u64,
    initial_registers: [32]u64,
    output: [43]u8,
};
pub fn verify(a: std.mem.Allocator, config: Request.Config, complete: bool) !Result {
    var request = try Request.Request.init(a, config);
    defer request.deinit();
    // Initialize only after Request reaches its final address. Cache entries
    // borrow its immutable authority/policy and are destroyed before Request.
    var verifier_cache = try VerifierCache.Cache.init(a, &request.authority, &request.policy, .{});
    defer verifier_cache.deinit();
    var directory = try std.fs.cwd().openDir(config.output_directory, .{});
    defer directory.close();
    const summary_bytes = try directory.readFileAlloc(a, "summary.json", 16384);
    defer a.free(summary_bytes);
    const Summary = struct { verified_batches: u32, completed: bool };
    const summary = try std.json.parseFromSlice(Summary, a, summary_bytes, .{ .ignore_unknown_fields = true });
    defer summary.deinit();
    if (summary.value.verified_batches == 0 or summary.value.verified_batches > config.max_steps or (complete and !summary.value.completed)) return error.IncompleteEthereumProof;
    const cpu = A.frontend.rv64.machine.Cpu.init(request.loaded.info.entry, config.symbols.stack_top);
    return verifyInDirectory(a, .{ .authority = &request.authority, .policy = &request.policy, .initial_root = request.initial_cache.root(), .initial_pc = cpu.pc, .initial_registers = cpu.regs, .output = request.expected_output }, config, &directory, &verifier_cache, summary.value.verified_batches, complete, false);
}
/// Count is transport framing, not execution authority. Every proof, endpoint,
/// service span, root and terminal certificate is still independently checked.
/// Unlike the legacy summary wrapper, finalization rejects extra receipt files.
pub fn verifyExpectedCount(a: std.mem.Allocator, expected: ExpectedContext, config: Request.Config, count: u32, complete: bool) !Result {
    if (count == 0 or count > config.max_steps) return error.IncompleteEthereumProof;
    var verifier_cache = try VerifierCache.Cache.init(a, expected.authority, expected.policy, .{});
    defer verifier_cache.deinit();
    var directory = try std.fs.cwd().openDir(config.output_directory, .{ .iterate = true });
    defer directory.close();
    return verifyInDirectory(a, expected, config, &directory, &verifier_cache, count, complete, true);
}
fn verifyInDirectory(a: std.mem.Allocator, expected: ExpectedContext, config: Request.Config, directory: *std.fs.Dir, verifier_cache: *VerifierCache.Cache, count: u32, complete: bool, strict_count: bool) !Result {
    if (strict_count) try rejectExtraReceipts(directory.*, count);
    var cursor = Chain.Cursor{ .root = expected.initial_root, .pc = expected.initial_pc, .registers = expected.initial_registers, .expected_state_policy = config.state_policy };
    var setup_ns: u64 = 0;
    var verify_ns: u64 = 0;
    var proof_bytes: u64 = 0;
    for (0..count) |index| {
        const meta_name = try std.fmt.allocPrint(a, "batch-{d:0>6}.json", .{index});
        defer a.free(meta_name);
        const proof_name = try std.fmt.allocPrint(a, "batch-{d:0>6}.proof", .{index});
        defer a.free(proof_name);
        const metadata = try directory.readFileAlloc(a, meta_name, 128 * 1024);
        defer a.free(metadata);
        const receipt = try std.json.parseFromSlice(Receipt.Receipt, a, metadata, .{});
        defer receipt.deinit();
        const public = try receipt.value.bound(expected.authority);
        if (public.cpu.statement.steps > config.batch_steps) return error.EthereumBatchResourceLimit;
        try cursor.check(public, receipt.value.index, receipt.value.first_step, config.max_steps);
        const bytes = try directory.readFileAlloc(a, proof_name, 128 * 1024 * 1024);
        defer a.free(bytes);
        try Request.pin(bytes, &receipt.value.proof_sha256);
        proof_bytes = try std.math.add(u64, proof_bytes, bytes.len);
        var timer = try std.time.Timer.start();
        const cold_before = verifier_cache.stats().cold_setup_ns;
        try verifier_cache.verifyOwned(public, receipt.value.claims, try @import("stwo_proof_wire").decodeProofBytesBinary(a, bytes));
        const elapsed = timer.read();
        const cold = verifier_cache.stats().cold_setup_ns - cold_before;
        setup_ns += cold;
        verify_ns += elapsed - @min(elapsed, cold);
        try cursor.advanceVerified(public);
    }
    if (complete) {
        if (cursor.pc != config.terminal_pc) return error.InvalidEthereumTerminalPc;
        const bytes = try directory.readFileAlloc(a, "terminal.proof", 128 * 1024 * 1024);
        defer a.free(bytes);
        var timer = try std.time.Timer.start();
        try Terminal.verify(a, .{ .geometry = .chunk512, .root = cursor.root, .policy = expected.policy, .halt_flag = config.symbols.halt_flag, .output = expected.output }, bytes);
        verify_ns += timer.read();
        proof_bytes += bytes.len;
    }
    return .{ .status = if (complete) "ethereum_execution_proof_verified" else "authenticated_execution_prefix_verified", .full_block_proof_verified = complete, .batches = cursor.batches, .instructions = cursor.steps, .calls = cursor.calls, .final_root = cursor.root, .final_pc = cursor.pc, .final_registers = cursor.registers, .setup_ns = setup_ns, .verify_ns = verify_ns, .proof_bytes = proof_bytes, .verifier_cache = verifier_cache.stats() };
}

fn rejectExtraReceipts(directory: std.fs.Dir, count: u32) !void {
    var iterator = directory.iterate();
    while (try iterator.next()) |entry| {
        if (!std.mem.startsWith(u8, entry.name, "batch-")) continue;
        const suffix: usize = if (std.mem.endsWith(u8, entry.name, ".proof")) 6 else if (std.mem.endsWith(u8, entry.name, ".json")) 5 else continue;
        if (entry.name.len <= 6 + suffix) continue;
        const digits = entry.name[6 .. entry.name.len - suffix];
        const index = std.fmt.parseInt(u32, digits, 10) catch |err| {
            if (err == error.Overflow) return error.UnexpectedEthereumReceipt;
            continue;
        };
        if (index >= count) return error.UnexpectedEthereumReceipt;
    }
}
