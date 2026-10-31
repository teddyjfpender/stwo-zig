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
    var cursor = Chain.Cursor{ .root = request.initial_cache.root(), .pc = cpu.pc, .registers = cpu.regs, .expected_state_policy = config.state_policy };
    var setup_ns: u64 = 0;
    var verify_ns: u64 = 0;
    var proof_bytes: u64 = 0;
    for (0..summary.value.verified_batches) |index| {
        const meta_name = try std.fmt.allocPrint(a, "batch-{d:0>6}.json", .{index});
        defer a.free(meta_name);
        const proof_name = try std.fmt.allocPrint(a, "batch-{d:0>6}.proof", .{index});
        defer a.free(proof_name);
        const metadata = try directory.readFileAlloc(a, meta_name, 128 * 1024);
        defer a.free(metadata);
        const receipt = try std.json.parseFromSlice(Receipt.Receipt, a, metadata, .{});
        defer receipt.deinit();
        const public = try receipt.value.bound(&request.authority);
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
        try Terminal.verify(a, .{ .geometry = .chunk512, .root = cursor.root, .policy = &request.policy, .halt_flag = config.symbols.halt_flag, .output = request.expected_output }, bytes);
        verify_ns += timer.read();
        proof_bytes += bytes.len;
    }
    return .{ .status = if (complete) "ethereum_execution_proof_verified" else "authenticated_execution_prefix_verified", .full_block_proof_verified = complete, .batches = cursor.batches, .instructions = cursor.steps, .calls = cursor.calls, .final_root = cursor.root, .final_pc = cursor.pc, .final_registers = cursor.registers, .setup_ns = setup_ns, .verify_ns = verify_ns, .proof_bytes = proof_bytes, .verifier_cache = verifier_cache.stats() };
}
