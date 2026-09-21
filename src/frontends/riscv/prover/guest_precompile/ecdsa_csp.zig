//! Complete CSP ECDSA success proof using the canonical Ethereum instruction.
//! The guest proves key equality and low-S policy; the host's parity selection
//! is only a routing hint. Unsupported inputs use the software guest product.
const std = @import("std");
const core = @import("stwo_core");
const stage_profile = @import("stwo_prover_api").stage_profile;
const runner = @import("../../runner/mod.zig");
const public_mod = @import("../../air/public_data.zig");
const statement_mod = @import("../../air/statement.zig");
const program_commitment = @import("../../air/program/commitment.zig");
const memory_boundary = @import("../../air/memory_commitment/boundary.zig");
const recover = @import("../../runner/guest_precompile/secp256k1_recover_v1.zig");
const artifact = @import("ethereum_proof_artifact.zig");
const orchestration = @import("ethereum_orchestration.zig");
const verifier = @import("ethereum_verifier.zig");
const admission = @import("../../prover.zig");

pub fn recoveryId(input: []const u8) ?u32 {
    if (input.len != 161 or input[32] != 4) return null;
    const s = std.mem.readInt(u256, input[129..161], .big);
    if (s == 0 or s > std.crypto.ecc.Secp256k1.scalar.field_order / 2) return null;
    for (0..2) |id| {
        const key = recover.recoverSigner(input[0..32].*, input[97..129].*, input[129..161].*, @intCast(id)) catch continue;
        if (std.mem.eql(u8, &key, input[33..97])) return @intCast(id);
    }
    return null;
}

pub const Result = struct {
    encoded: []u8,
    statement_sha256: [32]u8,
    execution_ns: u64,
    proving_ns: u64,
    verification_ns: u64,
    cycles: usize,
    proof_bytes: usize,
    recovery_id: u32,
};

pub fn prove(comptime Engine: type, allocator: std.mem.Allocator, elf: []const u8, input: []const u8, config: core.pcs.PcsConfig, workers: usize) !Result {
    return proveWithRecorder(Engine, allocator, elf, input, config, workers, null);
}

pub fn proveWithRecorder(comptime Engine: type, allocator: std.mem.Allocator, elf: []const u8, input: []const u8, config: core.pcs.PcsConfig, workers: usize, recorder: ?*stage_profile.Recorder) !Result {
    var timer = try std.time.Timer.start();
    const id = recoveryId(input) orelse return error.SoftwareFallbackRequired;
    var run = try runner.runEthereumExtensionWithInput(allocator, elf, input, 100_000);
    defer run.deinit();
    try admission.admitRunForProving(&run.base);
    if (run.signer_recovery_calls.len() != 1 or run.keccakf_calls.len() != 0)
        return error.InvalidPrecompileCallCount;
    var public = try OwnedPublic.init(allocator, &run.base);
    defer public.deinit(allocator);
    try validateIo(public.value, input);
    const execution_ns = timer.lap();
    var output = try orchestration.proveWithEngineUsingExecution(
        Engine,
        allocator,
        config,
        &run.base.execution_trace,
        &run.keccakf_calls,
        &run.keccakf_execution_rows,
        &run.signer_recovery_calls,
        &run.signer_recovery_execution_rows,
        &run.base.state_chain_tracker,
        &run.base.rw_memory,
        recorder,
        public.value,
        .{ .cpu = .{ .worker_count = workers, .host_byte_budget = std.math.maxInt(usize), .contention_policy = .strict } },
    );
    defer output.deinit(allocator);
    const proving_ns = timer.lap();
    const encoded = try artifact.encodeAlloc(allocator, .{
        .pcs_config = config,
        .statement = &output.statement,
        .extension = &output.extension,
        .base_claim = output.base_claim,
        .extension_claim = &output.extension_claim,
        .proof = &output.proof,
    });
    errdefer allocator.free(encoded);
    timer.reset();
    const statement_sha256 = try verify(Engine, allocator, elf, input, config, encoded);
    const verification_ns = timer.read();
    return .{ .encoded = encoded, .statement_sha256 = statement_sha256, .execution_ns = execution_ns, .proving_ns = proving_ns, .verification_ns = verification_ns, .cycles = run.base.step_count, .recovery_id = id, .proof_bytes = std.mem.readInt(u32, encoded[artifact.HeaderOffset.proof_length..][0..4], .little) };
}

pub fn verify(comptime Engine: type, allocator: std.mem.Allocator, elf: []const u8, input: []const u8, config: core.pcs.PcsConfig, encoded: []const u8) ![32]u8 {
    var decoded = try artifact.decodeAllocForConfig(allocator, encoded, config, .{});
    var moved = false;
    defer if (moved) decoded.deinitAfterProofMoved(allocator) else decoded.deinit(allocator);
    try decoded.statement.public_data.validate();
    try validateIo(decoded.statement.public_data, input);
    try validateElf(allocator, elf, input, &decoded.statement);
    if (decoded.extension.counts.signer_calls != 1 or decoded.extension.counts.keccak_calls != 0)
        return error.InvalidPrecompileCallCount;
    moved = true;
    try verifier.verifyWithEngine(Engine, allocator, config, decoded.statement, decoded.extension, decoded.proof, decoded.base_claim, &decoded.extension_claim);
    return decoded.identity.metadata_sha256;
}

fn validateIo(public: public_mod.PublicData, input: []const u8) !void {
    const io = public.io_entries;
    const completion = public.completion orelse return error.InvalidCspPublicIo;
    if (input.len != 161 or io.input_len != input.len or io.output_len != 32 or
        io.output_words.len != 9 or completion.kind != .halt_flag)
        return error.InvalidCspPublicIo;
    for (input, 0..) |byte, index| {
        const value: u8 = @truncate(io.input_words[index / 4] >> @as(u5, @intCast((index % 4) * 8)));
        if (value != byte) return error.CspInputMismatch;
    }
    for (input[0..32], 0..) |byte, index| {
        const value: u8 = @truncate(io.output_words[1 + index / 4].value >> @as(u5, @intCast((index % 4) * 8)));
        if (value != byte) return error.CspOutputMismatch;
    }
}

fn validateElf(allocator: std.mem.Allocator, elf: []const u8, input: []const u8, statement: *const statement_mod.RiscVStatement) !void {
    try runner.elf_loader.validateReleaseAbiForProfile(elf, .rv32im_zkvm_ethereum_v1);
    var memory = runner.Memory.init(allocator);
    defer memory.deinit();
    const info = try runner.elf_loader.loadElfForProfile(elf, &memory, .rv32im_zkvm_ethereum_v1);
    memory.writeSlice(info.input_start, input);
    var tracker = runner.state_chain.StateChainTracker.init(allocator);
    defer tracker.deinit();
    var snapshot = try runner.memory_state.capture(allocator, &memory, &tracker, info.memory_layout, runner.memory_state.SegmentRole.single(), 0, null);
    defer snapshot.deinit(allocator);
    var program = try program_commitment.buildDeclaredForProfileSources(allocator, .rv32im_zkvm_ethereum_v1, .{}, snapshot.program_words, null);
    defer program.deinit(allocator);
    var boundary = try memory_boundary.build(allocator, snapshot.words);
    defer boundary.deinit(allocator);
    const initial_root = if (boundary.initial_tree) |tree| tree.root else 0;
    const public = statement.public_data;
    var cpu = runner.Cpu.init(info.entry_point, info.stack_pointer);
    cpu.writeReg(3, info.global_pointer);
    if (public.program_root != program.tree.root or public.initial_rw_root != initial_root or
        public.initial_pc != info.entry_point or !std.mem.eql(u32, &public.initial_regs, &cpu.regs) or
        public.io_entries.input_start != info.input_start or public.io_entries.output_len_addr != info.output_len or
        public.io_entries.output_data_addr != info.output_data or public.completion.?.address != info.halt_flag or
        memory.readU32(info.halt_flag) != 0)
        return error.CspElfBindingMismatch;
}

const OwnedPublic = struct {
    value: public_mod.PublicData,
    input_words: []u32,
    output_words: []public_mod.OutputWord,

    fn init(allocator: std.mem.Allocator, run: *const runner.RunResult) !OwnedPublic {
        const input_words = try public_mod.packInputWords(allocator, run.input);
        errdefer allocator.free(input_words);
        const output_words = try allocator.alloc(public_mod.OutputWord, run.output_words.len);
        errdefer allocator.free(output_words);
        for (output_words, run.output_words) |*dst, src|
            dst.* = .{ .addr = src.addr, .value = src.value, .clock = src.clock };
        return .{ .input_words = input_words, .output_words = output_words, .value = .{
            .initial_pc = run.initial_pc,
            .final_pc = run.final_pc,
            .clock = @intCast(run.step_count),
            .initial_regs = run.initial_regs,
            .final_regs = run.final_regs,
            .reg_last_clock = run.state_chain_tracker.reg_last_clk,
            .program_root = null,
            .initial_rw_root = null,
            .final_rw_root = null,
            .completion = try public_mod.completionFromRun(run.*),
            .io_entries = .{ .input_start = run.input_start, .input_len = @intCast(run.input.len), .input_words = input_words, .output_len = run.output_len, .output_len_addr = run.output_len_addr, .output_data_addr = run.output_data_addr, .output_words = output_words },
        } };
    }
    fn deinit(self: *OwnedPublic, allocator: std.mem.Allocator) void {
        allocator.free(self.input_words);
        allocator.free(self.output_words);
    }
};
