//! Independently bind a complete base execution claim to the supplied ELF and
//! input. No guest execution or prover-owned Poseidon commitments are needed.
const std = @import("std");
const runner = @import("../runner/mod.zig");
const public = @import("../air/public_data.zig");
const manifest = @import("blake3_execution_manifest.zig");
const program = @import("../air/program/blake3_commitment.zig");
const memory_source = @import("../recursion/air/blake3_memory_snapshot.zig");

pub fn validate(a: std.mem.Allocator, elf: []const u8, input: []const u8, data: *const public.Blake3PublicData) !manifest.Source {
    return validateProfile(.rv32im_zkvm_v1, a, elf, input, data);
}
pub fn validateProfile(comptime profile: @import("../isa/execution_profile.zig").ExecutionProfile, a: std.mem.Allocator, elf: []const u8, input: []const u8, data: *const public.Blake3PublicData) !manifest.Source {
    if (profile != .rv32im_zkvm_v1 and profile != .rv32im_zkvm_ethereum_v1) @compileError("unsupported full-width source profile");
    try data.validate();
    try runner.elf_loader.validateReleaseAbiForProfile(elf, profile);
    try data.io_entries.validateInputBytes(input);
    var memory = try runner.Memory.initFallible(a);
    defer memory.deinit();
    const info = try runner.elf_loader.loadElfForProfile(elf, &memory, profile);
    if (input.len > info.input_end -| info.input_start) return error.InputTooLarge;
    if (data.io_entries.input_start != info.input_start or
        data.io_entries.output_len_addr != info.output_len or
        data.io_entries.output_data_addr != info.output_data) return error.GuestAbiBindingMismatch;
    var initial_cpu = runner.Cpu.init(info.entry_point, info.stack_pointer);
    initial_cpu.writeReg(3, info.global_pointer);
    if (data.initial_pc != initial_cpu.pc or !std.meta.eql(data.initial_regs, initial_cpu.regs)) return error.InitialCpuMismatch;
    if (input.len != 0) memory.writeSlice(info.input_start, input);
    const completion = data.completion orelse return error.MissingCompletion;
    switch (completion.kind) {
        .halt_flag => {
            if (completion.address != info.halt_flag) return error.CompletionSymbolMismatch;
            if (memory.readU32(info.halt_flag) != 0) return error.NonZeroInitialHaltFlag;
        },
        .unretired_self_loop => {
            if (memory.readU32(completion.address) != completion.value) return error.CompletionInstructionMismatch;
        },
        .unretired_program_fetch => return error.UnsupportedCompletion,
    }
    var tracker = runner.state_chain.StateChainTracker.init(a);
    defer tracker.deinit();
    var snapshot = try runner.memory_state.capture(a, &memory, &tracker, info.memory_layout, runner.memory_state.SegmentRole.single(), 0, null);
    defer snapshot.deinit(a);
    const no_fetches: []const runner.trace.TraceRow = &.{};
    var rom = try program.buildDeclared(a, @as(@import("../air/program/commitment.zig").DeclaredDecodeAuthority, if (profile == .rv32im_zkvm_v1) .base else .{ .profile = profile }), .{no_fetches}, snapshot.program_words, null);
    defer rom.deinit();
    if (!std.meta.eql(data.program_root, @as(@TypeOf(data.program_root), rom.root))) return error.ProgramRootMismatch;
    var initial = try memory_source.fromSnapshot(a, &snapshot, .entry, .ordinary_boundary);
    defer initial.deinit();
    if (!std.meta.eql(data.initial_rw_root, @as(@TypeOf(data.initial_rw_root), initial.root))) return error.InitialMemoryRootMismatch;
    var source: manifest.Source = undefined;
    std.crypto.hash.sha2.Sha256.hash(elf, &source.elf_sha256, .{});
    std.crypto.hash.sha2.Sha256.hash(input, &source.input_sha256, .{});
    return source;
}
