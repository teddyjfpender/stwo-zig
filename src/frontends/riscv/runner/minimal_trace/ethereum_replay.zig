//! Independent typed replay of one compact Ethereum leaf.

const std = @import("std");
const isa_profile = @import("../../isa/profile.zig");
const custom0 = @import("../../isa/custom0.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const recovery_abi = @import("../../isa/ethereum_signer_recovery.zig");
const Cpu = @import("../cpu.zig").Cpu;
const DecodedInst = @import("../decode.zig").DecodedInst;
const decode = @import("../decode.zig");
const generated = @import("../generated_retirement.zig");
const ethereum_v1 = @import("../guest_precompile/ethereum_v1.zig");
const session_state = @import("../guest_precompile/session_state.zig");
const Memory = @import("../memory.zig").Memory;
const MemoryLayout = @import("../memory_state.zig").MemoryLayout;
const segment_capacity = @import("../segment_capacity.zig");
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const Trace = @import("../trace.zig").Trace;
const trace_mod = @import("../trace.zig");
const base_replay = @import("replay.zig");
const types = @import("ethereum_types.zig");

pub const RequestV1 = struct {
    leaf: *const types.LeafV1,
    program: base_replay.ProgramSource,
    boundary: base_replay.BoundarySource,
    /// Exact memory layout derived from the admitted ELF, never from the
    /// resealable compact tape.
    expected_memory_layout: MemoryLayout,
    /// Journal/plan-owned source authority. This must not be copied from the
    /// untrusted leaf during admission.
    expected_source: types.SourceIdentityV1,
    /// Journal/plan-owned CPU boundary authorities. Adjacency between
    /// resealable leaves is not sufficient to authenticate either endpoint.
    expected_entry_cpu_sha256: types.Digest,
    expected_exit_cpu_sha256: types.Digest,
    /// Journal/plan-owned terminal authority. This must not be projected from
    /// the untrusted leaf being replayed.
    expected_completion: ?types.CompletionV1,
};

pub const ResultV1 = struct {
    cpu: Cpu,
    execution_trace: Trace,
    state_chain_tracker: StateChainTracker,
    touched_memory: Memory,
    keccakf_calls: @import("../guest_precompile/keccakf_call_buffer.zig").Frozen,
    keccakf_execution_rows: @import("../guest_precompile/keccakf_v1.zig").FrozenExecutionRows,
    signer_recovery_calls: @import("../guest_precompile/secp256k1_recover_call_buffer.zig").Frozen,
    signer_recovery_execution_rows: @import("../guest_precompile/secp256k1_recover_v1.zig").FrozenExecutionRows,

    pub fn deinit(self: *ResultV1) void {
        self.keccakf_calls.deinit();
        self.keccakf_execution_rows.deinit();
        self.signer_recovery_calls.deinit();
        self.signer_recovery_execution_rows.deinit();
        self.touched_memory.deinit();
        self.state_chain_tracker.deinit();
        self.execution_trace.deinit();
        self.* = undefined;
    }
};

pub fn replay(
    allocator: std.mem.Allocator,
    request: RequestV1,
) !ResultV1 {
    const leaf = request.leaf;
    try leaf.validate();
    if (!std.meta.eql(leaf.source, request.expected_source))
        return error.SourceAuthorityMismatch;
    if (!std.mem.eql(
        u8,
        &types.cpuIdentity(leaf.entry_cpu),
        &request.expected_entry_cpu_sha256,
    )) return error.EntryCpuAuthorityMismatch;
    if (!std.mem.eql(
        u8,
        &types.cpuIdentity(leaf.exit_cpu),
        &request.expected_exit_cpu_sha256,
    )) return error.ExitCpuAuthorityMismatch;
    if (!std.meta.eql(leaf.completion, request.expected_completion))
        return error.CompletionAuthorityMismatch;
    if (!std.mem.eql(u8, &leaf.source.program, &request.program.identity))
        return error.ProgramIdentityMismatch;
    if (!std.mem.eql(u8, &leaf.entry_boundary, &request.boundary.entry_identity) or
        !std.mem.eql(u8, &leaf.exit_boundary, &request.boundary.exit_identity))
    {
        return error.MemoryBoundaryIdentityMismatch;
    }

    var memory = try Memory.initFallible(allocator);
    errdefer memory.deinit();
    var trace = Trace.init(allocator);
    errdefer trace.deinit();
    trace.initial_pc = leaf.entry_cpu.pc;
    var tracker = StateChainTracker.init(allocator);
    errdefer tracker.deinit();
    try segment_capacity.reserveLeafLogs(
        &trace,
        &tracker,
        leaf.core_cycle_count,
    );
    const external_count = leaf.keccak_records.len + leaf.recovery_records.len;
    var extension = try session_state.Ethereum.init(
        allocator,
        external_count,
        0,
    );
    errdefer extension.deinit();
    var touched = std.AutoHashMap(u32, void).init(allocator);
    defer touched.deinit();
    var ordinary_cursor = base_replay.MemoryReadCursor{
        .words = leaf.ordinary_memory_read_words,
    };
    var keccak_index: usize = 0;
    var recovery_index: usize = 0;
    var cpu = leaf.entry_cpu;

    for (1..@as(usize, leaf.cycle_count) + 1) |clock_usize| {
        const instruction_clock: u32 = @intCast(clock_usize);
        isa_profile.requireInstructionAligned(cpu.pc) catch
            return error.InstructionAddressMisaligned;
        const inst_word = try request.program.fetch(cpu.pc);
        if (@as(u7, @truncate(inst_word)) == custom0.major_opcode) {
            const decoded = custom0.decode(types.PROFILE, inst_word) catch
                return error.InvalidExternalInstruction;
            switch (decoded.opcode) {
                .keccakf_1600_permute_in_place_v1 => {
                    if (keccak_index == leaf.keccak_records.len)
                        return error.ExternalTapeExhausted;
                    const expected = leaf.keccak_records[keccak_index];
                    if (expected.execution_clock != instruction_clock or
                        expected.pc != cpu.pc)
                    {
                        return error.ExternalTapeMismatch;
                    }
                    try preloadKeccak(
                        &memory,
                        &touched,
                        request.boundary,
                        expected,
                    );
                    try ethereum_v1.executeWithRecordedClock(
                        execution_profile.ExecutionProfile.rv32im_zkvm_ethereum_v1,
                        inst_word,
                        instruction_clock,
                        &cpu,
                        &memory,
                        request.expected_memory_layout,
                        &tracker,
                        &trace,
                        &extension,
                    );
                    const actual = extension.keccakf_calls.records()[keccak_index];
                    if (!std.meta.eql(expected, actual))
                        return error.ExternalTapeMismatch;
                    keccak_index += 1;
                },
                .secp256k1_recover_signer_v1 => {
                    if (recovery_index == leaf.recovery_records.len)
                        return error.ExternalTapeExhausted;
                    const expected = leaf.recovery_records[recovery_index];
                    if (expected.execution_clock != instruction_clock or
                        expected.pc != cpu.pc)
                    {
                        return error.ExternalTapeMismatch;
                    }
                    try preloadRecovery(
                        &memory,
                        &touched,
                        request.boundary,
                        expected,
                    );
                    try ethereum_v1.executeWithRecordedClock(
                        execution_profile.ExecutionProfile.rv32im_zkvm_ethereum_v1,
                        inst_word,
                        instruction_clock,
                        &cpu,
                        &memory,
                        request.expected_memory_layout,
                        &tracker,
                        &trace,
                        &extension,
                    );
                    const actual = extension.signer_recovery_calls.records()[recovery_index];
                    if (!std.meta.eql(expected, actual))
                        return error.ExternalTapeMismatch;
                    recovery_index += 1;
                },
                .poseidon2_m31_permute_in_place_v1 => return error.InvalidExternalInstruction,
            }
            continue;
        }

        const instruction = DecodedInst.decode(inst_word) catch
            return error.InvalidProgramInstruction;
        if (@import("types.zig").isUnretiredSelfLoop(instruction, cpu))
            return error.UnretiredSelfLoop;
        if (decode.isLoad(instruction.opcode) or decode.isStore(instruction.opcode)) {
            const address = cpu.readReg(instruction.rs1) +%
                @as(u32, @bitCast(instruction.imm));
            const aligned = address & ~@as(u32, 3);
            const previous_word = try ordinary_cursor.next();
            try preloadWord(
                &memory,
                &touched,
                request.boundary,
                aligned,
                previous_word,
            );
        }
        const retired = try generated.retireAtomic(
            &cpu,
            &memory,
            &trace,
            &tracker,
            instruction,
            inst_word,
            instruction_clock,
        );
        if (!retired) return error.UnsupportedReplayInstruction;
        const row = trace.rows.items[trace.rows.items.len - 1];
        const family = trace_mod.proofOpcodeFamily(row.opcode) catch
            return error.UnsupportedReplayInstruction;
        trace_mod.validateFamilyRow(row, family) catch
            return error.InvalidReplayedTraceRow;
    }
    try ordinary_cursor.finish();
    if (keccak_index != leaf.keccak_records.len or
        recovery_index != leaf.recovery_records.len)
    {
        return error.ExternalTapeNotExhausted;
    }
    if (trace.rows.items.len != leaf.core_cycle_count)
        return error.InvalidReplayedTraceShape;
    trace.final_pc = cpu.pc;
    trace.validateClockRange(0, leaf.cycle_count, external_count) catch
        return error.InvalidReplayedClockRange;
    if (!cpuEqual(cpu, leaf.exit_cpu)) return error.ExitCpuMismatch;
    var touched_iterator = touched.keyIterator();
    while (touched_iterator.next()) |address| {
        if (memory.readU32(address.*) != request.boundary.exitWord(address.*))
            return error.MemoryBoundaryExitMismatch;
    }
    try validateCompletion(
        request.expected_completion,
        request.program,
        request.expected_memory_layout,
        cpu,
        &memory,
        &tracker,
    );

    return .{
        .cpu = cpu,
        .execution_trace = trace,
        .state_chain_tracker = tracker,
        .touched_memory = memory,
        .keccakf_calls = extension.keccakf_calls.freeze(),
        .keccakf_execution_rows = extension.keccakf_rows.freeze(),
        .signer_recovery_calls = extension.signer_recovery_calls.freeze(),
        .signer_recovery_execution_rows = extension.signer_recovery_rows.freeze(),
    };
}

fn validateCompletion(
    completion: ?types.CompletionV1,
    program: base_replay.ProgramSource,
    memory_layout: MemoryLayout,
    cpu: Cpu,
    memory: *const Memory,
    tracker: *const StateChainTracker,
) !void {
    const value = completion orelse return;
    switch (value.kind) {
        1 => {
            const address = value.address & ~@as(u32, 3);
            if (!memory_layout.isRwAddr(address) or
                memory.readU32(address) != value.value or
                (tracker.mem_last_clk.get(address) orelse 0) != value.clock)
            {
                return error.CompletionObservationMismatch;
            }
        },
        2 => {
            const inst_word = program.fetch(cpu.pc) catch
                return error.CompletionObservationMismatch;
            const instruction = DecodedInst.decode(inst_word) catch
                return error.CompletionObservationMismatch;
            if (!@import("types.zig").isUnretiredSelfLoop(instruction, cpu) or
                value.address != cpu.pc or value.value != inst_word or
                value.clock != 0)
            {
                return error.CompletionObservationMismatch;
            }
        },
        else => return error.UnsupportedCompletionAuthority,
    }
}

fn preloadKeccak(
    memory: *Memory,
    touched: *std.AutoHashMap(u32, void),
    boundary: base_replay.BoundarySource,
    expected: types.KeccakRecord,
) !void {
    for (expected.input, 0..) |word, index| {
        const address = expected.state_ptr + @as(u32, @intCast(index * 4));
        try preloadWord(memory, touched, boundary, address, word);
    }
}

fn preloadRecovery(
    memory: *Memory,
    touched: *std.AutoHashMap(u32, void),
    boundary: base_replay.BoundarySource,
    expected: types.RecoveryRecord,
) !void {
    var input_bytes: [recovery_abi.input_word_count * 4]u8 = .{0} **
        (recovery_abi.input_word_count * 4);
    input_bytes[recovery_abi.digest_offset..][0..recovery_abi.digest_size].* =
        expected.digest_big_endian;
    input_bytes[recovery_abi.r_offset..][0..recovery_abi.scalar_size].* =
        expected.r_big_endian;
    input_bytes[recovery_abi.s_offset..][0..recovery_abi.scalar_size].* =
        expected.s_big_endian;
    input_bytes[recovery_abi.recovery_id_offset..][0..4].* =
        recovery_abi.bytesFromWord(expected.recovery_id);
    for (0..recovery_abi.input_word_count) |index| {
        const word = recovery_abi.wordFromBytes(input_bytes[index * 4 ..][0..4]);
        try preloadWord(
            memory,
            touched,
            boundary,
            recovery_abi.inputWordAddress(expected.io_ptr, index),
            word,
        );
    }
    for (expected.output_previous_words, 0..) |word, index| {
        try preloadWord(
            memory,
            touched,
            boundary,
            recovery_abi.outputWordAddress(expected.io_ptr, index),
            word,
        );
    }
}

fn preloadWord(
    memory: *Memory,
    touched: *std.AutoHashMap(u32, void),
    boundary: base_replay.BoundarySource,
    address: u32,
    previous_word: u32,
) !void {
    const observed = try touched.getOrPut(address);
    if (observed.found_existing) {
        if (memory.readU32(address) != previous_word)
            return error.ReplayMemoryMismatch;
        return;
    }
    if (boundary.entryWord(address) != previous_word)
        return error.MemoryBoundaryEntryMismatch;
    try memory.prepareAlignedWordWrites(&.{address});
    memory.writeU32AssumePrepared(address, previous_word);
}

fn cpuEqual(left: Cpu, right: Cpu) bool {
    return left.pc == right.pc and std.mem.eql(u32, &left.regs, &right.regs);
}
