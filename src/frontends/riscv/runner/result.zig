//! Owned output of one RISC-V execution.

const std = @import("std");
const Cpu = @import("cpu.zig").Cpu;
const trace = @import("trace.zig");
const state_chain = @import("state_chain.zig");
const memory_state = @import("memory_state.zig");
const guest_precompile = @import("guest_precompile/mod.zig");

pub const CompletionReason = enum {
    halt_flag,
    self_loop,
    stalled_pc,
    ecall,
    ebreak,
    host_halt,
    invalid_instruction,
    max_steps,
};

pub const CONTINUATION_SCHEMA_VERSION: u32 = 2;

/// Clock namespace used by one segmented trace.
///
/// The existing SegmentV2 path uses `global_continuous`. Large recursive jobs
/// use `leaf_local`: every independently proved leaf starts at instruction
/// clock one, while a versioned outer statement owns its global position.
/// Keeping this explicit prevents a locally rebased trace from being mistaken
/// for the existing globally clocked protocol.
pub const SegmentClockFrame = enum(u8) {
    global_continuous = 1,
    leaf_local = 2,
};

pub const MemoryAccessClock = struct {
    addr: u32,
    clock: u32,
};

/// Exact predecessor-clock custody at a segment edge. Global-continuous V2
/// segments authenticate this boundary explicitly. Leaf-local segments reset
/// it to zero and require a versioned outer state-adjacency statement.
pub const AccessClockBoundary = struct {
    register_clocks: [32]u32,
    memory_clocks: []MemoryAccessClock,

    pub fn deinit(self: *AccessClockBoundary, allocator: std.mem.Allocator) void {
        allocator.free(self.memory_clocks);
        self.* = undefined;
    }

    pub fn identity(self: AccessClockBoundary) u64 {
        var fingerprint: u64 = 0xcbf2_9ce4_8422_2325;
        fingerprint = mix(fingerprint, 0x434c_4f43); // "CLOC"
        for (self.register_clocks, 0..) |clock, register| {
            fingerprint = mix(fingerprint, register);
            fingerprint = mix(fingerprint, clock);
        }
        fingerprint = mix(fingerprint, self.memory_clocks.len);
        for (self.memory_clocks) |entry| {
            fingerprint = mix(fingerprint, entry.addr);
            fingerprint = mix(fingerprint, entry.clock);
        }
        return fingerprint;
    }
};

inline fn mix(current: u64, value: u64) u64 {
    var result = current;
    inline for (0..8) |byte| {
        result ^= @as(u8, @truncate(value >> @intCast(byte * 8)));
        result *%= 0x0000_0100_0000_01b3;
    }
    return result;
}

/// Copyable authority required to resume exactly one yielded execution.
/// Validation happens before the session mutates any architectural state.
pub const ContinuationToken = struct {
    schema_version: u32 = CONTINUATION_SCHEMA_VERSION,
    clock_frame: SegmentClockFrame,
    session_tag: u64,
    next_segment_index: u32,
    next_cycle: u64,
    cpu: Cpu,
    rw_memory: memory_state.ContinuationIdentity,
    access_clocks: u64,
};

/// A final, word-aligned guest output value and its last access clock.
pub const OutputWord = struct {
    addr: u32,
    value: u32,
    clock: u32,
};

/// Owned proof input for one bounded execution segment.
///
/// A yielded segment has `completion_reason == null`, no output, and a
/// continuation token.  A completed segment has the inverse shape.  Keeping
/// this distinct from `RunResult` prevents an intermediate boundary from ever
/// being admitted as a completed V1 execution by accident.
pub const SegmentResult = struct {
    segment_index: u32,
    segment_role: memory_state.SegmentRole,
    clock_frame: SegmentClockFrame,
    global_first_cycle: u64,
    cycle_count: usize,
    entry_cpu: Cpu,
    exit_cpu: Cpu,
    completion_reason: ?CompletionReason,
    completion_address: u32,
    completion_value: u32,
    completion_clock: u32,
    continuation: ?ContinuationToken,
    input: ?[]u8,
    input_start: u32,
    input_end: u32,
    output: ?[]u8,
    output_len: u32,
    output_len_addr: u32,
    output_data_addr: u32,
    output_end_addr: u32,
    output_words: []OutputWord,
    execution_trace: trace.Trace,
    state_chain_tracker: state_chain.StateChainTracker,
    entry_access_clocks: AccessClockBoundary,
    exit_access_clocks: AccessClockBoundary,
    rw_memory: memory_state.Snapshot,
    exit_code: ?u32,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *SegmentResult) void {
        if (self.input) |input| self.allocator.free(input);
        if (self.output) |output| self.allocator.free(output);
        self.allocator.free(self.output_words);
        self.execution_trace.deinit();
        self.state_chain_tracker.deinit();
        self.entry_access_clocks.deinit(self.allocator);
        self.exit_access_clocks.deinit(self.allocator);
        self.rw_memory.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn isComplete(self: SegmentResult) bool {
        return self.completion_reason != null;
    }

    /// Fail closed at the only V1 compatibility seam.  V1 public compensation
    /// assumes all initial register and memory predecessor clocks are zero;
    /// an adjacent non-first segment requires versioned V2 public data.
    pub fn requireV1SingleExecution(
        self: SegmentResult,
    ) error{SegmentedExecutionRequiresPublicDataV2}!void {
        if (!self.segment_role.is_first or !self.segment_role.is_last or
            self.completion_reason == null)
        {
            return error.SegmentedExecutionRequiresPublicDataV2;
        }
        for (self.entry_access_clocks.register_clocks) |clock|
            if (clock != 0) return error.SegmentedExecutionRequiresPublicDataV2;
        if (self.entry_access_clocks.memory_clocks.len != 0)
            return error.SegmentedExecutionRequiresPublicDataV2;
    }
};

pub const Poseidon2SegmentResult = struct {
    base: SegmentResult,
    calls: guest_precompile.call_buffer.Frozen,
    execution_rows: guest_precompile.poseidon2_v1.FrozenExecutionRows,

    pub fn deinit(self: *Poseidon2SegmentResult) void {
        self.calls.deinit();
        self.execution_rows.deinit();
        self.base.deinit();
        self.* = undefined;
    }
};

pub const KeccakfSegmentResult = struct {
    base: SegmentResult,
    calls: guest_precompile.keccakf_call_buffer.Frozen,
    execution_rows: guest_precompile.keccakf_v1.FrozenExecutionRows,

    pub fn deinit(self: *KeccakfSegmentResult) void {
        self.calls.deinit();
        self.execution_rows.deinit();
        self.base.deinit();
        self.* = undefined;
    }
};

/// Segment-owned result for the combined Ethereum execution profile. Each
/// precompile retains an independent local call-index tape.
pub const EthereumSegmentResult = struct {
    base: SegmentResult,
    keccakf_calls: guest_precompile.keccakf_call_buffer.Frozen,
    keccakf_execution_rows: guest_precompile.keccakf_v1.FrozenExecutionRows,
    signer_recovery_calls: guest_precompile.secp256k1_recover_call_buffer.Frozen,
    signer_recovery_execution_rows: guest_precompile.secp256k1_recover_v1.FrozenExecutionRows,

    pub fn deinit(self: *EthereumSegmentResult) void {
        self.keccakf_calls.deinit();
        self.keccakf_execution_rows.deinit();
        self.signer_recovery_calls.deinit();
        self.signer_recovery_execution_rows.deinit();
        self.base.deinit();
        self.* = undefined;
    }
};

/// Allocation-free ownership transfer from the mutable combined extension.
pub fn freezeEthereumSegment(
    base: SegmentResult,
    extension: *guest_precompile.session_state.Ethereum,
) EthereumSegmentResult {
    return .{
        .base = base,
        .keccakf_calls = extension.keccakf_calls.freeze(),
        .keccakf_execution_rows = extension.keccakf_rows.freeze(),
        .signer_recovery_calls = extension.signer_recovery_calls.freeze(),
        .signer_recovery_execution_rows = extension.signer_recovery_rows.freeze(),
    };
}

/// Owned result of running a RISC-V program to completion.
pub const RunResult = struct {
    initial_pc: u32,
    initial_regs: [32]u32,
    cpu_final: Cpu,
    final_pc: u32,
    final_regs: [32]u32,
    step_count: usize,
    completion_reason: CompletionReason,
    completion_address: u32,
    completion_value: u32,
    completion_clock: u32,
    input: []u8,
    input_start: u32,
    input_end: u32,
    output: ?[]u8,
    output_len: u32,
    output_len_addr: u32,
    output_data_addr: u32,
    output_end_addr: u32,
    output_words: []OutputWord,
    execution_trace: trace.Trace,
    state_chain_tracker: state_chain.StateChainTracker,
    /// Sorted RW-memory commitment input and its oracle layout policy.
    rw_memory: memory_state.Snapshot,
    exit_code: ?u32,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *RunResult) void {
        self.allocator.free(self.input);
        if (self.output) |output| self.allocator.free(output);
        self.allocator.free(self.output_words);
        self.execution_trace.deinit();
        self.state_chain_tracker.deinit();
        self.rw_memory.deinit(self.allocator);
        self.* = undefined;
    }
};

/// Owned result for the explicit Poseidon2 extension runner. Keeping extension
/// storage outside `RunResult` preserves the base runner's type and hot state.
pub const Poseidon2RunResult = struct {
    base: RunResult,
    calls: guest_precompile.call_buffer.Frozen,
    execution_rows: guest_precompile.poseidon2_v1.FrozenExecutionRows,

    pub fn deinit(self: *Poseidon2RunResult) void {
        self.calls.deinit();
        self.execution_rows.deinit();
        self.base.deinit();
        self.* = undefined;
    }
};

/// Owned result for the explicit Keccak-f extension runner.
pub const KeccakfRunResult = struct {
    base: RunResult,
    calls: guest_precompile.keccakf_call_buffer.Frozen,
    execution_rows: guest_precompile.keccakf_v1.FrozenExecutionRows,

    pub fn deinit(self: *KeccakfRunResult) void {
        self.calls.deinit();
        self.execution_rows.deinit();
        self.base.deinit();
        self.* = undefined;
    }
};

/// Owned one-shot result for the combined Ethereum execution profile.
pub const EthereumRunResult = struct {
    base: RunResult,
    keccakf_calls: guest_precompile.keccakf_call_buffer.Frozen,
    keccakf_execution_rows: guest_precompile.keccakf_v1.FrozenExecutionRows,
    signer_recovery_calls: guest_precompile.secp256k1_recover_call_buffer.Frozen,
    signer_recovery_execution_rows: guest_precompile.secp256k1_recover_v1.FrozenExecutionRows,

    pub fn deinit(self: *EthereumRunResult) void {
        self.keccakf_calls.deinit();
        self.keccakf_execution_rows.deinit();
        self.signer_recovery_calls.deinit();
        self.signer_recovery_execution_rows.deinit();
        self.base.deinit();
        self.* = undefined;
    }
};

/// Transfer an already-frozen segment payload into its one-shot result.
pub fn ethereumRunFromSegment(
    base: RunResult,
    segment: *const EthereumSegmentResult,
) EthereumRunResult {
    return .{
        .base = base,
        .keccakf_calls = segment.keccakf_calls,
        .keccakf_execution_rows = segment.keccakf_execution_rows,
        .signer_recovery_calls = segment.signer_recovery_calls,
        .signer_recovery_execution_rows = segment.signer_recovery_execution_rows,
    };
}
