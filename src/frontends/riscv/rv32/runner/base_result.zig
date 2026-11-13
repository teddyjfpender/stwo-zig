//! Generic native/Poseidon/Keccak execution results; product records compose these.

const std = @import("std");
const Cpu = @import("stwo_riscv_isa").machine.cpu.Cpu;
const trace = @import("trace.zig");
const state_chain = @import("stwo_riscv_isa").machine.state_chain;
const memory_state = @import("stwo_riscv_isa").machine.memory_state;
const execution_boundary = @import("stwo_riscv_isa").machine.execution_boundary;
pub const CompletionReason = execution_boundary.CompletionReason;
pub const CONTINUATION_SCHEMA_VERSION = execution_boundary.CONTINUATION_SCHEMA_VERSION;
pub const SegmentClockFrame = execution_boundary.SegmentClockFrame;
pub const MemoryAccessClock = execution_boundary.MemoryAccessClock;
pub const AccessClockBoundary = execution_boundary.AccessClockBoundary;
pub const ContinuationToken = execution_boundary.ContinuationToken;
pub const OutputWord = execution_boundary.OutputWord;
const guest_precompile = struct {
    pub const call_buffer = @import("stwo_riscv_precompiles").runner.call_buffer;
    pub const poseidon2_v1 = @import("guest_precompile/poseidon2.zig");
    pub const keccakf_call_buffer = @import("stwo_riscv_precompiles").runner.keccakf_call_buffer;
    pub const keccakf_v1 = @import("guest_precompile/keccakf.zig");
};

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
