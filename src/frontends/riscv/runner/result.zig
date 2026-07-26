//! Owned output of one RISC-V execution.

const std = @import("std");
const Cpu = @import("cpu.zig").Cpu;
const trace = @import("trace.zig");
const state_chain = @import("state_chain.zig");
const memory_state = @import("memory_state.zig");

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

/// A final, word-aligned guest output value and its last access clock.
pub const OutputWord = struct {
    addr: u32,
    value: u32,
    clock: u32,
};

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
