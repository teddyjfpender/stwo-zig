//! Cairo VM trace adapter.
//!
//! Converts raw Cairo VM execution output into typed `ProverInput`:
//! - Instruction decoding (`decode.zig`)
//! - Opcode classification into 20 categories (`opcodes.zig`)
//! - Memory relocation (segment:offset → flat addresses)
//! - State transition grouping by opcode

const std = @import("std");
const cpu = @import("../common/cpu.zig");
const memory_mod = @import("../common/memory.zig");

pub const decode = @import("decode.zig");
pub const opcodes = @import("opcodes.zig");
pub const trace_reader = @import("trace_reader.zig");
pub const adapted_input = @import("adapted_input.zig");
pub const official_input = @import("official_input/mod.zig");

const CasmState = cpu.CasmState;
const Memory = memory_mod.Memory;

pub const MemorySegmentAddresses = struct {
    begin_addr: usize,
    stop_ptr: usize,
};

/// Builtin segment descriptors in canonical stwo-cairo order.
pub const BuiltinSegments = struct {
    add_mod_builtin: ?MemorySegmentAddresses = null,
    bitwise_builtin: ?MemorySegmentAddresses = null,
    output: ?MemorySegmentAddresses = null,
    mul_mod_builtin: ?MemorySegmentAddresses = null,
    pedersen_builtin: ?MemorySegmentAddresses = null,
    poseidon_builtin: ?MemorySegmentAddresses = null,
    range_check96_builtin: ?MemorySegmentAddresses = null,
    range_check_builtin: ?MemorySegmentAddresses = null,
    ec_op_builtin: ?MemorySegmentAddresses = null,
};

pub const N_PUBLIC_SEGMENTS: usize = 11;
pub const PublicSegmentContext = [N_PUBLIC_SEGMENTS]bool;

/// State transitions extracted from a Cairo VM trace.
pub const StateTransitions = struct {
    initial_state: CasmState,
    final_state: CasmState,
    casm_states_by_opcode: opcodes.CasmStatesByOpcode,

    pub fn deinit(self: *StateTransitions, allocator: std.mem.Allocator) void {
        self.casm_states_by_opcode.deinit(allocator);
        self.* = undefined;
    }
};

/// Input to the Cairo prover, produced by adapting a Cairo VM trace.
pub const ProverInput = struct {
    state_transitions: StateTransitions,
    memory: Memory,
    pc_count: usize,
    public_memory_addresses: []u32,
    builtin_segments: BuiltinSegments,
    public_segment_context: PublicSegmentContext,

    pub fn deinit(self: *ProverInput, allocator: std.mem.Allocator) void {
        self.state_transitions.deinit(allocator);
        self.memory.deinit(allocator);
        allocator.free(self.public_memory_addresses);
        self.* = undefined;
    }
};
