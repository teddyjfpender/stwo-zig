//! Product-neutral frontend namespace of the block pipeline. Shared records
//! keep their native owners (`stwo_riscv_rv64`, `stwo_riscv_frontend`); the
//! guest ABI and services session are the only pipeline-local members.
const execution = @import("stwo_riscv_rv64").execution;

pub const rv64_air = @import("stwo_riscv_frontend").rv64_air;
pub const rv64 = struct {
    pub const boundary_capture = execution.boundary_capture;
    pub const checkpoint = execution.checkpoint;
    pub const compact_tape = execution.compact_tape;
    pub const compact_tape_wire = execution.compact_tape_wire;
    pub const decode = execution.decode;
    pub const elf = execution.elf;
    pub const execution_profile = execution.execution_profile;
    pub const fast_execution = execution.fast_execution;
    pub const machine = execution.machine;
    pub const memory = execution.memory;
    pub const ram_word_set = execution.ram_word_set;
    /// Product guest ABI, supplied through the `rv64_pipeline_hooks` module.
    pub const guest_abi = @import("guest_abi.zig");
    /// v1..v3 services session over the neutral `stwo_riscv_rv64` call ABI.
    pub const services = @import("services_session.zig");
};
