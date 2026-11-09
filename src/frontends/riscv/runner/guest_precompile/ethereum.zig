//! Combined-profile dispatch over independent Keccak and signer-recovery tapes.

const custom0 = @import("stwo_riscv_isa").custom0;
const execution_profile = @import("stwo_riscv_isa").execution_profile;
const Cpu = @import("stwo_riscv_isa").runner_cpu.Cpu;
const Memory = @import("stwo_riscv_isa").runner_memory.Memory;
const MemoryLayout = @import("stwo_riscv_isa").runner_memory_state.MemoryLayout;
const StateChainTracker = @import("stwo_riscv_isa").runner_state_chain.StateChainTracker;
const Trace = @import("stwo_riscv_rv32").runner_trace.Trace;
const keccakf_v1 = @import("stwo_riscv_rv32").runner_guest_precompile_keccakf;
const secp256k1_recover_v1 = @import("stwo_riscv_rv32").runner_guest_precompile_secp256k1_recover;
const session_state = @import("session_state.zig");

pub const ExecutionProfile = execution_profile.ExecutionProfile;

/// Decode once for tape selection, then let the selected transaction recheck
/// the complete fixed instruction word before any mutation.
pub fn executeWithRecordedClock(
    profile: ExecutionProfile,
    inst_word: u32,
    execution_clock: u32,
    cpu: *Cpu,
    memory: *Memory,
    layout: MemoryLayout,
    tracker: *StateChainTracker,
    trace: *Trace,
    extension: *session_state.Ethereum,
) !void {
    return executeWithAggregateRecordedClock(profile, inst_word, execution_clock, cpu, memory, layout, tracker, trace, extension, try extension.externalCounts());
}

/// The enclosing combined session supplies counts across every precompile tape.
/// The selected transaction authenticates these against the trace authority.
pub fn executeWithAggregateRecordedClock(
    profile: ExecutionProfile,
    inst_word: u32,
    execution_clock: u32,
    cpu: *Cpu,
    memory: *Memory,
    layout: MemoryLayout,
    tracker: *StateChainTracker,
    trace: *Trace,
    extension: *session_state.Ethereum,
    counts: session_state.ExternalCounts,
) !void {
    const decoded = try custom0.decode(profile, inst_word);
    switch (decoded.opcode) {
        .keccakf_1600_permute_in_place_v1 => try keccakf_v1.executeWithAggregateRecordedClock(
            profile,
            inst_word,
            execution_clock,
            extension.external_step_origin,
            cpu,
            memory,
            layout,
            tracker,
            trace,
            counts.calls,
            counts.rows,
            &extension.keccakf_calls,
            &extension.keccakf_rows,
        ),
        .secp256k1_recover_signer_v1 => try secp256k1_recover_v1.executeWithRecordedClock(
            profile,
            inst_word,
            execution_clock,
            extension.external_step_origin,
            cpu,
            memory,
            layout,
            tracker,
            trace,
            counts.calls,
            counts.rows,
            &extension.signer_recovery_calls,
            &extension.signer_recovery_rows,
        ),
        .poseidon2_m31_permute_in_place_v1, .sha256_compress_v1 => return error.InvalidPrecompileEncoding,
    }
}
