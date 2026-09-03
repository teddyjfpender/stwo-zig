//! Combined-profile dispatch over independent Keccak and signer-recovery tapes.

const custom0 = @import("../../isa/custom0.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const MemoryLayout = @import("../memory_state.zig").MemoryLayout;
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const Trace = @import("../trace.zig").Trace;
const keccakf_v1 = @import("keccakf_v1.zig");
const secp256k1_recover_v1 = @import("secp256k1_recover_v1.zig");
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
    const decoded = try custom0.decode(profile, inst_word);
    const counts = try extension.externalCounts();
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
        .poseidon2_m31_permute_in_place_v1 => return error.InvalidPrecompileEncoding,
    }
}
