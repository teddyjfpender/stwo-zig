//! Block-v2 typed execution transition proof surface.
//!
//! The receipt shape is shared with the native global closure. A receipt is
//! authoritative only after its same-root typed opcode sidecar STARK has been
//! freshly verified. The implementation of that sidecar is being built in
//! `block_execution_access_bridge_v2.zig`; callers must not construct this
//! record from replay events or a host-only LogUp sum.
const core = @import("stwo_core");

pub const VerifiedExecutionReceipt = struct {
    instance_index: u32,
    transition_sum: core.fields.qm31.QM31,
    first_round_roots: [2][32]u8,
    sealed_channel_digest: [32]u8,
    event_count: u64,
};
