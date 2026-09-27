//! Typed production receive seam for the exact nested open v3 forest. Native
//! leaf policy must come from the complete receiver's internal fresh callback;
//! independently pinned recursive setups/schedules choose every verifier. The
//! actual outer STARK proves the entire mixed DAG, not a digest-only fold.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const mixed = @import("../prover/block_v5_open_exact_forest_plan_v1.zig");
const normalized = @import("block_v5_open_child_frames_v2.zig");
const bus = @import("block_v5_open_parent_public_bus_v2.zig");
const protocol = @import("block_v5_reusable_open_parent_protocol_v2.zig");
const parent = @import("blake3_execution_parent_proof.zig");
const open_receiver = @import("block_v5_open_parent_receiver_v2.zig");
pub const LeafPolicy = @import("block_v5_open_parent_receiver_v1.zig").ExpectedChild;
pub const NodePin = struct { key: protocol.Key, expected_id: [32]u8, schedule: []const bus.Wire };
pub const OuterPins = open_receiver.OuterPins;
pub const FilePin = struct { byte_len: u64, sha256: [32]u8 };
pub const Limits = struct { max_execution_count: u32, max_outer_proof_bytes: u64 };
pub const Verified = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    sealed_digest: [32]u8,
    execution_count: u32,
    combined_native_open_sum: Q,
    span: @import("block_v5_pc_clock_span_v1.zig").Span,
    pub fn deinit(self: *Verified) void {
        self.equation.deinit();
        self.* = undefined;
    }
};

/// Explicit typed specialization; original leaf policy/API remain the default.
pub const ForLeafAdapter = @import("block_v5_open_exact_forest_receiver_impl_v1.zig").ForLeafAdapter;
const Default = ForLeafAdapter(@import("block_v5_native_exact_leaf_adapter_v1.zig"));
pub const verifyLoaded = Default.verifyLoaded;
pub const verifyLoadedWithLimits = Default.verifyLoadedWithLimits;
pub const admitLeafPolicy = Default.admitLeafPolicy;
