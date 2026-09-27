//! Genuine B5CT/B5CF program closure. Every native/fused proof is freshly
//! verified before hooks; the shared ROM/caller loop preserves open residuals.
const Stack = struct {
    pub const capacity = true;
    pub const Catalog = @import("block_v5_native_capacity_catalog_v1.zig");
    pub const Fused = @import("block_v5_native_capacity_fused_proof_v1.zig");
    pub const Source = @import("block_v5_native_capacity_fused_source_v1.zig");
    pub const Receiver = @import("block_v5_native_capacity_fused_receiver_v1.zig");
};
const Impl = @import("block_v5_program_native_batch_common_v1.zig").ForNativeStack(
    @import("block_v5_native_capacity_proof_v1.zig"),
    @import("block_v5_native_capacity_protocol_v1.zig"),
    @import("block_v5_native_public_admission_v1.zig").Admission,
    true,
    true,
    Stack,
);
pub const InstancePin = Impl.InstancePin;
pub const ExtensionPin = Impl.ExtensionPin;
pub const CallerMemoryPin = Impl.CallerMemoryPin;
pub const Loader = Impl.Loader;
pub const Hooks = Impl.Hooks;
pub const ScopedPrograms = Impl.ScopedPrograms;
pub const ForBackend = Impl.ForBackend;
pub const externalRetirements = Impl.externalRetirements;
pub const expectedInstance = Impl.expectedInstance;
pub const fusedPin = Impl.fusedPin;
