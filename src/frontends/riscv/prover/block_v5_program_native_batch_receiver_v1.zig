//! Explicit v1 program admission; fresh verification uses the shared body.
const Impl = @import("block_v5_program_native_batch_common_v1.zig").ForNative(@import("block_v5_native_execution_proof_v1.zig"), @import("block_v5_native_template_protocol.zig"), @import("blake3_commitment_plan.zig").Admission, false);
pub const InstancePin = Impl.InstancePin;
pub const ExtensionPin = Impl.ExtensionPin;
pub const Loader = Impl.Loader;
pub const Hooks = Impl.Hooks;
pub const ScopedPrograms = Impl.ScopedPrograms;
pub const ForBackend = Impl.ForBackend;
