//! Explicit v3 program admission; fresh verification uses the shared body.
const Impl = @import("block_v5_program_native_batch_common_v1.zig").ForNativeProtocol(@import("block_v5_native_execution_proof_v3.zig"), @import("block_v5_native_template_protocol_v3.zig"), @import("block_v5_native_public_admission_v1.zig").Admission, true, true);
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
