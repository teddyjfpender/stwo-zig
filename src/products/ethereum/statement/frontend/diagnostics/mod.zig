//! Explicit product diagnostic compatibility; native diagnostics retain their owners.
const neutral = @import("stwo_riscv_frontend").diagnostics;
pub const revm_legacy = neutral.revm_legacy;
pub const public_values = neutral.public_values;
pub const OPCODE_WITNESS_AUDIT_ENV = neutral.OPCODE_WITNESS_AUDIT_ENV;
pub const segment_manifest = @import("segment_manifest.zig");
