//! Proof-independent diagnostic surfaces owned by the RISC-V frontend.

pub const public_values = @import("public_values.zig");

/// Opts a `ReleaseFast` prover into the pre-commit opcode-witness semantic
/// audit. Debug, ReleaseSafe, and ReleaseSmall builds run the audit by default;
/// ReleaseFast normally relies on the proof constraints and verifier instead
/// of evaluating the same direct AIR a second time before commitment.
///
/// Presence is the switch: CI and one-off diagnostics set the variable to `1`.
pub const OPCODE_WITNESS_AUDIT_ENV = "STWO_ZIG_RISCV_AUDIT_OPCODE_WITNESS";

test {
    @import("std").testing.refAllDecls(@This());
}
