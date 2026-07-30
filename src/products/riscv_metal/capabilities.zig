//! Authoritative capability and release-admission data for Sail RV32IM on the
//! fail-closed Metal backend.
//!
//! Every string below except `backend` is deliberately byte-identical to
//! `src/products/riscv_cpu/capabilities.zig`: the RISC-V *adapter* release gate
//! is a property of the AIR, not of the commitment backend, so both product
//! lanes must take the same admission path and report the same adapter, AIR and
//! ISA identity. Only the backend token distinguishes them, and it is the single
//! value that flows into this product's registry `backends` list.
//!
//! The two files are intentionally not shared: importing the CPU product's
//! capabilities here would put `src/products/riscv_cpu` inside the Metal
//! product's source closure, which the closure gate forbids.

/// RF-01 flips this in the same commit as the artifact release status after
/// every RISC-V soundness and oracle gate passes. It must stay in lockstep with
/// the CPU product's value so `riscv_cli_admission` needs only a backend
/// substitution to admit this CLI.
pub const adapter_release_gated = true;
pub const adapter = "sail-rv32im-zkvm-elf";
pub const air = "sail_rv32im_zkvm_v1";
pub const isa = "rv32im";
pub const backend = "metal";
pub const deferred_reason = "RISC-V formal release contract is not yet fully satisfied";

pub fn requireAdmission(experimental: bool) !void {
    if (adapter_release_gated) {
        if (experimental) return error.ExperimentalFlagAfterPromotion;
    } else if (!experimental) {
        return error.ExperimentalFlagRequired;
    }
}

test "staged admission is explicit and fail closed" {
    const std = @import("std");
    if (adapter_release_gated) {
        try requireAdmission(false);
        try std.testing.expectError(error.ExperimentalFlagAfterPromotion, requireAdmission(true));
    } else {
        try requireAdmission(true);
        try std.testing.expectError(error.ExperimentalFlagRequired, requireAdmission(false));
    }
}

test "this product can only ever report the Metal backend" {
    const std = @import("std");
    try std.testing.expectEqualStrings("metal", backend);
}
