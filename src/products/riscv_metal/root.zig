//! Focused facade for the RV32IM frontend and fail-closed Metal engine.
//!
//! This is the Metal counterpart of `src/stwo_riscv_cpu.zig`: declarations
//! outside this product's capability closure cannot enter the focused executable
//! through a convenience re-export. The `interop` namespace mirrors that file
//! because the engine-generic proof adapter reaches the artifact wire, the
//! postcard proof encoding and the atomic publication helpers through the
//! product facade it is handed as `stwo`.

pub const core = @import("stwo_core");
pub const prover = @import("stwo_prover_engine");

pub const frontends = struct {
    pub const riscv = @import("stwo_riscv_frontend");
};

pub const integrations = struct {
    pub const riscv_metal = @import("stwo_riscv_metal_integration");
};

pub const interop = struct {
    pub const atomic_file = @import("../../interop/atomic_file.zig");
    pub const postcard = @import("../../interop/postcard.zig");
    pub const riscv_artifact = @import("../../interop/riscv_artifact.zig");
};

test {
    @import("std").testing.refAllDecls(@This());
}
