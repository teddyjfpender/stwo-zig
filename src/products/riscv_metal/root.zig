//! Focused facade for the RV32IM frontend and fail-closed Metal engine.
//!
//! This is the Metal counterpart of `src/stwo_riscv_cpu.zig`: declarations
//! outside this product's capability closure cannot enter the focused executable
//! through a convenience re-export. The `interop` namespace mirrors that file
//! because the engine-generic proof adapter reaches the artifact wire, the
//! postcard proof encoding and the atomic publication helpers through the
//! product facade it is handed as `stwo`.
//!
//! Unlike the CPU facade, the three interop files arrive as named modules
//! (`interop_atomic_file`, `interop_postcard`, `interop_riscv_artifact`, wired in
//! `build_support/products/riscv_metal.zig`). `src/stwo_riscv_cpu.zig` can write
//! `@import("interop/atomic_file.zig")` because its module root is `src/`; this
//! facade's root is two directories deeper and Zig rejects a relative `@import`
//! that escapes the importing module's root directory.

pub const core = @import("stwo_core");
pub const prover = @import("stwo_prover_engine");

pub const frontends = struct {
    pub const riscv = @import("stwo_riscv_frontend");
};

pub const integrations = struct {
    pub const riscv_metal = @import("stwo_riscv_metal_integration");
};

pub const interop = struct {
    pub const atomic_file = @import("interop_atomic_file");
    pub const postcard = @import("interop_postcard");
    pub const riscv_artifact = @import("interop_riscv_artifact");
};

test {
    @import("std").testing.refAllDecls(@This());
}
