//! Focused Stwo facade for the Sail RV32IM + CPU/SIMD product.
//!
//! This is intentionally not `src/products/stwo/root.zig`: declarations outside this
//! product's capability closure cannot enter the focused executable through a
//! convenience re-export.

pub const core = @import("stwo_core");
pub const prover = @import("stwo_prover_engine");

pub const frontends = struct {
    pub const riscv = @import("legacy_riscv_frontend");
};

pub const integrations = struct {
    pub const riscv_cpu = @import("legacy_riscv_cpu_integration");
};

pub const interop = struct {
    pub const atomic_file = @import("atomic_file");
    pub const postcard = @import("interop_postcard");
    pub const riscv_artifact = @import("interop_riscv_artifact");
};
