//! Focused Stwo facade for the Sail RV32IM + CPU/SIMD product.
//!
//! This is intentionally not `src/stwo.zig`: declarations outside this
//! product's capability closure cannot enter the focused executable through a
//! convenience re-export.

pub const core = @import("stwo_core");
pub const prover = @import("stwo_prover_impl");

pub const frontends = struct {
    pub const riscv = @import("stwo_riscv_frontend");
};

pub const integrations = struct {
    pub const riscv_cpu = @import("integrations/riscv_cpu/mod.zig");
};

pub const interop = struct {
    pub const atomic_file = @import("interop/atomic_file.zig");
    pub const postcard = @import("interop/postcard.zig");
    pub const riscv_artifact = @import("interop/riscv_artifact.zig");
};
