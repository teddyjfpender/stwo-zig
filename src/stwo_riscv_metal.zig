//! Focused facade for the RV32IM frontend and fail-closed Metal engine.

pub const core = @import("stwo_core");
pub const prover = @import("stwo_prover_impl");

pub const frontends = struct {
    pub const riscv = @import("frontends/riscv/mod.zig");
};

pub const integrations = struct {
    pub const riscv_metal = @import("integrations/riscv_metal/mod.zig");
};

test {
    @import("std").testing.refAllDecls(@This());
}
