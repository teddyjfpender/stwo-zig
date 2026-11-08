//! Focused Stwo facade for official Cairo programs on Apple Metal.

const std = @import("std");

pub const core = @import("stwo_core");
pub const prover = @import("stwo_prover_engine");

pub const backends = struct {
    pub const metal = @import("stwo_metal_backend");
};

pub const frontends = struct {
    pub const cairo = @import("stwo_cairo_frontend");
};

pub const integrations = struct {
    pub const cairo_metal = @import("stwo_cairo_metal_integration").prover;
};

pub const interop = struct {
    pub const atomic_file = @import("atomic_file");
    pub const bzip2 = @import("interop_bzip2");
    pub const output_transaction = @import("output_transaction");
};

test {
    std.testing.refAllDecls(@This());
}
