//! Focused Stwo facade for official Cairo programs on CPU scalar/SIMD.

const std = @import("std");

pub const core = @import("stwo_core");
pub const prover = @import("stwo_prover_engine");

pub const backends = struct {
    pub const cpu = @import("stwo_cpu_backend");
};

pub const frontends = struct {
    pub const cairo = @import("stwo_cairo_frontend");
};

pub const integrations = struct {
    pub const cairo_cpu = @import("stwo_cairo_cpu_integration");
};

pub const interop = struct {
    pub const atomic_file = @import("interop/atomic_file.zig");
    pub const bzip2 = @import("interop/bzip2.zig");
    pub const output_transaction = @import("interop/output_transaction.zig");
};

test {
    std.testing.refAllDecls(@This());
}
