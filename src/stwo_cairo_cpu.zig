//! Focused Stwo facade for official Cairo programs on CPU scalar/SIMD.

const std = @import("std");

pub const core = @import("stwo_core");
pub const prover = @import("stwo_prover_impl");

pub const backends = struct {
    pub const cpu = @import("backends/cpu_scalar/mod.zig");
};

pub const frontends = struct {
    pub const cairo = @import("frontends/cairo/mod.zig");
};

pub const integrations = struct {
    pub const cairo_cpu = @import("integrations/cairo_cpu/mod.zig");
};

pub const interop = struct {
    pub const atomic_file = @import("interop/atomic_file.zig");
    pub const output_transaction = @import("interop/output_transaction.zig");
};

test {
    std.testing.refAllDecls(@This());
}
