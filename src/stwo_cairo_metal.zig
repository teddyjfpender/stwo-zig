//! Focused Stwo facade for official Cairo programs on Apple Metal.

const std = @import("std");

pub const core = @import("stwo_core");
pub const prover = @import("stwo_prover_impl");

pub const backends = struct {
    pub const metal = @import("backends/metal/mod.zig");
};

pub const frontends = struct {
    pub const cairo = @import("frontends/cairo/mod.zig");
};

pub const integrations = struct {
    pub const cairo_metal =
        @import("integrations/cairo_metal/prover/mod.zig");
};

pub const interop = struct {
    pub const atomic_file = @import("interop/atomic_file.zig");
    pub const bzip2 = @import("interop/bzip2.zig");
    pub const output_transaction = @import("interop/output_transaction.zig");
};

test {
    std.testing.refAllDecls(@This());
}
