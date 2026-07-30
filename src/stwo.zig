//! Root module for stwo-zig.
const std = @import("std");

pub const core = @import("stwo_core");
pub const backend = @import("stwo_backend_contracts");
pub const prover_api = @import("stwo_prover_api");
pub const backends = @import("backends/mod.zig");
pub const prover = @import("stwo_prover_engine");
pub const frontends = @import("frontends/mod.zig");
pub const integrations = @import("integrations/mod.zig");
pub const examples = @import("stwo_native_examples");
pub const interop = @import("interop/mod.zig");
pub const metal_session = @import("stwo_metal_session");
pub const std_shims = @import("std_shims/mod.zig");
pub const tracing = @import("tracing/mod.zig");

test {
    // Ensure `zig build test` at least compiles the root graph eagerly.
    std.testing.refAllDecls(@This());
}
