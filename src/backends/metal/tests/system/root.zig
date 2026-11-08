//! Resident Metal backend parity test root (formerly the `metal_only` branch
//! of `src/tests.zig`).

const std = @import("std");

test {
    _ = @import("backend_test.zig");
    _ = @import("composition_binding_test.zig");
    _ = @import("composition_fusion_test.zig");
    _ = @import("composition_library_parity_test.zig");
    _ = @import("composition_lift_bridge_test.zig");
    _ = @import("composition_option_b_test.zig");
    std.testing.refAllDecls(@This());
}
