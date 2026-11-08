//! M5 stream outer-gkr: production outer LogUp-GKR section (profile outer_gkr_om31_strict_v1).
test {
    _ = @import("outer_gkr/tests.zig");
    _ = @import("outer_gkr/binding_v2_test.zig");
    _ = @import("outer_gkr/hybrid_air_test.zig");
    _ = @import("outer_gkr/hybrid_wire_test.zig");
    _ = @import("outer_gkr/hybrid_cpu_test.zig");
    _ = @import("outer_gkr/cpu_polynomial_test.zig");
    _ = @import("outer_gkr/cpu_binding_test.zig");
    _ = @import("outer_gkr/cpu_traversal_test.zig");
    _ = @import("outer_gkr/cpu_aux_test.zig");
}
