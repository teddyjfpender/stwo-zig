//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("vm_air_composition_circuit.zig");
    _ = @import("tests/vm_air_profile_test.zig");
    _ = @import("tests/vm_leaf_context_test.zig");
}
