//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("../../composition/vm/vm_air_composition_circuit.zig");
    _ = @import("../vm_air_profile_test.zig");
    _ = @import("../vm_leaf_context_test.zig");
}
