//! Compile-isolated edit loop for the production VM composition bridge.
//!
//! This root is deliberately tiny.  Zig test filters select which discovered
//! tests run, but they do not reduce the module graph the compiler must
//! analyse.  Importing the broad recursion roots here would therefore defeat
//! this target's purpose and turn every row-18 edit into a rebuild of the
//! complete recursive verifier.

test {
    _ = @import("recursion/air/composition_circuit_test.zig");
    _ = @import("recursion/vm_air_composition_circuit.zig");
    _ = @import("recursion/vm_air_profile_test.zig");
    _ = @import("recursion/vm_leaf_context_test.zig");
}
