//! Compile-isolated edit loop for the production VM composition bridge.
//!
//! This root is deliberately tiny.  Zig test filters select which discovered
//! tests run, but they do not reduce the module graph the compiler must
//! analyse.  Importing the broad recursion roots here would therefore defeat
//! this target's purpose and turn every row-18 edit into a rebuild of the
//! complete recursive verifier.

test {
    _ = @import("recursion/air/tests/composition_circuit_test.zig");
    _ = @import("stwo_riscv_recursion").modules.vm_air_composition_circuit;
    _ = @import("stwo_riscv_recursion").modules.tests_vm_air_profile_test;
    _ = @import("stwo_riscv_recursion").modules.tests_vm_leaf_context_test;
}
