//! Focused root for the M9 Poseidon2 mixed-leaf reference (default-off flag
//! STWO_RV64_M9_POSEIDON2_LEAVES). `zig test src/core/m9_poseidon2_leaves_test_root.zig`
test {
    _ = @import("vcs_lifted/poseidon2_m31_mixed_leaf.zig");
}
