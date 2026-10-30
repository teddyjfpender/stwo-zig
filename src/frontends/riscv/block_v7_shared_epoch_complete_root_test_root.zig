//! Same genuine execution and hostile cases as the independent-prefix baseline.
//! Opt-in shared epoch must preserve every original verifier/global obligation.
test "v7 shared epoch actual complete root" {
    try @import("prover/tests/block_v7_complete_root_test.zig").qualify(true);
}
