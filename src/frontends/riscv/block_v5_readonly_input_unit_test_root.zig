//! Isolated authenticated input classification; no guest/STARK/segment runs.
test {
    _ = @import("prover/tests/block_v5_readonly_input_unit_test.zig");
}
