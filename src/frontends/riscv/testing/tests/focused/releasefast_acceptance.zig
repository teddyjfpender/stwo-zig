//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("cases/recursion/air/tests/range_check_8_8_bridge_test.zig");
    _ = @import("cases/air/lang/tests/opcode_composition_manifest_test.zig");
    _ = @import("cases/prover/tests/blake3_commitment_components_test.zig");
}
