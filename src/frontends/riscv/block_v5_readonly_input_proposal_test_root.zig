//! Selection/physical PCS/late binding; no guest or STARK functions invoked.
test {
    _ = @import("prover/tests/block_v5_readonly_input_proposal_test.zig");
    _ = @import("prover/tests/block_v5_readonly_input_unit_test.zig");
}
