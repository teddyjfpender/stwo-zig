//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("cases/prover/guest_precompile/tests/split_pcs_prepare_test.zig");
    _ = @import("cases/prover/guest_precompile/tests/proof_finalize_test.zig");
    _ = @import("cases/prover/guest_precompile/tests/trace_geometry_test.zig");
    _ = @import("cases/prover/guest_precompile/tests/types_test.zig");
}
