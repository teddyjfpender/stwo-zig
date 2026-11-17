//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("cases/air/guest_precompile/tests/provider_component_test.zig");
    _ = @import("cases/prover/guest_precompile/tests/component_assembly_test.zig");
    _ = @import("cases/prover/guest_precompile/tests/split_component_assembly_test.zig");
    _ = @import("cases/prover/guest_precompile/tests/split_leaf_statement_test.zig");
    _ = @import("cases/prover/guest_precompile/tests/split_leaf_prepare_test.zig");
    _ = @import("cases/prover/guest_precompile/tests/split_main_trace_test.zig");
}
