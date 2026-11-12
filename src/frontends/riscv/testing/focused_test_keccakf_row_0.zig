//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("cases/air/guest_precompile/tests/keccakf_tables_test.zig");
    _ = @import("cases/air/guest_precompile/tests/keccakf_multiplicities_test.zig");
    _ = @import("cases/air/guest_precompile/tests/keccakf_trace_test.zig");
    _ = @import("cases/air/guest_precompile/tests/keccakf_air_test.zig");
    _ = @import("cases/air/guest_precompile/tests/keccakf_interaction_test.zig");
    _ = @import("cases/air/guest_precompile/tests/keccakf_component_test.zig");
    _ = @import("cases/air/guest_precompile/tests/keccakf_table_component_test.zig");
    _ = @import("cases/runner/guest_precompile/tests/keccakf_test.zig");
}
