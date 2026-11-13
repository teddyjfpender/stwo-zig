//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("cases/air/guest_precompile/tests/caller_component_test.zig");
    _ = @import("cases/air/guest_precompile/tests/caller_component_prepared_test.zig");
    _ = @import("cases/air/guest_precompile/tests/direct_constraints_test.zig");
    _ = @import("cases/air/guest_precompile/tests/interaction_chunk_test.zig");
    _ = @import("cases/air/guest_precompile/tests/interaction_test.zig");
}
