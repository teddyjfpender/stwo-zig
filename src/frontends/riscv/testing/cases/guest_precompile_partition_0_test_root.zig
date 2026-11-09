//! One required compilation partition of the complete focused target.

test {
    _ = @import("stwo_riscv_precompiles");
    _ = @import("air/guest_precompile/tests/caller_component_test.zig");
    _ = @import("air/guest_precompile/tests/caller_component_prepared_test.zig");
    _ = @import("air/guest_precompile/tests/direct_constraints_test.zig");
    _ = @import("air/guest_precompile/tests/interaction_chunk_test.zig");
    _ = @import("air/guest_precompile/tests/interaction_test.zig");
}
