//! Focused shared-provider shell and composition gate.
test {
    _ = @import("recursion/air/tests/universal_shared_provider_test.zig");
    _ = @import("recursion/air/universal_shared_provider_composition.zig");
    _ = @import("recursion/air/universal_provider_authority.zig");
}
