//! Retained typed adapter authority and quotient lifecycle regressions.
test {
    _ = @import("recursion/tests/vm_composition_program_v2_test.zig");
    _ = @import("recursion/air/tests/universal_typed_component_test.zig");
    _ = @import("recursion/air/tests/universal_typed_quotient_test.zig");
}
