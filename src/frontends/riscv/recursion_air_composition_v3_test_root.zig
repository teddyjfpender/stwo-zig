//! Compile-isolated executable gate for the versioned 39+2 composition ABI.

const std = @import("std");
const subject = @import("recursion/recursion_air_composition_circuit_v3.zig");
const canonical_empty = @import("recursion/canonical_empty_cohort_v3.zig");
const canonical_empty_test = @import("recursion/canonical_empty_cohort_v3_test.zig");
const focused = @import("recursion/recursion_air_composition_circuit_v3_test.zig");

test "V3 shared recursion composition declarations compile" {
    std.testing.refAllDeclsRecursive(subject);
    std.testing.refAllDeclsRecursive(canonical_empty);
    std.testing.refAllDeclsRecursive(canonical_empty_test);
    std.testing.refAllDeclsRecursive(focused);
}
