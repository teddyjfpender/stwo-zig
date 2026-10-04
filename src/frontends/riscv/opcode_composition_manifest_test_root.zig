//! Compile-isolated E-022 opcode composition-manifest gate.

test {
    _ = @import("air/lang/tests/opcode_composition_manifest_test.zig");
    _ = @import("air/tests/relation_export_test.zig");
}
