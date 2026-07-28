//! Unstable package-owned hooks for adversarial and structural tests.
//!
//! Keeping these behind one named namespace lets repository tests exercise
//! committed-witness rejection without turning their implementation files into
//! cross-package relative-import entry points.

pub const clock_update_component_test =
    @import("air/clock_update_component_test.zig");
pub const relation_export_components_test =
    @import("air/relation_export_components_test.zig");
pub const relation_export_test = @import("air/relation_export_test.zig");
pub const semantic_component_test = @import("air/semantic_component_test.zig");
pub const jalr_semantics = @import("air/semantics/jalr.zig");
pub const prover_orchestration = @import("prover/orchestration.zig");
pub const witness_hook = @import("prover/test_witness_hook.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
