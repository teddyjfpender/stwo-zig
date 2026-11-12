//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("compat/host/mod.zig");
    _ = @import("compat/assembly/rv32/diagnostics/segment_manifest.zig");
    _ = @import("compat/tests/testing/cases/runner/guest_precompile/tests/c011_semantic_equivalence_test.zig");
    _ = @import("runner/guest_precompile/tests/ethereum_runner_test.zig");
    _ = @import("runner/guest_precompile/mod.zig");
    _ = @import("compat/tests/testing/cases/runner/guest_precompile/tests/runner_test.zig");
    _ = @import("compat/tests/testing/cases/runner/tests/host_integration_test.zig");
    _ = @import("compat/assembly/rv32/runner/minimal_trace/mod.zig");
    _ = @import("compat/tests/rv32/runner/minimal_trace/test.zig");
    _ = @import("runner/mod.zig");
    _ = @import("compat/qualification/sail_oracle.zig");
    _ = @import("compat/assembly/rv32/runner/trace_dump.zig");
}
