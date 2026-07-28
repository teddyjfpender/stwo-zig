//! Cross-module tests that do not belong to one public package surface.

const std = @import("std");
const test_options = @import("test_options");

test {
    if (test_options.metal_only) {
        _ = @import("tests/metal/backend_test.zig");
        // Reachability, not preference: no green step compiles the `else` branch
        // below (it is selected by neither `metal_only` nor `riscv_only`), so a
        // test placed there would compile nowhere and run nowhere. `metal-test`
        // is the one step that both owns `stwo_cairo_metal_integration` and
        // filters on the `metal:` prefix this test's name carries.
        _ = @import("tests/metal/composition_binding_test.zig");
        _ = @import("tests/metal/composition_fusion_test.zig");
        _ = @import("tests/metal/composition_library_parity_test.zig");
        _ = @import("tests/metal/composition_lift_bridge_test.zig");
        _ = @import("tests/metal/composition_option_b_test.zig");
    } else if (test_options.riscv_only) {
        if (test_options.riscv_exhaustive) {
            _ = @import("tests/riscv/trace_test.zig");
        } else {
            _ = @import("tests/riscv/product_test.zig");
        }
    } else {
        _ = @import("tests/cairo/prove_trace_test.zig");
        _ = @import("tests/cairo/prover_test.zig");
        _ = @import("tests/cairo/source_semantic_pack_test.zig");
        _ = @import("tests/cairo/claim_generator_test.zig");
        _ = @import("tests/cairo/metal_process_backend_test.zig");
        _ = @import("tests/cairo/statement_bootstrap_test.zig");
        _ = @import("tests/metal/arena_plan_test.zig");
        _ = @import("tests/metal/cairo_transcript_fixture_test.zig");
        _ = @import("tests/metal/eval_codegen_test.zig");
        _ = @import("tests/metal/recipe_requirements_test.zig");
        _ = @import("tests/metal/runtime_decommit_geometry_test.zig");
        _ = @import("stwo_metal_session").artifact_manifest;
        _ = @import("stwo_metal_session").artifact_store;
        _ = @import("stwo_metal_session").artifact_views;
    }
    std.testing.refAllDecls(@This());
}
