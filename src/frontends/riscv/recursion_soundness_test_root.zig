//! Focused recursion soundness tests with the frontend directory as module root.
//! Keep this separate from the complete frontend inventory so changing one
//! recursive gate does not recompile the entire RISC-V test corpus.
test {
    _ = @import("recursion/tests/transcript_program_v2_test.zig");
    _ = @import("recursion/tests/recursion_air_composition_circuit_test.zig");
    _ = @import("recursion/ethereum_vm_composition_graph_base_v2.zig");
    _ = @import("recursion/vm_public_semantics_circuit_logup_reference.zig");
    _ = @import("recursion/tests/fixed_wire_custody_test.zig");
    _ = @import("recursion/tests/segment_statement_outer_source_v2_test.zig");
    _ = @import("recursion/detached_fixed_tree0_key_recipe_v1.zig");
    _ = @import("recursion/detached_native_column_geometry_v1.zig");
    _ = @import("recursion/detached_fixed_tree0_pcs_recipe_v1.zig");
    _ = @import("recursion/air/tests/universal_shared_provider_test.zig");
    _ = @import("recursion/air/tests/segment_outer_adapter_manifest_v2_test.zig");
    _ = @import("leaf_manifest_contract_test_root.zig");
}
