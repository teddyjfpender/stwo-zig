test {
    _ = @import("poseidon2_outer/truth_local_gkr/resource.zig");
    _ = @import("poseidon2_outer/truth_local_gkr/security.zig");
    _ = @import("poseidon2_outer/truth_local_gkr/actual_test.zig");
    _ = @import("poseidon2_outer/truth_local_gkr/r6_leaf_test.zig");
    _ = @import("poseidon2_outer/truth_local_gkr/projection.zig");
    _ = @import("poseidon2_outer/truth_local_gkr/leaf_test.zig");
    _ = @import("poseidon2_outer/truth_local_gkr/legacy_parity_test.zig");
    _ = @import("word16_global_execution/services/roster.zig");
    _ = @import("poseidon2_outer/truth_local_gkr/worker_test.zig");
    _ = @import("poseidon2_outer/truth_local_gkr/child_test.zig");
    _ = @import("poseidon2_outer/truth_local_gkr/fixture_test.zig");
    _ = @import("poseidon2_outer/truth_local_gkr/native.zig");
    _ = @import("poseidon2_outer/truth_local_gkr/authority.zig");
    _ = @import("poseidon2_outer/truth_local_gkr/source_inputs.zig");
    _ = @import("poseidon2_outer/native_omul/proof_test.zig");
    _ = @import("poseidon2_outer/native_omul/row.zig");
    _ = @import("poseidon2_outer/native_omul/scope.zig");
    _ = @import("poseidon2_outer/pure_p2_gkr_template.zig");
    _ = @import("poseidon2_outer/pure_p2_gkr_templates_wire.zig");
    _ = @import("poseidon2_outer/om31_actual_census_test.zig");
    _ = @import("poseidon2_outer/om31_operation_census_test.zig");
    _ = @import("poseidon2_outer/pure_p2_op_recursion_test.zig");
    _ = @import("poseidon2_outer/pure_p2_op_root_receiver_test.zig");
    _ = @import("poseidon2_outer/pure_p2_truth_leaf_test.zig");
    _ = @import("poseidon2_outer/pure_p2_tower_leaf_test.zig");
    _ = @import("poseidon2_outer/pure_p2_parity_test.zig");
    _ = @import("poseidon2_outer/pure_p2_cpu_fixture.zig");
    _ = @import("poseidon2_outer/pure_p2_cpu_leaf_test.zig");
    _ = @import("poseidon2_outer/pure_p2_op_cpu_leaf_test.zig");
    _ = @import("poseidon2_outer/pure_p2_fold_test.zig");
    _ = @import("poseidon2_outer/pure_p2_heterogeneous_fold_test.zig");
}

test {
    _ = @import("poseidon2_outer/native_omul/source_census_test.zig");
}

test {
    _ = @import("poseidon2_outer/native_omul/fold_test.zig");
}

test {
    _ = @import("poseidon2_outer/native_omul/root_test.zig");
}

test {
    _ = @import("poseidon2_outer/miller_local_gkr/authority.zig");
    _ = @import("poseidon2_outer/miller_local_gkr/source_inputs.zig");
}

test {
    _ = @import("poseidon2_outer/miller_local_gkr/native.zig");
    _ = @import("poseidon2_outer/miller_local_gkr/projection.zig");
}

test {
    _ = @import("poseidon2_outer/miller_local_gkr/equations.zig");
    _ = @import("poseidon2_outer/miller_local_gkr/witness.zig");
}

test {
    _ = @import("poseidon2_outer/miller_local_gkr/global_witness.zig");
}

test {
    _ = @import("poseidon2_outer/miller_local_gkr/component.zig");
}

test {
    _ = @import("poseidon2_outer/miller_local_gkr/physical_test.zig");
}
