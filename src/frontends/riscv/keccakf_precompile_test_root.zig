//! Fast edit-loop root for the Keccak-f precompile authority.

test {
    _ = @import("air/guest_precompile/keccakf_row.zig");
    _ = @import("air/guest_precompile/tests/keccakf_authority_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_relations_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_tables_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_multiplicities_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_trace_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_air_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_interaction_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_component_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_table_component_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_witness_test.zig");
    _ = @import("air/guest_precompile/tests/keccakf_throughput_candidate_test.zig");
    _ = @import("isa/custom0.zig");
    _ = @import("runner/guest_precompile/tests/keccakf_v1_test.zig");
    _ = @import("runner/guest_precompile/tests/keccakf_runner_test.zig");
}
