//! Fast edit-loop root for the Keccak-f precompile authority.

test {
    _ = @import("air/guest_precompile/keccakf_authority_test.zig");
    _ = @import("air/guest_precompile/keccakf_relations_test.zig");
    _ = @import("air/guest_precompile/keccakf_tables_test.zig");
    _ = @import("air/guest_precompile/keccakf_witness_test.zig");
    _ = @import("isa/custom0.zig");
    _ = @import("runner/guest_precompile/keccakf_v1_test.zig");
}
