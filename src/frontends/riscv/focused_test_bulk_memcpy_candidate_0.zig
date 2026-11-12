//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("compat/product_tree/isa/ethereum_bulk_memcpy_candidate.zig");
    _ = @import("runner/ethereum_bulk_memcpy_candidate_result.zig");
    _ = @import("runner/ethereum_candidate_combined_result.zig");
    _ = @import("runner/guest_precompile/ethereum_bulk_memcpy_candidate.zig");
    _ = @import("runner/guest_precompile/tests/ethereum_bulk_memcpy_candidate_test.zig");
    _ = @import("runner/guest_precompile/ethereum_candidate_combined_dispatch.zig");
    _ = @import("runner/guest_precompile/ethereum_candidate_combined_elf_receipt.zig");
    _ = @import("runner/guest_precompile/tests/ethereum_candidate_combined_test.zig");
    _ = @import("runner/guest_precompile/ethereum_candidate_combined.zig");
}
