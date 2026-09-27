comptime {
    _ = @import("recursion/air/blake3_parent_append_test.zig");
    _ = @import("prover/blake3_continuation_witness_test.zig");
    _ = @import("recursion/air/blake3_memory_custody_test.zig");
    _ = @import("recursion/air/blake3_memory_update_chain_test.zig");
    _ = @import("recursion/air/blake3_memory_update_proof_test.zig");
}
