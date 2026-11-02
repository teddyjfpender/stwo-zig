test {
    _ = @import("word16_execution/memory/joint_write_invariants_test.zig");
    _ = @import("word16_execution/memory/joint_write_proof_test.zig");
    _ = @import("word16_execution/memory/affine_projection_test.zig");
    _ = @import("word16_execution/memory/range_induction_proof_test.zig");
    _ = @import("word16_execution/memory/range_induction_test.zig");
    _ = @import("word16_execution/memory/boundary_anchor_test.zig");
    _ = @import("word16_execution/memory/parallel_test.zig");
    _ = @import("word16_execution/memory/expected_claim_test.zig");
    _ = @import("word16_execution/memory/native_test.zig");
}
