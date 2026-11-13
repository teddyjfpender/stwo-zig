//! Physical CPU boundary proofs, also retained in default CPU discovery.
//! Focused commands select a complete subject and enforce its named count.
test {
    _ = @import("word16_execution/alu_fused_tail_proof_test.zig");
    _ = @import("word16_execution/alu_read_induction_proof_test.zig");
    _ = @import("word16_execution/cpu_clock_induction_proof_test.zig");
    _ = @import("word16_execution/cpu_compact_decode_proof_test.zig");
    _ = @import("word16_execution/cpu_fused_tail_proof_test.zig");
    _ = @import("word16_execution/cpu_u8_pairs_proof_test.zig");
    _ = @import("word16_execution/cpu_zero_induction_proof_test.zig");
    _ = @import("word16_execution/ls_fused_pairs_proof_test.zig");
    _ = @import("word16_execution/memory/boundary_anchor_test.zig");
    _ = @import("word16_execution/memory/joint_write_proof_test.zig");
    _ = @import("word16_execution/memory/range_induction_proof_test.zig");
    _ = @import("word16_execution/mul_u8_pairs_proof_test.zig");
    _ = @import("word16_execution/shift_read_induction_proof_test.zig");
}
