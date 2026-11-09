//! Focused segment-statement V2 boundary/root test root.

test {
    _ = @import("stwo_riscv_isa").modules.access_clock;
    _ = @import("recursion/tests/segment_statement_test.zig");
    _ = @import("recursion/tests/segment_statement_transcript_layout_test.zig");
    _ = @import("stwo_riscv_rv32").modules.recursion_segment_statement_identity_preimage;
    _ = @import("stwo_riscv_rv32").modules.air_statement_authority_preimage;
}
