test {
    _ = @import("prover/block_v5_page_fixed_transcript_test_v1.zig");
}
test "PAGE fixed transcript: genuine admitted owner PCS and original live body retention" {
    @import("block_v5_page_fixed_transcript_codegen_v1.zig").stwo_page_fixed_transcript_body_gate();
}
