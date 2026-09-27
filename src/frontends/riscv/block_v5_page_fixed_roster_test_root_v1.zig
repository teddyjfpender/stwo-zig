test {
    _ = @import("prover/block_v5_page_fixed_roster_test_v1.zig");
    _ = @import("prover/block_v5_page_fixed_transcript_test_v1.zig");
}
test "PAGE fixed roster: actual native factory key original defaults and live bodies retained" {
    @import("block_v5_page_fixed_roster_codegen_v1.zig").stwo_page_fixed_roster_body_gate();
}
