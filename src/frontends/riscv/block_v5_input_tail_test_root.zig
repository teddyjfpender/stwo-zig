comptime {
    _ = @import("prover/block_v5_input_tail_test_v1.zig");
}
test "input tail provider body: genuine publisher receiver nested capture and bounded B5PD hash bodies" {
    @import("block_v5_input_tail_codegen_v1.zig").stwo_input_tail_provider_body_gate();
}
