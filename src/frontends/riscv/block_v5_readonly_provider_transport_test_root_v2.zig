//! Transport-only pure fixtures plus genuine production body retention.
test {
    _ = @import("prover/block_v5_readonly_provider_files_test_v2.zig");
}
test "readonly provider transport: actual production bodies retained without invocation" {
    @import("block_v5_readonly_provider_transport_body_v2.zig").retain();
}
