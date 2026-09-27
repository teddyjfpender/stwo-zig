test {
    _ = @import("prover/block_v5_recursive_source_frame_check_test_v1.zig");
    _ = @import("prover/block_v5_recursive_statement_compare_test_v1.zig");
}
test "recursive source frame check: real PUBLIC21 VERSION20 Source and Admission validation bodies without invocation" {
    const std = @import("std");
    const Public = @import("recursion/block_v5_requester_public_source_v1.zig");
    const Memory = @import("recursion/block_v5_source_ram_forest_join_source_v1.zig");
    std.mem.doNotOptimizeAway(&Public.Source.validate);
    std.mem.doNotOptimizeAway(&Memory.Source.validate);
    std.mem.doNotOptimizeAway(&Public.Admission.validate);
    std.mem.doNotOptimizeAway(&Memory.Admission.validate);
}
