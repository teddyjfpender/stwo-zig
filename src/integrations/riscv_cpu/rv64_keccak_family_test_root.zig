const std = @import("std");
test {
    _ = @import("word16_global_execution/services/gkr_local/keccak_family_profile.zig");
    _ = @import("word16_global_execution/services/gkr_local/truth_worker_test.zig");
    _ = @import("word16_global_execution/ethereum/plan.zig");
}
test "Keccak family coordinator typed body" {
    std.mem.doNotOptimizeAway(&@import("word16_global_execution/services/gkr_local/coordinator.zig").produceWithAuthority);
}
