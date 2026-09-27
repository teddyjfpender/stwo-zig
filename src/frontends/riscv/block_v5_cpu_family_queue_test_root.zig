const std = @import("std");
const Driver = @import("prover/block_v5_cpu_driver_v1.zig");
comptime {
    _ = @import("prover/block_v5_cpu_family_queue_test.zig");
}
test "v5 independent family driver body codegen without execution or segment proving" {
    std.mem.doNotOptimizeAway(&Driver.run);
}
test "v5 independent family CLI body codegen without execution or segment proving" {
    std.mem.doNotOptimizeAway(&@import("ethereum_block_v5_cpu_produce.zig").main);
}
