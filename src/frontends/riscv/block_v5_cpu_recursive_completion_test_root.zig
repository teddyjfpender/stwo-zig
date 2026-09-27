test {
    _ = @import("prover/block_v5_cpu_recursive_completion_test_v1.zig");
    _ = @import("prover/block_v5_cpu_recursive_completion_rollback_test_v1.zig");
}
pub export fn stwo_cpu_recursive_completion_body_gate() void {
    const std = @import("std");
    std.mem.doNotOptimizeAway(&@import("prover/block_v5_cpu_recursive_completion_v1.zig").publish);
    std.mem.doNotOptimizeAway(&@import("prover/block_v5_cpu_driver_common_v1.zig").ForCapacity(true).run);
    std.mem.doNotOptimizeAway(&@import("prover/block_v5_cpu_driver_common_v1.zig").ForCapacity(false).run);
    std.mem.doNotOptimizeAway(&@import("ethereum_block_v5_cpu_produce.zig").main);
}
test "cpu recursive completion: actual selected coordinator and both original driver bodies retained without running" {
    stwo_cpu_recursive_completion_body_gate();
}
