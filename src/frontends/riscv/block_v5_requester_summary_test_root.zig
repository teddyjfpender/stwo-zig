test {
    _ = @import("prover/block_v5_requester_summary_test_v1.zig");
}
test "requester summary: actual static producer fresh receiver source and planner bodies retained without invocation" {
    const std = @import("std");
    const Owner = @import("recursion/block_v5_heterogeneous_scoped_owner_v1.zig");
    std.mem.doNotOptimizeAway(&Owner.ForRecipe(.requesters).prepareJob);
    std.mem.doNotOptimizeAway(&Owner.ForRecipe(.requesters).init);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_scoped_plan_v1.zig").ForRecipe(.requesters).init);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_requester_summary_source_v1.zig").Source.init);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_requester_summary_source_v1.zig").Admission.validate);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_scoped_owned_receiver_v1.zig").verify);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_scoped_owned_receiver_v1.zig").verifyLeaf);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_scoped_owned_preparation_v1.zig").prepareVerifierRows);
    std.mem.doNotOptimizeAway(&@import("prover/block_v5_heterogeneous_scoped_owned_stage_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend).publish);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_source_ram_forest_join_source_v1.zig").Source.init);
}
