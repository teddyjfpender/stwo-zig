test {
    _ = @import("prover/block_v5_cpu_scoped_job_receive_guard_test_v1.zig");
}
test "cpu scoped receive guard: real receiver and genuine-input transfer harness bodies retained" {
    const Recipe = @import("prover/block_v5_execution_recipe_v1.zig");
    try @import("std").testing.expectEqual(@as(Recipe.Recipe, @enumFromInt(@import("root").BLOCK_V5_EXECUTION_RECIPE)), Recipe.canonical);
    @import("prover/block_v5_cpu_scoped_job_transfer_fixture_v1.zig").stwo_scoped_job_positive_transfer_fixture_body_gate();
    @import("std").mem.doNotOptimizeAway(&@import("prover/block_v5_cpu_scoped_job_receive_v1.zig").verify);
}
