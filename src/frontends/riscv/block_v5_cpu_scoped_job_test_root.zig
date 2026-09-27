test {
    _ = @import("prover/block_v5_cpu_scoped_job_test_v1.zig");
}
test "cpu scoped job: actual dual driver late-bound source fold producer independent reconstruction and setup transfer bodies retained" {
    const Recipe = @import("prover/block_v5_execution_recipe_v1.zig");
    try @import("std").testing.expectEqual(@as(Recipe.Recipe, @enumFromInt(@import("root").BLOCK_V5_EXECUTION_RECIPE)), Recipe.canonical);
    @import("block_v5_cpu_scoped_job_codegen_v1.zig").stwo_cpu_scoped_job_body_gate();
}
