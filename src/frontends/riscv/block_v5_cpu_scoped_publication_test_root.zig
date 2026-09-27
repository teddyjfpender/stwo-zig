test {
    _ = @import("prover/block_v5_cpu_scoped_publication_test_v1.zig");
}

test "cpu scoped publication: actual complete requester fold and requester job bodies retained without invocation" {
    const std = @import("std");
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const Fold = @import("prover/block_v5_cpu_scoped_job_fold_v1.zig");
    std.mem.doNotOptimizeAway(&Fold.ForBackend(Cpu).run);
    std.mem.doNotOptimizeAway(&Fold.ForRecipe(.complete).ForBackend(Cpu).run);
    std.mem.doNotOptimizeAway(&Fold.ForRecipe(.requesters).ForBackend(Cpu).run);
    std.mem.doNotOptimizeAway(&@import("prover/block_v5_cpu_requester_job_v1.zig").ForBackend(Cpu).build);
}
