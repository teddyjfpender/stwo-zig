const std = @import("std");
const Spool = @import("prover/block_v5_memory_source_fold_spool_v1.zig");
const Job = @import("prover/block_v5_memory_source_page_job_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend).Job;
test "source fold spool bodies: real original collect stream and Job typed commit path" {
    inline for (.{ &Spool.collect, &Spool.Reader.open, &Spool.Reader.next, &Job.collectWithOperations, &@import("prover/block_v5_cpu_source_pages_v1.zig").collect }) |body| std.mem.doNotOptimizeAway(body);
}
