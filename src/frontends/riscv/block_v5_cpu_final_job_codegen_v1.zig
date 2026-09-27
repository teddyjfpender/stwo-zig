//! Actual PUB21/FINAL22 row reconstruction, consuming prover and fresh receive
//! retention. This marker does not invoke any proof or create a Fresh.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Job = @import("prover/block_v5_cpu_final_job_v1.zig");
pub export fn stwo_cpu_final_job_body_gate() void {
    inline for (.{ &Job.ForBackend(Cpu).build, &Job.publish, &Job.reconstruct, &Job.Owner.deinit, &Job.Built.deinit, &@import("recursion/block_v5_requester_public_preparation_v1.zig").prepare, &@import("recursion/block_v5_requester_public_receiver_v1.zig").verify, &@import("recursion/block_v5_requester_public_source_v1.zig").Source.init, &@import("recursion/block_v5_requester_memory_preparation_v1.zig").prepare, &@import("recursion/block_v5_requester_memory_receiver_v1.zig").verify, &@import("recursion/block_v5_source_ram_forest_join_source_v1.zig").Source.init }) |body| std.mem.doNotOptimizeAway(body);
}
