//! Nonproving exact-roster publication/codec guards and retained real bodies.
const std = @import("std");
test "source PAGE publisher root" {
    _ = @import("prover/block_v5_memory_source_page_job_test_v1.zig");
    _ = @import("prover/block_v5_memory_source_unified_page_codec_test_v1.zig");
}
test "source PAGE publisher bodies: actual Job and opted-in Controller publication" {
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const Job = @import("prover/block_v5_memory_source_page_job_v1.zig").ForBackend(Cpu).Job;
    inline for (.{ &Job.publishAll, &Job.publishNext, &@import("prover/block_v5_cpu_source_pages_v1.zig").publishAndVerify }) |body| std.mem.doNotOptimizeAway(body);
}
