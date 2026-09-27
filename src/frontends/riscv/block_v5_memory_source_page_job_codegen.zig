//! Retained actual job bodies only. No PCS/proofs/guest/devices invoked.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Job = @import("prover/block_v5_memory_source_page_job_v1.zig").ForBackend(Cpu).Job;
test "source PAGE job bodies: actual collect persist roster seal replay prove decode fresh verify and publication" {
    inline for (.{ &Job.init, &Job.collect, &Job.publishNext, &Job.publishAll, &Job.requirePublished, &Job.deinit }) |body| std.mem.doNotOptimizeAway(body);
}
