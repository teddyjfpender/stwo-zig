//! Actual producer/worker/cache body retention only, without Session/Driver.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
pub export fn stwo_scoped_parent_admission_isolated_body_gate() void {
    @setEvalBranchQuota(1_000_000);
    const Producer = @import("recursion/blake3_native_parent_producer.zig");
    const Workers = @import("recursion/blake3_native_parent_worker.zig");
    const Caches = @import("prover/block_v5_native_recursive_setup_cache_v1.zig");
    const pairs = .{
        .{ @import("recursion/block_v5_recursive_public_bus_v1.zig"), @import("recursion/block_v5_reusable_native_parent_protocol_v1.zig") },
        .{ @import("recursion/block_v5_caller_fused_recursive_public_bus_v1.zig"), @import("recursion/block_v5_reusable_caller_fused_parent_protocol_v1.zig") },
        .{ @import("recursion/block_v5_native_capacity_fused_recursive_public_bus_v1.zig"), @import("recursion/block_v5_reusable_native_capacity_fused_parent_protocol_v1.zig") },
    };
    inline for (pairs) |pair| {
        const Default = Producer.PlanForProtocol(Cpu, pair[1]);
        const Scoped = Producer.PlanForProtocolScopedAdmission(Cpu, pair[1]);
        const DefaultWorker = Workers.WorkerForProtocol(Cpu, pair[1]);
        const Worker = Workers.WorkerForProtocolScopedAdmission(Cpu, pair[1]);
        const Cache = Caches.ForModules(Cpu, pair[0], pair[1]);
        inline for (.{ &Default.init, &Default.tryRebindAdmission, &Default.validateRowsForAdmission, &Default.proveConsumingWithWorkspace, &Scoped.init, &Scoped.tryRebindAdmission, &Scoped.validateRowsForAdmission, &Scoped.releaseAdmission, &Scoped.proveConsumingWithWorkspace, &DefaultWorker.init, &DefaultWorker.proveAdmittedConsuming, &Worker.init, &Worker.Lease.deinit, &Worker.proveAdmittedConsuming, &Cache.init, &Cache.deinit, &Cache.provePreparedConsumingWithPreflight, &Cache.provePreparedConsuming, &Cache.acquire }) |body| std.mem.doNotOptimizeAway(body);
    }
}
