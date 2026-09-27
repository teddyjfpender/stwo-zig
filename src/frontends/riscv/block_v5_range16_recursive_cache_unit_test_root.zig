//! No proving entry is invoked. These pointers retain genuine generic cold/warm
//! bodies so qualification cannot pass using only detached metadata helpers.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Stage = @import("prover/block_v5_range16_recursive_stage_v1.zig").ForBackend(Cpu);
const Native = @import("prover/block_v5_range16_proof_v1.zig");
const Admission = @import("prover/block_v5_range16_recursive_admission_v1.zig");
const Bus = @import("recursion/block_v5_range16_recursive_public_bus_v1.zig");
const Cache = Stage.SetupCache;
fn publish(a: std.mem.Allocator, proof: *const Native.Proof, admitted: *const Admission.Prepared, options: Stage.Options, sink: @import("prover/block_v5_range16_recursive_stage_v1.zig").Sink) anyerror!void {
    return Stage.publish(a, proof, admitted, options, sink);
}
fn cached(cache: *Cache, prepared: *Bus.Prepared) anyerror!Cache.Proved {
    return cache.provePreparedConsuming(prepared);
}
fn retained(cache: *Cache, prepared: *Bus.Prepared) anyerror!Cache.Proved {
    return cache.provePrepared(prepared);
}
fn lease(cache: *Cache, prepared: *Bus.Prepared) anyerror!Cache.Lease {
    return cache.acquire(prepared);
}
export fn stwo_range16_recursive_cache_body_gate() void {
    inline for (.{ &publish, &cached, &retained, &lease, &Cache.Lease.deinit, &Cache.deinit }) |function| std.mem.doNotOptimizeAway(function);
}
test {
    _ = @import("prover/block_v5_range16_recursive_cache_test_v1.zig");
}
