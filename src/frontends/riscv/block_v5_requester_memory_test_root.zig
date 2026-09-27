test {
    _ = @import("prover/block_v5_requester_memory_test_v1.zig");
}
test "requester memory join: actual genuine two-root child verifier preparation producer and standalone receiver bodies retained only" {
    const std = @import("std");
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const P = @import("recursion/block_v5_requester_memory_preparation_v1.zig");
    const Producer = @import("recursion/block_v5_requester_memory_producer_v1.zig").ForBackend(Cpu);
    std.mem.doNotOptimizeAway(&P.prepare);
    std.mem.doNotOptimizeAway(&Producer.deriveKey);
    std.mem.doNotOptimizeAway(&Producer.init);
    std.mem.doNotOptimizeAway(&Producer.proveEncodedConsuming);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_requester_memory_receiver_v1.zig").verify);
}
