//! Real compiler/fixed-key/live-family bodies retained, never invoked here.
const std = @import("std");
const Assembly = @import("recursion/block_v5_requester_public_fixed_assembly_v1.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
pub export fn stwo_requester_public_fixed_assembly_body_gate() void {
    inline for (.{ &Assembly.Owned.init, &Assembly.Owned.validateAgainst, &Assembly.Owned.validateLive, &Assembly.Owned.deinit, &Assembly.ForBackend(Cpu).deriveKey }) |body| std.mem.doNotOptimizeAway(body);
    const Producer = @import("recursion/block_v5_requester_public_producer_v1.zig").ForBackend(Cpu);
    inline for (.{ &@import("recursion/block_v5_requester_public_preparation_v1.zig").prepare, &Producer.deriveKey, &Producer.init, &Producer.proveEncodedConsuming, &@import("recursion/block_v5_requester_public_receiver_v1.zig").verify }) |body| std.mem.doNotOptimizeAway(body);
}
