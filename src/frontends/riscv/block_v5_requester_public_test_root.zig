test {
    _ = @import("prover/block_v5_requester_public_test_v1.zig");
}
pub export fn stwo_requester_public_body_gate() void {
    const std = @import("std");
    const Public = @import("recursion/block_v5_requester_public_compensation_v1.zig");
    const Source = @import("recursion/block_v5_requester_public_source_v1.zig");
    const Producer = @import("recursion/block_v5_requester_public_producer_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
    std.mem.doNotOptimizeAway(&Public.init);
    std.mem.doNotOptimizeAway(&Public.Owner.validate);
    std.mem.doNotOptimizeAway(&@import("recursion/air/block_v5_requester_public_composition_v1.zig").prepare);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_requester_public_preparation_v1.zig").prepare);
    std.mem.doNotOptimizeAway(&Producer.deriveKey);
    std.mem.doNotOptimizeAway(&Producer.init);
    std.mem.doNotOptimizeAway(&Producer.proveEncodedConsuming);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_requester_public_receiver_v1.zig").verify);
    std.mem.doNotOptimizeAway(&Source.Source.init);
    std.mem.doNotOptimizeAway(&Source.Source.validate);
    std.mem.doNotOptimizeAway(&Source.Admission.validate);
}
test "requester public: original producer receiver tuple and source bodies retained without proving" {
    stwo_requester_public_body_gate();
}
