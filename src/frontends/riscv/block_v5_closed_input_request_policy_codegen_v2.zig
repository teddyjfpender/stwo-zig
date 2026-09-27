const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Setup = @import("prover/block_v5_closed_input_request_policy_owner_v2.zig");
const Selected = @import("prover/block_v5_cpu_owned_closed_input_request_forest_v2.zig");
pub export fn stwo_closed_input_request_policy_body_gate() void {
    inline for (.{ &Setup.ForBackend(Cpu).build, &Setup.Owner.validate, &Setup.Owner.rootPolicy, &Setup.Owner.readRoot, &Setup.Owner.deinit, &Setup.Owner.retain, &Selected.publish, &Selected.reconstruct }) |body| std.mem.doNotOptimizeAway(body);
    std.mem.doNotOptimizeAway(&@import("block_v5_closed_input_request_forest_codegen_v2.zig").stwo_closed_input_request_forest_body_gate);
}
