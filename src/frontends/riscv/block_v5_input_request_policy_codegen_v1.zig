//! Actual independent setup/publisher/standalone reconstruction bodies retained
//! without invocation. No fake proof or verified-flag initializer exists here.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Snapshot = @import("recursion/block_v5_input_request_policy_snapshot_v1.zig");
const Setup = @import("prover/block_v5_input_request_policy_owner_v1.zig");
const Selected = @import("prover/block_v5_cpu_owned_input_request_forest_v1.zig");
pub export fn stwo_input_request_policy_body_gate() void {
    inline for (.{ &Snapshot.pins, &Snapshot.Owner.create, &Snapshot.Owner.validate, &Snapshot.Owner.retain, &Snapshot.Owner.deinit, &Snapshot.cloneIo, &Snapshot.cloneShape, &Setup.ForBackend(Cpu).build, &Setup.Owner.validate, &Setup.Owner.rootPolicy, &Setup.Owner.readRoot, &Setup.Owner.retain, &Setup.Owner.deinit, &Setup.Built.deinit, &Selected.publish, &Selected.reconstruct }) |body| std.mem.doNotOptimizeAway(body);
}
