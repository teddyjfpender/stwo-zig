//! Retain actual source admission/parent producer/CPU receiver/store bodies.
//! No address-retained function is invoked by this marker.
const std = @import("std");
pub export fn stwo_heterogeneous_scoped_owned_body_gate() void {
    const Owner = @import("recursion/block_v5_heterogeneous_scoped_owner_v1.zig");
    const Receiver = @import("recursion/block_v5_heterogeneous_scoped_owned_receiver_v1.zig");
    const Store = @import("prover/block_v5_heterogeneous_scoped_owned_files_v1.zig").Store;
    std.mem.doNotOptimizeAway(&Owner.init);
    std.mem.doNotOptimizeAway(&Owner.Owner.node);
    std.mem.doNotOptimizeAway(&Owner.Owner.borrow);
    std.mem.doNotOptimizeAway(&Owner.Owner.deinit);
    std.mem.doNotOptimizeAway(&Receiver.verify);
    std.mem.doNotOptimizeAway(&Receiver.verifyLeaf);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_scoped_owned_preparation_v1.zig").prepareVerifierRows);
    std.mem.doNotOptimizeAway(&@import("prover/block_v5_heterogeneous_scoped_owned_stage_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend).publish);
    std.mem.doNotOptimizeAway(&Store.initWriter);
    std.mem.doNotOptimizeAway(&Store.initReader);
    std.mem.doNotOptimizeAway(&Store.put);
    std.mem.doNotOptimizeAway(&Store.proofBytes);
    std.mem.doNotOptimizeAway(&Store.fresh);
    std.mem.doNotOptimizeAway(&Store.filePins);
    std.mem.doNotOptimizeAway(&Store.deinit);
}
