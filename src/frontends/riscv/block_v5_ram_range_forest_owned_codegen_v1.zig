//! Emitted real producer/standalone receiver retention, never invocation.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Catalogue = @import("prover/block_v5_ram_range_forest_catalogue_v1.zig");
const Manifest = @import("prover/block_v5_ram_range_forest_manifest_v1.zig");
const Owned = @import("prover/block_v5_ram_range_forest_policy_owner_v1.zig");
const CpuSelected = @import("prover/block_v5_cpu_owned_ram_range_forest_v1.zig");
const Receive = @import("recursion/block_v5_ram_range_forest_summary_receiver_v1.zig");
const Source = @import("recursion/block_v5_ram_range_forest_source_v1.zig");
const Preparation = @import("recursion/block_v5_ram_range_forest_preparation_v1.zig").ForNode(Receive, Source);
pub export fn stwo_ram_range_forest_owned_body_gate() void {
    inline for (.{ &Catalogue.Owned.init, &Catalogue.Owned.deinit, &Manifest.encode, &Manifest.decode, &Manifest.read, &Owned.ForBackend(Cpu).build, &Owned.Owner.deinit, &Owned.Built.deinit, &CpuSelected.publish, &CpuSelected.reconstruct, &Preparation.prepare, &Receive.verify, &Receive.verifyRoot, &Receive.Fresh.deinit, &Source.Source.init, &Source.Source.deinit, &@import("recursion/block_v5_source_ram_forest_join_receiver_v1.zig").verify, &@import("recursion/block_v5_source_ram_forest_join_preparation_v1.zig").prepare }) |body| std.mem.doNotOptimizeAway(body);
}
