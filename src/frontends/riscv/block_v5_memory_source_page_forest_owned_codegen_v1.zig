//! LLVM retention only. The marker does not invoke proof/PCS/receiver work.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Catalogue = @import("prover/block_v5_memory_source_page_leaf_catalogue_v1.zig");
const Plan = @import("recursion/block_v5_memory_source_page_forest_plan_v1.zig");
const Receiver = @import("recursion/block_v5_memory_source_page_forest_summary_receiver_v1.zig");
const Source = @import("recursion/block_v5_memory_source_page_forest_summary_source_v1.zig");
const Rows = @import("recursion/block_v5_memory_source_page_forest_preparation_v1.zig");
const Owner = @import("prover/block_v5_memory_source_page_forest_policy_owner_v1.zig");
const LiveBudget = @import("prover/block_v5_memory_source_page_forest_live_budget_v1.zig");
const Selected = @import("prover/block_v5_cpu_owned_memory_source_page_forest_v1.zig");
fn rawScope(owner: *Catalogue.Catalogue, index: u32) !Catalogue.Scope(.raw) {
    return owner.acquire(.raw, index);
}
fn foldScope(owner: *Catalogue.Catalogue, index: u32) !Catalogue.Scope(.fold) {
    return owner.acquire(.fold, index);
}
pub export fn stwo_source_page_forest_owned_body_gate() void {
    inline for (.{ &LiveBudget.create, &Catalogue.Catalogue.create, &Catalogue.Catalogue.deinit, &rawScope, &foldScope, &Catalogue.Scope(.raw).prepared, &Catalogue.Scope(.fold).prepared, &Catalogue.Scope(.raw).decodeOriginal, &Catalogue.Scope(.fold).decodeOriginal, &Catalogue.Scope(.raw).deinit, &Catalogue.Scope(.fold).deinit, &Catalogue.Group.acquire, &Catalogue.Group.deinit, &Plan.Owned.init, &Plan.Owned.initWithCatalogue, &Rows.prepare, &Rows.ForNode(Receiver, Source).prepare, &Receiver.verify, &Receiver.verifyRoot, &Receiver.Fresh.deinit, &Source.Source.init, &Source.Source.validate, &Source.Source.deinit, &Owner.ForBackend(Cpu).build, &Owner.Owner.require, &Owner.Built.deinit, &Selected.publish, &Selected.reconstruct }) |body| std.mem.doNotOptimizeAway(body);
}
