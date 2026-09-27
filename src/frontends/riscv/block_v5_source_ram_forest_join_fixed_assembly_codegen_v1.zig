//! Actual independent lower forests/V20/FINAL22 compiler bodies, never invoked.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
pub export fn stwo_source_ram_forest_join_fixed_assembly_body_gate() void {
    @import("block_v5_ram_range_forest_fixed_assembly_codegen_v1.zig").stwo_ram_range_forest_fixed_assembly_body_gate();
    const Page = @import("recursion/block_v5_memory_source_page_forest_fixed_assembly_v1.zig");
    const PF = Page.ForBackend(Cpu);
    inline for (.{ &PF.derive, &PF.deriveWithCatalogue, &PF.materialize, &Page.Catalogue.requireSelected, &Page.Catalogue.policy, &Page.Catalogue.deinit, &Page.Owned.validateLive, &Page.Owned.deinit }) |body| std.mem.doNotOptimizeAway(body);
    const Memory = @import("recursion/block_v5_source_ram_forest_join_fixed_assembly_v1.zig");
    const MF = Memory.ForBackend(Cpu);
    inline for (.{ &MF.derive, &MF.deriveWithCatalogue, &MF.deriveFromCatalogues, &Memory.Owned.validate, &Memory.Owned.validateLive, &Memory.Owned.validateAgainstSource, &Memory.Owned.releaseFixedRows, &Memory.Owned.deinit, &Memory.Admission.init, &Memory.Admission.validate }) |body| std.mem.doNotOptimizeAway(body);
    const Final = @import("recursion/block_v5_requester_memory_fixed_assembly_v1.zig");
    const FF = Final.ForBackend(Cpu);
    inline for (.{ &FF.initViaIndependentMemory, &FF.initViaAuthenticatedMemorySetup, &FF.validateAgainstViaAuthenticatedMemorySetup, &FF.deriveKeyViaAuthenticatedMemorySetup, &FF.deriveKeyAndScheduleForAuthenticatedMemory, &FF.validateAgainstViaIndependentMemory, &FF.deriveKeyViaIndependentMemory, &Final.IndependentOwned.validateLive, &Final.IndependentOwned.deinit }) |body| std.mem.doNotOptimizeAway(body);
    inline for (.{ &@import("recursion/block_v5_requester_public_fixed_assembly_v1.zig").ForBackend(Cpu).deriveKeyAndScheduleForPolicy, &@import("recursion/block_v5_requester_public_fixed_assembly_v1.zig").KeyAndSchedule.deinit, &Final.KeyAndSchedule.deinit }) |body| std.mem.doNotOptimizeAway(body);
    const Producer = @import("recursion/block_v5_source_ram_forest_join_producer_v1.zig").ForBackend(Cpu);
    inline for (.{ &@import("recursion/block_v5_source_ram_forest_join_preparation_v1.zig").prepare, &Producer.deriveKey, &Producer.init, &@import("recursion/block_v5_source_ram_forest_join_receiver_v1.zig").verify }) |body| std.mem.doNotOptimizeAway(body);
}
