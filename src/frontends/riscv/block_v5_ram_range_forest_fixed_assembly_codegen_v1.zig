//! Actual constructors/key compiler retained without invocation or fake Fresh.
const std = @import("std");
const Factory = @import("recursion/block_v5_ram_range_forest_fixed_assembly_v1.zig");
pub export fn stwo_ram_range_forest_fixed_assembly_body_gate() void {
    const F = Factory.ForBackend(@import("stwo_cpu_backend").CpuBackend);
    inline for (.{ &F.derive, &F.materialize, &Factory.Catalogue.require, &Factory.Catalogue.requireSelected, &Factory.Catalogue.policy, &Factory.Catalogue.deinit, &Factory.Owned.validateLive, &Factory.Owned.deinit }) |body| std.mem.doNotOptimizeAway(body);
    const Source = @import("recursion/block_v5_ram_range_forest_recursive_shape_admission_v1.zig").Node;
    inline for (.{ &Source.Source.init, &Source.Source.validate, &Source.Source.deinit, &Source.Admission.init, &Source.Admission.validate }) |body| std.mem.doNotOptimizeAway(body);
    const Original = @import("recursion/block_v5_ram_range_forest_preparation_v1.zig");
    inline for (.{ &Original.prepare, &@import("recursion/block_v5_ram_range_forest_receiver_v1.zig").verify }) |body| std.mem.doNotOptimizeAway(body);
}
