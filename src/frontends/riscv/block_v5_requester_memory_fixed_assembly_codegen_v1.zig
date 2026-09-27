//! Real FINAL22 fixed compiler/expected-key and original producer/receiver
//! bodies retained. Marker performs no construction, commitment or proving.
const std = @import("std");
const Family = @import("recursion/block_v5_requester_memory_fixed_assembly_v1.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
pub export fn stwo_requester_memory_fixed_assembly_body_gate() void {
    const F = Family.ForBackend(Cpu);
    inline for (.{ &F.initViaOriginalMemory, &F.validateAgainstViaOriginalMemory, &F.deriveKeyViaOriginalMemory, &Family.Owned.validateLive, &Family.Owned.deinit }) |body| std.mem.doNotOptimizeAway(body);
    const S = @import("recursion/block_v5_source_ram_forest_join_recursive_shape_admission_v1.zig");
    inline for (.{ &S.Source.init, &S.Source.validate, &S.Source.deinit, &S.Admission.init, &S.Admission.validate }) |body| std.mem.doNotOptimizeAway(body);
    const Producer = @import("recursion/block_v5_requester_memory_producer_v1.zig").ForBackend(Cpu);
    inline for (.{ &@import("recursion/block_v5_requester_memory_preparation_v1.zig").prepare, &Producer.deriveKey, &Producer.init, &Producer.proveEncodedConsuming, &@import("recursion/block_v5_requester_memory_receiver_v1.zig").verify }) |body| std.mem.doNotOptimizeAway(body);
    const Memory = @import("recursion/block_v5_source_ram_forest_join_producer_v1.zig").ForBackend(Cpu);
    inline for (.{ &@import("recursion/block_v5_source_ram_forest_join_preparation_v1.zig").prepare, &Memory.deriveKey, &@import("recursion/block_v5_source_ram_forest_join_receiver_v1.zig").verify }) |body| std.mem.doNotOptimizeAway(body);
}
