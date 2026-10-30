const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Producer = @import("../block_v7_streaming_execution_v1.zig");
const Guest = @import("block_v7_scaling_guest_test_support.zig");
const Metadata = @import("../../recursion/block_v7_mixed_metadata_v1.zig");
const Inputs = @import("../../recursion/block_v7_mixed_inputs_v1.zig");
const Consumer = struct {
    pub const Result = *Metadata.Owned;
    pub fn consume(fixture: Producer.Fixture) !Result {
        const metadata = try Metadata.Owned.init(fixture.allocator, fixture.trusted, fixture.input);
        errdefer metadata.deinit();
        var shortened = fixture.input.memory.separate.*;
        shortened.ram = shortened.ram[0 .. shortened.ram.len - 1];
        var missing = fixture.input;
        missing.memory = .{ .separate = &shortened };
        const Collection = @import("../../recursion/block_v7_mixed_collection_v1.zig");
        inline for (.{ false, true }) |shared| {
            try Collection.For(shared).requireMatchingOriginalShape(fixture.input, metadata.input());
            try std.testing.expectError(error.UntrustedV7CollectionInput, Collection.For(shared).requireMatchingOriginalShape(missing, metadata.input()));
        }
        return metadata;
    }
};
test "v7 execution externally sorts and proves bounded memory cohorts" {
    const iterations = 1;
    const cycles = try Guest.cycles(iterations);
    const code = try Guest.instructions(iterations);
    const elf = Guest.releaseElf(&code);
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 24 << 30);
    defer budget.destroy();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = budget.allocator() });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var dir = std.testing.tmpDir(.{ .iterate = true });
    defer dir.cleanup();
    const result = try Producer.run(budget, dir.dir, .{ .elf = &elf, .elf_sha256 = @import("../block_v5_initial_sources_v1.zig").sha256(&elf), .cycles = cycles, .output = try Guest.output(iterations), .config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config() }, .{ .segment_cycles = @intCast(try std.math.divCeil(u64, cycles, 3)), .max_segments = 58, .max_callers = 3, .ram_events_per_shard = 32, .memory_sort_chunk = 4, .memory_cohorts = .{ .max_live_bytes = 128 << 20, .memory = .{ .max_events = 1 << 20 } } }, &pool, Consumer);
    defer result.value.deinit();
    var canonical = try Inputs.Owned.init(budget.allocator(), result.value.input());
    defer canonical.deinit();
    try std.testing.expect(result.value.memory == null);
    try std.testing.expect(result.value.separate_memory != null);
    try std.testing.expectEqual(result.stats.original_proofs, try result.value.input().count());
    const Families = @import("../../recursion/block_v7_memory_component_recursive_v1.zig");
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    // Proposal caps are larger, but the receiver cap wins before allocation.
    for (result.value.separate_memory.?.ram) |ram| try std.testing.expectError(error.V7MemoryResourceLimit, Families.For(.ram).Profile.requireFixedRootWithLimit(Cpu, std.testing.failing_allocator, ram, 1));
    inline for (.{ @import("../../recursion/air/block_v7_memory_composition_v1.zig").Family.interval, .range16, .terminal }) |kind| {
        const profile = @field(result.value.separate_memory.?, @tagName(kind));
        try std.testing.expectError(error.V7MemoryResourceLimit, Families.For(kind).Profile.requireFixedRootWithLimit(Cpu, std.testing.failing_allocator, profile, 1));
    }
    var missing = result.value.input();
    missing.separate_memory.?.ram = missing.separate_memory.?.ram[1..];
    try std.testing.expectError(error.InvalidV7CompleteMixedRoster, Inputs.Owned.init(budget.allocator(), missing));
    var wrong_mode = result.value.input();
    wrong_mode.separate_memory = null;
    try std.testing.expectError(error.InvalidV7MixedMemoryMode, Inputs.Owned.init(budget.allocator(), wrong_mode));
    const swapped = try budget.allocator().dupe(@TypeOf(result.value.separate_memory.?.ram[0]), result.value.separate_memory.?.ram);
    defer budget.allocator().free(swapped);
    std.mem.swap(@TypeOf(swapped[0]), &swapped[0], &swapped[1]);
    var reordered = result.value.input();
    reordered.separate_memory.?.ram = swapped;
    try std.testing.expectError(error.UntrustedV7MixedIndex, Inputs.Owned.init(budget.allocator(), reordered));
    try std.testing.expect(result.stats.events > 32);
    try std.testing.expect(result.stats.original_proofs > result.stats.segments + result.stats.callers + 3);
    try std.testing.expect(result.stats.event_storage_bytes <= 8 * @sizeOf(@import("../../air/block/memory_transition.zig").Transition));
    var iterator = dir.dir.iterate();
    try std.testing.expect(try iterator.next() == null);
    std.debug.print("V7_COHORT_EXECUTION cycles={d} events={d} original_proofs={d} sort_buffer={d} peak={d} whole_ns={d} recursion=false\n", .{ result.stats.cycles, result.stats.events, result.stats.original_proofs, result.stats.event_storage_bytes, result.stats.charged_peak_bytes, result.stats.whole_ns });
}
