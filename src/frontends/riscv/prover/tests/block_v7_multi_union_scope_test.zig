//! Genuine multi-window metadata admission, not a union-proof qualification.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Scope = @import("../block_v7_multi_union_scope_v1.zig");
const Producer = @import("../block_v7_streaming_execution_v1.zig");
const Epoch = @import("../block_v7_execution_epoch_v1.zig");
const Native = @import("../block_v7_native_source_v1.zig");
const Caller = @import("../block_v7_caller_active_source_v1.zig");
const Guest = @import("block_v7_scaling_guest_test_support.zig");
const Consumer = struct {
    pub const Result = struct { windows: usize, callers: usize, trees: usize, retained: u64 };
    pub fn consume(f: Producer.Fixture) !Result {
        const a = f.allocator;
        const natives = try a.alloc(Native.Pin, f.input.natives.len);
        defer a.free(natives);
        for (natives, f.input.natives) |*pin, source| pin.* = source.pin;
        const callers = try a.alloc(Caller.Pin, f.input.active_callers.len);
        defer a.free(callers);
        for (callers, f.input.active_callers) |*pin, source| pin.* = source.pin;
        const memory = f.input.memory.joint;
        const geometry = try a.alloc(@import("../block_v5_ram_lanes_protocol_v1.zig").Claim, memory.ram.len);
        defer a.free(geometry);
        for (geometry, memory.ram) |*g, claim| g.* = claim.geometry;
        const input = Scope.Input{ .epoch = f.input.epoch, .entries = f.input.entries, .natives = natives, .callers = callers, .program_plan = f.input.program_plan, .program_roots = f.input.program_roots, .lookup_plan = f.input.lookup_plan, .lookup_layout = f.input.lookup.compact.layout, .lookup_roots = f.input.lookup_roots, .memory_roots = memory.roots, .memory_geometry = geometry, .interval_log = memory.interval_log };
        const limits = Scope.Limits{ .max_retained_pcs_bytes = 8 << 30 };
        const admitted = try Scope.Owned.init(a, f.trusted, input, limits);
        defer admitted.deinit();
        try std.testing.expect(natives.len >= 2 and callers.len != 0);
        try std.testing.expectEqual(natives.len + callers.len + 3, admitted.sources.len);
        // Storage changes resource admission only. The independently rebuilt
        // source geometry/placement and statement remain identical.
        const storage: @import("../block_v7_multi_union_residency_v1.zig").ProducerStorage = .{ .memory_inputs = .{ .coefficients = .{ .minimum_trace_log = 1 } }, .memory_interaction = .{ .coefficients = .{ .minimum_trace_log = 1 } } };
        const compact = try Scope.Owned.initForProducer(a, f.trusted, input, limits, storage);
        defer compact.deinit();
        try std.testing.expectEqualDeep(admitted.sources, compact.sources);
        try std.testing.expectEqualDeep(admitted.placement.parts, compact.placement.parts);
        try std.testing.expectEqual(try admitted.policy.digest(), try compact.policy.digest());
        try std.testing.expect(compact.retained.total_bytes < admitted.retained.total_bytes);
        var compact_limit = limits;
        compact_limit.max_retained_pcs_bytes = @intCast(compact.retained.total_bytes);
        const bounded_compact = try Scope.Owned.initForProducer(a, f.trusted, input, compact_limit, storage);
        bounded_compact.deinit();
        // Default receiver admission remains materialized and is never silently
        // changed by a producer's storage policy.
        try std.testing.expectError(error.MultiUnionRetainedPCSExceedsBudget, Scope.Owned.init(a, f.trusted, input, compact_limit));
        var small = limits;
        small.max_retained_pcs_bytes = @intCast(admitted.retained.total_bytes - 1);
        try std.testing.expectError(error.MultiUnionRetainedPCSExceedsBudget, Scope.Owned.init(a, f.trusted, input, small));
        small = limits;
        small.max_trace_trees = admitted.placement.trace_trees - 1;
        try std.testing.expectError(error.MultiUnionTreeBudgetExceeded, Scope.Owned.init(a, f.trusted, input, small));
        var wrong = input;
        wrong.natives = natives[0 .. natives.len - 1];
        try std.testing.expectError(error.InvalidMultiUnionRoster, Scope.Owned.init(a, f.trusted, wrong, limits));
        wrong = input;
        wrong.entries = input.entries[0 .. input.entries.len - 1];
        try std.testing.expectError(error.InvalidMultiUnionRoster, Scope.Owned.init(a, f.trusted, wrong, limits));
        // Recompute every affected source entry and the epoch after the clock
        // mutation, so rejection tests original window custody, not a stale hash.
        const saved = natives[1];
        natives[1].frame.global_first_cycle += 1;
        const saved_callers = try a.dupe(Caller.Pin, callers);
        defer a.free(saved_callers);
        for (callers) |*pin| if (pin.execution_index == 1) {
            pin.frame = natives[1].frame;
            pin.execution_identity = (try natives[1].entry(a)).identity;
        };
        const entries = try a.dupe(Epoch.Entry, input.entries);
        defer a.free(entries);
        for (natives, entries[0..natives.len]) |pin, *entry| entry.* = try pin.entry(a);
        for (callers, entries[natives.len..][0..callers.len]) |pin, *entry| entry.* = try pin.entry(a);
        wrong = input;
        wrong.entries = entries;
        wrong.epoch = try Epoch.Epoch.init(input.epoch.statement, input.epoch.config, input.epoch.counts, entries, entries.len);
        try std.testing.expectError(error.UntrustedV7ExecutionBoundary, Scope.Owned.init(a, f.trusted, wrong, limits));
        try std.testing.expectError(error.UntrustedV7ExecutionBoundary, Scope.Owned.initForProducer(a, f.trusted, wrong, limits, storage));
        natives[1] = saved;
        @memcpy(callers, saved_callers);
        // A fully resealed proposed initial-register change must still fail
        // independently selected cross-window register custody.
        var changed_shape = saved.shape.*;
        changed_shape.public_data.initial_regs[1] ^= 1;
        natives[1].shape = &changed_shape;
        for (callers) |*pin| if (pin.execution_index == 1) {
            pin.execution_identity = (try natives[1].entry(a)).identity;
        };
        for (natives, entries[0..natives.len]) |pin, *entry| entry.* = try pin.entry(a);
        for (callers, entries[natives.len..][0..callers.len]) |pin, *entry| entry.* = try pin.entry(a);
        wrong = input;
        wrong.entries = entries;
        wrong.epoch = try Epoch.Epoch.init(input.epoch.statement, input.epoch.config, input.epoch.counts, entries, entries.len);
        try std.testing.expectError(error.UntrustedV7ExecutionBoundary, Scope.Owned.init(a, f.trusted, wrong, limits));
        try std.testing.expectError(error.UntrustedV7ExecutionBoundary, Scope.Owned.initForProducer(a, f.trusted, wrong, limits, storage));
        natives[1] = saved;
        @memcpy(callers, saved_callers);
        const restored = try Scope.Owned.init(a, f.trusted, input, limits);
        restored.deinit();
        return .{ .windows = natives.len, .callers = callers.len, .trees = admitted.placement.trace_trees + 1, .retained = admitted.retained.total_bytes };
    }
};
test "multi union scope admits actual contiguous windows and rejects resealed clock gap" {
    const code = try Guest.instructions(1);
    const elf = Guest.releaseElf(&code);
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 16 << 30);
    defer budget.destroy();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = budget.allocator() });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var dir = std.testing.tmpDir(.{ .iterate = true });
    defer dir.cleanup();
    const result = try Producer.run(budget, dir.dir, .{ .elf = &elf, .elf_sha256 = @import("../block_v5_initial_sources_v1.zig").sha256(&elf), .cycles = try Guest.cycles(1), .output = try Guest.output(1), .config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config() }, .{ .segment_cycles = 7, .max_segments = 8, .max_callers = 3, .active_callers = true }, &pool, Consumer);
    try std.testing.expectEqual(@as(usize, 3), result.value.windows);
    std.debug.print("MULTI_UNION_SCOPE windows={d} callers={d} proof_trees={d} estimated_trace_pcs_bytes={d} original_sources_verified=true union_proof=false\n", .{ result.value.windows, result.value.callers, result.value.trees, result.value.retained });
}
