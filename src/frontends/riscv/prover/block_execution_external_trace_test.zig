const std = @import("std");
const engine = @import("stwo_prover_engine");
const Column = engine.pcs.ColumnEvaluation;
const runner = @import("../runner/mod.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const external = @import("block_execution_external_trace_v2.zig");
const pair_source = @import("block_execution_access_bridge_v2.zig");

test "SHA and Keccak committed caller rows cover 103 external accesses" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const fixture = @import("../runner/guest_precompile/test_elf.zig");
    const diagnostic = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = fixture.withReleaseAbi(diagnostic.len, &diagnostic);
    var session = try runner.EthereumShaExecutionSession.initLegacy(a, &elf, .{});
    defer session.deinit();
    var run = try session.runLegacy(16);
    defer run.deinit();
    var owner = try Profile.Witness.initCompactRun(a, &run);
    defer owner.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    var fixed: std.ArrayList(Column) = .empty;
    try fixed.appendSlice(scratch, owner.native.preprocessed.items);
    try fixed.appendSlice(scratch, owner.hashes.preprocessed());
    try fixed.appendSlice(scratch, try Profile.preprocessed(scratch, &owner.statement));
    var extension_main = try Profile.mainWitness(a, &owner);
    defer extension_main.deinit(a);
    var main: std.ArrayList(Column) = .empty;
    try main.appendSlice(scratch, owner.native.main.items);
    if (owner.native.compact_ranges) |ranges| try main.appendSlice(scratch, &ranges.columns);
    try main.appendSlice(scratch, try owner.hashes.main());
    try main.appendSlice(scratch, extension_main.columns);
    const fixed_logs = try scratch.alloc(u32, fixed.items.len);
    for (fixed.items, fixed_logs) |column, *log_size| log_size.* = column.log_size;
    const main_logs = try scratch.alloc(u32, main.items.len);
    for (main.items, main_logs) |column, *log_size| log_size.* = column.log_size;
    const frame = @import("../air/block/memory_event.zig").Frame{
        .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = owner.native.statement.public_data.clock,
    };
    const slots = try external.descriptorsFromStatement(scratch, &owner.statement, fixed_logs, main_logs, frame);
    try std.testing.expectEqual(@as(usize, 77), slots.len);
    try std.testing.expectEqual(@as(u64, 103), try external.expectedEventCount(&owner.statement));
    var active: u64 = 0;
    const Key = struct { space: u1, address: u32, clock: u32, after: u32 };
    var recorded = std.AutoHashMap(Key, u32).init(a);
    defer recorded.deinit();
    for (run.base.state_chain_tracker.accesses.items) |access| {
        const entry = try recorded.getOrPut(.{ .space = access.addr_space, .address = access.addr, .clock = access.clk, .after = access.value });
        if (!entry.found_existing) entry.value_ptr.* = 0;
        entry.value_ptr.* += 1;
    }
    for (slots) |slot| {
        var trace = try external.Trace.init(a, slot, fixed.items, main.items);
        defer trace.deinit();
        for (0..trace.domainSize()) |logical| {
            const pair = try pair_source.decodePair(try trace.pairAt(logical));
            if (!pair.active) continue;
            active += 1;
            const address = if (pair.space == 0) pair.source_address else try std.math.mul(u32, pair.source_address, 4);
            const key = Key{ .space = pair.space, .address = address, .clock = pair.local_clock, .after = pair.after };
            const count = recorded.getPtr(key) orelse return error.ExternalAccessMissingFromRunner;
            if (count.* == 0) return error.ExternalAccessDuplicatedAgainstRunner;
            count.* -= 1;
        }
    }
    try std.testing.expectEqual(@as(u64, 103), active);
    try std.testing.expectEqual(@as(usize, 108), run.base.state_chain_tracker.accesses.items.len);
    var remaining: u64 = 0;
    var it = recorded.valueIterator();
    while (it.next()) |count| remaining += count.*;
    try std.testing.expectEqual(@as(u64, 5), remaining);
}
