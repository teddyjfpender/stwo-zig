const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const groups_mod = @import("../block_v5_cpu_lookup_groups_v1.zig");
const planning = @import("../block_v5_native_lookup_plan_v1.zig");
const tables = @import("../../air/lookups/tables/mod.zig");
const global_mod = @import("../block_v5_cpu_global_plans_v1.zig");
const spool = @import("../../air/block/memory_spool.zig");
const transition = @import("../../air/block/memory_transition.zig");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const Sorted = struct {
    spool: *spool.Spool,
    fn open(raw: *anyopaque) anyerror!transition.Reader {
        const self: *Sorted = @ptrCast(@alignCast(raw));
        return .{ .sorted = try self.spool.reopenSorted(), .initial = .{ .context = self, .load = initial } };
    }
    fn initial(_: *anyopaque, space: u1, address: u32) anyerror!u32 {
        return if (space == 1 and address == 0x2000) 7 else 0;
    }
};

test "block-v5 global plans collect actual sorted roots and mandatory full image sources" {
    const a = std.testing.allocator;
    var sorted_dir = std.testing.tmpDir(.{});
    defer sorted_dir.cleanup();
    var sorted = try spool.Spool.init(a, sorted_dir.dir, 8);
    defer sorted.deinit();
    try sorted.append(.{ .space = 1, .address = 0x2000, .clock = 1, .value = 9 });
    try sorted.append(.{ .space = 0, .address = 1, .clock = 2, .value = 5 });
    var reader = try sorted.finish();
    reader.deinit();
    var source = Sorted{ .spool = &sorted };
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const layout = @import("../../runner/memory_state.zig").MemoryLayout{ .program_base = 0x1000, .program_end = 0x2000, .data_base = 0x2000, .data_end = 0x5000, .stack_bottom = 0x8000, .stack_top = 0x9000, .io_base = 0x6000, .io_end = 0x7000, .input_base = 0x6000, .input_end = 0x6100, .output_len_addr = 0x6200, .output_data_addr = 0x6204, .output_base = 0x6200, .output_end = 0x7000 };
    const words = [_]@import("../block_memory_replay.zig").InitialWord{ .{ .address = 0x2000, .value = 7, .source = .rw_root }, .{ .address = 0x2004, .value = 11, .source = .rw_root } };
    const hasher = tree.TreeHasher.init(.memory);
    var last_registers: [32]u32 = @splat(0);
    last_registers[1] = 5;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var globals = try global_mod.ForBackend(Cpu).collect(a, dir.dir, .{ .context = &source, .open = Sorted.open }, .{ .layout = layout, .initial_words = &words, .public_input = &.{}, .initial_registers = @splat(0), .expected_final_registers = last_registers, .expected_initial_rw_root = (try hasher.root(&.{ .{ .index = 0x2000 / 4, .value = 7 }, .{ .index = 0x2004 / 4, .value = 11 } })).bytes, .expected_final_rw_root = (try hasher.root(&.{ .{ .index = 0x2000 / 4, .value = 9 }, .{ .index = 0x2004 / 4, .value = 11 } })).bytes, .expected_total_events = 2, .caps = .{ .max_initial_words = 8, .max_events = 8, .max_first_touches = 8, .max_file_bytes = 4096 } }, config, .{ .minimum_memory_log = 8, .maximum_memory_log = 8, .max_memory_instances = 1, .max_range_shards = 4, .max_program_rows = 256 });
    defer globals.deinit();
    const digests = try globals.digests();
    try digests.validate();
    try std.testing.expectEqual(@as(usize, 1), globals.memory.instanceCount());
    try std.testing.expectEqual(@as(u64, 2), globals.sources.event_count);
    try std.testing.expectEqual(@as(u64, 1), globals.sources.endpoint_file_pin.records);
    try std.testing.expectEqual(@as(u32, 2), globals.sources.register_pins.first_touch_mask);
    try std.testing.expectError(error.IncompleteV5GlobalProviders, globals.entries(a, 8));
}

test "block-v5 online global providers spool signed counters with exact greedy plans" {
    const a = std.testing.allocator;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const limits = groups_mod.Limits{ .request_limit = 3, .max_groups = 4, .max_metadata_bytes = 4096, .max_counter_file_bytes = 32 * 1024 * 1024 };
    var collector = try groups_mod.ForBackend(Cpu).init(a, dir.dir, config, limits);
    defer collector.deinit();
    var counters = try tables.counter.Set.init(a);
    defer counters.deinit(a);
    counters.get(.range_check_8_8).values[8190] = core.fields.m31.M31.one();
    counters.counters[0].values[7] = core.fields.m31.M31.one().neg();
    var demand: groups_mod.Demand = @splat(0);
    demand[0] = 1;
    demand[@intFromEnum(tables.schema.Kind.range_check_8_8)] += 1;
    const demands = [_]groups_mod.Demand{ demand, demand, @splat(0) };
    try collector.addExecution(0, demand, &counters);
    try std.testing.expect(collector.current != null and collector.records.items.len == 0);
    try collector.addExecution(1, demand, &counters);
    try std.testing.expect(collector.records.items.len == 1);
    var zero = try tables.counter.Set.init(a);
    defer zero.deinit(a);
    try collector.addExecution(2, @splat(0), &zero);
    var stage = try collector.finish(3);
    defer stage.deinit();
    try std.testing.expect(collector.current == null and collector.basis == null);
    const expected = try planning.buildRoster(a, &demands, 3);
    defer a.free(expected);
    try stage.requirePlans(expected);
    try std.testing.expectEqual(@as(usize, 2), stage.records.len);
    var substituted = try a.dupe(planning.Plan, expected);
    defer a.free(substituted);
    substituted[0].max_requests[0] += 1;
    try std.testing.expectError(error.ChangedV5OnlineLookupPlans, stage.requirePlans(substituted));
    const source = stage.source();
    for (stage.records) |record| {
        var reopened = try source.load(source.context, record.plan);
        defer reopened.deinit(a);
        for (reopened.counters, counters.counters) |actual, supplied| try std.testing.expectEqualSlices(core.fields.m31.M31, supplied.values, actual.values);
        var recomputed = try @import("../block_v5_native_lookup_proof_v1.zig").ForBackend(Cpu).commitFirstRound(a, &reopened, record.plan, config);
        defer recomputed.deinit(a);
        try std.testing.expectEqualDeep(record.roots, recomputed.roots);
    }
    const file = try dir.dir.openFile("v5-native-group-0.counters", .{ .mode = .read_write });
    defer file.close();
    // Mutate a canonical residue, preserving file length/header/schema.
    var changed: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 4), try file.preadAll(&changed, 24));
    changed[0] ^= 1;
    try file.pwriteAll(&changed, 24);
    try std.testing.expectError(error.UntrustedV5CounterFile, source.load(source.context, stage.records[0].plan));
    try std.testing.expectError(error.InvalidV5OnlineLookupOrder, collector.addExecution(3, demand, &counters));
    var limited_dir = std.testing.tmpDir(.{});
    defer limited_dir.cleanup();
    var limited = try groups_mod.ForBackend(Cpu).init(a, limited_dir.dir, config, .{ .request_limit = 3, .max_groups = 1, .max_metadata_bytes = 4096, .max_counter_file_bytes = 16 });
    defer limited.deinit();
    try limited.addExecution(0, demand, &counters);
    try std.testing.expectError(error.V5OnlineLookupResourceLimit, limited.finish(1));
    try std.testing.expectError(error.FileNotFound, limited_dir.dir.openFile("v5-native-group-0.counters", .{}));
}
