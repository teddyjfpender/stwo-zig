const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const fixture = @import("block_v5_initial_source_test.zig");
const base = @import("../block_v5_memory_batch_receiver_v1.zig");
const sources = @import("../block_v5_rw_endpoint_sources_v1.zig");
const endpoint = @import("../block_v5_rw_endpoint_proof_v1.zig");
const receive = @import("../block_v5_rw_endpoint_receiver_v1.zig");
const instance = @import("../block_memory_shared_instance_proof_v2.zig");
const table = @import("../block_memory_shared_table_proof_v2.zig");
const shard = @import("../block_memory_range_shard_v2.zig");
const counter_mod = @import("../../air/lookups/tables/counter.zig");
const memory = @import("../../air/block/memory_component.zig");
const trace = @import("../../air/block/memory_component_trace.zig");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const initial_sources = @import("../block_v5_initial_sources_v1.zig");
const v5 = @import("../block_v5_source_seal_v1.zig");
const MemorySeal = @import("../block_v5_initial_memory_receiver_v1.zig").MemorySeal;
const Loader = struct {
    sorted: [2]instance.Proof,
    endpoints: [2]endpoint.Proof,
    range: table.Proof,
    memory_at: u32 = 0,
    endpoint_at: u32 = 0,
    table_taken: bool = false,
    fn takeMemory(ctx: *anyopaque, index: u32) anyerror!instance.Proof {
        const self: *Loader = @ptrCast(@alignCast(ctx));
        if (index != self.memory_at or self.endpoint_at != index + 1) return error.InvalidEndpointFixtureLoad;
        self.memory_at += 1;
        return self.sorted[index];
    }
    fn takeEndpoint(ctx: *anyopaque, index: u32) anyerror!endpoint.Proof {
        const self: *Loader = @ptrCast(@alignCast(ctx));
        if (index != self.endpoint_at or index >= 2) return error.InvalidEndpointFixtureLoad;
        self.endpoint_at += 1;
        return self.endpoints[index];
    }
    fn takeTable(ctx: *anyopaque, index: u32) anyerror!table.Proof {
        const self: *Loader = @ptrCast(@alignCast(ctx));
        if (index != 0 or self.memory_at != 2 or self.table_taken) return error.InvalidEndpointFixtureLoad;
        self.table_taken = true;
        return self.range;
    }
    fn interface(self: *Loader) receive.Loader {
        return .{ .memory = .{ .context = self, .take_memory = takeMemory, .take_table = takeTable }, .context = self, .take_endpoint = takeEndpoint };
    }
};
fn record(address: u32, clock: u64, value: u32) [sources.RECORD_BYTES]u8 {
    var bytes: [sources.RECORD_BYTES]u8 = undefined;
    std.mem.writeInt(u32, bytes[0..4], address, .little);
    std.mem.writeInt(u64, bytes[4..12], clock, .little);
    std.mem.writeInt(u32, bytes[12..16], value, .little);
    return bytes;
}
fn produce(comptime compact: bool, a: std.mem.Allocator, traces: *const [2](if (compact) trace.CompactTrace else trace.Trace), counter: *counter_mod.Counter, plan: *const shard.Plan, roots: [2][2][32]u8, table_roots: [2][32]u8, pins: v5.Pins, entries: []const v5.Entry, sealed: v5.Sealed) !Loader {
    var result: Loader = undefined;
    result.memory_at = 0;
    result.endpoint_at = 0;
    result.table_taken = false;
    const api = if (compact) instance.ForCompactBackend(Cpu) else instance.ForBackend(Cpu);
    const endpoint_api = if (compact) endpoint.ForCompactBackend(Cpu) else endpoint.ForBackend(Cpu);
    const bound = MemorySeal{ .source = sealed, .memory_instance_count = 2, .range_shard_digest = plan.digest };
    for (traces, 0..) |*source, index| {
        var first = try api.replayFirstRound(a, source, @intCast(index), roots[index], pins.config);
        defer first.deinit(a);
        result.sorted[index] = try api.prove(a, &first, source, bound, @intCast(index), roots[index]);
        var projection = try api.replayFirstRound(a, source, @intCast(index), roots[index], pins.config);
        defer projection.deinit(a);
        result.endpoints[index] = try endpoint_api.prove(a, &projection, source, sealed, pins, entries, @intCast(index), roots[index]);
    }
    var first_table = try table.ForBackend(Cpu).replayFirstRound(a, counter, plan.shards[0], table_roots, pins.config);
    defer first_table.deinit(a);
    result.range = try table.ForBackend(Cpu).prove(a, &first_table, counter, plan.shards[0], bound, table_roots);
    return result;
}
test "block-v5 final RW endpoint fresh same-root proof crosses independently sized instances" {
    try exercise(false);
}
test "block-v5 compact memory66 fresh sorted range and final endpoint closure" {
    try exercise(true);
}
fn exercise(comptime compact: bool) !void {
    const Trace = if (compact) trace.CompactTrace else trace.Trace;
    const api = if (compact) instance.ForCompactBackend(Cpu) else instance.ForBackend(Cpu);
    const receiver = if (compact) receive.verifyCompact else receive.verify;
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const input_word = fixture.recordWord(0x6000, fixture.input_value);
    const rw_words = [_][8]u8{ fixture.recordWord(0x2000, 9), fixture.recordWord(0x2008, 5) }; // untouched word persists
    const touches = [_][9]u8{ fixture.recordTouch(0, 1, 7), fixture.recordTouch(1, 0x2000, 9), fixture.recordTouch(1, 0x2004, 0), fixture.recordTouch(1, 0x6000, fixture.input_value) };
    const records = [_][16]u8{ record(0x2000, 2, 10), record(0x2004, 3, 1), record(0x6000, 4, fixture.input_value + 1) };
    const bytes = std.mem.sliceAsBytes(&records);
    try fixture.writeFile(tmp.dir, "input.bin", &input_word);
    try fixture.writeFile(tmp.dir, "rw.bin", std.mem.sliceAsBytes(&rw_words));
    try fixture.writeFile(tmp.dir, "touches.bin", std.mem.sliceAsBytes(&touches));
    try fixture.writeFile(tmp.dir, "endpoints.bin", bytes);
    var files = try fixture.OpenFiles.open(tmp.dir);
    defer files.deinit();
    const endpoints_file = try tmp.dir.openFile("endpoints.bin", .{});
    defer endpoints_file.close();
    const opened = sources.Sources{ .initial = files.files, .endpoints = endpoints_file };
    var source_pins = try fixture.sourcePins(&input_word, std.mem.sliceAsBytes(&rw_words), std.mem.sliceAsBytes(&touches));
    const hasher = tree.TreeHasher.init(.memory);
    source_pins.initial_rw_root = (try hasher.root(&.{ .{ .index = 0x2000 / 4, .value = 9 }, .{ .index = 0x2008 / 4, .value = 5 }, .{ .index = 0x6000 / 4, .value = fixture.input_value } })).bytes;
    const final_root = (try hasher.root(&.{ .{ .index = 0x2000 / 4, .value = 10 }, .{ .index = 0x2004 / 4, .value = 1 }, .{ .index = 0x2008 / 4, .value = 5 }, .{ .index = 0x6000 / 4, .value = fixture.input_value + 1 } })).bytes;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const claims = [_]memory.Claim{
        try memory.Claim.fromSummary(.{ .first_row = 0, .rows = 2, .first = fixture.initial[0], .last = fixture.initial[1] }, 4, 8, null),
        try memory.Claim.fromSummary(.{ .first_row = 2, .rows = 2, .first = fixture.initial[2], .last = fixture.initial[3] }, 4, 9, fixture.initial[1]),
    };
    var traces: [2]Trace = undefined;
    for (&traces, claims, 0..) |*source, claim, index| {
        source.* = try Trace.init(a, claim);
        for (fixture.initial[index * 2 ..][0..2]) |event| try source.append(event);
        try source.seal();
    }
    defer for (&traces) |*source| source.deinit();
    var counter = try counter_mod.Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    var roots: [2][2][32]u8 = undefined;
    for (&traces, &roots, 0..) |*source, *root_pair, index| root_pair.* = (try api.commitFirstRoundRootsOnly(a, source, &counter, @intCast(index), config)).roots;
    if (compact) {
        var original_counter = try counter_mod.Counter.init(a, .range_check_8_8);
        defer original_counter.deinit(a);
        for (&traces, claims, roots, 0..) |*source, claim, root_pair, index| {
            var full = try trace.Trace.init(a, claim);
            defer full.deinit();
            for (fixture.initial[index * 2 ..][0..2]) |event| try full.append(event);
            try full.seal();
            try std.testing.expectEqual(@as(usize, 66) * source.domainSize(), source.main_storage.len);
            for (0..source.domainSize()) |logical| {
                try std.testing.expectEqualDeep(full.inputRow(logical), source.inputRow(logical));
                try std.testing.expectEqualDeep(full.eventRow(logical), source.eventRow(logical));
            }
            const full_first = try instance.ForBackend(Cpu).commitFirstRoundRootsOnly(a, &full, &original_counter, @intCast(index), config);
            try std.testing.expectEqualDeep(full_first.roots[0], root_pair[0]);
            try std.testing.expect(!std.meta.eql(full_first.roots[1], root_pair[1]));
        }
        try std.testing.expectEqualDeep(@import("../../air/block/memory_range_interaction_v2.zig").counterSnapshot(&original_counter), @import("../../air/block/memory_range_interaction_v2.zig").counterSnapshot(&counter));
    }
    var plan = try shard.plan(a, &claims, 4);
    defer plan.deinit(a);
    var table_first = try table.ForBackend(Cpu).commitFirstRound(a, &counter, plan.shards[0], config);
    defer table_first.deinit(a);
    var pins = try fixture.sealPins(source_pins, config);
    pins.counts[@intFromEnum(v5.Family.memory) - 1] = 2;
    pins.memory_plan_digest = if (compact) try @import("../block_v5_memory_compact_v1.zig").planDigest(&claims, &roots, &.{table_first.roots}, &plan) else try base.memoryPlanDigest(&claims, &roots, &.{table_first.roots}, &plan);
    pins.expected_final_rw_root = final_root;
    var endpoint_pins = sources.Pins{ .initial = source_pins, .memory_plan_digest = pins.memory_plan_digest, .expected_final_rw_root = final_root, .endpoints = .{ .sha256 = initial_sources.sha256(bytes), .records = 3 } };
    pins.rw_endpoint_plan_digest = try endpoint_pins.digest();
    const entries = [_]v5.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(11), .roots = .{ @splat(12), @splat(13) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(14), .roots = .{ @splat(15), @splat(16) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(17), .roots = .{ @splat(18), @splat(19) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(26), .roots = .{ @splat(27), @splat(28) } },
        .{ .family = .memory, .index = 0, .instance_id = if (compact) @import("../block_v5_memory_compact_v1.zig").instanceId(claims[0], 0) else base.memoryInstanceId(claims[0], 0), .roots = roots[0] },
        .{ .family = .memory, .index = 1, .instance_id = if (compact) @import("../block_v5_memory_compact_v1.zig").instanceId(claims[1], 1) else base.memoryInstanceId(claims[1], 1), .roots = roots[1] },
        .{ .family = .memory_range, .index = 0, .instance_id = base.rangeShardId(plan.digest, 0), .roots = table_first.roots },
    };
    var sealed = try v5.seal(pins, &entries);
    var loader = try produce(compact, a, &traces, &counter, &plan, roots, table_first.roots, pins, &entries, sealed);
    var batch_pins = base.Pins{ .source = source_pins, .seal = pins, .expected_seal_digest = sealed.digest, .first_round = &entries, .claims = &claims, .memory_roots = &roots, .range_roots = &.{table_first.roots}, .expected_total_events = 4 };
    // Corrupted public bytes and independent root mutations fail before taking proofs.
    var corrupted = records;
    corrupted[0][4] ^= 1;
    try fixture.writeFile(tmp.dir, "endpoints.bin", std.mem.sliceAsBytes(&corrupted));
    try std.testing.expectError(error.UntrustedV5InitialSourceBytes, receiver(Cpu, a, batch_pins, endpoint_pins, &fixture.input, opened, loader.interface(), sealed));
    try fixture.writeFile(tmp.dir, "endpoints.bin", bytes);
    var wrong_root = endpoint_pins;
    wrong_root.expected_final_rw_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5EndpointPlan, receiver(Cpu, a, batch_pins, wrong_root, &fixture.input, opened, loader.interface(), sealed));
    try std.testing.expectEqual(@as(u32, 0), loader.memory_at);
    const accepted = try receiver(Cpu, a, batch_pins, endpoint_pins, &fixture.input, opened, loader.interface(), sealed);
    try std.testing.expectEqual(@as(u64, 3), accepted.memory_endpoints);
    try std.testing.expectEqual(@as(u64, 1), accepted.input_endpoints);
    try std.testing.expectEqual(@as(u64, 2), accepted.rw_endpoints);
    try std.testing.expectEqualDeep(final_root, accepted.final_rw_root);
    try std.testing.expect(loader.table_taken);
    // Re-pinned/re-sealed clock changes retain the same final root but fail
    // against newly fresh-proved endpoint claims, after all sorted/range checks.
    endpoint_pins.endpoints.sha256 = initial_sources.sha256(std.mem.sliceAsBytes(&corrupted));
    pins.rw_endpoint_plan_digest = try endpoint_pins.digest();
    sealed = try v5.seal(pins, &entries);
    batch_pins.seal = pins;
    batch_pins.expected_seal_digest = sealed.digest;
    try fixture.writeFile(tmp.dir, "endpoints.bin", std.mem.sliceAsBytes(&corrupted));
    loader = try produce(compact, a, &traces, &counter, &plan, roots, table_first.roots, pins, &entries, sealed);
    try std.testing.expectError(error.UnclosedV5RwEndpointRelation, receiver(Cpu, a, batch_pins, endpoint_pins, &fixture.input, opened, loader.interface(), sealed));
    try std.testing.expect(loader.table_taken);
}
