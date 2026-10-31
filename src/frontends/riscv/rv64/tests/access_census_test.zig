const std = @import("std");
const census = @import("../access_census.zig");
const a = std.testing.allocator;

test "RV64 census: typed service counts survive exact batch flush boundaries" {
    var c = try census.Census.init(a, 2);
    defer c.deinit();
    try c.retireService(.keccak);
    try c.retireService(.secp_add);
    try c.retireService(.secp_double);
    try c.retireOpcode(@intFromEnum(@import("../decode.zig").Opcode.ADD));
    const rows = try c.finish();
    defer a.free(rows);
    try std.testing.expectEqual(@as(usize, 2), rows.len);
    try std.testing.expectEqual(@as(u64, 1), rows[0].keccak_calls);
    try std.testing.expectEqual(@as(u64, 1), rows[0].secp_add_calls);
    try std.testing.expectEqual(@as(u64, 0), rows[0].secp_double_calls);
    try std.testing.expectEqual(@as(u64, 1), rows[1].secp_double_calls);
    try std.testing.expectEqual(@as(u64, 0), rows[1].keccak_calls + rows[1].secp_add_calls);
    try std.testing.expectError(error.CensusFinished, c.retireService(.keccak));
    try std.testing.checkAllAllocationFailures(a, serviceAllocationCase, .{});
}
fn serviceAllocationCase(allocator: std.mem.Allocator) !void {
    var c = try census.Census.init(allocator, 1);
    defer c.deinit();
    c.retireService(.secp_add) catch |err| {
        try std.testing.expectEqual(@as(u64, 0), c.total_steps);
        try std.testing.expectEqualDeep([3]u64{ 0, 0, 0 }, c.service_counts);
        return err;
    };
    const rows = try c.finish();
    defer allocator.free(rows);
    try std.testing.expectEqual(@as(u64, 1), rows[0].secp_add_calls);
}

test "RV64 census: exact canonical cells and aligned chunks include high addresses" {
    var c = try census.Census.init(a, 2);
    defer c.deinit();
    const addresses = [_]u64{ 0, 63, 64, 127, 128, 255, 256, 4095, 4096, std.math.maxInt(u64) };
    for (addresses) |address| try c.observe(address, 0, 0, false);
    try c.retire();
    const rows = try c.finish();
    defer a.free(rows);
    try std.testing.expectEqual(@as(usize, 1), rows.len);
    try std.testing.expectEqual(@as(u64, addresses.len), rows[0].distinct_touched_cells);
    try std.testing.expectEqualDeep([7]u64{ 8, 6, 5, 4, 4, 4, 3 }, rows[0].touched_chunks);
    try std.testing.expectEqual(@as(u64, 0), rows[0].distinct_written_cells);
    try std.testing.expectEqualDeep([7]u64{ 0, 0, 0, 0, 0, 0, 0 }, rows[0].net_changed_chunks);
    for (census.CHUNK_BYTES, 0..) |bytes, i| try std.testing.expectEqual(try oracleNodes(&addresses, bytes), rows[0].touched_internal_nodes[i]);
}

test "RV64 census: repeated writes and net-zero reversals are not net changes" {
    var c = try census.Census.init(a, 100);
    defer c.deinit();
    try c.observe(0, 10, 11, true);
    try c.observe(7, 11, 10, true);
    try c.observe(64, 0, 9, true);
    try c.observe(64, 9, 12, true);
    try c.observe(128, 5, 5, true);
    try c.observe(4096, 1, 2, true);
    try c.retire(); // All six events can belong to one atomic service.
    const rows = try c.finish();
    defer a.free(rows);
    try std.testing.expectEqual(@as(u64, 6), rows[0].access_events);
    try std.testing.expectEqual(@as(u32, 1), rows[0].instructions);
    try std.testing.expectEqual(@as(u64, 4), rows[0].distinct_written_cells);
    try std.testing.expectEqual(@as(u64, 2), rows[0].net_changed_cells);
    try std.testing.expectEqualDeep([7]u64{ 2, 2, 2, 2, 2, 2, 2 }, rows[0].net_changed_chunks);
    for (census.CHUNK_BYTES, 0..) |bytes, i| try std.testing.expectEqual(try oracleNodes(&.{ 64, 4096 }, bytes), rows[0].net_changed_internal_nodes[i]);
}

test "RV64 census: batch boundaries count memory-free retirements and reset local net values" {
    var c = try census.Census.init(a, 2);
    defer c.deinit();
    try c.observe(0x1000, 0, 9, true);
    try c.retire();
    const page_capacity = c.pages.capacity();
    const word_capacity = c.words.capacity();
    try c.retire(); // Instruction with no RAM access still closes the batch.
    try std.testing.expectEqual(@as(usize, 0), c.pages.count());
    try std.testing.expectEqual(page_capacity, c.pages.capacity());
    try std.testing.expectEqual(word_capacity, c.words.capacity());
    try c.observe(0x1000, 9, 9, true);
    try c.retire();
    const rows = try c.finish();
    defer a.free(rows);
    try std.testing.expectEqual(@as(usize, 2), rows.len);
    try std.testing.expectEqual(@as(u64, 0), rows[0].first_step);
    try std.testing.expectEqual(@as(u64, 2), rows[0].end_step);
    try std.testing.expectEqual(@as(u64, 2), rows[1].first_step);
    try std.testing.expectEqual(@as(u64, 3), rows[1].end_step);
    try std.testing.expectEqual(@as(u64, 1), rows[0].net_changed_cells);
    try std.testing.expectEqual(@as(u64, 0), rows[1].net_changed_cells);
}

test "RV64 census: phases and malformed native events fail without publishing counts" {
    try std.testing.expectError(error.InvalidCensusBatchSteps, census.Census.init(a, 0));
    try std.testing.expectError(error.InvalidCensusBatchSteps, census.Census.init(a, census.MAX_BATCH_STEPS + 1));
    var c = try census.Census.init(a, 4);
    defer c.deinit();
    try std.testing.expectError(error.CensusLoadMutation, c.observe(0, 0, 1, false));
    try std.testing.expectEqual(@as(u64, 0), c.events);
    try c.observe(0, 0, 1, true);
    try std.testing.expectError(error.CensusWordDiscontinuity, c.observe(0, 0, 2, true));
    try std.testing.expectEqual(@as(u64, 1), c.events);
    try std.testing.expectError(error.UnretiredCensusEvents, c.finish());
    try c.retire();
    const rows = try c.finish();
    defer a.free(rows);
    try std.testing.expectError(error.CensusFinished, c.finish());
    try std.testing.expectError(error.CensusFinished, c.retire());
    try std.testing.expectError(error.CensusFinished, c.observe(0, 1, 1, false));
}

fn failingFixture(allocator: std.mem.Allocator) !void {
    var c = try census.Census.init(allocator, 2);
    defer c.deinit();
    for (0..25) |i| try c.observe(@as(u64, @intCast(i)) * 4096, 0, 1, true);
    try c.retire();
    try c.retire();
    try c.observe(0, 1, 0, true);
    try c.retire();
    const rows = try c.finish();
    defer allocator.free(rows);
    try std.testing.expectEqual(@as(usize, 2), rows.len);
    try std.testing.expectEqual(@as(u64, 25), rows[0].net_changed_cells);
    try std.testing.expectEqual(@as(u64, 1), rows[1].net_changed_cells);
}

test "RV64 census: complete batch and owned reports clean every allocation failure" {
    try std.testing.checkAllAllocationFailures(a, failingFixture, .{});
}

test "RV64 census: failed observe reserves publish no keys or bits" {
    for (0..2) |index| {
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = index });
        var c = try census.Census.init(failing.allocator(), 2);
        defer c.deinit();
        try std.testing.expectError(error.OutOfMemory, c.observe(0x1234, 0, 1, true));
        try std.testing.expectEqual(@as(usize, 0), c.pages.count());
        try std.testing.expectEqual(@as(usize, 0), c.words.count());
        try std.testing.expectEqual(@as(u64, 0), c.events);
        try std.testing.expect(!c.unretired_events);
    }
}

// Deliberately materializes the parent set as an independent small oracle;
// production counts it from adjacent ordered prefixes without per-chunk memory.
fn oracleNodes(addresses: []const u64, bytes: u32) !u64 {
    const Node = struct { height: u8, index: u64 };
    var parents = std.AutoHashMap(Node, void).init(a);
    defer parents.deinit();
    const log = std.math.log2_int(u32, bytes);
    for (addresses) |address| {
        const leaf = address >> @intCast(log);
        for (1..65 - @as(usize, log)) |height| try parents.put(.{ .height = @intCast(height), .index = leaf >> @intCast(height) }, {});
    }
    return parents.count();
}

test "RV64 census: shared nodes match independent parent sets for unsorted sparse and dense pages" {
    var c = try census.Census.init(a, 1);
    defer c.deinit();
    var addresses: [512 + 3]u64 = undefined;
    for (0..512) |i| addresses[i] = @as(u64, @intCast(511 - i)) * 8;
    addresses[512] = std.math.maxInt(u64);
    addresses[513] = 0x1_0000_0000;
    addresses[514] = std.math.maxInt(u64) - 4096;
    for (addresses) |address| try c.observe(address, 0, 1, true);
    try c.retire();
    const rows = try c.finish();
    defer a.free(rows);
    for (census.CHUNK_BYTES, 0..) |bytes, i| {
        const expected = try oracleNodes(&addresses, bytes);
        try std.testing.expectEqual(expected, rows[0].touched_internal_nodes[i]);
        try std.testing.expectEqual(expected, rows[0].net_changed_internal_nodes[i]);
    }
}

test "RV64 census: key-scratch OOM precedes retirement-counter publication" {
    var failing = std.testing.FailingAllocator.init(a, .{});
    var c = try census.Census.init(failing.allocator(), 1);
    defer c.deinit();
    try c.observe(0x1000, 0, 1, true);
    // First reserve allocates report storage; the next allocates page keys.
    failing.fail_index = failing.alloc_index + 1;
    try std.testing.expectError(error.OutOfMemory, c.retireOpcode(63));
    try std.testing.expectEqual(@as(u64, 0), c.total_steps);
    try std.testing.expectEqual(@as(u32, 0), c.steps);
    try std.testing.expectEqual(@as(u64, 0), c.opcode_counts[63]);
    try std.testing.expect(c.unretired_events);
    try std.testing.expectEqual(@as(u64, 1), c.events);
    failing.fail_index = std.math.maxInt(usize);
    try c.retireOpcode(63);
    const rows = try c.finish();
    defer failing.allocator().free(rows);
    try std.testing.expectEqual(@as(u64, 1), rows[0].end_step);
    try std.testing.expectEqual(@as(u64, 1), rows[0].opcode_counts[63]);
}

test "RV64 census: opcode batches count ECALL and preserve unclassified compatibility" {
    var c = try census.Census.init(a, 2);
    defer c.deinit();
    try c.retireOpcode(63);
    try std.testing.expectError(error.InvalidCensusOpcode, c.retireOpcode(65));
    try std.testing.expectEqual(@as(u64, 1), c.total_steps);
    try c.retireOpcode(0);
    try c.retire();
    const rows = try c.finish();
    defer a.free(rows);
    try std.testing.expectEqual(@as(u64, 1), rows[0].opcode_counts[63]);
    try std.testing.expectEqual(@as(u64, 1), rows[0].opcode_counts[0]);
    try std.testing.expectEqual(@as(u64, 0), rows[0].unclassified_instructions);
    try std.testing.expectEqual(@as(u64, 1), rows[1].unclassified_instructions);
    for (rows) |row| {
        var count = row.unclassified_instructions;
        for (row.opcode_counts) |n| count += n;
        try std.testing.expectEqual(@as(u64, row.instructions), count);
    }
}
