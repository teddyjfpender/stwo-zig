const std = @import("std");
const compression = @import("stwo_core").crypto.blake3_compression;
const topology = @import("blake3_compression_plan.zig");
const partition = @import("blake3_compression_partition.zig");
test "compression partitions preserve all native transitions and exact external uses" {
    var random = std.Random.DefaultPrng.init(0x8abcef32);
    for (1..57) |width| {
        const plan = try partition.build(@intCast(width));
        try plan.validate();
        for (0..8) |_| {
            var cv: [8]u32 = undefined;
            var block: [16]u32 = undefined;
            for (&cv) |*word| word.* = random.random().int(u32);
            for (&block) |*word| word.* = random.random().int(u32);
            const counter = random.random().int(u64);
            const len = random.random().uintLessThan(u32, 65);
            const flags = random.random().int(u32);
            try check(plan, cv, block, counter, len, flags);
        }
    }
}
fn check(plan: partition.Plan, cv: [8]u32, block: [16]u32, counter: u64, len: u32, flags: u32) !void {
    const graph = topology.canonical();
    var wires: [topology.WIRE_COUNT]u32 = @splat(0);
    var available: [topology.WIRE_COUNT]bool = @splat(false);
    var balance: [topology.WIRE_COUNT]i64 = @splat(0);
    wires[0..32].* = cv ++ compression.IV[0..4].* ++ [4]u32{ @truncate(counter), @truncate(counter >> 32), len, flags } ++ block;
    @memset(available[0..32], true);
    // Initial producers are outside the fused component. Count their consumers
    // independently from the declared exports; intermediate balances must close.
    for (plan.groups[0..plan.count]) |group| {
        var local: [topology.WIRE_COUNT]u32 = undefined;
        var defined: [topology.WIRE_COUNT]bool = @splat(false);
        for (group.inputs[0..group.input_count]) |wire| {
            try std.testing.expect(available[wire]);
            local[wire] = wires[wire];
            defined[wire] = true;
            balance[wire] -= 1;
        }
        var ops = compression.Native{};
        for (graph.g[group.first..][0..group.count]) |call| {
            var input: [6]u32 = undefined;
            for (&input, call.input) |*word, wire| {
                try std.testing.expect(defined[wire]);
                word.* = local[wire];
            }
            const output = try compression.g(compression.Native, &ops, input);
            for (call.output, output) |wire, word| {
                try std.testing.expect(!defined[wire]);
                local[wire] = word;
                defined[wire] = true;
            }
        }
        for (group.outputs[0..group.output_count], group.output_uses[0..group.output_count]) |wire, uses| {
            try std.testing.expect(defined[wire] and !available[wire]);
            wires[wire] = local[wire];
            available[wire] = true;
            balance[wire] += uses;
        }
    }
    var output: [16]u32 = undefined;
    for (graph.xor, &output) |call, *word| {
        for (call.input) |wire| {
            try std.testing.expect(available[wire]);
            balance[wire] -= 1;
        }
        word.* = wires[call.input[0]] ^ wires[call.input[1]];
    }
    try std.testing.expectEqualDeep(try compression.compress(cv, block, counter, len, flags), output);
    for (balance[32..]) |value| try std.testing.expectEqual(@as(i64, 0), value);
}
test "compression partition admission rejects changed schedules and weights" {
    try std.testing.expectError(error.InvalidCompressionPartition, partition.build(0));
    try std.testing.expectError(error.InvalidCompressionPartition, partition.build(57));
    const plan = try partition.build(8);
    var changed = plan;
    changed.groups[0].inputs[0] ^= 1;
    try std.testing.expectError(error.InvalidCompressionPartition, changed.validate());
    changed = plan;
    changed.groups[0].output_uses[0] += 1;
    try std.testing.expectError(error.InvalidCompressionPartition, changed.validate());
    changed = plan;
    changed.groups[0].count -= 1;
    try std.testing.expectError(error.InvalidCompressionPartition, changed.validate());
    var cells: usize = 0;
    var events: usize = 0;
    for (plan.groups[0..plan.count]) |group| {
        cells += group.mainColumns();
        events += group.lookupEvents();
    }
    try std.testing.expectEqual(@as(usize, 5824), cells);
    try std.testing.expectEqual(@as(usize, 3024), events);
}
