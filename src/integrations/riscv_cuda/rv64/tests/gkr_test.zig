const std = @import("std");
const G = @import("../gkr.zig");
const R = @import("../resident.zig");
const A = @import("../abi.zig");
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
test "complete GKR arena admits exact requested payload and rejects invalid geometry before allocation" {
    const p = try G.Plan.init(&.{ 1, 3, 2 }, std.math.maxInt(usize));
    try std.testing.expectEqual(@as(u32, 3), p.layers);
    try std.testing.expectEqual(@as(u32, 3), p.count);
    for (p.layer[0..3], [_]u32{ 1, 2, 3 }, 0..) |l, active, depth| {
        try std.testing.expectEqual(active, l.active);
        try std.testing.expectEqual(active * 32, l.masks.words);
        try std.testing.expectEqual(depth * A.round_record_words, l.records.words);
        try std.testing.expect(l.records.offset_words % 64 == 0 and l.masks.offset_words % 64 == 0);
    }
    _ = try G.Plan.init(&.{ 1, 3, 2 }, p.total_words * 4);
    try std.testing.expectError(error.GkrWorkspaceBudgetExceeded, G.Plan.init(&.{ 1, 3, 2 }, p.total_words * 4 - 1));
    try std.testing.expectError(error.InvalidGeometry, G.Plan.init(&.{}, 1));
    try std.testing.expectError(error.InvalidGeometry, G.Plan.init(&.{0}, std.math.maxInt(usize)));
    try std.testing.expectError(error.InvalidGeometry, G.Plan.init(&.{29}, std.math.maxInt(usize)));
    const largest = try G.Plan.init(&.{28}, std.math.maxInt(usize));
    try std.testing.expect(largest.total_words > 1 << 30);
    try std.testing.expectError(error.GkrWorkspaceBudgetExceeded, G.Plan.init(&.{28}, 16 << 30));
}
const Context = struct {
    pub fn deviceSlicePointer(_: *@This(), comptime T: type, slice: Slice, count: usize) ![*]T {
        if (slice.owner != 1 or slice.generation != 2 or count > slice.len) return error.InvalidDeviceAddress;
        return @ptrFromInt(slice.address);
    }
};
const Commands = struct {
    context: *Context,
    poisoned: bool = false,
    batched_trees: bool = false,
    tree_waves: usize = 0,
    tree_edges: [2048][5]usize = undefined,
    calls: usize = 0,
    layers: u32 = 0,
    batches: u32 = 0,
    masks: u32 = 0,
    parents: u32 = 0,
    closures: u32 = 0,
    projected_validations: usize = 0,
    projected_layers: usize = 0,
    projected_sums: usize = 0,
    projected_folds: usize = 0,
    projected_masks: usize = 0,
    pub fn validateProjection(s: *@This(), _: R.Fraction) !void {
        s.projected_validations += 1;
    }
    pub fn closeLocalRoots(s: *@This(), _: Slice, _: u32, _: Slice) !void {
        s.calls += 1;
        s.closures += 1;
    }
    pub fn layer(s: *@This(), input: R.Fraction, levels: u32, output: R.Fraction) !void {
        try std.testing.expectEqual(@as(u32, 1), levels);
        try std.testing.expectEqual(input.count / 2, output.count);
        s.calls += 1;
        s.projected_layers += @intFromBool(input.projected != null);
        s.recordEdge(input, output);
    }
    fn recordEdge(s: *@This(), input: R.Fraction, output: R.Fraction) void {
        s.tree_edges[s.layers] = .{ input.n.data.address, input.d.data.address, output.n.data.address, output.d.data.address, input.count };
        s.layers += 1;
    }
    pub fn layerBatch(s: *@This(), jobs: []const R.BatchFold) !void {
        try std.testing.expect(jobs.len != 0);
        const count = jobs[0].input.count;
        for (jobs) |job| {
            try std.testing.expectEqual(count, job.input.count);
            try std.testing.expectEqual(count / 2, job.output.count);
            s.recordEdge(job.input, job.output);
        }
        s.calls += 1;
        s.tree_waves += 1;
    }
    pub fn packRoots(s: *@This(), roots: []const R.Fraction, _: Slice) !void {
        for (roots) |r| try std.testing.expectEqual(@as(u32, 1), r.count);
        s.calls += 1;
    }
    pub fn initGkr(s: *@This(), _: Slice, _: Slice, _: []const u32, _: u32, _: u64) !void {
        s.calls += 1;
    }
    pub fn beginGkr(s: *@This(), _: Slice, depth: u32, _: u32, _: u32, _: Slice, _: Slice) !void {
        try std.testing.expectEqual(s.parents, depth);
        s.calls += 1;
    }
    pub fn closeGkr(s: *@This(), _: Slice, _: Slice, _: Slice, _: Slice, depth: u32, _: u32, _: u32) !void {
        try std.testing.expectEqual(s.parents, depth);
        s.parents += 1;
        s.calls += 1;
    }
    pub fn initBatch(s: *@This(), _: Slice, _: Slice, _: Slice, _: Slice, _: []const R.BatchOracle, _: u32) !void {
        s.batches += 1;
        s.calls += 1;
    }
    pub fn eq(s: *@This(), _: Slice, _: u32, _: R.Plane) !void {
        s.calls += 1;
    }
    pub fn sum(s: *@This(), input: R.Fraction, _: R.Plane, _: Slice, _: R.Plane, _: R.Plane, _: R.Plane) !void {
        s.calls += 1;
        s.projected_sums += @intFromBool(input.projected != null);
    }
    pub fn batchRound(s: *@This(), _: Slice, _: []const R.BatchOracle, _: u32, _: u32, _: Slice, _: Slice) !void {
        s.calls += 1;
    }
    pub fn fold(s: *@This(), input: R.Fraction, _: Slice, _: R.Fraction) !void {
        s.calls += 1;
        s.projected_folds += @intFromBool(input.projected != null);
    }
    pub fn packBatchMask(s: *@This(), input: R.Fraction, _: Slice) !void {
        try std.testing.expectEqual(@as(u32, 2), input.count);
        s.masks += 1;
        s.projected_masks += @intFromBool(input.projected != null);
        s.calls += 1;
    }
};
test "projected GKR sources are revisited at the final layer and all borrowed slabs reject arena aliasing" {
    var f = Factory{};
    var context = Context{};
    var commands = Commands{ .context = &context };
    var inputs = [_]R.Fraction{ f.fraction(2), f.fraction(8), f.fraction(4) };
    var borrowed: [3][2]Slice = undefined;
    for (&inputs, &borrowed) |*input, *spans| {
        spans.* = .{ input.n.data, input.d.data };
        input.projected = .{ .descriptor = @ptrFromInt(1), .borrowed = spans, .validate = undefined, .layer = undefined, .sum = undefined, .fold = undefined, .mask = undefined };
    }
    const seed = f.slice(9);
    const plan = try G.Plan.init(&.{ 1, 3, 2 }, std.math.maxInt(usize));
    const arena = f.slice(plan.total_words);
    _ = try G.enqueue(&commands, &inputs, seed, arena, plan.total_words * 4, 1);
    try std.testing.expectEqual(@as(usize, 6), commands.projected_validations);
    try std.testing.expectEqual(@as(usize, 3), commands.projected_layers);
    try std.testing.expectEqual(@as(usize, 2), commands.projected_sums);
    try std.testing.expectEqual(@as(usize, 2), commands.projected_folds);
    try std.testing.expectEqual(@as(usize, 1), commands.projected_masks);
    commands = .{ .context = &context };
    borrowed[2][1] = try arena.sub(0, 32);
    try std.testing.expectError(error.OverlappingWorkspace, G.enqueue(&commands, &inputs, seed, arena, plan.total_words * 4, 1));
    try std.testing.expectEqual(@as(usize, 0), commands.calls);
}
const Factory = struct {
    at: usize = 4096,
    fn slice(s: *@This(), words: usize) Slice {
        const at = s.at;
        s.at += (words * 4 + 255) & ~@as(usize, 255);
        return .{ .address = at, .len = words, .owner = 1, .generation = 2 };
    }
    fn plane(s: *@This(), count: u32, coordinates: u32) R.Plane {
        return .{ .data = s.slice(count * coordinates), .stride = count, .coordinates = coordinates };
    }
    fn fraction(s: *@This(), count: u32) R.Fraction {
        return .{ .n = s.plane(count, 1), .d = s.plane(count, 8), .count = count };
    }
};
test "complete GKR uses one arena and native mixed batch traversal without host claims" {
    var f = Factory{};
    var context = Context{};
    var commands = Commands{ .context = &context };
    const inputs = [_]R.Fraction{ f.fraction(2), f.fraction(8), f.fraction(4) };
    const seed = f.slice(9);
    const p = try G.Plan.init(&.{ 1, 3, 2 }, std.math.maxInt(usize));
    const done = try G.enqueue(&commands, &inputs, seed, f.slice(p.total_words), p.total_words * 4, 123);
    try std.testing.expectEqual(@as(u32, 6), commands.layers);
    try std.testing.expectEqual(@as(u32, 3), commands.batches);
    try std.testing.expectEqual(@as(u32, 3), commands.parents);
    try std.testing.expectEqual(@as(u32, 6), commands.masks);
    try std.testing.expectEqual(p.total_words * 4, done.requested_workspace_bytes);
    var h = G.Header{ .channel = .{ .digest = @splat(0), .draws = 1, .cursor = 6, .status = 0, .reserved = 0, .chain = 123, .padding = .{ 0, 0 } }, .layers = 3, .count = 3, .next_layer = 3, .phase = 2 };
    try h.validate(done);
    h.phase = 1;
    try std.testing.expectError(error.IncompleteGkrTraversal, h.validate(done));
    h.phase = 2;
    h.channel.chain += 1;
    try std.testing.expectError(error.InvalidDeviceTranscript, h.validate(done));
}
test "batched product trees retain every exact serial intermediate with one wave per height" {
    const heights = [_]u32{ 1, 3, 8, 6, 8, 2, 4 };
    var f = Factory{};
    var inputs: [heights.len]R.Fraction = undefined;
    for (&inputs, heights) |*input, height| input.* = f.fraction(@as(u32, 1) << @intCast(height));
    const seed = f.slice(9);
    const plan = try G.Plan.init(&heights, std.math.maxInt(usize));
    const arena = f.slice(plan.total_words);
    var context = Context{};
    var serial = Commands{ .context = &context };
    var batched = Commands{ .context = &context, .batched_trees = true };
    _ = try G.enqueue(&serial, &inputs, seed, arena, plan.total_words * 4, 1);
    _ = try G.enqueue(&batched, &inputs, seed, arena, plan.total_words * 4, 1);
    try std.testing.expectEqual(serial.layers, batched.layers);
    try std.testing.expectEqual(@as(usize, 8), batched.tree_waves);
    try std.testing.expectEqual(serial.calls - serial.layers + batched.tree_waves, batched.calls);
    for (serial.tree_edges[0..serial.layers]) |edge| {
        var matches: usize = 0;
        for (batched.tree_edges[0..batched.layers]) |other| if (std.mem.eql(usize, &edge, &other)) {
            matches += 1;
        };
        try std.testing.expectEqual(@as(usize, 1), matches);
    }
    try std.testing.expectEqual(serial.batches, batched.batches);
    try std.testing.expectEqual(serial.parents, batched.parents);
    try std.testing.expectEqual(serial.masks, batched.masks);
}
test "complete GKR rejects late invalid input alias generation and cap before any launch" {
    var f = Factory{};
    var context = Context{};
    var commands = Commands{ .context = &context };
    var inputs = [_]R.Fraction{ f.fraction(2), f.fraction(8), f.fraction(4) };
    const seed = f.slice(9);
    const p = try G.Plan.init(&.{ 1, 3, 2 }, std.math.maxInt(usize));
    const arena = f.slice(p.total_words);
    try std.testing.expectError(error.GkrWorkspaceBudgetExceeded, G.enqueue(&commands, &inputs, seed, arena, p.total_words * 4 - 1, 1));
    var short = arena;
    short.len -= 1;
    try std.testing.expectError(error.InvalidDeviceAddress, G.enqueue(&commands, &inputs, seed, short, p.total_words * 4, 1));
    var stale = arena;
    stale.generation = 1;
    try std.testing.expectError(error.InvalidDeviceAddress, G.enqueue(&commands, &inputs, seed, stale, p.total_words * 4, 1));
    try std.testing.expectError(error.OverlappingWorkspace, G.enqueue(&commands, &inputs, try arena.sub(0, 9), arena, p.total_words * 4, 1));
    const before = inputs[2].d.data;
    inputs[2].d.data = try arena.sub(0, before.len);
    try std.testing.expectError(error.OverlappingWorkspace, G.enqueue(&commands, &inputs, seed, arena, p.total_words * 4, 1));
    inputs[2].d.data = before;
    inputs[2].d.data.len -= 1;
    try std.testing.expectError(error.InvalidDeviceAddress, G.enqueue(&commands, &inputs, seed, arena, p.total_words * 4, 1));
    try std.testing.expectEqual(@as(usize, 0), commands.calls);
}

test "closure GKR path reserves its verdict before any launch and requires it after completion" {
    var f = Factory{};
    var context = Context{};
    var commands = Commands{ .context = &context };
    const inputs = [_]R.Fraction{ f.fraction(2), f.fraction(8), f.fraction(4) };
    const seed = f.slice(9);
    const p = try G.Plan.init(&.{ 1, 3, 2 }, std.math.maxInt(usize));
    const arena = f.slice(p.total_words);
    try std.testing.expectError(error.OverlappingWorkspace, G.enqueueWithClosure(&commands, &inputs, seed, arena, p.total_words * 4, 123, try arena.sub(0, 1)));
    var status = f.slice(1);
    status.generation = 1;
    try std.testing.expectError(error.InvalidDeviceAddress, G.enqueueWithClosure(&commands, &inputs, seed, arena, p.total_words * 4, 123, status));
    try std.testing.expectEqual(@as(usize, 0), commands.calls);
    status.generation = 2;
    const done = try G.enqueueWithClosure(&commands, &inputs, seed, arena, p.total_words * 4, 123, status);
    try std.testing.expectEqual(@as(u32, 1), commands.closures);
    const header = G.Header{ .channel = .{ .digest = @splat(0), .draws = 1, .cursor = 6, .status = 0, .reserved = 0, .chain = 123, .padding = .{ 0, 0 } }, .layers = 3, .count = 3, .next_layer = 3, .phase = 2 };
    try done.validate(header, 0);
    try std.testing.expectError(error.LocalGkrClosureRejected, done.validate(header, 8));
}

fn regionOverlaps(x: @import("../plan.zig").Region, y: @import("../plan.zig").Region) bool {
    if (x.words == 0 or y.words == 0) return false;
    return x.offset_words < y.offset_words + y.words and y.offset_words < x.offset_words + x.words;
}
test "consumed GKR tree levels are the exact fold banks and never overlap live gate inputs" {
    const heights = [_]u32{ 1, 2, 3, 4, 7, 10, 12 };
    const plan = try G.Plan.init(&heights, std.math.maxInt(usize));
    for (heights, 0..) |height, oracle| {
        var remaining = height;
        while (remaining != 0) : (remaining -= 1) {
            const banks = try plan.foldingBanks(oracle, remaining);
            const source_count = (@as(u32, 1) << @intCast(height)) >> @intCast(remaining - 1);
            try std.testing.expectEqual(@max(1, source_count / 2), banks[0].count);
            try std.testing.expectEqual(@max(1, source_count / 4), banks[1].count);
            // At zero/one sumcheck variables the unused second bank may be the
            // same root; B.enqueue does not reserve or touch that unused bank.
            const used_banks: usize = if (source_count == 2) 0 else if (source_count == 4) 1 else 2;
            for (banks[0..used_banks]) |bank| {
                try std.testing.expectEqual(@as(u64, 8) * bank.count, bank.n.words);
                try std.testing.expectEqual(@as(u64, 8) * bank.count, bank.d.words);
                try std.testing.expect(!regionOverlaps(bank.n, bank.d));
                for (plan.oracles[oracle].tree[0 .. remaining - 1]) |live| {
                    for ([_]@import("../plan.zig").Region{ bank.n, bank.d }) |target| {
                        try std.testing.expect(!regionOverlaps(target, live.n));
                        try std.testing.expect(!regionOverlaps(target, live.d));
                    }
                }
                for (heights, 0..) |other_height, other| {
                    if (other == oracle) continue;
                    for (plan.oracles[other].tree[0..other_height]) |foreign| {
                        try std.testing.expect(!regionOverlaps(bank.n, foreign.n));
                        try std.testing.expect(!regionOverlaps(bank.n, foreign.d));
                        try std.testing.expect(!regionOverlaps(bank.d, foreign.n));
                        try std.testing.expect(!regionOverlaps(bank.d, foreign.d));
                    }
                }
                for ([_]@import("../plan.zig").Region{ plan.state, plan.batch_state, plan.roots, plan.eq, plan.projected }) |authority| {
                    try std.testing.expect(!regionOverlaps(bank.n, authority));
                    try std.testing.expect(!regionOverlaps(bank.d, authority));
                }
            }
            if (used_banks == 2) {
                try std.testing.expect(!regionOverlaps(banks[0].n, banks[1].n));
                try std.testing.expect(!regionOverlaps(banks[0].n, banks[1].d));
                try std.testing.expect(!regionOverlaps(banks[0].d, banks[1].n));
                try std.testing.expect(!regionOverlaps(banks[0].d, banks[1].d));
            }
        }
    }
    try std.testing.expectError(error.InvalidGeometry, plan.foldingBanks(heights.len, 1));
    try std.testing.expectError(error.InvalidGeometry, plan.foldingBanks(0, 0));
    try std.testing.expectError(error.InvalidGeometry, plan.foldingBanks(0, 2));
}

test "GKR consumed-bank arena removes independent maximum fold allocations" {
    const height: u32 = 26;
    const plan = try G.Plan.init(&.{height}, std.math.maxInt(usize));
    const input_rows = @as(u64, 1) << height;
    const removed_bytes = 48 * input_rows;
    // Eq plus the full reduction tree dominate what remains. Dedicated fold
    // banks formerly cost another48bytes per input fact, independent of proof.
    try std.testing.expect(plan.total_words * 4 < removed_bytes * 2);
    try std.testing.expect(plan.total_words * 4 > removed_bytes);
}

test "accepted CPU0 GKR geometry reuses consumed tree for Eq as well as fold banks" {
    // Native accepted CPU0 authority, gkr-capacity.json. No Ethereum execution
    // or GPU timing is inferred from this exact allocation model.
    const variables = [_]u32{ 26, 18, 6, 22, 21, 20, 18, 16, 23, 20, 17, 16, 8, 22, 17, 18, 21, 17, 21, 18, 17, 12, 16, 17, 19, 20, 23, 13, 12, 10, 19, 14, 19, 23, 23, 21 };
    const plan = try G.Plan.init(&variables, std.math.maxInt(usize));
    var facts: u64 = 0;
    for (variables) |v| facts += @as(u64, 1) << @intCast(v);
    try std.testing.expectEqual(@as(u64, 124093760), facts);
    // The 128-oracle state adds 13,056 B over the frozen 64-oracle receipt.
    const state_delta = 4 * (A.gkr_state_words - 1428 + A.batch_state_words - 2173);
    const removed_eq = (@as(usize, 8) << 24) * 4 - 256;
    const expected = 8510105088 + state_delta - removed_eq;
    try std.testing.expectEqual(@as(usize, expected), plan.total_words * 4);
    try std.testing.expectEqual(@as(u64, 5956500480), 48 * facts);
    try std.testing.expectEqual(@as(u64, 14466605568 + state_delta - removed_eq), plan.total_words * 4 + 48 * facts);
    _ = try G.Plan.init(&variables, expected);
    try std.testing.expectError(error.GkrWorkspaceBudgetExceeded, G.Plan.init(&variables, expected - 1));
}
test "GKR Eq lifetime is disjoint from every live input and fold bank at mixed heights" {
    const Region = @import("../plan.zig").Region;
    const heights = [_]u32{ 1, 2, 3, 4, 7, 10, 12, 28 };
    const plan = try G.Plan.init(&heights, std.math.maxInt(usize));
    var remaining = plan.layers;
    while (remaining != 0) : (remaining -= 1) {
        const eq = try plan.equalityWorkspace(remaining);
        const depth = plan.layers - remaining;
        try std.testing.expectEqual(if (depth < 2) @as(u64, 64) else @as(u64, 8) << @intCast(depth - 1), eq.words);
        try std.testing.expect(eq.offset_words + eq.words <= plan.total_words);
        for (heights, 0..) |height, oracle| {
            if (height < remaining) continue;
            for (plan.oracles[oracle].tree[0 .. remaining - 1]) |live| {
                try std.testing.expect(!regionOverlaps(eq, live.n));
                try std.testing.expect(!regionOverlaps(eq, live.d));
            }
            for (try plan.foldingBanks(oracle, remaining)) |bank| {
                try std.testing.expect(!regionOverlaps(eq, bank.n));
                try std.testing.expect(!regionOverlaps(eq, bank.d));
            }
            for ([_]Region{ plan.oracles[oracle].scratch_a, plan.oracles[oracle].scratch_b, plan.oracles[oracle].sums }) |scratch| try std.testing.expect(!regionOverlaps(eq, scratch));
        }
        for ([_]Region{ plan.state, plan.batch_state, plan.roots, plan.projected }) |authority| try std.testing.expect(!regionOverlaps(eq, authority));
        for (plan.layer[0..plan.layers]) |layer| {
            try std.testing.expect(!regionOverlaps(eq, layer.records));
            try std.testing.expect(!regionOverlaps(eq, layer.masks));
        }
    }
    try std.testing.expectError(error.InvalidGeometry, plan.equalityWorkspace(0));
    try std.testing.expectError(error.InvalidGeometry, plan.equalityWorkspace(plan.layers + 1));
    const real = try G.Plan.init(&.{ 23, 22, 23, 21, 27, 26, 24, 24 }, std.math.maxInt(usize));
    try std.testing.expectEqual(@as(usize, 16573396480), real.total_words * 4);
}
