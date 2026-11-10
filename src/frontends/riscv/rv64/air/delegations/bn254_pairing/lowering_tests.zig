const std = @import("std");
const S = @import("spec.zig");
const W = @import("witness.zig");
const L = @import("lowering.zig");
const NW = @import("normalized_witness.zig");
const V = @import("../bn254_miller/vectors.zig");
const R = @import("../bn254_residue/vectors.zig");
fn private() W.Private {
    return .{ .seed = R.POSITIVE.seed, .scale = R.POSITIVE.c[0..6].*, .inverse2 = R.POSITIVE.inverse2 };
}
test "complete pairing MAC12 lowering shares every source writer and counts all25 ports" {
    var p = try L.Program.init(std.testing.allocator);
    defer p.deinit();
    try std.testing.expectEqual(32543, p.stages.len);
    try std.testing.expectEqual(1438, p.hints.len);
    try std.testing.expectEqual(34035, p.value_count);
    try std.testing.expectEqual(1514, L.FRONTIER_ROWS);
    var next: u32 = S.INITIAL;
    for (p.events) |event| switch (event.kind) {
        .hint => {
            const hint = p.hints[event.index];
            try std.testing.expectEqual(next, hint.writer);
            if (hint.kind == .inverse) try std.testing.expect(hint.denominator < hint.writer);
            next += 1;
        },
        .arithmetic => {
            const stage = p.stages[event.index];
            try std.testing.expectEqual(next, stage.writer);
            for (stage.input) |id| try std.testing.expect(id < stage.writer);
            _ = try p.fixed(event.index);
            next += 1;
        },
    };
    try std.testing.expectEqual(next, p.value_count);
    var mass: usize = 0;
    for (p.fanout) |n| mass += n;
    try std.testing.expectEqual(25 * p.stages.len + p.assertions.len, mass);
    try std.testing.expectEqual(815035, mass);
    var independently = try std.testing.allocator.alloc(u32, p.value_count);
    defer std.testing.allocator.free(independently);
    @memset(independently, 0);
    for (p.stages) |stage| for (stage.input) |id| {
        independently[id] += 1;
    };
    for (p.assertions) |obligation| independently[obligation.id] += 1;
    try std.testing.expectEqualSlices(u32, independently, p.fanout);
    for (p.assertions, W.ROM.assertions) |actual, old| {
        try std.testing.expectEqual(p.source_to_new[old.id], actual.id);
        try std.testing.expectEqual(old.value, actual.value);
    }
    for (0..L.FRONTIER_ROWS) |i| {
        try std.testing.expect(p.frontierId(i) < p.value_count);
        if (i >= S.INITIAL) try std.testing.expectEqual(-1, p.frontierWeight(i));
    }
}
test "complete pairing normalized canonical values equal every original source and row" {
    var p = try L.Program.init(std.testing.allocator);
    defer p.deinit();
    var source = try W.Witness.init(std.testing.allocator, V.INPUT, private());
    defer source.deinit();
    var actual = try NW.Witness.init(std.testing.allocator, &p, &source);
    defer actual.deinit();
    try std.testing.expect(actual.satisfied(&p));
    for (p.source_to_new, source.values) |id, value| try std.testing.expectEqual(value, actual.values[id]);
    const indices = [_]usize{ 0, 15, 1000, 32000, 32542 };
    for (indices) |i| {
        const row = try actual.row(&p, i);
        try std.testing.expect(NW.MW.valid(&row, p.stages[i].coefficients));
    }
    for ([_]usize{ 0, 351, 1408, 1437 }) |i| {
        const row = try actual.hintRow(&p, i);
        const hint = p.hints[i];
        try std.testing.expect(NW.HW.valid(&row, .{ 1, hint.writer, p.fanout[hint.writer] }));
    }
    const expected = try S.initialValues(V.INPUT);
    for (0..L.FRONTIER_ROWS) |i| {
        const required = p.frontierExpected(i, &expected);
        if (i < S.INITIAL) try std.testing.expectEqual(required, actual.values[i]) else try std.testing.expectEqual(required, actual.values[p.frontierId(i)]);
    }
    const changed = p.stages[1000].writer;
    actual.values[changed] = (actual.values[changed] + 1) % S.B.BN254_P;
    try std.testing.expect(!actual.satisfied(&p));
}
test "complete pairing lowering rejects coherently disconnected source reference" {
    var p = try L.Program.init(std.testing.allocator);
    defer p.deinit();
    var source = try W.Witness.init(std.testing.allocator, V.INPUT, private());
    defer source.deinit();
    try source.corruptForTesting(.swapped_subgroup_q);
    try std.testing.expectError(error.NormalizedSourceOutputMismatch, NW.Witness.init(std.testing.allocator, &p, &source));
}
test "complete pairing lowering cleans early and late allocation failures" {
    for ([_]usize{ 0, 1, 2, 3, 4, 5, 6, 32001 }) |index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        const result = L.Program.init(failing.allocator());
        if (result) |value| {
            var p = value;
            p.deinit();
            return error.ExpectedAllocationFailure;
        } else |err| try std.testing.expectEqual(error.OutOfMemory, err);
    }
}
