//! Emits a bounded reference for settlement's OM31 DEEP verifier.
//! Run at repo root with:
//! zig run --dep core -Mroot=settlement/tools/export_deep_vector.zig -Mcore=src/core/mod.zig > settlement/fixtures/native-deep-vector.json
const std = @import("std");
const core = @import("core");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Point = core.circle.CirclePoint(O);
const Pcs = core.pcs.ForField(O);
const Channel = core.channel.raw_mod_m31.Om31Channel;
const CanonicCoset = core.poly.circle.canonic.CanonicCoset;
const log: u32 = 5;

const Column = struct { logSize: u32, samplePoints: []const u16 };
const columns = [_]Column{
    .{ .logSize = 5, .samplePoints = &.{ 0, 1 } },
    .{ .logSize = 2, .samplePoints = &.{} },
    .{ .logSize = 3, .samplePoints = &.{ 0, 1 } },
    .{ .logSize = 2, .samplePoints = &.{0} },
    .{ .logSize = 4, .samplePoints = &.{ 1, 0 } },
};
const tree_widths = [_]usize{ 2, 1, 2 };
const tree_logs = [_]u32{ 5, 3, 4 };
const queries = [_]usize{ 0, 1, 2, 13, 17, 22, 31 };

fn element(seed: u32) O {
    var limbs: [8]M = undefined;
    for (&limbs, 0..) |*limb, i| limb.* = M.fromCanonical(seed + @as(u32, @intCast(i)) * 31);
    return O.fromM31Array(limbs);
}

fn words(value: O) [8]u32 {
    var out: [8]u32 = undefined;
    for (value.toM31Array(), 0..) |word, i| out[i] = word.toU32();
    return out;
}

fn polynomial(point: Point, column: usize) O {
    const reduced = point.repeatedDouble(log - columns[column].logSize);
    return reduced.x.mulM31(M.fromCanonical(@intCast(3 * column + 1)))
        .add(reduced.y.mulM31(M.fromCanonical(@intCast(column + 2))))
        .add(O.fromBase(M.fromCanonical(@intCast(5 * column + 9))));
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const points = [_]Point{
        try core.circle.secureFieldPointFromRandomSeedCheckedFor(O, element(7)),
        try core.circle.secureFieldPointFromRandomSeedCheckedFor(O, element(101)),
    };
    var sample_values: [columns.len][]O = undefined;
    var sample_points: [columns.len][]Point = undefined;
    var queried_values: [columns.len][]M = undefined;
    var column_logs: [columns.len]u32 = undefined;
    var flat_samples = std.ArrayList(O).empty;
    for (columns, 0..) |column, i| {
        column_logs[i] = column.logSize;
        sample_values[i] = try a.alloc(O, column.samplePoints.len);
        sample_points[i] = try a.alloc(Point, column.samplePoints.len);
        queried_values[i] = try a.alloc(M, queries.len);
        for (column.samplePoints, 0..) |point_index, j| {
            sample_points[i][j] = points[point_index];
            sample_values[i][j] = polynomial(points[point_index], i);
            try flat_samples.append(a, sample_values[i][j]);
        }
    }

    var offset: usize = 0;
    var all_rows: [tree_widths.len][]u32 = undefined;
    var tree_log_slices: [tree_widths.len][]u32 = undefined;
    var tree_points: [tree_widths.len][][]Point = undefined;
    var tree_samples: [tree_widths.len][][]O = undefined;
    var tree_values: [tree_widths.len][][]M = undefined;
    for (tree_widths, tree_logs, 0..) |width, tree_log, tree| {
        const tree_domain = CanonicCoset.new(tree_log).circleDomain();
        const tree_rows = try a.alloc(u32, width * tree_domain.size());
        for (0..tree_domain.size()) |position| {
            const p = tree_domain.at(core.utils.bitReverseIndex(position, tree_log));
            for (0..width) |col| {
                const i = offset + col;
                const reduced = p.repeatedDouble(tree_log - columns[i].logSize);
                const value = reduced.x.mul(M.fromCanonical(@intCast(3 * i + 1)))
                    .add(reduced.y.mul(M.fromCanonical(@intCast(i + 2))))
                    .add(M.fromCanonical(@intCast(5 * i + 9)));
                tree_rows[position * width + col] = value.toU32();
            }
        }
        const positions = try core.pcs.utils.prepareTreeQueryPositions(a, &queries, log, tree_log);
        for (positions, 0..) |position, j| {
            for (0..width) |col| queried_values[offset + col][j] = M.fromCanonical(tree_rows[position * width + col]);
        }
        all_rows[tree] = tree_rows;
        tree_log_slices[tree] = column_logs[offset..][0..width];
        tree_points[tree] = sample_points[offset..][0..width];
        tree_samples[tree] = sample_values[offset..][0..width];
        tree_values[tree] = queried_values[offset..][0..width];
        offset += width;
    }

    var channel = Channel.init();
    channel.mixU32s(&.{ 1, 3, 17, 29 });
    const prefix = channel.digestBytes();
    channel.mixFelts(flat_samples.items);
    const alpha = channel.drawSecureFelt();
    const answers = try Pcs.quotients.friAnswers(
        a,
        Pcs.TreeVec([]u32).initOwned(&tree_log_slices),
        Pcs.TreeVec([][]Point).initOwned(&tree_points),
        Pcs.TreeVec([][]O).initOwned(&tree_samples),
        alpha,
        &queries,
        Pcs.TreeVec([][]M).initOwned(&tree_values),
        log,
    );

    const FixturePoint = struct { x: [8]u32, y: [8]u32 };
    var wire_points: [points.len]FixturePoint = undefined;
    for (points, 0..) |point, i| wire_points[i] = .{ .x = words(point.x), .y = words(point.y) };
    const sample_words = try a.alloc([8]u32, flat_samples.items.len);
    for (flat_samples.items, 0..) |sample, i| sample_words[i] = words(sample);
    var wire_answers: [queries.len][8]u32 = undefined;
    for (answers, 0..) |answer, i| wire_answers[i] = words(answer);
    const json = try std.json.Stringify.valueAlloc(a, .{
        .domainLog = log,
        .prefixBytes = prefix,
        .alpha = words(alpha),
        .points = wire_points,
        .columns = columns,
        .samples = sample_words,
        .treeWidths = tree_widths,
        .treeLogs = tree_logs,
        .rows = all_rows,
        .queries = queries,
        .answers = wire_answers,
    }, .{ .whitespace = .indent_2, .emit_strings_as_arrays = true });
    var buffer: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&buffer);
    try stdout.interface.print("{s}\n", .{json});
    try stdout.interface.flush();
}
