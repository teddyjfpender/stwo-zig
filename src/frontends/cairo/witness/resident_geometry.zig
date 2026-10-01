//! Cairo AIR mask geometry and sampled-value shape derivation.

const std = @import("std");
const circle = @import("stwo_core").circle;
const composition_bundle = @import("composition_bundle.zig");
const types = @import("resident_types.zig");

const Point = circle.CirclePointQM31;
const Error = types.Error;

pub fn validateMaximumDegreeLog(lifting_log_size: u32, max_log_degree_bound: u32) !void {
    if (lifting_log_size == 0 or max_log_degree_bound != lifting_log_size - 1)
        return Error.InvalidComponentShape;
}

pub const Span = struct { start: usize, end: usize };

pub fn componentSpan(component: composition_bundle.Component, tree: u32) !Span {
    var found: ?Span = null;
    for (component.trace_spans) |span| {
        if (span.tree != tree) continue;
        if (found != null or span.start > span.end) return Error.InvalidComponentShape;
        found = .{ .start = span.start, .end = span.end };
    }
    return found orelse Error.InvalidComponentShape;
}

pub fn spanLength(component: composition_bundle.Component, tree: u32) !usize {
    const span = try componentSpan(component, tree);
    return span.end - span.start;
}

pub fn componentOffsets(
    allocator: std.mem.Allocator,
    component: composition_bundle.Component,
    tree: u32,
) ![]std.ArrayList(i32) {
    const offsets = try allocator.alloc(std.ArrayList(i32), try spanLength(component, tree));
    for (offsets) |*list| list.* = .empty;
    errdefer freeOffsetLists(allocator, offsets);
    for (component.parts) |part| for (part.program.base_insts) |instruction| {
        if (instruction.op != .trace_col or instruction.interaction != tree) continue;
        if (instruction.a >= offsets.len) return Error.InvalidComponentShape;
        var exists = false;
        for (offsets[instruction.a].items) |existing| exists = exists or existing == instruction.imm;
        if (!exists) try offsets[instruction.a].append(allocator, instruction.imm);
    };
    for (offsets) |list| if (list.items.len == 0) return Error.InvalidComponentShape;
    return offsets;
}

pub fn freeOffsetLists(allocator: std.mem.Allocator, lists: []std.ArrayList(i32)) void {
    for (lists) |*list| list.deinit(allocator);
    allocator.free(lists);
}

pub fn pointsFromOffsets(
    allocator: std.mem.Allocator,
    offsets: []const std.ArrayList(i32),
    point: Point,
    step: Point,
) ![][]Point {
    const columns = try allocator.alloc([]Point, offsets.len);
    errdefer allocator.free(columns);
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column| allocator.free(column);
    for (offsets, columns) |column_offsets, *column| {
        column.* = try allocator.alloc(Point, column_offsets.items.len);
        for (column_offsets.items, column.*) |offset, *sample_point| {
            sample_point.* = point.add(step.mulSigned(offset));
        }
        initialized += 1;
    }
    return columns;
}

pub fn freePointTree(allocator: std.mem.Allocator, tree: [][]Point) void {
    for (tree) |column| allocator.free(column);
    allocator.free(tree);
}

pub fn offsetIndex(offsets: []const i32, wanted: i32) ?usize {
    for (offsets, 0..) |offset, index| if (offset == wanted) return index;
    return null;
}

/// Derives the exact sampled-value tree shape from the captured programs.
/// The returned slices are owned and can be passed directly to `decodeProof`.
pub fn sampleShape(
    allocator: std.mem.Allocator,
    bundle: composition_bundle.Bundle,
    tree_column_counts: [3]usize,
) ![][]usize {
    return sampleShapeWithPolicy(allocator, bundle, tree_column_counts, false);
}

/// The pinned circuit leaf samples every preprocessed column, including
/// columns unused by the AIR; the ordinary Cairo proof samples used columns.
pub fn sampleShapeWithPolicy(
    allocator: std.mem.Allocator,
    bundle: composition_bundle.Bundle,
    tree_column_counts: [3]usize,
    include_all_preprocessed: bool,
) ![][]usize {
    const used_preprocessed = try allocator.alloc(bool, tree_column_counts[0]);
    defer allocator.free(used_preprocessed);
    @memset(used_preprocessed, include_all_preprocessed);
    const base_counts = try allocator.alloc(usize, tree_column_counts[1]);
    defer allocator.free(base_counts);
    @memset(base_counts, 0);
    const interaction_counts = try allocator.alloc(usize, tree_column_counts[2]);
    defer allocator.free(interaction_counts);
    @memset(interaction_counts, 0);

    for (bundle.components) |component| {
        for (component.preprocessed_indices) |index| {
            if (index >= used_preprocessed.len) return Error.InvalidComponentShape;
        }
        const base_span = try componentSpan(component, 1);
        const interaction_span = try componentSpan(component, 2);
        const base_offsets = try componentOffsets(allocator, component, 1);
        defer freeOffsetLists(allocator, base_offsets);
        const interaction_offsets = try componentOffsets(allocator, component, 2);
        defer freeOffsetLists(allocator, interaction_offsets);
        for (component.parts) |part| for (part.program.base_insts) |instruction| switch (instruction.op) {
            .preprocessed_col => {
                if (instruction.a >= component.preprocessed_indices.len) return Error.InvalidComponentShape;
                used_preprocessed[component.preprocessed_indices[instruction.a]] = true;
            },
            .trace_col => switch (instruction.interaction) {
                0 => {
                    if (instruction.a >= component.preprocessed_indices.len) return Error.InvalidComponentShape;
                    used_preprocessed[component.preprocessed_indices[instruction.a]] = true;
                },
                else => {},
            },
            else => {},
        };
        if (base_span.end > base_counts.len or interaction_span.end > interaction_counts.len)
            return Error.InvalidComponentShape;
        for (base_offsets, 0..) |offsets, local| base_counts[base_span.start + local] = offsets.items.len;
        for (interaction_offsets, 0..) |offsets, local| interaction_counts[interaction_span.start + local] = offsets.items.len;
    }

    const trees = try allocator.alloc([]usize, 4);
    errdefer allocator.free(trees);
    var initialized: usize = 0;
    errdefer for (trees[0..initialized]) |tree| allocator.free(tree);
    trees[0] = try allocator.alloc(usize, used_preprocessed.len);
    initialized += 1;
    for (used_preprocessed, trees[0]) |used, *count| count.* = @intFromBool(used);
    trees[1] = try allocator.dupe(usize, base_counts);
    initialized += 1;
    trees[2] = try allocator.dupe(usize, interaction_counts);
    initialized += 1;
    trees[3] = try allocator.dupe(usize, &[_]usize{1} ** 8);
    return trees;
}

pub fn freeSampleShape(allocator: std.mem.Allocator, shape: [][]usize) void {
    for (shape) |tree| allocator.free(tree);
    allocator.free(shape);
}

test "resident verifier accepts runtime lifting logs 24 and 25" {
    try validateMaximumDegreeLog(24, 23);
    try validateMaximumDegreeLog(25, 24);
    try std.testing.expectError(Error.InvalidComponentShape, validateMaximumDegreeLog(24, 24));
    try std.testing.expectError(Error.InvalidComponentShape, validateMaximumDegreeLog(0, 0));
}

test "resident verifier derives exact SN2 OODS shape" {
    const allocator = std.testing.allocator;
    var captured = try composition_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer captured.deinit();
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_CAPTURED_PARTS")) {
        const component = captured.components[0];
        for (component.parts, 0..) |part, part_index| {
            std.debug.print(
                "captured_part index={} rc_base={} constraints={} base_insts={} ext_insts={} roots={any}\n",
                .{
                    part_index,
                    part.rc_base,
                    part.program.header.n_constraints,
                    part.program.base_insts.len,
                    part.program.ext_insts.len,
                    part.program.constraint_roots,
                },
            );
        }
    }
    const shape = try sampleShape(allocator, captured, .{ 161, 3449, 2268 });
    defer freeSampleShape(allocator, shape);
    try std.testing.expectEqual(@as(usize, 4), shape.len);
    try std.testing.expectEqual(@as(usize, 161), shape[0].len);
    try std.testing.expectEqual(@as(usize, 3449), shape[1].len);
    try std.testing.expectEqual(@as(usize, 2268), shape[2].len);
    try std.testing.expectEqual(@as(usize, 8), shape[3].len);
    var samples: usize = 0;
    for (shape) |tree| {
        for (tree) |count| samples += count;
    }
    try std.testing.expectEqual(@as(usize, 6110), samples);
}
