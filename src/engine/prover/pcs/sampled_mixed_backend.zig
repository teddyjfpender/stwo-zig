//! Borrowed partitioning of mixed coefficient/evaluation trees into device epochs.
const std = @import("std");
const core = @import("stwo_core");
const sampled_work = @import("sampled_value_work.zig");
const Point = core.circle.CirclePointQM31;
const Q = core.fields.qm31.QM31;

pub fn evaluate(
    comptime B: type,
    comptime H: type,
    trees: anytype,
    points: [][][]Point,
    output: [][][]Q,
    a: std.mem.Allocator,
    lifting_log: u32,
    coefficient_audit: ?*sampled_work.Audit,
    barycentric_audit: ?*sampled_work.Audit,
    comptime coefficients: anytype,
    comptime barycentric: anytype,
) !bool {
    if (trees.len != points.len or trees.len != output.len) return error.ShapeMismatch;
    var coefficient_count: usize = 0;
    for (trees) |tree| coefficient_count += @intFromBool(tree.coefficients != null);
    if (coefficient_count == 0 or coefficient_count == trees.len) return false;
    // Borrow pointers, never copy owning trees or transfer their coefficients.
    const refs = try a.alloc(*const @TypeOf(trees[0]), trees.len);
    defer a.free(refs);
    const point_refs = try a.alloc([][]Point, trees.len);
    defer a.free(point_refs);
    const output_refs = try a.alloc([][]Q, trees.len);
    defer a.free(output_refs);
    var coefficient_samples = false;
    var barycentric_samples = false;
    var c: usize = 0;
    var b = coefficient_count;
    for (trees, points, output) |*tree, tree_points, tree_output| {
        const index = if (tree.coefficients != null) blk: {
            const index = c;
            c += 1;
            break :blk index;
        } else blk: {
            const index = b;
            b += 1;
            break :blk index;
        };
        for (tree_points) |samples| {
            if (tree.coefficients != null) coefficient_samples = coefficient_samples or samples.len != 0 else barycentric_samples = barycentric_samples or samples.len != 0;
        }
        refs[index] = tree;
        point_refs[index] = tree_points;
        output_refs[index] = tree_output;
    }
    // Barycentric eligibility is checked before dispatch and work accounting.
    // A declined route leaves every output for the existing CPU fallback.
    if (barycentric_samples and !try barycentric(B, H, refs[coefficient_count..], point_refs[coefficient_count..], output_refs[coefficient_count..], a, lifting_log, barycentric_audit)) return false;
    // Every tree in this partition has coefficients; declining is an invariant
    // failure, not permission to repeat already-completed work on the CPU.
    if (coefficient_samples and !try coefficients(B, H, refs[0..coefficient_count], point_refs[0..coefficient_count], output_refs[0..coefficient_count], a, lifting_log, coefficient_audit)) return error.ShapeMismatch;
    return true;
}

test "sampled mixed backend preserves borrowed ownership and declined outputs" {
    try exercise(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exercise, .{});
}
fn exercise(a: std.mem.Allocator) !void {
    const Tree = struct { coefficients: ?[]const u8, token: u32 };
    var trees = [_]Tree{
        .{ .coefficients = null, .token = 3 },
        .{ .coefficients = "retained", .token = 5 },
        .{ .coefficients = null, .token = 7 },
    };
    const original = trees;
    var point = [_]Point{core.circle.SECURE_FIELD_CIRCLE_GEN.mul(17)};
    var point_slices = [_][]Point{ &point, &point, &point };
    var points = [_][][]Point{ point_slices[0..1], point_slices[1..2], point_slices[2..3] };
    var values = [_]Q{ Q.zero(), Q.zero(), Q.zero() };
    var slices = [_][]Q{ values[0..1], values[1..2], values[2..3] };
    var output = [_][][]Q{ slices[0..1], slices[1..2], slices[2..3] };
    const Callbacks = struct {
        fn run(comptime B: type, comptime _: type, refs: anytype, _: [][][]Point, out: [][][]Q, _: std.mem.Allocator, _: u32, _: ?*sampled_work.Audit) !bool {
            if (B.decline) return false;
            for (refs, out) |tree, result| result[0][0] = Q.fromBase(core.fields.m31.M31.fromU64(tree.token));
            return true;
        }
    };
    const Yes = struct {
        pub const decline = false;
    };
    const No = struct {
        pub const decline = true;
    };
    try std.testing.expect(try evaluate(Yes, void, &trees, &points, &output, a, 1, null, null, Callbacks.run, Callbacks.run));
    for (values, original) |value, tree| try std.testing.expect(value.eql(Q.fromBase(core.fields.m31.M31.fromU64(tree.token))));
    @memset(&values, Q.zero());
    try std.testing.expect(!try evaluate(No, void, &trees, &points, &output, a, 1, null, null, Callbacks.run, Callbacks.run));
    for (values) |value| try std.testing.expect(value.isZero());
    points[1] = &.{};
    output[1] = &.{};
    try std.testing.expect(try evaluate(Yes, void, &trees, &points, &output, a, 1, null, null, Callbacks.run, Callbacks.run));
    try std.testing.expect(values[1].isZero());
    try std.testing.expect(values[0].eql(Q.fromBase(core.fields.m31.M31.fromU64(3))));
    try std.testing.expect(values[2].eql(Q.fromBase(core.fields.m31.M31.fromU64(7))));
    try std.testing.expectEqualDeep(original, trees);
}
