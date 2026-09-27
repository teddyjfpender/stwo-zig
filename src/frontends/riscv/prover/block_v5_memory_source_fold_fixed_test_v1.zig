//! Independent public-only fixed reconstruction against original packed cores.
//! No PCS, proof, FRI, guest execution or device is invoked.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Blake = @import("block_v5_memory_source_packed_blake_columns_v1.zig");
const Fixed = @import("block_v5_memory_source_fold_fixed_columns_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Hash = @import("block_v5_memory_source_packed_hash_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Recipe = @import("block_v5_memory_source_blake_semantics_v1.zig").Recipe;
const Premix = @import("block_v5_memory_source_fold_premix_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Place = @import("../air/block/memory_component_trace.zig");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
fn equalColumns(left: []const Column, right: []const Column) !void {
    try std.testing.expectEqual(left.len, right.len);
    for (left, right) |a, b| {
        try std.testing.expectEqual(a.log_size, b.log_size);
        try std.testing.expectEqual(a.values.len, b.values.len);
        for (a.values, b.values) |x, y| try std.testing.expect(x.eql(y));
    }
}
fn leaf(ordinal: u64, before: u32, after: u32) Fold.Operation {
    return .{ .ordinal = ordinal, .kind = .leaf, .coordinate = .{ .height = 0, .index = @intCast(ordinal) }, .value = .{ .before = (Hash.Frame{ .leaf = before }).nativeDigest(), .after = (Hash.Frame{ .leaf = after }).nativeDigest() }, .leaf = .{ .address = @intCast(4 * ordinal), .before = before, .after = after, .clock = 0xffff000000000001, .image = .rw, .touched = true } };
}
test "source unified PAGE: independent fold fixed rows match original changed shared default and branch recipes" {
    const a = std.testing.allocator;
    const same = [_]u8{7} ** 32;
    const right = [_]u8{11} ** 32;
    const node_frame = Hash.Frame{ .node = .{ .left = same, .right = right } };
    const node_digest = node_frame.nativeDigest();
    const operations = [_]Fold.Operation{
        leaf(0, 7, 9),                                                                                                                                                                                                                        leaf(1, 11, 11), leaf(2, 0, 7),
        .{ .ordinal = 3, .kind = .branch, .coordinate = .{ .height = 1, .index = 0 }, .value = .{ .before = node_digest, .after = node_digest }, .left = .{ .before = same, .after = same }, .right = .{ .before = right, .after = right } },
    };
    const setup = try Blake.Setup.create(a);
    defer setup.release();
    const original = try Blake.Columns.regenerateWithSetup(a, &operations, 17, .{}, setup);
    defer original.deinit();
    var recipes: [8]Recipe = undefined;
    var rows: [4]Semantic.FoldRow = undefined;
    var frame: usize = 0;
    var compression: u32 = 0;
    for (&rows, operations, 0..) |*row, operation, ordinal| {
        const start = frame;
        const first = compression;
        while (frame < original.frames.len and original.frames[frame].operation == ordinal) : (frame += 1) {
            recipes[frame] = Recipe.fromCapture(original.frames[frame]);
            compression += original.frames[frame].compression_count;
        }
        row.* = .{ .descriptor = .{ .kind = operation.kind, .height = operation.coordinate.height }, .recipes = recipes[start..frame], .first_compression = first, .compressions = compression - first };
    }
    const page = Protocol.Page{ .index = 0, .first = 0, .count = 4, .row_log = 2 };
    const pin = Protocol.FoldPin{ .page = page, .plan_id = @splat(7), .inventory_id = try Premix.inventoryId(page, 17, &rows), .geometry = original.geometry, .roots = @splat(@splat(9)) };
    var public = try Fixed.Columns.init(a, pin, &rows, .{});
    defer public.deinit();
    try equalColumns(original.fixed.items, public.core.items[0..original.fixed.items.len]);
    try equalColumns(original.capture_fixed.?.columns, public.capture.columns);
    for (rows, 0..) |row, ordinal| {
        const physical = Place.committedRow(ordinal, 2);
        const expected = [_]M{ M.one(), M.fromCanonical(@intFromEnum(row.descriptor.kind)), M.fromCanonical(row.descriptor.height), M.fromCanonical(@intCast(ordinal)) };
        for (public.source.columns, expected) |column, value| try std.testing.expect(column.values[physical].eql(value));
    }
    var bad = pin;
    bad.inventory_id[0] ^= 1;
    try std.testing.expectError(error.InvalidSourceFoldFixedInventory, Fixed.Columns.init(a, bad, &rows, .{}));
    bad = pin;
    bad.geometry.first_circuit += 1;
    try std.testing.expectError(error.InvalidSourceFoldFixedInventory, Fixed.Columns.init(a, bad, &rows, .{}));
    try std.testing.expectError(error.SourcePackedBlakeResourceLimit, Fixed.Columns.init(a, pin, &rows, .{ .max_cells = 1 }));
}
fn allocationFixture(a: std.mem.Allocator) !void {
    const rows = [_]Semantic.FoldRow{
        .{ .descriptor = .{ .kind = .empty, .height = 30 }, .recipes = &.{}, .first_compression = 0, .compressions = 0 },
        .{ .descriptor = .{ .kind = .root, .height = 30 }, .recipes = &.{}, .first_compression = 0, .compressions = 0 },
    };
    const page = Protocol.Page{ .index = 0, .first = 0, .count = 2, .row_log = 1 };
    const pin = Protocol.FoldPin{ .page = page, .plan_id = @splat(7), .inventory_id = try Premix.inventoryId(page, 1, &rows), .geometry = try Fixed.geometry(page, 1, &rows, .{}), .roots = @splat(@splat(9)) };
    var public = try Fixed.Columns.init(a, pin, &rows, .{});
    defer public.deinit();
    try std.testing.expectEqual(@as(u32, 0), pin.geometry.compressions);
    for (public.capture.columns) |column| for (column.values) |value| try std.testing.expect(value.isZero());
}
test "source unified PAGE: every public-only fold fixed allocation failure releases exact owners" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFixture, .{});
}
