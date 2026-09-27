//! Canonical inventory custody from committed pack columns, without retained
//! logical pack rows. Allocation failures must release masks and use scratch.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const Graph = @import("composition_circuit.zig");
const Pack = @import("qm31_pack_wire.zig");
const Boundary = @import("blake3_boundary.zig");
const Scalar = @import("scalar_wire_source.zig");
const Direct = @import("blake3_direct_cohort_columns_v1.zig");
const View = @import("blake3_recursive_column_rows_v1.zig");
const Inventory = @import("blake3_parent_input_inventory.zig");
const storage = @import("blake3_parent_row_storage.zig");

fn expectInventoryError(expected: anyerror, result: anyerror!usize) !void {
    if (result) |_| {
        return error.TestUnexpectedError;
    } else |err| {
        // Allocation fault injection must reach the outer harness rather than
        // being mistaken for the expected custody rejection.
        if (err == error.OutOfMemory) return err;
        try std.testing.expectEqual(expected, err);
    }
}

fn checkInventory(a: std.mem.Allocator) !void {
    const nodes: [3]Graph.Node = @splat(.{ .op = .input });
    const outputs = [_]u32{ 0, 1, 2 };
    const graph = try Graph.CircuitGraph.authenticate(&nodes, &outputs, Graph.computeGraphDigest(&nodes, &outputs));
    const graphs = [_]Graph.CircuitGraph{graph};
    const values = [_]Q{ Q.fromBase(M.fromCanonical(5)), Q.fromU32Unchecked(7, 8, 9, 10), Q.fromU32Unchecked(11, 12, 13, 14) };
    const evaluations = [_][]const Q{&values};
    const scalars = [_]Scalar.Row{try Scalar.logicalRow(1500, 0, 1, M.fromCanonical(5))};
    const boundaries = [_]Boundary.Row{try Boundary.logicalCoordinates(1500, 1, M.one(), values[1].toM31Array())};
    const packed_rows = [_]Pack.Row{try Pack.logicalRow(.{ .source_circuit = 1600, .source_nodes = .{ 0, 1, 2, 3 }, .destination_circuit = 1500, .destination_wire = 2 }, values[2])};
    var emitter = try Direct.ForAir(Pack).init(a, 1);
    defer emitter.deinit();
    try emitter.append(packed_rows[0]);
    const borrowed = try View.ForAir(Pack).init(emitter.main, emitter.fixed);
    var scalar_emitter = try Direct.ForAir(Scalar).init(a, scalars.len);
    defer scalar_emitter.deinit();
    for (scalars) |row| try scalar_emitter.append(row);
    const scalar_borrowed = try View.ForAir(Scalar).init(scalar_emitter.main, scalar_emitter.fixed);
    try std.testing.expectEqual(@as(usize, 3), try Inventory.check(a, graphs, evaluations, &scalars, &boundaries, &packed_rows));
    try std.testing.expectEqual(@as(usize, 3), try Inventory.check(a, graphs, evaluations, &scalars, &boundaries, borrowed));
    try std.testing.expectEqual(@as(usize, 3), try Inventory.check(a, graphs, evaluations, scalar_borrowed, &boundaries, borrowed));
    const scalar_at = @import("framework_interaction.zig").committedRow(0, scalar_emitter.log);
    scalar_emitter.mutable_main[0][scalar_at] = M.fromCanonical(99);
    try expectInventoryError(error.InvalidNativeParentInput, Inventory.check(a, graphs, evaluations, scalar_borrowed, &boundaries, borrowed));
    scalar_emitter.mutable_main[0][scalar_at] = scalars[0][0];
    scalar_emitter.fixed[0][0] = M.fromCanonical(1501);
    try expectInventoryError(error.InvalidNativeParentInput, Inventory.check(a, graphs, evaluations, scalar_borrowed, &boundaries, borrowed));
    scalar_emitter.fixed[0][0] = scalars[0][1];
    const duplicate_scalar = [_]Boundary.Row{ try Boundary.logicalCoordinates(1500, 0, M.one(), values[0].toM31Array()), boundaries[0] };
    try expectInventoryError(error.DuplicateNativeParentInput, Inventory.check(a, graphs, evaluations, scalar_borrowed, &duplicate_scalar, borrowed));
    try expectInventoryError(error.MissingNativeParentInput, Inventory.check(a, graphs, evaluations, &scalars, &boundaries, @as([]const Pack.Row, &.{})));
    const duplicate = [_]Boundary.Row{ boundaries[0], try Boundary.logicalCoordinates(1500, 2, M.one(), values[2].toM31Array()) };
    try expectInventoryError(error.DuplicateNativeParentInput, Inventory.check(a, graphs, evaluations, &scalars, &duplicate, borrowed));
    const physical = @import("framework_interaction.zig").committedRow(0, emitter.log);
    emitter.mutable_main[0][physical] = M.fromCanonical(99);
    try expectInventoryError(error.InvalidNativeParentInput, Inventory.check(a, graphs, evaluations, &scalars, &boundaries, borrowed));
    emitter.mutable_main[0][physical] = packed_rows[0][0];
    emitter.fixed[0][11 - Pack.PHYSICAL_MAIN_COLUMN_COUNT] = M.fromCanonical(3);
    try expectInventoryError(error.InvalidNativeParentInput, Inventory.check(a, graphs, evaluations, &scalars, &boundaries, borrowed));
    emitter.fixed[0][11 - Pack.PHYSICAL_MAIN_COLUMN_COUNT] = packed_rows[0][11];
    emitter.fixed[0][10 - Pack.PHYSICAL_MAIN_COLUMN_COUNT] = M.fromCanonical(1501);
    try expectInventoryError(error.InvalidNativeParentInput, Inventory.check(a, graphs, evaluations, &scalars, &boundaries, borrowed));
}
test "direct recursive inventory matches legacy rows and rejects source custody mutations without leaks" {
    try checkInventory(std.testing.allocator);
}
test "direct recursive inventory cleans up every failing allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkInventory, .{});
}
test "direct recursive borrowed rows reject malformed committed geometry" {
    const a = std.testing.allocator;
    var emitter = try Direct.ForAir(Pack).init(a, 1);
    defer emitter.deinit();
    const Borrowed = View.ForAir(Pack);
    try std.testing.expectError(error.InvalidNativeParentRows, Borrowed.init(&.{}, emitter.fixed));
    var columns: [Pack.PHYSICAL_MAIN_COLUMN_COUNT]Column = emitter.main[0..Pack.PHYSICAL_MAIN_COLUMN_COUNT].*;
    columns[0].log_size = 0;
    try std.testing.expectError(error.InvalidNativeParentRows, Borrowed.init(&columns, emitter.fixed));
    columns[0].log_size = 25;
    try std.testing.expectError(error.InvalidNativeParentRows, Borrowed.init(&columns, emitter.fixed));
    columns[0] = emitter.main[0];
    columns[1].log_size += 1;
    try std.testing.expectError(error.InvalidNativeParentRows, Borrowed.init(&columns, emitter.fixed));
    columns[1] = emitter.main[1];
    columns[2].values = columns[2].values[0..1];
    try std.testing.expectError(error.InvalidNativeParentRows, Borrowed.init(&columns, emitter.fixed));
    const fixed: [3]storage.FixedRow(Pack) = @splat(@splat(M.zero()));
    try std.testing.expectError(error.InvalidNativeParentRows, Borrowed.init(emitter.main, &fixed));
}
test "direct recursive boundary columns release initial rows before appending public terms" {
    const a = std.testing.allocator;
    var initial: [3]Boundary.Row = undefined;
    for (&initial, 0..) |*row, i| row.* = try Boundary.privateCoordinates(1600, @intCast(i), M.one(), Q.fromU32Unchecked(@intCast(i), 7, 8, 9).toM31Array());
    const public = [_]Boundary.Row{
        try Boundary.logicalCoordinates(1500, 0, M.one(), Q.fromU32Unchecked(11, 12, 13, 14).toM31Array()),
        try Boundary.logicalCoordinates(1500, 1, M.fromCanonical(3), Q.fromU32Unchecked(15, 16, 17, 18).toM31Array()),
    };
    const all = initial ++ public;
    var legacy = storage.Builder.init(a);
    defer legacy.deinit();
    try legacy.append(2, &initial, &initial);
    var emitter = try Direct.ForAir(Boundary).init(a, all.len);
    defer emitter.deinit();
    for (legacy.rows[2].items) |row| try emitter.append(row);
    legacy.rows[2].deinit(a);
    legacy.rows[2] = .empty;
    legacy.fixed[2].deinit(a);
    legacy.fixed[2] = .empty;
    try std.testing.expectEqual(@as(usize, 0), legacy.rows[2].capacity);
    try std.testing.expectEqual(@as(usize, 0), legacy.fixed[2].capacity);
    for (public) |row| try emitter.append(row);
    const taken = try emitter.take();
    defer {
        for (taken.main) |column| a.free(column.values);
        a.free(taken.main);
        a.free(taken.fixed);
    }
    const borrowed = try View.ForAir(Boundary).init(taken.main, taken.fixed);
    for (all, 0..) |row, i| try std.testing.expectEqualDeep(row, borrowed.rowAt(i));
    var projected: std.ArrayList(Column) = .empty;
    defer {
        for (projected.items) |column| a.free(column.values);
        projected.deinit(a);
    }
    try @import("blake3_row_columns.zig").project(Boundary, a, &all, taken.main[0].log_size, 1, &projected);
    for (projected.items, taken.main) |old, new| try std.testing.expectEqualSlices(M, old.values, new.values);
}
