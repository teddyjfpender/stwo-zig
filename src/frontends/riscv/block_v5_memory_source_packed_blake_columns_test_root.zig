//! Nonproving page geometry checks and retention of the real column owner.
const std = @import("std");
const Columns = @import("prover/block_v5_memory_source_packed_blake_columns_v1.zig");
const Fold = @import("prover/block_v5_memory_source_batch_fold_v1.zig");
const Hash = @import("prover/block_v5_memory_source_packed_hash_v1.zig");

fn leaf(ordinal: u64, before: u32, after: u32) Fold.Operation {
    return .{
        .ordinal = ordinal,
        .kind = .leaf,
        .coordinate = .{ .height = 0, .index = 0 },
        .value = .{
            .before = (Hash.Frame{ .leaf = before }).nativeDigest(),
            .after = (Hash.Frame{ .leaf = after }).nativeDigest(),
        },
        .leaf = .{ .address = 0, .before = before, .after = after, .clock = 1, .image = .rw, .touched = true },
    };
}

fn sharedBranch(ordinal: u64) Fold.Operation {
    const left = (Hash.Frame{ .leaf = 7 }).nativeDigest();
    const right = (Hash.Frame{ .leaf = 8 }).nativeDigest();
    const digest = (Hash.Frame{ .node = .{ .left = left, .right = right } }).nativeDigest();
    return .{
        .ordinal = ordinal,
        .kind = .branch,
        .coordinate = .{ .height = 1, .index = 0 },
        .value = .{ .before = digest, .after = digest },
        .left = .{ .before = left, .after = left },
        .right = .{ .before = right, .after = right },
    };
}

test "source packed BLAKE columns: original shared changed and default leaf geometry" {
    const shared = try Columns.Geometry.fromOperations(&.{leaf(5, 7, 7)}, 1, .{});
    try std.testing.expectEqual(@as(u32, 1), shared.frames);
    try std.testing.expectEqual(@as(u32, 1), shared.compressions);
    try std.testing.expectEqual([2]u32{ 6, 4 }, shared.logs);
    const changed = try Columns.Geometry.fromOperations(&.{leaf(5, 7, 8)}, 1, .{});
    try std.testing.expectEqual(@as(u32, 2), changed.frames);
    try std.testing.expectEqual(@as(u32, 2), changed.compressions);
    try std.testing.expectEqual([2]u32{ 7, 5 }, changed.logs);
    const zero = try Columns.Geometry.fromOperations(&.{leaf(5, 0, 0)}, 1, .{});
    try std.testing.expectEqual(@as(u32, 1), zero.frames);
    try std.testing.expectEqual(@as(u32, 0), zero.compressions);
    try std.testing.expectEqual([2]u32{ 1, 1 }, zero.logs);
    try std.testing.expectEqual(@as(u64, 5), zero.first_ordinal);
}

test "source packed BLAKE columns: bounded ordinal circuit compression and cell admission" {
    const G = Columns.Geometry;
    try std.testing.expectError(error.InvalidSourcePackedBlakeOrder, G.fromOperations(&.{ leaf(5, 1, 1), leaf(7, 1, 1) }, 1, .{}));
    try std.testing.expectError(error.Overflow, G.fromOperations(&.{ leaf(std.math.maxInt(u64), 1, 1), leaf(0, 1, 1) }, 1, .{}));
    try std.testing.expectError(error.SourcePackedBlakeResourceLimit, G.fromOperations(&.{leaf(0, 1, 1)}, 0, .{}));
    try std.testing.expectError(error.SourcePackedBlakeResourceLimit, G.fromOperations(&.{leaf(0, 1, 2)}, 1, .{ .max_compressions = 1 }));
    try std.testing.expectError(error.SourcePackedBlakeResourceLimit, G.fromOperations(&.{leaf(0, 1, 1)}, 1, .{ .max_cells = 1 }));
    try std.testing.expectError(error.SourcePackedBlakeResourceLimit, G.fromOperations(&.{leaf(0, 1, 1)}, 1, .{ .max_capture_metadata_bytes = 1 }));
    const empty = try G.fromOperations(&.{}, 1, .{});
    try std.testing.expectEqual(@as(u32, 0), empty.operations);
    try std.testing.expectEqual(@as(u32, 0), empty.frames);
}

test "source packed BLAKE columns: actual regeneration and retained allocator cleanup bodies" {
    inline for (.{ &Columns.Columns.regenerate, &Columns.Columns.regenerateWithSetup, &Columns.Columns.deinit, &Columns.Setup.create }) |body| std.mem.doNotOptimizeAway(body);
}

test "source packed BLAKE columns: regenerated matrices counters and captures match original row projection" {
    const core = @import("stwo_core");
    const M = core.fields.m31.M31;
    const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
    const G = Columns.Airs[0];
    const Xor = Columns.Airs[1];
    const Project = @import("recursion/air/blake3_row_columns.zig");
    const Counter = @import("air/lookups/tables/counter.zig").Counter;
    const Place = @import("air/block/memory_component_trace.zig");
    const Witness = struct {
        g_rows: [5 * 56]G.Row = undefined,
        xor_rows: [5 * 16]Xor.Row = undefined,
        boundaries: [5]Hash.Boundary = undefined,
        g_count: usize = 0,
        xor_count: usize = 0,
        boundary_count: usize = 0,
        pub fn g(self: *@This(), row: *const G.Row) !void {
            self.g_rows[self.g_count] = row.*;
            self.g_count += 1;
        }
        pub fn xor(self: *@This(), row: *const Xor.Row) !void {
            self.xor_rows[self.xor_count] = row.*;
            self.xor_count += 1;
        }
        pub fn boundary(self: *@This(), value: Hash.Boundary) !void {
            self.boundaries[self.boundary_count] = value;
            self.boundary_count += 1;
        }
    };
    const a = std.testing.allocator;
    var operations = [_]Fold.Operation{ leaf(5, 0, 0), leaf(6, 7, 7), leaf(7, 1, 2), sharedBranch(8) };
    const actual = try Columns.Columns.regenerate(a, &operations, 9, .{});
    defer actual.deinit();
    try std.testing.expectEqual(@as(u32, 5), actual.geometry.compressions);
    try std.testing.expectEqual(@as(usize, 5), actual.frames.len);
    try std.testing.expectEqual(@as(?u32, 0), actual.frames[0].default_height);
    try std.testing.expectEqual(@as(u32, 0), actual.frames[0].compression_count);
    try std.testing.expectEqual(@as(u32, 2), actual.frames[1].multiplicity);
    try std.testing.expectEqual(@as(u32, 3), actual.frames[4].first_compression);
    try std.testing.expectEqual(@as(u32, 2), actual.frames[4].compression_count);
    try std.testing.expectEqual(@as(u32, 2), actual.frames[4].multiplicity);
    var witness: Witness = .{};
    var circuit: u32 = 9;
    for (operations) |operation| {
        const recipes = try Hash.recipes(operation);
        for (recipes.values[0..recipes.count]) |recipe| if (recipe.default_height == null) {
            const digest = try Hash.emit(recipe.frame, circuit, &witness);
            try std.testing.expectEqualSlices(u8, &recipe.frame.nativeDigest(), &digest);
            circuit += @intCast((recipe.frame.size() + 63) / 64);
        };
    }
    var expected_counters = [_]Counter{ try Counter.init(a, .bitwise), try Counter.init(a, .range_check_8_8) };
    defer for (&expected_counters) |*counter| counter.deinit(a);
    var fixed_offset: usize = 0;
    var main_offset: usize = 0;
    inline for (Columns.Airs, 0..) |Air, i| {
        const rows = if (i == 0) witness.g_rows[0..witness.g_count] else witness.xor_rows[0..witness.xor_count];
        var main: std.ArrayList(Column) = .empty;
        defer {
            for (main.items) |column| a.free(column.values);
            main.deinit(a);
        }
        var fixed: std.ArrayList(Column) = .empty;
        defer {
            for (fixed.items) |column| a.free(column.values);
            fixed.deinit(a);
        }
        try Project.project(Air, a, rows, actual.geometry.logs[i], 1, &main);
        try Project.project(Air, a, rows, actual.geometry.logs[i], 0, &fixed);
        for (main.items, actual.main[main_offset..][0..main.items.len]) |old, new| try std.testing.expectEqualSlices(M, old.values, new.values);
        for (fixed.items, actual.fixed.items[fixed_offset..][0..fixed.items.len]) |old, new| try std.testing.expectEqualSlices(M, old.values, new.values);
        const padded = try Project.padded(Air, a, rows, actual.geometry.logs[i]);
        defer a.free(padded);
        try Project.register(Air, &actual.plans[i], padded, &expected_counters);
        main_offset += main.items.len;
        fixed_offset += fixed.items.len;
    }
    for (expected_counters, actual.counters) |old, new| try std.testing.expectEqualSlices(M, old.values, new.values);
    for (witness.boundaries, 0..) |boundary, ordinal| {
        const physical = Place.committedRow(ordinal, actual.geometry.capture_log);
        for (boundary.initial ++ boundary.output, 0..) |word, index| for (0..4) |part| {
            const expected = M.fromCanonical((word >> @as(u5, @intCast(8 * part))) & 255);
            try std.testing.expectEqual(expected, actual.capture_main.?.columns[4 * index + part].values[physical]);
        };
        try std.testing.expectEqual(M.fromCanonical(boundary.circuit), actual.capture_fixed.?.columns[1].values[physical]);
    }
    operations[1].value.before[0] ^= 1;
    try std.testing.expectError(error.UntrustedSourcePackedBlakeDigest, Columns.Columns.regenerate(a, &operations, 9, .{}));
}

test "source packed BLAKE columns: shared immutable setup survives coordinator and allocator release" {
    const M = @import("stwo_core").fields.m31.M31;
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const a = std.testing.allocator;
    const budget = try Budget.create(a, 32 << 20);
    var owns_budget = true;
    defer if (owns_budget) budget.destroy();
    const observer = budget.retain();
    defer observer.destroy();
    const setup = try Columns.Setup.create(budget.allocator());
    var owns_setup = true;
    defer if (owns_setup) setup.release();
    const operations = [_]Fold.Operation{leaf(1, 7, 7)};
    const cached = try Columns.Columns.regenerateWithSetup(budget.allocator(), &operations, 9, .{}, setup);
    var owns_cached = true;
    defer if (owns_cached) cached.deinit();
    const cold = try Columns.Columns.regenerate(a, &operations, 9, .{});
    defer cold.deinit();
    for (cached.main, cold.main) |shared, independent| try std.testing.expectEqualSlices(M, independent.values, shared.values);
    for (cached.fixed.items, cold.fixed.items) |shared, independent| try std.testing.expectEqualSlices(M, independent.values, shared.values);
    for (cached.counters, cold.counters) |shared, independent| try std.testing.expectEqualSlices(M, independent.values, shared.values);
    try std.testing.expectEqualSlices(M, cold.capture_main.?.values, cached.capture_main.?.values);
    try std.testing.expectEqualSlices(M, cold.capture_fixed.?.values, cached.capture_fixed.?.values);
    try std.testing.expectEqual(@as(usize, 0), cached.definition_count);
    setup.release();
    owns_setup = false;
    budget.destroy();
    owns_budget = false;
    // The page's lease still owns the original immutable arenas and plans.
    inline for (0..Columns.Airs.len) |i| try cached.definitions[i].validate();
    cached.deinit();
    owns_cached = false;
    try std.testing.expectEqual(@as(usize, 0), observer.snapshot().live_bytes);
}

fn cachedColumnAllocation(a: std.mem.Allocator, setup: *const Columns.Setup) !void {
    const columns = try Columns.Columns.regenerateWithSetup(a, &.{leaf(1, 7, 7)}, 9, .{}, setup);
    defer columns.deinit();
}

test "source packed BLAKE columns: each page allocation unwinds without rebuilding shared AIR" {
    const setup = try Columns.Setup.create(std.testing.allocator);
    defer setup.release();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, cachedColumnAllocation, .{setup});
    var lease = try setup.lease();
    try std.testing.expect((try lease.get()) == setup);
    lease.deinit();
    lease.deinit();
    try std.testing.expectError(error.ReleasedPackedHashSetupLease, lease.get());
    try std.testing.expectEqual(@as(usize, 1), setup.references.load(.monotonic));
}
