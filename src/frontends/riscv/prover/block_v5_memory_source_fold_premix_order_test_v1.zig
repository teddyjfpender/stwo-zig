//! Actual first-round FOLD collection regression, including real padded hash
//! rows and table commitments. This does not qualify a complete source proof.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Hash = @import("block_v5_memory_source_packed_hash_v1.zig");
const Blake = @import("block_v5_memory_source_packed_blake_columns_v1.zig");
const Stage = @import("block_v5_memory_source_fold_premix_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Tables = @import("../air/lookups/tables/schema.zig");
const Place = @import("../air/block/memory_component_trace.zig");
const config = core.pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{ .log_blowup_factor = 1, .n_queries = 1, .log_last_layer_degree_bound = 0, .fold_step = 1 },
};

fn check(operations: []const Fold.Operation, census: Fold.Census, row_log: u32, padded_only: bool) !void {
    const a = std.testing.allocator;
    const admitted = try @import("block_v5_memory_source_page_raw_recursive_parity_test_v1.zig").emptyAdmission();
    const limits = Stage.Limits{ .protocol = .{ .page_row_log = row_log } };
    const plan = try Protocol.FoldPlan.init(&admitted, census, config, limits.protocol);
    const setup = try Blake.Setup.create(a);
    defer setup.release();
    const owner = try Stage.ForBackend(Cpu).collect(a, &admitted, plan, 0, operations, 1, setup, limits);
    defer owner.deinit() catch @panic("fold table-order test leaked a lease");
    const cores = owner.cores.?;
    try std.testing.expectEqual(padded_only, cores.geometry.compressions == 0);
    var changed_table: ?usize = null;
    for (&cores.counters, 0..) |*counter, i| {
        const expected = try counter.committedColumn(a);
        defer a.free(expected);
        const column = owner.main[cores.main.len + i];
        try std.testing.expectEqual(Tables.logSize(counter.kind), column.log_size);
        try std.testing.expectEqual(owner.table_main[i].ptr, column.values.ptr);
        try std.testing.expectEqualSlices(core.fields.m31.M31, expected, column.values);
        var differs = false;
        for (counter.values, 0..) |value, logical| {
            // Independent logical-to-physical check; the old direct copy fails
            // even when there are no real BLAKE compressions, due to padding.
            try std.testing.expect(value.eql(column.values[Place.committedRow(logical, column.log_size)]));
            differs = differs or !value.eql(column.values[logical]);
        }
        if (differs) changed_table = i;
    }
    // Require a nonuniform, moved multiplicity: uniform/zero counters cannot
    // accidentally make this regression pass against the former direct copy.
    const changed = changed_table orelse return error.TestExpectedNonuniformMovedCounter;
    try owner.require(&admitted, plan, owner.pin.?, limits);
    const original = try a.dupe(core.fields.m31.M31, owner.table_main[changed]);
    defer a.free(original);
    @memcpy(owner.table_main[changed], cores.counters[changed].values);
    try std.testing.expectError(error.ChangedSourceFoldPremix, owner.require(&admitted, plan, owner.pin.?, limits));
    @memcpy(owner.table_main[changed], original);
    try owner.require(&admitted, plan, owner.pin.?, limits);
}

test "source FOLD premix table order: zero compressions still commit padded requests in physical order" {
    const root = @import("block_v5_memory_source_batch_defaults_v1.zig").get().defaults[0].bytes;
    const operations = [_]Fold.Operation{
        .{ .ordinal = 0, .kind = .empty, .coordinate = .{ .height = 30, .index = 0 }, .value = .{ .before = root, .after = root } },
        .{ .ordinal = 1, .kind = .root, .coordinate = .{ .height = 30, .index = 0 }, .value = .{ .before = root, .after = root } },
    };
    try check(&operations, .{ .empty = 1, .roots = 1 }, 1, true);
}

fn leaf(ordinal: u64, before: u32, after: u32) Fold.Operation {
    return .{ .ordinal = ordinal, .kind = .leaf, .coordinate = .{ .height = 0, .index = @intCast(ordinal) }, .value = .{ .before = (Hash.Frame{ .leaf = before }).nativeDigest(), .after = (Hash.Frame{ .leaf = after }).nativeDigest() }, .leaf = .{ .address = @intCast(4 * ordinal), .before = before, .after = after, .clock = 1, .image = .rw, .touched = true } };
}

test "source FOLD premix table order: changed shared default and branch recipes" {
    const left: [32]u8 = @splat(7);
    const right: [32]u8 = @splat(11);
    const node = (Hash.Frame{ .node = .{ .left = left, .right = right } }).nativeDigest();
    const operations = [_]Fold.Operation{
        leaf(0, 7, 9),                                                                                                                                                                                                          leaf(1, 11, 11), leaf(2, 0, 7),
        .{ .ordinal = 3, .kind = .branch, .coordinate = .{ .height = 1, .index = 0 }, .value = .{ .before = node, .after = node }, .left = .{ .before = left, .after = left }, .right = .{ .before = right, .after = right } },
    };
    // A local page-collection fixture, not an admitted complete memory tree:
    // subsequent branch/root pages and global source closure are not proved.
    try check(&operations, .{ .leaves = 3, .branches = 2, .roots = 1, .compressions = 6 }, 2, false);
}
