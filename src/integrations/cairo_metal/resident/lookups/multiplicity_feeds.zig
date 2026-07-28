//! Runtime-derived multiplicity-feed geometry and prepared batch ownership.

const std = @import("std");
const arena_plan = @import("../../../../backends/metal/arena_plan.zig");
const metal_runtime = @import("../../../../backends/metal/runtime.zig");
const protocol_recipes = @import("../../../../backends/metal/protocol_recipes.zig");
const feed_bundle_mod = @import("stwo_cairo_frontend").witness.feed_bundle;
const schedule_bindings = @import("../../schedule_bindings.zig");
const Error = @import("../errors.zig").Error;

const oneComponent = schedule_bindings.oneComponent;
const oneComponentOrdinal = schedule_bindings.oneComponentOrdinal;

pub const MultiplicityFeedBatch = struct {
    allocator: std.mem.Allocator,
    bounds: []protocol_recipes.BoundWitnessFeed,
    producers: []const []const u8,
    batch: protocol_recipes.WitnessFeedBatchRecipe,

    pub fn execute(self: *MultiplicityFeedBatch) !void {
        try self.batch.execute();
    }

    pub fn begin(self: *MultiplicityFeedBatch) !void {
        try self.batch.clear();
    }

    pub fn resetForRequest(self: *MultiplicityFeedBatch) void {
        self.batch.resetForRequest();
    }

    pub fn executeProducer(self: *MultiplicityFeedBatch, producer: []const u8) !void {
        for (self.producers, 0..) |candidate, index| {
            if (!std.mem.eql(u8, candidate, producer)) continue;
            try self.batch.executeIndex(index);
            return;
        }
        return Error.MissingBinding;
    }

    pub fn deinit(self: *MultiplicityFeedBatch) void {
        self.batch.deinit();
        for (self.producers) |producer| self.allocator.free(producer);
        self.allocator.free(self.producers);
        for (self.bounds) |*bound| bound.deinit();
        self.allocator.free(self.bounds);
        self.* = undefined;
    }
};

fn runtimeFeedRowCount(source_slab: arena_plan.Binding, sub_words_per_row: u32) !u32 {
    const row_bytes = std.math.mul(u64, sub_words_per_row, @sizeOf(u32)) catch return Error.InvalidBindingSize;
    if (row_bytes == 0 or source_slab.size_bytes == 0 or source_slab.size_bytes % row_bytes != 0)
        return Error.InvalidBindingSize;
    const row_count = std.math.cast(u32, source_slab.size_bytes / row_bytes) orelse return Error.InvalidBindingSize;
    if (!std.math.isPowerOfTwo(row_count)) return Error.InvalidBindingSize;
    return row_count;
}

fn runtimeFeedDestinationColumnBytes(slab: arena_plan.Binding, width: u32) !u64 {
    if (width == 0 or slab.size_bytes == 0 or slab.size_bytes % width != 0)
        return Error.InvalidBindingSize;
    const column_bytes = slab.size_bytes / width;
    if (column_bytes % @sizeOf(u32) != 0 or !std.math.isPowerOfTwo(column_bytes / @sizeOf(u32)))
        return Error.InvalidBindingSize;
    return column_bytes;
}

fn recordFeedDestinationWidth(
    widths: *std.StringHashMap(u32),
    destination: feed_bundle_mod.Destination,
    table_size: u32,
    referenced_columns: u32,
) !void {
    if (table_size == 0 or destination.words == 0 or destination.words % table_size != 0)
        return Error.InvalidCardinality;
    const width = std.math.cast(u32, destination.words / table_size) orelse return Error.InvalidCardinality;
    if (width < referenced_columns) return Error.InvalidCardinality;
    const entry = try widths.getOrPut(destination.name);
    if (entry.found_existing and entry.value_ptr.* != width) return Error.InvalidCardinality;
    entry.value_ptr.* = width;
}

pub fn prepareMultiplicityFeedBatch(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    bundle: feed_bundle_mod.Bundle,
) !MultiplicityFeedBatch {
    var widths = std.StringHashMap(u32).init(allocator);
    defer widths.deinit();
    for (bundle.feeds) |feed| {
        var descriptor_index: usize = 0;
        while (descriptor_index < feed.descriptors.len) : (descriptor_index += 14) {
            const descriptor = feed.descriptors[descriptor_index .. descriptor_index + 14];
            if (descriptor[10] >= feed.destinations.len) return Error.InvalidCardinality;
            const primary_width: u32 = if (descriptor[11] == 3) 16 else descriptor[7] + 1;
            try recordFeedDestinationWidth(
                &widths,
                feed.destinations[descriptor[10]],
                descriptor[8],
                primary_width,
            );
            if (descriptor[11] == 1) {
                if (descriptor[13] >= feed.destinations.len) return Error.InvalidCardinality;
                try recordFeedDestinationWidth(
                    &widths,
                    feed.destinations[descriptor[13]],
                    descriptor[12],
                    descriptor[7] + 1,
                );
            }
        }
    }

    const bounds = try allocator.alloc(protocol_recipes.BoundWitnessFeed, bundle.feeds.len);
    const column_lengths = try allocator.alloc(u32, bundle.feeds.len);
    defer allocator.free(column_lengths);
    var initialized: usize = 0;
    errdefer {
        for (bounds[0..initialized]) |*bound| bound.deinit();
        allocator.free(bounds);
    }
    while (initialized < bundle.feeds.len) : (initialized += 1) {
        const feed = bundle.feeds[initialized];
        const source_slab = try oneComponent(schedule, plan, "SubcomponentInputs", feed.producer);
        const row_count = try runtimeFeedRowCount(source_slab, feed.sub_words_per_row);
        column_lengths[initialized] = row_count;
        const source_column_bytes = @as(u64, row_count) * @sizeOf(u32);
        const source_columns = try allocator.alloc(arena_plan.Binding, feed.sub_words_per_row);
        defer allocator.free(source_columns);
        for (source_columns, 0..) |*column, index| {
            column.* = source_slab;
            column.offset_bytes += @as(u64, @intCast(index)) * source_column_bytes;
            column.size_bytes = source_column_bytes;
            if (column.offset_bytes >= @as(u64, std.math.maxInt(u32)) * 4) {
                std.debug.print("multiplicity_feed_high_source feed={d} producer={s} column={d} offset={d} size={d}\n", .{
                    initialized, feed.producer, index, column.offset_bytes, column.size_bytes,
                });
            }
        }

        const destinations = try allocator.alloc(protocol_recipes.DestinationColumns, feed.destinations.len);
        defer allocator.free(destinations);
        const destination_columns = try allocator.alloc([]arena_plan.Binding, feed.destinations.len);
        defer {
            for (destination_columns) |columns| allocator.free(columns);
            allocator.free(destination_columns);
        }
        for (feed.destinations, destinations, destination_columns) |destination, *bound_destination, *columns| {
            const slab = try multiplicityDestination(schedule, plan, destination.name);
            const width = widths.get(destination.name) orelse return Error.InvalidCardinality;
            if (destination.words == 0 or destination.words % width != 0) return Error.InvalidBindingSize;
            const column_bytes = try runtimeFeedDestinationColumnBytes(slab, width);
            columns.* = try allocator.alloc(arena_plan.Binding, width);
            for (columns.*, 0..) |*column, index| {
                column.* = slab;
                column.offset_bytes += @as(u64, @intCast(index)) * column_bytes;
                column.size_bytes = column_bytes;
                if (column.offset_bytes >= @as(u64, std.math.maxInt(u32)) * 4) {
                    std.debug.print("multiplicity_feed_high_destination feed={d} producer={s} destination={s} column={d} offset={d} size={d}\n", .{
                        initialized, feed.producer, destination.name, index, column.offset_bytes, column.size_bytes,
                    });
                }
            }
            bound_destination.* = .{ .columns = columns.* };
        }
        bounds[initialized] = protocol_recipes.BoundWitnessFeed.init(
            allocator,
            source_columns,
            destinations,
            feed.descriptors,
            feed.luts,
            row_count,
        ) catch |err| {
            std.debug.print(
                "multiplicity_feed_invalid feed={d} producer={s} source_offset={d} source_end={d} source_words={d}\n",
                .{ initialized, feed.producer, source_slab.offset_bytes, source_slab.offset_bytes + source_slab.size_bytes, source_slab.size_bytes / 4 },
            );
            for (feed.destinations, destination_columns) |destination, columns| {
                if (columns.len == 0) continue;
                const first = columns[0];
                const last = columns[columns.len - 1];
                std.debug.print(
                    "multiplicity_feed_invalid_destination name={s} first_offset={d} end={d} columns={d}\n",
                    .{ destination.name, first.offset_bytes, last.offset_bytes + last.size_bytes, columns.len },
                );
            }
            return err;
        };
    }

    const entries = try allocator.alloc(protocol_recipes.WitnessFeedBatchEntry, bounds.len);
    defer allocator.free(entries);
    for (bounds, column_lengths, entries) |*bound, column_length, *entry|
        entry.* = .{ .bound = bound, .column_length = column_length };
    const producers = try allocator.alloc([]const u8, bundle.feeds.len);
    var producers_initialized: usize = 0;
    errdefer {
        for (producers[0..producers_initialized]) |producer| allocator.free(producer);
        allocator.free(producers);
    }
    while (producers_initialized < bundle.feeds.len) : (producers_initialized += 1)
        producers[producers_initialized] = try allocator.dupe(u8, bundle.feeds[producers_initialized].producer);
    return .{
        .allocator = allocator,
        .bounds = bounds,
        .producers = producers,
        .batch = try protocol_recipes.WitnessFeedBatchRecipe.init(allocator, metal, resident_arena, entries),
    };
}

fn multiplicityDestination(
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    name: []const u8,
) !arena_plan.Binding {
    if (std.mem.eql(u8, name, "memory_address_to_id"))
        return oneComponentOrdinal(schedule, plan, "RuntimeMultiplicity", "memory_address_to_id", 21);
    if (std.mem.eql(u8, name, "memory_id_to_big"))
        return oneComponentOrdinal(schedule, plan, "RuntimeMultiplicity", "memory_id_to_big", 22);
    if (std.mem.eql(u8, name, "memory_id_to_big#small"))
        return oneComponentOrdinal(schedule, plan, "RuntimeMultiplicity", "memory_id_to_big", 23);
    return oneComponent(schedule, plan, "FixedMultiplicity", name);
}

test "Cairo multiplicity feed geometry follows scheduled runtime rows" {
    const sn2_rows: u32 = 1 << 19;
    const sub_words: u32 = 11;
    for ([_]u32{ sn2_rows, sn2_rows * 2, sn2_rows * 4 }) |rows| {
        const source = arena_plan.Binding{
            .logical_id = 0,
            .slot = 0,
            .offset_bytes = 0,
            .size_bytes = @as(u64, rows) * sub_words * @sizeOf(u32),
            .materialization = .resident,
            .occupied = [_]u64{0} ** 16,
        };
        try std.testing.expectEqual(rows, try runtimeFeedRowCount(source, sub_words));

        const destination = arena_plan.Binding{
            .logical_id = 1,
            .slot = 0,
            .offset_bytes = 0,
            .size_bytes = @as(u64, rows) * 3 * @sizeOf(u32),
            .materialization = .resident,
            .occupied = [_]u64{0} ** 16,
        };
        try std.testing.expectEqual(
            @as(u64, rows) * @sizeOf(u32),
            try runtimeFeedDestinationColumnBytes(destination, 3),
        );
    }

    var invalid: arena_plan.Binding = .{
        .logical_id = 2,
        .slot = 0,
        .offset_bytes = 0,
        .size_bytes = @as(u64, sn2_rows) * sub_words * @sizeOf(u32) - 1,
        .materialization = .resident,
        .occupied = [_]u64{0} ** 16,
    };
    try std.testing.expectError(Error.InvalidBindingSize, runtimeFeedRowCount(invalid, sub_words));
    invalid.size_bytes = @as(u64, sn2_rows) * 3 * @sizeOf(u32) - 4;
    try std.testing.expectError(Error.InvalidBindingSize, runtimeFeedDestinationColumnBytes(invalid, 3));

    var widths = std.StringHashMap(u32).init(std.testing.allocator);
    defer widths.deinit();
    var name = "range_check_18".*;
    const destination = feed_bundle_mod.Destination{ .name = &name, .words = 2 * (1 << 18) };
    try recordFeedDestinationWidth(&widths, destination, 1 << 18, 1);
    try std.testing.expectEqual(@as(?u32, 2), widths.get(&name));
    try recordFeedDestinationWidth(&widths, destination, 1 << 18, 2);
    try std.testing.expectError(Error.InvalidCardinality, recordFeedDestinationWidth(&widths, destination, 1 << 17, 1));

    var narrow_name = "range_check_11".*;
    const narrow_destination = feed_bundle_mod.Destination{ .name = &narrow_name, .words = 1 << 11 };
    try std.testing.expectError(
        Error.InvalidCardinality,
        recordFeedDestinationWidth(&widths, narrow_destination, 1 << 11, 2),
    );
}
