//! Authenticated resident binding for Cairo multiplicity-feed programs.

const std = @import("std");
const common = @import(
    "../../../../backends/cuda/runtime/stages/common.zig",
);
const feed_stage = @import(
    "../../../../backends/cuda/runtime/stages/cairo_base/multiplicity_feed.zig",
);
const feed_bundle = @import(
    "../../../../frontends/cairo/witness/feed_bundle.zig",
);
const recorded_binding = @import("../../recorded_binding.zig");
const fixed_plan = @import("../../base_writer_plan/fixed_tables.zig");
const resident_plan = @import("../resident_plan.zig");
const trace_schedule = @import("../trace_schedule.zig");
const trace_writer = @import("../trace_writer_controller.zig");

const pointer_words = @sizeOf(u64) / @sizeOf(u32);

pub const ComponentSubwords = struct {
    component_index: u32,
    words: common.Words,
};

const Destination = struct {
    name: []const u8,
    words: common.Words,
};

pub const Bound = struct {
    allocator: std.mem.Allocator,
    post_feeds: []trace_writer.PostFeed,
    destinations: []Destination,
    clear: feed_stage.Clear,

    pub fn deinit(self: *Bound) void {
        self.allocator.free(self.destinations);
        self.allocator.free(self.post_feeds);
        self.* = undefined;
    }

    pub fn graph(self: Bound) trace_writer.FeedGraph {
        return .{
            .clear = self.clear,
            .post_feeds = self.post_feeds,
        };
    }

    pub fn destination(
        self: Bound,
        name: []const u8,
    ) ?common.Words {
        for (self.destinations) |candidate| {
            if (std.mem.eql(u8, candidate.name, name))
                return candidate.words;
        }
        return null;
    }
};

pub fn prepareAndUpload(
    allocator: std.mem.Allocator,
    uploader: anytype,
    provider: anytype,
    plan: *const resident_plan.Plan,
    schedule: trace_schedule.Schedule,
    feeds: feed_bundle.Bundle,
    fixed_tables: fixed_plan.Plan,
    sources: []const ComponentSubwords,
) !Bound {
    const shape = try deriveShape(feeds, fixed_tables);
    const pointer_slot = try exactSlot(
        provider,
        plan,
        .writer_pointer_tables,
    );
    const metadata_slot = try exactSlot(
        provider,
        plan,
        .writer_descriptors,
    );
    const scratch_slot = try exactSlot(
        provider,
        plan,
        .writer_scratch,
    );
    if (pointer_slot.len < shape.pointer_words or
        metadata_slot.len < shape.metadata_words or
        scratch_slot.len < shape.multiplicity_words)
    {
        return error.InvalidMultiplicityFeedExtent;
    }
    var pointer_cursor = pointer_slot.len - shape.pointer_words;
    var metadata_cursor = metadata_slot.len - shape.metadata_words;
    var multiplicity_cursor = scratch_slot.len -
        shape.multiplicity_words;

    const destinations = try allocator.alloc(
        Destination,
        shape.destination_count,
    );
    errdefer allocator.free(destinations);
    var destination_count: usize = 0;
    for (feeds.feeds) |feed| {
        for (feed.destinations) |candidate| {
            if (findDestination(
                destinations[0..destination_count],
                candidate.name,
            ) != null) continue;
            const words = std.math.cast(
                usize,
                candidate.words,
            ) orelse return error.InvalidMultiplicityFeedExtent;
            destinations[destination_count] = .{
                .name = candidate.name,
                .words = try scratch_slot.sub(
                    multiplicity_cursor,
                    words,
                ),
            };
            multiplicity_cursor = try add(multiplicity_cursor, words);
            destination_count += 1;
        }
    }
    for (fixed_tables.entries) |entry| {
        const expected_words = try mul(
            entry.row_count,
            entry.multiplicity_column_count,
        );
        if (findDestination(
            destinations[0..destination_count],
            entry.name,
        )) |existing| {
            if (existing.len != expected_words)
                return error.InvalidMultiplicityFeedExtent;
            continue;
        }
        destinations[destination_count] = .{
            .name = entry.name,
            .words = try scratch_slot.sub(
                multiplicity_cursor,
                expected_words,
            ),
        };
        multiplicity_cursor = try add(
            multiplicity_cursor,
            expected_words,
        );
        destination_count += 1;
    }
    if (destination_count != destinations.len or
        multiplicity_cursor != scratch_slot.len)
    {
        return error.InvalidMultiplicityFeedExtent;
    }

    const clear_pointer_words = try mul(
        destinations.len,
        pointer_words,
    );
    const clear_pointers = try pointer_slot.sub(
        pointer_cursor,
        clear_pointer_words,
    );
    pointer_cursor += clear_pointer_words;
    const clear_lengths = try metadata_slot.sub(
        metadata_cursor,
        destinations.len,
    );
    metadata_cursor += destinations.len;
    const host_pointers = try allocator.alloc(
        u32,
        clear_pointer_words,
    );
    defer allocator.free(host_pointers);
    const host_lengths = try allocator.alloc(u32, destinations.len);
    defer allocator.free(host_lengths);
    const destination_words = try allocator.alloc(
        common.Words,
        destinations.len,
    );
    defer allocator.free(destination_words);
    var maximum_words: u32 = 0;
    for (destinations, destination_words, host_lengths) |
        destination,
        *words,
        *length,
    | {
        words.* = destination.words;
        length.* = std.math.cast(u32, destination.words.len) orelse
            return error.InvalidMultiplicityFeedExtent;
        maximum_words = @max(maximum_words, length.*);
    }
    try recorded_binding.encodePointerTable(
        host_pointers,
        destination_words,
    );
    try uploader.uploadSlice(u32, clear_pointers, host_pointers);
    try uploader.uploadSlice(u32, clear_lengths, host_lengths);

    const post_feeds = try allocator.alloc(
        trace_writer.PostFeed,
        feeds.feeds.len,
    );
    errdefer allocator.free(post_feeds);
    for (feeds.feeds, post_feeds) |feed, *post| {
        const entry = schedule.find(feed.producer, 0) orelse
            return error.MissingMultiplicityFeedProducer;
        const source = findSource(
            sources,
            entry.component_index,
        ) orelse return error.MissingMultiplicityFeedProducer;
        if (source.len !=
            try mul(feed.row_count, feed.sub_words_per_row))
        {
            return error.InvalidMultiplicityFeedExtent;
        }

        const descriptors = try metadata_slot.sub(
            metadata_cursor,
            feed.descriptors.len,
        );
        metadata_cursor += feed.descriptors.len;
        try uploader.uploadSlice(u32, descriptors, feed.descriptors);

        const lut_columns = try allocator.alloc(
            common.Words,
            feed.luts.len,
        );
        defer allocator.free(lut_columns);
        for (feed.luts, lut_columns) |lut, *column| {
            column.* = try metadata_slot.sub(
                metadata_cursor,
                lut.len,
            );
            metadata_cursor += lut.len;
            try uploader.uploadSlice(u32, column.*, lut);
        }
        const lut_pointer_count = @max(feed.luts.len, 1);
        const lut_pointer_storage = try pointer_slot.sub(
            pointer_cursor,
            try mul(lut_pointer_count, pointer_words),
        );
        pointer_cursor += lut_pointer_storage.len;
        const lut_pointer_host = try allocator.alloc(
            u32,
            lut_pointer_storage.len,
        );
        defer allocator.free(lut_pointer_host);
        if (lut_columns.len == 0) {
            @memset(lut_pointer_host, 0);
        } else {
            try recorded_binding.encodePointerTable(
                lut_pointer_host,
                lut_columns,
            );
        }
        try uploader.uploadSlice(
            u32,
            lut_pointer_storage,
            lut_pointer_host,
        );

        const feed_destinations = try allocator.alloc(
            common.Words,
            feed.destinations.len,
        );
        defer allocator.free(feed_destinations);
        for (feed.destinations, feed_destinations) |
            candidate,
            *destination,
        | {
            destination.* = findDestination(
                destinations,
                candidate.name,
            ) orelse return error.MissingMultiplicityDestination;
            if (destination.len != candidate.words)
                return error.InvalidMultiplicityFeedExtent;
        }
        const feed_pointer_words = try mul(
            feed_destinations.len,
            pointer_words,
        );
        const feed_pointer_storage = try pointer_slot.sub(
            pointer_cursor,
            feed_pointer_words,
        );
        pointer_cursor += feed_pointer_words;
        const feed_pointer_host = try allocator.alloc(
            u32,
            feed_pointer_words,
        );
        defer allocator.free(feed_pointer_host);
        try recorded_binding.encodePointerTable(
            feed_pointer_host,
            feed_destinations,
        );
        try uploader.uploadSlice(
            u32,
            feed_pointer_storage,
            feed_pointer_host,
        );
        post.* = .{
            .component_index = entry.component_index,
            .binding = .{
                .sub_words_word_major = source,
                .column_length = feed.row_count,
                .descriptors = descriptors,
                .descriptor_count = @intCast(
                    feed.descriptors.len / feed_stage.descriptor_words,
                ),
                .lut_pointer_table = lut_pointer_storage,
                .lut_count = @intCast(feed.luts.len),
                .destination_pointer_table = feed_pointer_storage,
                .destination_count = @intCast(feed.destinations.len),
            },
        };
    }
    if (pointer_cursor != pointer_slot.len or
        metadata_cursor != metadata_slot.len)
    {
        return error.InvalidMultiplicityFeedExtent;
    }
    return .{
        .allocator = allocator,
        .post_feeds = post_feeds,
        .destinations = destinations,
        .clear = .{
            .destination_pointer_table = clear_pointers,
            .lengths = clear_lengths,
            .destination_count = @intCast(destinations.len),
            .maximum_words = maximum_words,
        },
    };
}

const Shape = struct {
    pointer_words: usize,
    metadata_words: usize,
    multiplicity_words: usize,
    destination_count: usize,
};

fn deriveShape(
    feeds: feed_bundle.Bundle,
    fixed_tables: fixed_plan.Plan,
) !Shape {
    var pointer_count: usize = 0;
    var metadata_count: usize = 0;
    var multiplicity_count: usize = 0;
    var unique_count: usize = 0;
    for (feeds.feeds) |feed| {
        pointer_count = try add(
            pointer_count,
            try mul(@max(feed.luts.len, 1), pointer_words),
        );
        pointer_count = try add(
            pointer_count,
            try mul(feed.destinations.len, pointer_words),
        );
        metadata_count = try add(
            metadata_count,
            feed.descriptors.len,
        );
        for (feed.luts) |lut|
            metadata_count = try add(metadata_count, lut.len);
        for (feed.destinations) |destination| {
            if (!isFirstDestination(feeds, destination)) continue;
            unique_count += 1;
            multiplicity_count = try add(
                multiplicity_count,
                std.math.cast(usize, destination.words) orelse
                    return error.InvalidMultiplicityFeedExtent,
            );
        }
    }
    for (fixed_tables.entries) |entry| {
        const expected_words = try mul(
            entry.row_count,
            entry.multiplicity_column_count,
        );
        if (destinationWords(feeds, entry.name)) |words| {
            if (words != expected_words)
                return error.InvalidMultiplicityFeedExtent;
            continue;
        }
        unique_count = try add(unique_count, 1);
        multiplicity_count = try add(
            multiplicity_count,
            expected_words,
        );
    }
    pointer_count = try add(
        pointer_count,
        try mul(unique_count, pointer_words),
    );
    metadata_count = try add(metadata_count, unique_count);
    return .{
        .pointer_words = pointer_count,
        .metadata_words = metadata_count,
        .multiplicity_words = multiplicity_count,
        .destination_count = unique_count,
    };
}

fn destinationWords(
    feeds: feed_bundle.Bundle,
    name: []const u8,
) ?usize {
    for (feeds.feeds) |feed| {
        for (feed.destinations) |destination| {
            if (!std.mem.eql(u8, destination.name, name)) continue;
            return std.math.cast(usize, destination.words);
        }
    }
    return null;
}

fn isFirstDestination(
    feeds: feed_bundle.Bundle,
    wanted: feed_bundle.Destination,
) bool {
    for (feeds.feeds) |feed| {
        for (feed.destinations) |destination| {
            if (!std.mem.eql(u8, destination.name, wanted.name)) continue;
            return destination.name.ptr == wanted.name.ptr;
        }
    }
    unreachable;
}

fn findDestination(
    values: []const Destination,
    name: []const u8,
) ?common.Words {
    for (values) |value| {
        if (std.mem.eql(u8, value.name, name)) return value.words;
    }
    return null;
}

fn findSource(
    values: []const ComponentSubwords,
    component_index: u32,
) ?common.Words {
    for (values) |value| {
        if (value.component_index == component_index) return value.words;
    }
    return null;
}

fn exactSlot(
    provider: anytype,
    plan: *const resident_plan.Plan,
    kind: resident_plan.SlotKind,
) !common.Words {
    const descriptor = plan.slot(kind, 0) orelse
        return error.MissingMultiplicityFeedSlot;
    const words = try provider.slot(descriptor.id);
    if (words.len != descriptor.words)
        return error.InvalidMultiplicityFeedExtent;
    return words;
}

fn add(left: anytype, right: anytype) !@TypeOf(left, right) {
    const T = @TypeOf(left, right);
    return std.math.add(T, left, right) catch
        error.InvalidMultiplicityFeedExtent;
}

fn mul(left: anytype, right: anytype) !@TypeOf(left, right) {
    const T = @TypeOf(left, right);
    return std.math.mul(T, left, right) catch
        error.InvalidMultiplicityFeedExtent;
}
