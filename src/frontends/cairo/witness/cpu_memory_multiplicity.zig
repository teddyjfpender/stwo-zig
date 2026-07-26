//! CPU reference accumulation for Cairo memory multiplicity columns.
//!
//! Values are derived only from adapted prover input and authenticated witness
//! programs/feed descriptors. This mirrors the Rust `AddInputs` calls and the
//! Metal witness-feed kernel without consuming proof or commitment artifacts.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const checkpoint = @import("../conformance/checkpoint.zig");
const direct_inputs = @import("direct_inputs.zig");
const execution_tables = @import("execution_tables.zig");
const feed_bundle = @import("feed_bundle.zig");
const feed_topology = @import("feed_topology.zig");
const memory = @import("../common/memory.zig");
const memory_tables = @import("memory_tables.zig");
const program = @import("program.zig");
const verify_inputs = @import("verify_instruction_inputs.zig");
const witness_bundle = @import("bundle.zig");
const recorded_trace = @import("../conformance/recorded_trace.zig");

const none = std.math.maxInt(u32);

pub const Counts = struct {
    allocator: std.mem.Allocator,
    address: []u32,
    big: []u32,
    small: []u32,

    pub fn deinit(self: *Counts) void {
        self.allocator.free(self.address);
        self.allocator.free(self.big);
        self.allocator.free(self.small);
        self.* = undefined;
    }
};

pub const Error = error{
    AllocationSizeOverflow,
    CountOverflow,
    DuplicateProducer,
    InvalidDescriptor,
    InvalidReceiptGeometry,
    InvalidWitnessProgram,
    MissingFeed,
    MissingReceiptComponent,
    MissingWitnessProgram,
    UnsupportedMemoryFeed,
    UnsupportedProducer,
};

/// Accumulates the three memory count tables exactly as the pinned Rust
/// component writers observe them before their base traces are emitted.
pub fn collect(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    witness: *const witness_bundle.Bundle,
    feeds: *const feed_bundle.Bundle,
    expected_components: []const checkpoint.Component,
) !Counts {
    const address_values = input.memory.address_to_id.len -| 1;
    var counts = Counts{
        .allocator = allocator,
        .address = try allocator.alloc(u32, try memory_tables.packedCount(address_values)),
        .big = try allocator.alloc(u32, try memory_tables.packedCount(input.memory.f252_values.len)),
        .small = try allocator.alloc(u32, try memory_tables.packedCount(input.memory.small_values.len)),
    };
    errdefer counts.deinit();
    @memset(counts.address, 0);
    @memset(counts.big, 0);
    @memset(counts.small, 0);
    try addPublicMemory(input, &counts);

    for (feeds.feeds, 0..) |feed, feed_index| {
        for (feeds.feeds[0..feed_index]) |previous| {
            if (std.mem.eql(u8, previous.producer, feed.producer)) return Error.DuplicateProducer;
        }
        const entry = witness.find(feed.producer) orelse return Error.MissingWitnessProgram;
        const row_count = try receiptRows(expected_components, feed.producer);
        if (std.mem.eql(u8, feed.producer, "verify_instruction")) {
            var source = try verify_inputs.gather(allocator, input);
            defer source.deinit();
            try executeAndAccumulate(allocator, input, source, entry.program, feed, row_count, &counts);
        } else {
            const source = try direct_inputs.resolve(input, feed.producer) orelse
                return Error.UnsupportedProducer;
            try executeAndAccumulate(allocator, input, source, entry.program, feed, row_count, &counts);
        }
    }
    for (witness.entries) |entry| {
        const supported = std.mem.eql(u8, entry.label, "verify_instruction") or
            (try direct_inputs.resolve(input, entry.label)) != null;
        if (supported and findFeed(feeds, entry.label) == null) return Error.MissingFeed;
    }
    return counts;
}

/// Accumulates memory multiplicities from an already executed official witness
/// graph. This is the production topology path; it has no fixture row geometry.
pub fn collectTopology(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    topology: feed_topology.Loaded,
    producers: []const recorded_trace.ProducerOutput,
) !Counts {
    const address_values = input.memory.address_to_id.len -| 1;
    var counts = Counts{
        .allocator = allocator,
        .address = try allocator.alloc(u32, try memory_tables.packedCount(address_values)),
        .big = try allocator.alloc(u32, try memory_tables.packedCount(input.memory.f252_values.len)),
        .small = try allocator.alloc(u32, try memory_tables.packedCount(input.memory.small_values.len)),
    };
    errdefer counts.deinit();
    @memset(counts.address, 0);
    @memset(counts.big, 0);
    @memset(counts.small, 0);
    try addPublicMemory(input, &counts);

    for (producers) |producer| {
        const component = topology.find(producer.label) orelse
            return error.MissingProducerTopology;
        if (component.sub_words_per_row != producer.words_per_row or
            producer.active_rows > producer.row_count or
            producer.words.len != @as(usize, producer.row_count) * producer.words_per_row)
            return error.InvalidDescriptor;
        for (component.feeds) |feed| {
            const is_address = std.mem.eql(u8, feed.target, "memory_address_to_id");
            const is_value = std.mem.eql(u8, feed.target, "memory_id_to_big");
            if (!is_address and !is_value) continue;
            if (feed.relation != 0 or feed.words_per_instance != 1)
                return error.UnsupportedMemoryFeed;
            for (0..producer.active_rows) |row| {
                const source_index = @as(usize, row) * producer.words_per_row + feed.word_base;
                const value = producer.words[source_index];
                if (is_address) {
                    if (value == 0 or value > counts.address.len) continue;
                    try increment(&counts.address[value - 1]);
                } else {
                    try addEncodedId(value, &counts);
                }
            }
        }
    }
    return counts;
}

/// `create_cairo_claim_generator` yields public memory before any component
/// writer runs. These uses are intentionally outside the generated feed files.
fn addPublicMemory(input: *const adapter.ProverInput, counts: *Counts) Error!void {
    for (input.public_memory_addresses) |address| {
        if (address == 0 or address >= input.memory.address_to_id.len or
            address - 1 >= counts.address.len)
            return Error.InvalidDescriptor;
        try increment(&counts.address[address - 1]);
        const encoded = input.memory.address_to_id[address].raw;
        if (encoded == memory.DEFAULT_ID) return Error.InvalidDescriptor;
        try addEncodedId(encoded, counts);
    }
}

fn addEncodedId(encoded: u32, counts: *Counts) !void {
    if (encoded == memory.DEFAULT_ID) return;
    const tag = encoded >> 30;
    const index = encoded & 0x3fff_ffff;
    if (tag == 1 and index < counts.big.len) {
        try increment(&counts.big[index]);
    } else if (tag == 0 and index < counts.small.len) {
        try increment(&counts.small[index]);
    } else {
        return error.InvalidDescriptor;
    }
}

fn increment(value: *u32) !void {
    value.* = std.math.add(u32, value.*, 1) catch return error.CountOverflow;
}

fn executeAndAccumulate(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    source: anytype,
    witness_program: program.Program,
    feed: feed_bundle.Feed,
    row_count: usize,
    counts: *Counts,
) !void {
    source.validateRowCount(row_count) catch return Error.InvalidReceiptGeometry;
    if (witness_program.n_inputs != source.columnCount() or
        witness_program.n_sub_words != feed.sub_words_per_row or
        witness_program.n_mult_tables != 0)
        return Error.InvalidWitnessProgram;

    const input_storage = try allocProduct(allocator, source.columnCount(), row_count);
    defer allocator.free(input_storage);
    const input_columns = try allocator.alloc([]const u32, source.columnCount());
    defer allocator.free(input_columns);
    for (input_columns, 0..) |*column, column_index| {
        const values = input_storage[column_index * row_count ..][0..row_count];
        try source.writeColumn(column_index, values);
        column.* = values;
    }

    const output_storage = try allocProduct(allocator, witness_program.n_cols, row_count);
    defer allocator.free(output_storage);
    const output_columns = try allocator.alloc([]u32, witness_program.n_cols);
    defer allocator.free(output_columns);
    for (output_columns, 0..) |*column, column_index|
        column.* = output_storage[column_index * row_count ..][0..row_count];
    const lookup_words = try allocProduct(allocator, witness_program.n_lookup_words, row_count);
    defer allocator.free(lookup_words);
    const sub_words = try allocProduct(allocator, witness_program.n_sub_words, row_count);
    defer allocator.free(sub_words);
    const registers = try allocator.alloc(u32, witness_program.n_regs);
    defer allocator.free(registers);
    const deduce_args = try allocator.alloc(u32, witness_program.n_regs);
    defer allocator.free(deduce_args);
    const no_multiplicity_tables = [_][]u32{};

    try program.executeAll(
        witness_program,
        input_columns,
        output_columns,
        .{
            .lookup_words = lookup_words,
            .sub_words = sub_words,
            .multiplicity_tables = &no_multiplicity_tables,
        },
        registers,
        deduce_args,
        execution_tables.fromInput(input),
        .unsupported(),
    );
    try applyFeed(feed, sub_words, row_count, counts);
}

fn applyFeed(feed: feed_bundle.Feed, sub_words: []const u32, row_count: usize, counts: *Counts) !void {
    if (feed.descriptors.len == 0 or feed.descriptors.len % 14 != 0 or
        feed.sub_words_per_row == 0 or sub_words.len != row_count * feed.sub_words_per_row)
        return Error.InvalidDescriptor;
    var descriptor_index: usize = 0;
    while (descriptor_index < feed.descriptors.len) : (descriptor_index += 14) {
        const descriptor = feed.descriptors[descriptor_index..][0..14];
        const kind = descriptor[11];
        const source_count: u32 = if (kind == 1) 1 else if (kind == 2 or kind == 3) 3 else descriptor[1];
        if (source_count == 0 or @as(u64, descriptor[0]) + source_count > feed.sub_words_per_row or
            descriptor[10] >= feed.destinations.len)
            return Error.InvalidDescriptor;
        if (descriptor[9] != none and descriptor[9] >= feed.luts.len) return Error.InvalidDescriptor;
        if (kind == 1 and descriptor[13] >= feed.destinations.len) return Error.InvalidDescriptor;

        const primary = feed.destinations[descriptor[10]].name;
        const secondary = if (kind == 1) feed.destinations[descriptor[13]].name else "";
        const touches_memory = isMemoryDestination(primary) or isMemoryDestination(secondary);
        if (!touches_memory) continue;
        if (descriptor[7] != 0) return Error.UnsupportedMemoryFeed;
        switch (kind) {
            0 => {
                if (!std.mem.eql(u8, primary, "memory_address_to_id"))
                    return Error.UnsupportedMemoryFeed;
                try applyAddressDescriptor(feed, descriptor, sub_words, row_count, counts.address);
            },
            1 => {
                if (!std.mem.eql(u8, primary, "memory_id_to_big") or
                    !std.mem.eql(u8, secondary, "memory_id_to_big#small"))
                    return Error.UnsupportedMemoryFeed;
                try applyMemoryIdDescriptor(descriptor, sub_words, row_count, counts);
            },
            else => return Error.UnsupportedMemoryFeed,
        }
    }
}

fn applyAddressDescriptor(
    feed: feed_bundle.Feed,
    descriptor: []const u32,
    sub_words: []const u32,
    row_count: usize,
    destination: []u32,
) !void {
    if (descriptor[1] > 5) return Error.InvalidDescriptor;
    const signed_offset: i32 = @bitCast(descriptor[12]);
    for (0..row_count) |row| {
        var key: u32 = 0;
        for (0..descriptor[1]) |word| {
            const bits = descriptor[2 + word];
            if (bits >= 32) return Error.InvalidDescriptor;
            key = (key << @intCast(bits)) | sourceWord(sub_words, row_count, feed.sub_words_per_row, descriptor[0] + @as(u32, @intCast(word)), row);
        }
        const keyed = @as(i64, key) + signed_offset;
        if (keyed < 0 or keyed >= destination.len) continue;
        var index: usize = @intCast(keyed);
        if (descriptor[9] != none) {
            const lut = feed.luts[descriptor[9]];
            if (index >= lut.len) return Error.InvalidDescriptor;
            index = lut[index];
            if (index >= destination.len) continue;
        }
        destination[index] = std.math.add(u32, destination[index], 1) catch
            return Error.CountOverflow;
    }
}

fn applyMemoryIdDescriptor(
    descriptor: []const u32,
    sub_words: []const u32,
    row_count: usize,
    counts: *Counts,
) Error!void {
    for (0..row_count) |row| {
        const encoded = sourceWord(sub_words, row_count, @intCast(sub_words.len / row_count), descriptor[0], row);
        if (encoded == memory.DEFAULT_ID) continue;
        const tag = encoded >> 30;
        const index = encoded & 0x3fff_ffff;
        if (tag == 1 and index < counts.big.len) {
            counts.big[index] = std.math.add(u32, counts.big[index], 1) catch
                return Error.CountOverflow;
        } else if (tag == 0 and index < counts.small.len) {
            counts.small[index] = std.math.add(u32, counts.small[index], 1) catch
                return Error.CountOverflow;
        }
    }
}

fn sourceWord(words: []const u32, row_count: usize, words_per_row: u32, word: u32, row: usize) u32 {
    _ = row_count;
    return words[row * words_per_row + word];
}

fn receiptRows(components: []const checkpoint.Component, label: []const u8) Error!usize {
    for (components) |component| {
        if (!std.mem.eql(u8, component.label, label)) continue;
        if (component.columns.len == 0) return Error.InvalidReceiptGeometry;
        const rows = std.math.cast(usize, component.columns[0].row_count) orelse
            return Error.InvalidReceiptGeometry;
        for (component.columns, 0..) |column, index| {
            if (column.ordinal != index or column.row_count != rows)
                return Error.InvalidReceiptGeometry;
        }
        return rows;
    }
    return Error.MissingReceiptComponent;
}

fn findFeed(feeds: *const feed_bundle.Bundle, label: []const u8) ?*const feed_bundle.Feed {
    for (feeds.feeds) |*feed| if (std.mem.eql(u8, feed.producer, label)) return feed;
    return null;
}

fn isMemoryDestination(name: []const u8) bool {
    return std.mem.eql(u8, name, "memory_address_to_id") or
        std.mem.eql(u8, name, "memory_id_to_big") or
        std.mem.eql(u8, name, "memory_id_to_big#small");
}

fn allocProduct(allocator: std.mem.Allocator, lhs: anytype, rhs: usize) ![]u32 {
    const count = std.math.mul(usize, @intCast(lhs), rhs) catch
        return Error.AllocationSizeOverflow;
    return allocator.alloc(u32, count);
}

test "Cairo CPU memory multiplicity: address and encoded IDs follow feed semantics" {
    var address = [_]u32{0} ** 8;
    var big = [_]u32{0} ** 4;
    var small = [_]u32{0} ** 4;
    var counts = Counts{ .allocator = undefined, .address = &address, .big = &big, .small = &small };
    const words = [_]u32{ 1, memory.EncodedMemoryValueId.f252(2).raw, 8, memory.EncodedMemoryValueId.small(3).raw };
    const destinations = [_]feed_bundle.Destination{
        .{ .name = @constCast("memory_address_to_id"), .words = 8 },
        .{ .name = @constCast("memory_id_to_big"), .words = 4 },
        .{ .name = @constCast("memory_id_to_big#small"), .words = 4 },
    };
    const descriptors = [_]u32{
        0, 1, 31, 0, 0, 0, 0, 0, 8, none, 0, 0, @bitCast(@as(i32, -1)), 0,
        1, 1, 31, 0, 0, 0, 0, 0, 4, none, 1, 1, 4,                      2,
    };
    try applyFeed(.{
        .producer = @constCast("test"),
        .row_count = 2,
        .sub_words_per_row = 2,
        .descriptors = @constCast(&descriptors),
        .luts = &.{},
        .destinations = @constCast(&destinations),
    }, &words, 2, &counts);
    try std.testing.expectEqual(@as(u32, 1), counts.address[0]);
    try std.testing.expectEqual(@as(u32, 1), counts.big[2]);
    try std.testing.expectEqual(@as(u32, 1), counts.small[3]);
}

test "Cairo CPU memory multiplicity: counters fail closed on overflow" {
    var address = [_]u32{std.math.maxInt(u32)};
    var counts = Counts{ .allocator = undefined, .address = &address, .big = &.{}, .small = &.{} };
    const destinations = [_]feed_bundle.Destination{.{
        .name = @constCast("memory_address_to_id"),
        .words = 1,
    }};
    const descriptors = [_]u32{
        0, 1, 31, 0, 0, 0, 0, 0, 1, none, 0, 0, @bitCast(@as(i32, -1)), 0,
    };
    try std.testing.expectError(Error.CountOverflow, applyFeed(.{
        .producer = @constCast("test"),
        .row_count = 1,
        .sub_words_per_row = 1,
        .descriptors = @constCast(&descriptors),
        .luts = &.{},
        .destinations = @constCast(&destinations),
    }, &.{1}, 1, &counts));
}

test "Cairo CPU memory multiplicity: public memory seeds both relations" {
    var address = [_]u32{0} ** 2;
    var big = [_]u32{0};
    var small = [_]u32{0};
    var counts = Counts{ .allocator = undefined, .address = &address, .big = &big, .small = &small };
    var address_to_id = [_]memory.EncodedMemoryValueId{
        memory.EncodedMemoryValueId.EMPTY,
        memory.EncodedMemoryValueId.small(0),
        memory.EncodedMemoryValueId.f252(0),
    };
    var public_addresses = [_]u32{ 1, 2 };
    var input: adapter.ProverInput = undefined;
    input.memory.address_to_id = &address_to_id;
    input.public_memory_addresses = &public_addresses;
    try addPublicMemory(&input, &counts);
    try std.testing.expectEqualSlices(u32, &.{ 1, 1 }, &address);
    try std.testing.expectEqual(@as(u32, 1), big[0]);
    try std.testing.expectEqual(@as(u32, 1), small[0]);
}
