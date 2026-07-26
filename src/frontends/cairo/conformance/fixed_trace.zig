//! CPU reference generation for Cairo's fixed-table base traces.
//!
//! Recorded witness programs produce subcomponent inputs. Authenticated feed
//! descriptors scatter those inputs into fixed-table multiplicity columns.
//! Memory value limbs feed `range_check_9_9` directly, matching the pinned Rust
//! writer. Tables without a producer remain implicit zero columns.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const witness_bundle = @import("../witness/bundle.zig");
const direct_inputs = @import("../witness/direct_inputs.zig");
const execution_tables = @import("../witness/execution_tables.zig");
const feed_bundle = @import("../witness/feed_bundle.zig");
const feed_topology = @import("../witness/feed_topology.zig");
const fixed_table_bundle = @import("../witness/fixed_table_bundle.zig");
const memory_tables = @import("../witness/memory_tables.zig");
const program = @import("../witness/program.zig");
const verify_instruction_inputs = @import("../witness/verify_instruction_inputs.zig");
const checkpoint = @import("checkpoint.zig");
const multiplicity_tables = @import("multiplicity_tables.zig");
const producer_output = @import("../witness/producer_output.zig");

const none = std.math.maxInt(u32);
const Tables = multiplicity_tables.Tables;

pub const Match = struct {
    ordinal: u32,
    label: []const u8,
    row_count: u64,
    column_count: u32,
};

pub const MismatchKind = enum {
    column_digest,
};

pub const Mismatch = struct {
    kind: MismatchKind,
    component_ordinal: u32,
    component_label: []const u8,
    column_ordinal: u32,
    expected_digest: checkpoint.Digest,
    actual_digest: checkpoint.Digest,
};

pub const Report = struct {
    allocator: std.mem.Allocator,
    matches: []Match,
    mismatch: ?Mismatch,

    pub fn deinit(self: *Report) void {
        self.allocator.free(self.matches);
        self.* = undefined;
    }
};

pub const Error = error{
    AllocationSizeOverflow,
    DuplicateProducer,
    DuplicateFixedTable,
    FeedGeometryMismatch,
    FixedGeometryMismatch,
    GeometryTooLarge,
    InvalidDescriptor,
    InvalidMultiplicityKey,
    MissingFixedTable,
    MissingProducerReceipt,
    MissingWitnessProgram,
    MultiplicityOverflow,
    UnsupportedMultiplicityTables,
    UnsupportedProducer,
    WitnessInputCountMismatch,
};

const SubWords = struct {
    allocator: std.mem.Allocator,
    row_count: u32,
    words_per_row: u32,
    values: []u32,

    fn deinit(self: *SubWords) void {
        self.allocator.free(self.values);
        self.* = undefined;
    }

    fn at(self: SubWords, row: u32, word: u32) !u32 {
        if (row >= self.row_count or word >= self.words_per_row)
            return Error.InvalidDescriptor;
        return self.values[@as(usize, row) * self.words_per_row + word];
    }
};

/// Compares the 17 fixed Cairo base components against raw logical-row Rust
/// checkpoint columns. The receipt supplies canonical component ordinals;
/// recorded bundle order is never treated as protocol order.
pub fn compare(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    witnesses: *const witness_bundle.Bundle,
    feeds: *const feed_bundle.Bundle,
    fixed: *const fixed_table_bundle.Bundle,
    expected_components: []const checkpoint.Component,
) !Report {
    var tables = try Tables.init(allocator, fixed);
    defer tables.deinit();

    try executeFixedFeeds(allocator, input, witnesses, feeds, expected_components, &tables);
    try addMemoryRangeChecks(input, expected_components, &tables);
    const report = try comparePopulated(allocator, fixed, &tables, expected_components);
    if (report.matches.len != fixed.entries.len) {
        var mutable = report;
        mutable.deinit();
        return Error.MissingFixedTable;
    }
    return report;
}

/// Compares fixture-independent fixed tables using the source-derived feed
/// topology and the outputs retained by the official recorded graph.
pub fn compareTopology(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    topology: feed_topology.Loaded,
    producers: []const producer_output.ProducerOutput,
    fixed: *const fixed_table_bundle.Bundle,
    expected_components: []const checkpoint.Component,
) !Report {
    var tables = try populateTopology(allocator, input, topology, producers, fixed, expected_components);
    defer tables.deinit();
    return comparePopulated(allocator, fixed, &tables, expected_components);
}

/// Populates every fixed-table multiplicity from the source-derived producer
/// graph and the memory value tables.
pub fn populateTopology(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    topology: feed_topology.Loaded,
    producers: []const producer_output.ProducerOutput,
    fixed: *const fixed_table_bundle.Bundle,
    expected_components: []const checkpoint.Component,
) !Tables {
    var tables = try Tables.init(allocator, fixed);
    errdefer tables.deinit();
    try tables.route(topology, producers);
    try validateMemoryGeometry(input, expected_components);
    try addMemoryRangeChecksLive(input, &tables);
    return tables;
}

/// Production population path. Memory table dimensions come from the admitted
/// input; no Rust receipt participates in routing or sizing.
pub fn populateLiveTopology(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    topology: feed_topology.Loaded,
    producers: []const producer_output.ProducerOutput,
    fixed: *const fixed_table_bundle.Bundle,
) !Tables {
    var tables = try Tables.init(allocator, fixed);
    errdefer tables.deinit();
    try tables.route(topology, producers);
    try addMemoryRangeChecksLive(input, &tables);
    return tables;
}

fn comparePopulated(
    allocator: std.mem.Allocator,
    fixed: *const fixed_table_bundle.Bundle,
    tables: *Tables,
    expected_components: []const checkpoint.Component,
) !Report {
    var max_rows: usize = 0;
    for (fixed.entries) |entry| max_rows = @max(max_rows, entry.row_count);
    const zeros = try allocator.alloc(u32, max_rows);
    defer allocator.free(zeros);
    @memset(zeros, 0);

    var matches = std.ArrayList(Match).empty;
    errdefer matches.deinit(allocator);
    for (expected_components) |expected| {
        const table = tables.find(expected.label) orelse continue;
        try validateExpectedGeometry(expected, table.entry.*);
        for (expected.columns, table.entry.trace_multiplicity_columns) |column, source_column| {
            const values = try tables.column(expected.label, source_column, zeros);
            const actual = try checkpoint.digestColumn(
                expected.ordinal,
                expected.label,
                column.ordinal,
                values,
            );
            if (!std.mem.eql(u8, &column.sha256, &actual)) return .{
                .allocator = allocator,
                .matches = try matches.toOwnedSlice(allocator),
                .mismatch = .{
                    .kind = .column_digest,
                    .component_ordinal = expected.ordinal,
                    .component_label = expected.label,
                    .column_ordinal = column.ordinal,
                    .expected_digest = column.sha256,
                    .actual_digest = actual,
                },
            };
        }
        try matches.append(allocator, .{
            .ordinal = expected.ordinal,
            .label = expected.label,
            .row_count = expected.columns[0].row_count,
            .column_count = @intCast(expected.columns.len),
        });
    }
    return .{
        .allocator = allocator,
        .matches = try matches.toOwnedSlice(allocator),
        .mismatch = null,
    };
}

fn executeFixedFeeds(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    witnesses: *const witness_bundle.Bundle,
    feeds: *const feed_bundle.Bundle,
    expected: []const checkpoint.Component,
    tables: *Tables,
) !void {
    for (feeds.feeds, 0..) |feed, feed_index| {
        for (feeds.feeds[0..feed_index]) |previous| {
            if (std.mem.eql(u8, previous.producer, feed.producer))
                return Error.DuplicateProducer;
        }
        if (!feedTouchesFixed(feed, tables)) continue;
        const component = findComponent(expected, feed.producer) orelse
            return Error.MissingProducerReceipt;
        const entry = witnesses.find(feed.producer) orelse return Error.MissingWitnessProgram;
        const rows = componentRowCount(component) catch return Error.FeedGeometryMismatch;
        var sub_words = if (std.mem.eql(u8, feed.producer, "verify_instruction")) blk: {
            var compact = try verify_instruction_inputs.gather(allocator, input);
            defer compact.deinit();
            break :blk try executeProducer(allocator, input, entry.program, compact, rows);
        } else blk: {
            const direct = try direct_inputs.resolve(input, feed.producer) orelse
                return Error.UnsupportedProducer;
            break :blk try executeProducer(allocator, input, entry.program, direct, rows);
        };
        defer sub_words.deinit();
        if (feed.sub_words_per_row != sub_words.words_per_row)
            return Error.FeedGeometryMismatch;
        try scatterFeed(feed, sub_words, tables);
    }
}

fn executeProducer(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    witness_program: program.Program,
    source: anytype,
    row_count: u32,
) !SubWords {
    if (source.columnCount() != witness_program.n_inputs)
        return Error.WitnessInputCountMismatch;
    if (witness_program.n_mult_tables != 0) return Error.UnsupportedMultiplicityTables;
    source.validateRowCount(row_count) catch return Error.FeedGeometryMismatch;
    const input_words = std.math.mul(usize, witness_program.n_inputs, row_count) catch
        return Error.AllocationSizeOverflow;
    const output_words = std.math.mul(usize, witness_program.n_cols, row_count) catch
        return Error.AllocationSizeOverflow;
    const lookup_words_count = std.math.mul(usize, witness_program.n_lookup_words, row_count) catch
        return Error.AllocationSizeOverflow;
    const sub_words_count = std.math.mul(usize, witness_program.n_sub_words, row_count) catch
        return Error.AllocationSizeOverflow;

    const input_storage = try allocator.alloc(u32, input_words);
    defer allocator.free(input_storage);
    const input_columns = try allocator.alloc([]const u32, witness_program.n_inputs);
    defer allocator.free(input_columns);
    for (input_columns, 0..) |*column, index| {
        const start = index * row_count;
        const values = input_storage[start .. start + row_count];
        try source.writeColumn(index, values);
        column.* = values;
    }

    const output_storage = try allocator.alloc(u32, output_words);
    defer allocator.free(output_storage);
    const output_columns = try allocator.alloc([]u32, witness_program.n_cols);
    defer allocator.free(output_columns);
    for (output_columns, 0..) |*column, index| {
        const start = index * row_count;
        column.* = output_storage[start .. start + row_count];
    }
    const lookup_words = try allocator.alloc(u32, lookup_words_count);
    defer allocator.free(lookup_words);
    const sub_words = try allocator.alloc(u32, sub_words_count);
    errdefer allocator.free(sub_words);
    const registers = try allocator.alloc(u32, witness_program.n_regs);
    defer allocator.free(registers);
    const deduce_args = try allocator.alloc(u32, witness_program.n_regs);
    defer allocator.free(deduce_args);
    const no_multiplicity_tables: []const []u32 = &.{};
    try program.executeAll(
        witness_program,
        input_columns,
        output_columns,
        .{
            .lookup_words = lookup_words,
            .sub_words = sub_words,
            .multiplicity_tables = no_multiplicity_tables,
        },
        registers,
        deduce_args,
        execution_tables.fromInput(input),
        .unsupported(),
    );
    return .{
        .allocator = allocator,
        .row_count = row_count,
        .words_per_row = witness_program.n_sub_words,
        .values = sub_words,
    };
}

fn scatterFeed(feed: feed_bundle.Feed, source: SubWords, tables: *Tables) !void {
    if (feed.descriptors.len == 0 or feed.descriptors.len % 14 != 0)
        return Error.InvalidDescriptor;
    var descriptor_index: usize = 0;
    while (descriptor_index < feed.descriptors.len) : (descriptor_index += 14) {
        const descriptor = feed.descriptors[descriptor_index..][0..14];
        if (descriptor[10] >= feed.destinations.len) return Error.InvalidDescriptor;
        const destination = feed.destinations[descriptor[10]].name;
        const table = tables.find(destination) orelse continue;
        const destination_words = std.math.mul(
            u64,
            table.entry.row_count,
            table.entry.multiplicity_columns,
        ) catch return Error.FeedGeometryMismatch;
        if (descriptor[8] != table.entry.row_count or
            feed.destinations[descriptor[10]].words != destination_words)
            return Error.FeedGeometryMismatch;
        for (0..source.row_count) |row| {
            try scatterRow(feed, descriptor, source, @intCast(row), destination, tables);
        }
    }
}

fn scatterRow(
    feed: feed_bundle.Feed,
    descriptor: []const u32,
    source: SubWords,
    row: u32,
    destination: []const u8,
    tables: *Tables,
) !void {
    const word_base = descriptor[0];
    const word_count = descriptor[1];
    const table_size = descriptor[8];
    const lut_index = descriptor[9];
    const relation = descriptor[7];
    switch (descriptor[11]) {
        0 => {
            if (word_count == 0 or word_count > 5) return Error.InvalidDescriptor;
            var key: u32 = 0;
            var key_bits: u32 = 0;
            for (0..word_count) |index| {
                const bits = descriptor[2 + index];
                if (bits == 0 or bits >= 32 or key_bits > 31 - bits)
                    return Error.InvalidDescriptor;
                const value = try source.at(row, word_base + @as(u32, @intCast(index)));
                if (value >= (@as(u32, 1) << @intCast(bits))) return Error.InvalidMultiplicityKey;
                key = (key << @intCast(bits)) | value;
                key_bits += bits;
            }
            const keyed = @as(i64, key) + @as(i32, @bitCast(descriptor[12]));
            if (keyed < 0 or keyed >= table_size) return Error.InvalidMultiplicityKey;
            const index = try lookupRow(feed, lut_index, @intCast(keyed), table_size);
            try tables.increment(destination, relation, index);
        },
        2 => {
            const bits = descriptor[2];
            if (bits == 0 or bits >= 16) return Error.InvalidDescriptor;
            const a = try source.at(row, word_base);
            const b = try source.at(row, word_base + 1);
            const c = try source.at(row, word_base + 2);
            const mask = (@as(u32, 1) << @intCast(bits)) - 1;
            if ((a | b | c) > mask or c != (a ^ b)) return Error.InvalidMultiplicityKey;
            const key = (a << @intCast(bits)) | b;
            const index = try lookupRow(feed, lut_index, key, table_size);
            try tables.increment(destination, relation, index);
        },
        3 => {
            const a = try source.at(row, word_base);
            const b = try source.at(row, word_base + 1);
            const c = try source.at(row, word_base + 2);
            if ((a | b | c) >= (1 << 12) or c != (a ^ b))
                return Error.InvalidMultiplicityKey;
            const relation_column = ((a >> 10) << 2) | (b >> 10);
            const index = ((a & 0x3ff) << 10) | (b & 0x3ff);
            if (index >= table_size) return Error.InvalidMultiplicityKey;
            try tables.increment(destination, relation_column, index);
        },
        else => return Error.InvalidDescriptor,
    }
}

fn lookupRow(feed: feed_bundle.Feed, lut_index: u32, key: u32, table_size: u32) !u32 {
    if (lut_index == none) return key;
    if (lut_index >= feed.luts.len or key >= feed.luts[lut_index].len)
        return Error.InvalidDescriptor;
    const row = feed.luts[lut_index][key];
    if (row >= table_size) return Error.InvalidMultiplicityKey;
    return row;
}

fn addMemoryRangeChecks(
    input: *const adapter.ProverInput,
    expected: []const checkpoint.Component,
    tables: *Tables,
) !void {
    try validateMemoryGeometry(input, expected);
    try addMemoryRangeChecksLive(input, tables);
}

fn validateMemoryGeometry(
    input: *const adapter.ProverInput,
    expected: []const checkpoint.Component,
) !void {
    const component_count = try memory_tables.bigComponentCount(input);
    for (0..component_count) |component_index| {
        var label_buffer: [64]u8 = undefined;
        const label = std.fmt.bufPrint(&label_buffer, "memory_id_to_big[{d}]", .{component_index}) catch
            return Error.FixedGeometryMismatch;
        const component = findComponent(expected, label) orelse return Error.MissingProducerReceipt;
        const row_count = componentRowCount(component) catch return Error.FixedGeometryMismatch;
        if (row_count != try memory_tables.bigRowCount(input, component_index))
            return Error.FixedGeometryMismatch;
    }
    const small_component = findComponent(expected, "memory_id_to_small") orelse
        return Error.MissingProducerReceipt;
    const small_rows = componentRowCount(small_component) catch
        return Error.FixedGeometryMismatch;
    if (small_rows != try memory_tables.smallRowCount(input))
        return Error.FixedGeometryMismatch;
}

fn addMemoryRangeChecksLive(
    input: *const adapter.ProverInput,
    tables: *Tables,
) !void {
    const component_count = try memory_tables.bigComponentCount(input);
    for (0..component_count) |component_index| {
        const row_count = try memory_tables.bigRowCount(input, component_index);
        const first = try tables.allocator.alloc(u32, row_count);
        defer tables.allocator.free(first);
        const second = try tables.allocator.alloc(u32, row_count);
        defer tables.allocator.free(second);
        for (0..memory_tables.big_limb_count / 2) |pair| {
            try memory_tables.writeBigValueColumn(input, component_index, pair * 2, first);
            try memory_tables.writeBigValueColumn(input, component_index, pair * 2 + 1, second);
            for (first, second) |low, high| {
                const relation: u32 = @intCast(pair % 8);
                const index = (low << 9) | high;
                try tables.increment("range_check_9_9", relation, index);
            }
        }
    }

    const small_rows = try memory_tables.smallRowCount(input);
    const first = try tables.allocator.alloc(u32, small_rows);
    defer tables.allocator.free(first);
    const second = try tables.allocator.alloc(u32, small_rows);
    defer tables.allocator.free(second);
    for (0..memory_tables.small_limb_count / 2) |pair| {
        try memory_tables.writeSmallValueColumn(input, pair * 2, first);
        try memory_tables.writeSmallValueColumn(input, pair * 2 + 1, second);
        for (first, second) |low, high| {
            const index = (low << 9) | high;
            try tables.increment("range_check_9_9", @intCast(pair), index);
        }
    }
}

fn validateExpectedGeometry(expected: checkpoint.Component, entry: fixed_table_bundle.Entry) !void {
    if (!std.mem.eql(u8, expected.label, entry.component) or expected.columns.len == 0 or
        expected.columns.len != entry.trace_multiplicity_columns.len)
        return Error.FixedGeometryMismatch;
    for (expected.columns, 0..) |column, index| {
        if (column.ordinal != index or column.row_count != entry.row_count)
            return Error.FixedGeometryMismatch;
    }
}

fn feedTouchesFixed(feed: feed_bundle.Feed, tables: *Tables) bool {
    var index: usize = 0;
    while (index < feed.descriptors.len) : (index += 14) {
        if (index + 14 > feed.descriptors.len) return true;
        const destination = feed.descriptors[index + 10];
        if (destination >= feed.destinations.len) return true;
        if (tables.find(feed.destinations[destination].name) != null) return true;
    }
    return false;
}

fn findComponent(components: []const checkpoint.Component, label: []const u8) ?checkpoint.Component {
    for (components) |component| {
        if (std.mem.eql(u8, component.label, label)) return component;
    }
    return null;
}

fn componentRowCount(component: checkpoint.Component) !u32 {
    if (component.columns.len == 0) return Error.FixedGeometryMismatch;
    const rows = std.math.cast(u32, component.columns[0].row_count) orelse
        return Error.FixedGeometryMismatch;
    for (component.columns) |column| {
        if (column.row_count != rows) return Error.FixedGeometryMismatch;
    }
    return rows;
}

test "Cairo fixed trace: implicit tables materialize only on first contribution" {
    var components = [_]fixed_table_bundle.Entry{.{
        .component = @constCast("range_check_4_3"),
        .log_size = 7,
        .row_count = 128,
        .multiplicity_columns = 1,
        .trace_multiplicity_columns = @constCast(&[_]u32{0}),
        .preprocessed_sources = @constCast(&[_][]u8{}),
        .lookup_descriptors = @constCast(&[_]u32{}),
    }};
    const fixed = fixed_table_bundle.Bundle{
        .allocator = std.testing.allocator,
        .graph_hash = fixed_table_bundle.expected_graph_hash,
        .preprocessed_identities = @constCast(&[_][]u8{}),
        .entries = &components,
    };
    var tables = try Tables.init(std.testing.allocator, &fixed);
    defer tables.deinit();
    try std.testing.expect(tables.items[0].dense == null);
    try tables.increment("range_check_4_3", 0, 17);
    try tables.increment("range_check_4_3", 0, 17);
    try std.testing.expectEqual(@as(u32, 2), tables.items[0].dense.?[17]);
    tables.items[0].dense.?[17] = std.math.maxInt(u32);
    try std.testing.expectError(
        Error.MultiplicityOverflow,
        tables.increment("range_check_4_3", 0, 17),
    );
}

test "Cairo fixed trace: generic descriptor scatters tuple keys and rejects overflow" {
    var components = [_]fixed_table_bundle.Entry{.{
        .component = @constCast("range_check_4_3"),
        .log_size = 7,
        .row_count = 128,
        .multiplicity_columns = 1,
        .trace_multiplicity_columns = @constCast(&[_]u32{0}),
        .preprocessed_sources = @constCast(&[_][]u8{}),
        .lookup_descriptors = @constCast(&[_]u32{}),
    }};
    const fixed = fixed_table_bundle.Bundle{
        .allocator = std.testing.allocator,
        .graph_hash = fixed_table_bundle.expected_graph_hash,
        .preprocessed_identities = @constCast(&[_][]u8{}),
        .entries = &components,
    };
    var tables = try Tables.init(std.testing.allocator, &fixed);
    defer tables.deinit();
    const descriptors = [_]u32{
        0, 2, 4, 3, 0, 0, 0, 0, 128, none, 0, 0, 0, 0,
    };
    const destinations = [_]feed_bundle.Destination{.{
        .name = @constCast("range_check_4_3"),
        .words = 128,
    }};
    const feed = feed_bundle.Feed{
        .producer = @constCast("producer"),
        .row_count = 2,
        .sub_words_per_row = 2,
        .descriptors = @constCast(&descriptors),
        .luts = &.{},
        .destinations = @constCast(&destinations),
    };
    var values = [_]u32{ 1, 2, 3, 4 };
    const source = SubWords{
        .allocator = undefined,
        .row_count = 2,
        .words_per_row = 2,
        .values = &values,
    };
    try scatterFeed(feed, source, &tables);
    try std.testing.expectEqual(@as(u32, 1), tables.items[0].dense.?[10]);
    try std.testing.expectEqual(@as(u32, 1), tables.items[0].dense.?[28]);

    values[0] = 16;
    try std.testing.expectError(
        Error.InvalidMultiplicityKey,
        scatterFeed(feed, source, &tables),
    );
}
