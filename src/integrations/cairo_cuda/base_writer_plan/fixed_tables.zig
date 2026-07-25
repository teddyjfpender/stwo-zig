//! Exact active fixed-table inventory derived from the proof semantics.

const std = @import("std");
const composition = @import(
    "../../../frontends/cairo/witness/composition_bundle.zig",
);
const fixed_bundle = @import(
    "../../../frontends/cairo/witness/fixed_table_bundle.zig",
);

pub const identity_domain =
    "stwo-zig/cairo/cuda/fixed-table-lowering/v1\x00";

pub const Entry = struct {
    component_index: u32,
    fixed_ordinal: u32,
    graph_hash: u64,
    name: []const u8,
    instance: u32,
    log_size: u32,
    row_count: u32,
    source_column_count: u32,
    multiplicity_column_count: u32,
    trace_output_count: u32,
    lookup_output_count: u32,
    preprocessed_sources: []const []u8,
    trace_multiplicity_columns: []const u32,
    lookup_descriptors: []const u32,
    identity: [32]u8,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    entries: []Entry,
    identity: [32]u8,

    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn find(
        self: Plan,
        name: []const u8,
        instance: u32,
    ) ?Entry {
        for (self.entries) |entry| {
            if (entry.instance == instance and
                std.mem.eql(u8, entry.name, name))
            {
                return entry;
            }
        }
        return null;
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    components: composition.Bundle,
    fixed: fixed_bundle.Bundle,
) !Plan {
    if (fixed.graph_hash != fixed_bundle.expected_graph_hash)
        return error.FixedTableGraphMismatch;
    var active_count: usize = 0;
    for (components.components) |component| {
        if (fixed.find(component.label) != null) active_count += 1;
    }
    if (active_count == 0) return error.MissingFixedTable;

    const entries = try allocator.alloc(Entry, active_count);
    errdefer allocator.free(entries);
    var entry_index: usize = 0;
    for (components.components, 0..) |component, component_index| {
        const fixed_entry = findWithOrdinal(
            fixed,
            component.label,
        ) orelse continue;
        if (component.instance != 0 or
            component.trace_log_size != fixed_entry.entry.log_size or
            component.trace_spans.len == 0)
        {
            return error.FixedTableGeometryMismatch;
        }
        var lowered = Entry{
            .component_index = @intCast(component_index),
            .fixed_ordinal = fixed_entry.ordinal,
            .graph_hash = fixed.graph_hash,
            .name = fixed_entry.entry.component,
            .instance = component.instance,
            .log_size = fixed_entry.entry.log_size,
            .row_count = fixed_entry.entry.row_count,
            .source_column_count = @intCast(fixed_entry.entry.preprocessed_sources.len),
            .multiplicity_column_count = fixed_entry.entry.multiplicity_columns,
            .trace_output_count = @intCast(
                fixed_entry.entry.trace_multiplicity_columns.len,
            ),
            .lookup_output_count = @intCast(
                fixed_entry.entry.lookupCount(),
            ),
            .preprocessed_sources = fixed_entry.entry.preprocessed_sources,
            .trace_multiplicity_columns = fixed_entry.entry.trace_multiplicity_columns,
            .lookup_descriptors = fixed_entry.entry.lookup_descriptors,
            .identity = undefined,
        };
        lowered.identity = recomputeIdentity(lowered);
        entries[entry_index] = lowered;
        entry_index += 1;
    }
    if (entry_index != entries.len)
        return error.FixedTableInventoryMismatch;
    const identity = planIdentity(fixed.graph_hash, entries);
    return .{
        .allocator = allocator,
        .entries = entries,
        .identity = identity,
    };
}

pub fn recomputeIdentity(entry: Entry) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(identity_domain);
    hashInt(&hash, u64, entry.graph_hash);
    hashInt(&hash, u32, entry.fixed_ordinal);
    hashBytes(&hash, entry.name);
    hashInt(&hash, u32, entry.instance);
    hashInt(&hash, u32, entry.log_size);
    hashInt(&hash, u32, entry.row_count);
    hashInt(&hash, u32, entry.multiplicity_column_count);
    hashWords(&hash, entry.trace_multiplicity_columns);
    hashInt(&hash, u64, entry.preprocessed_sources.len);
    for (entry.preprocessed_sources) |source| hashBytes(&hash, source);
    hashWords(&hash, entry.lookup_descriptors);
    return hash.finalResult();
}

pub fn entryIdentity(
    graph_hash: u64,
    component: composition.Component,
    fixed_ordinal: u32,
    entry: fixed_bundle.Entry,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(identity_domain);
    hashInt(&hash, u64, graph_hash);
    hashInt(&hash, u32, fixed_ordinal);
    hashBytes(&hash, component.label);
    hashInt(&hash, u32, component.instance);
    hashInt(&hash, u32, component.trace_log_size);
    hashInt(&hash, u32, entry.row_count);
    hashInt(&hash, u32, entry.multiplicity_columns);
    hashWords(&hash, entry.trace_multiplicity_columns);
    hashInt(&hash, u64, entry.preprocessed_sources.len);
    for (entry.preprocessed_sources) |source| hashBytes(&hash, source);
    hashWords(&hash, entry.lookup_descriptors);
    return hash.finalResult();
}

fn planIdentity(graph_hash: u64, entries: []const Entry) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/fixed-table-plan/v1\x00");
    hashInt(&hash, u64, graph_hash);
    hashInt(&hash, u64, entries.len);
    for (entries) |entry| {
        hashInt(&hash, u32, entry.component_index);
        hash.update(&entry.identity);
    }
    return hash.finalResult();
}

const Located = struct {
    ordinal: u32,
    entry: fixed_bundle.Entry,
};

fn findWithOrdinal(
    fixed: fixed_bundle.Bundle,
    name: []const u8,
) ?Located {
    for (fixed.entries, 0..) |entry, ordinal| {
        if (std.mem.eql(u8, entry.component, name)) return .{
            .ordinal = @intCast(ordinal),
            .entry = entry,
        };
    }
    return null;
}

fn hashBytes(
    hash: *std.crypto.hash.sha2.Sha256,
    bytes: []const u8,
) void {
    hashInt(hash, u64, bytes.len);
    hash.update(bytes);
}

fn hashWords(
    hash: *std.crypto.hash.sha2.Sha256,
    words: []const u32,
) void {
    hashInt(hash, u64, words.len);
    for (words) |word| hashInt(hash, u32, word);
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

test "SN2 fixed-table plan binds the 21 active components" {
    const allocator = std.testing.allocator;
    var components = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer components.deinit();
    var fixed = try fixed_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_fixed_tables.bin",
    );
    defer fixed.deinit();

    var plan = try compile(allocator, components, fixed);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 21), plan.entries.len);
    try std.testing.expect(!std.mem.allEqual(u8, &plan.identity, 0));
    for (plan.entries, 0..) |entry, index| {
        try std.testing.expect(entry.component_index <
            components.components.len);
        try std.testing.expect(entry.fixed_ordinal < fixed.entries.len);
        try std.testing.expect(entry.row_count >= 16);
        try std.testing.expect(std.math.isPowerOfTwo(entry.row_count));
        try std.testing.expect(entry.trace_output_count > 0);
        try std.testing.expect(entry.lookup_output_count > 0);
        if (index != 0) {
            try std.testing.expect(
                plan.entries[index - 1].component_index <
                    entry.component_index,
            );
        }
        try std.testing.expectEqual(
            entry,
            plan.find(entry.name, entry.instance).?,
        );
    }
}

test "fixed-table identity detects descriptor drift" {
    const allocator = std.testing.allocator;
    var components = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer components.deinit();
    var fixed = try fixed_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_fixed_tables.bin",
    );
    defer fixed.deinit();

    const component = for (components.components) |candidate| {
        if (findWithOrdinal(fixed, candidate.label) != null)
            break candidate;
    } else return error.MissingFixedTable;
    const located = findWithOrdinal(fixed, component.label).?;
    const before = entryIdentity(
        fixed.graph_hash,
        component,
        located.ordinal,
        located.entry,
    );
    located.entry.lookup_descriptors[0] ^= 1;
    defer located.entry.lookup_descriptors[0] ^= 1;
    const after = entryIdentity(
        fixed.graph_hash,
        component,
        located.ordinal,
        located.entry,
    );
    try std.testing.expect(!std.mem.eql(u8, &before, &after));
}
