//! Exact memory-table lowering plan derived from Cairo input geometry.

const std = @import("std");
const adapter = @import("stwo_cairo_frontend").adapter;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const memory_tables = @import("stwo_cairo_frontend").witness.memory_tables;

pub const Kind = enum(u8) {
    address_to_id,
    id_to_big,
    id_to_small,
};

pub const Entry = struct {
    component_index: u32,
    name: []const u8,
    instance: u32,
    kind: Kind,
    log_size: u32,
    row_count: u32,
    source_value_offset: u32,
    source_value_count: u32,
    source_words_per_value: u32,
    limb_count: u32,
    output_column_count: u32,
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
};

pub fn compile(
    allocator: std.mem.Allocator,
    components: composition.Bundle,
    input: *const adapter.ProverInput,
) !Plan {
    const expected_count = std.math.add(
        usize,
        try memory_tables.bigComponentCount(input),
        2,
    ) catch return error.MemoryGeometryOverflow;
    const entries = try allocator.alloc(Entry, expected_count);
    errdefer allocator.free(entries);

    var count: usize = 0;
    for (components.components, 0..) |component, component_index| {
        const kind = kindFor(component.label) orelse continue;
        if (count >= entries.len) return error.MemoryComponentInventoryMismatch;
        entries[count] = try compileEntry(
            input,
            component,
            @intCast(component_index),
            kind,
        );
        count += 1;
    }
    if (count != entries.len) return error.MemoryComponentInventoryMismatch;
    validateOrder(entries);
    return .{
        .allocator = allocator,
        .entries = entries,
        .identity = planIdentity(entries),
    };
}

fn compileEntry(
    input: *const adapter.ProverInput,
    component: composition.Component,
    component_index: u32,
    kind: Kind,
) !Entry {
    const row_count: usize = @as(usize, 1) << @intCast(
        component.trace_log_size,
    );
    const geometry = switch (kind) {
        .address_to_id => Geometry{
            .expected_rows = try memory_tables.addressRowCount(input),
            .source_value_offset = 1,
            .source_value_count = input.memory.address_to_id.len -| 1,
            .source_words_per_value = 1,
            .limb_count = 0,
            .output_column_count = memory_tables.address_column_count,
        },
        .id_to_big => blk: {
            const expected_rows = try memory_tables.bigRowCount(
                input,
                component.instance,
            );
            const offset = std.math.mul(
                usize,
                component.instance,
                memory_tables.max_big_rows,
            ) catch return error.MemoryGeometryOverflow;
            break :blk Geometry{
                .expected_rows = expected_rows,
                .source_value_offset = offset,
                .source_value_count = @min(
                    expected_rows,
                    input.memory.f252_values.len - offset,
                ),
                .source_words_per_value = 8,
                .limb_count = memory_tables.big_limb_count,
                .output_column_count = memory_tables.big_column_count,
            };
        },
        .id_to_small => Geometry{
            .expected_rows = try memory_tables.smallRowCount(input),
            .source_value_offset = 0,
            .source_value_count = input.memory.small_values.len,
            .source_words_per_value = 4,
            .limb_count = memory_tables.small_limb_count,
            .output_column_count = memory_tables.small_column_count,
        },
    };
    if (row_count != geometry.expected_rows or
        component.trace_spans.len == 0 or
        (kind != .id_to_big and component.instance != 0))
    {
        return error.MemoryComponentGeometryMismatch;
    }
    const entry = Entry{
        .component_index = component_index,
        .name = component.label,
        .instance = component.instance,
        .kind = kind,
        .log_size = component.trace_log_size,
        .row_count = try castU32(row_count),
        .source_value_offset = try castU32(geometry.source_value_offset),
        .source_value_count = try castU32(geometry.source_value_count),
        .source_words_per_value = geometry.source_words_per_value,
        .limb_count = geometry.limb_count,
        .output_column_count = geometry.output_column_count,
        .identity = undefined,
    };
    var finalized = entry;
    finalized.identity = recomputeIdentity(finalized);
    return finalized;
}

const Geometry = struct {
    expected_rows: usize,
    source_value_offset: usize,
    source_value_count: usize,
    source_words_per_value: u32,
    limb_count: u32,
    output_column_count: u32,
};

fn kindFor(name: []const u8) ?Kind {
    if (std.mem.eql(u8, name, "memory_address_to_id"))
        return .address_to_id;
    if (std.mem.eql(u8, name, "memory_id_to_big"))
        return .id_to_big;
    if (std.mem.eql(u8, name, "memory_id_to_small"))
        return .id_to_small;
    return null;
}

fn validateOrder(entries: []const Entry) void {
    std.debug.assert(entries.len >= 2);
    for (entries[1..], 1..) |entry, index| {
        std.debug.assert(entries[index - 1].component_index <
            entry.component_index);
    }
}

pub fn recomputeIdentity(entry: Entry) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/memory-entry/v1\x00");
    hashBytes(&hash, entry.name);
    inline for (.{
        entry.component_index,
        entry.instance,
        @intFromEnum(entry.kind),
        entry.log_size,
        entry.row_count,
        entry.source_value_offset,
        entry.source_value_count,
        entry.source_words_per_value,
        entry.limb_count,
        entry.output_column_count,
    }) |value| hashInt(&hash, value);
    return hash.finalResult();
}

fn planIdentity(entries: []const Entry) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/memory-plan/v1\x00");
    hashInt(&hash, tryCastLen(entries.len));
    for (entries) |entry| hash.update(&entry.identity);
    return hash.finalResult();
}

fn hashBytes(
    hash: *std.crypto.hash.sha2.Sha256,
    bytes: []const u8,
) void {
    hashInt(hash, tryCastLen(bytes.len));
    hash.update(bytes);
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    value: anytype,
) void {
    const T = @TypeOf(value);
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

fn castU32(value: usize) !u32 {
    return std.math.cast(u32, value) orelse error.MemoryGeometryOverflow;
}

fn tryCastLen(value: usize) u64 {
    return std.math.cast(u64, value) orelse unreachable;
}

test "SN2 memory plan binds address, big, and small components exactly" {
    const allocator = std.testing.allocator;
    const path = std.process.getEnvVarOwned(
        allocator,
        "STWO_ZIG_TEST_SN2_ADAPTED_INPUT",
    ) catch return error.SkipZigTest;
    defer allocator.free(path);
    var input = try adapter.adapted_input.readFile(allocator, path);
    defer input.deinit(allocator);
    var components = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer components.deinit();

    var plan = try compile(allocator, components, &input);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 3), plan.entries.len);
    try std.testing.expectEqual(Kind.address_to_id, plan.entries[0].kind);
    try std.testing.expectEqual(Kind.id_to_big, plan.entries[1].kind);
    try std.testing.expectEqual(Kind.id_to_small, plan.entries[2].kind);
    try std.testing.expect(!std.mem.allEqual(u8, &plan.identity, 0));
}
