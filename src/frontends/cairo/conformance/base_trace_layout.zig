//! Canonical Rust-order layout for recorded Cairo base-trace programs.
//!
//! The claim registry is generated from the pinned Rust `CairoClaim` field
//! order. A witness bundle may store programs in any order; this module joins
//! those programs to resolved claim geometry and emits their committed order.

const std = @import("std");
const claim_generator = @import("../claim_generator.zig");
const claim_registry = @import("../air/official_claim_registry.zig");
const witness_bundle = @import("../witness/bundle.zig");

pub const Error = error{
    DuplicateBundleEntry,
    DuplicateGeometry,
    IncompleteGeometry,
    InvalidComponentInstance,
    MissingGeometry,
    NonCanonicalInstancePrefix,
    UnknownComponent,
    InvalidColumnCount,
    ColumnCountOverflow,
};

/// One recorded program projected into the pinned Rust base-trace order.
/// `ordinal` counts every active resolved Cairo claim component, including
/// native or fixed components absent from the witness bundle. Width offsets
/// count only the recorded-program projection because unrecorded widths are not
/// represented by `Bundle`. `bundle_entry_index` remains the program authority;
/// several `memory_id_to_big` instances may intentionally share it.
pub const Component = struct {
    ordinal: u32,
    enable_slot: u8,
    claim_field_index: u8,
    instance: u8,
    bundle_entry_index: u32,
    /// Rust checkpoint label. Memory instances use `memory_id_to_big[index]`.
    label: []const u8,
    /// Base witness-program name used for bundle lookup.
    name: []const u8,
    log_size: u32,
    projected_first_column: u64,
    column_count: u32,
};

pub const Layout = struct {
    allocator: std.mem.Allocator,
    components: []Component,
    active_component_count: u32,
    projected_total_columns: u64,

    pub fn deinit(self: *Layout) void {
        self.allocator.free(self.components);
        self.* = undefined;
    }

    pub fn find(self: Layout, name: []const u8, instance: u8) ?*const Component {
        for (self.components) |*component| {
            if (component.instance == instance and std.mem.eql(u8, component.name, name))
                return component;
        }
        return null;
    }
};

/// Maps every recorded witness program to resolved active claim geometry.
///
/// Claim components without a recorded program are valid: native and fixed
/// writers own those traces. The reverse is not valid. A bundle program that
/// lacks active geometry would otherwise silently commit the wrong trace.
pub fn fromBundle(
    allocator: std.mem.Allocator,
    bundle: *const witness_bundle.Bundle,
    geometry: []const claim_generator.ComponentGeometry,
) (Error || std.mem.Allocator.Error)!Layout {
    var geometry_by_slot = [_]?claim_generator.ComponentGeometry{null} ** claim_registry.enable_slot_count;
    var bundle_by_field = [_]?u32{null} ** claim_registry.claim_field_count;

    for (geometry) |component| {
        const field = findField(component.name) orelse return Error.UnknownComponent;
        if (component.instance >= field.enable_slot_count) return Error.InvalidComponentInstance;
        const slot: usize = @as(usize, field.first_enable_slot) + component.instance;
        if (geometry_by_slot[slot] != null) return Error.DuplicateGeometry;
        switch (component.log_size) {
            .known => {},
            .deferred => return Error.IncompleteGeometry,
        }
        geometry_by_slot[slot] = component;
    }
    try validateInstancePrefixes(&geometry_by_slot);

    for (bundle.entries, 0..) |entry, entry_index| {
        const field = findField(entry.label) orelse return Error.UnknownComponent;
        if (bundle_by_field[field.field_index] != null) return Error.DuplicateBundleEntry;
        bundle_by_field[field.field_index] = std.math.cast(u32, entry_index) orelse
            return Error.ColumnCountOverflow;
    }

    var components = std.ArrayList(Component).empty;
    errdefer components.deinit(allocator);
    var projected_total_columns: u64 = 0;
    var active_ordinal: u32 = 0;
    var mapped_fields = [_]bool{false} ** claim_registry.claim_field_count;
    for (claim_registry.enable_slots) |slot| {
        const component_geometry = geometry_by_slot[slot.enable_slot] orelse continue;
        if (bundle_by_field[slot.claim_field_index]) |entry_index| {
            const entry = bundle.entries[entry_index];
            const column_count = entry.program.n_cols;
            if (column_count == 0) return Error.InvalidColumnCount;
            projected_total_columns = std.math.add(u64, projected_total_columns, column_count) catch
                return Error.ColumnCountOverflow;
            const log_size = switch (component_geometry.log_size) {
                .known => |value| value,
                .deferred => unreachable,
            };
            try components.append(allocator, .{
                .ordinal = active_ordinal,
                .enable_slot = slot.enable_slot,
                .claim_field_index = slot.claim_field_index,
                .instance = slot.field_slot_index,
                .bundle_entry_index = entry_index,
                .label = slot.name,
                .name = entry.label,
                .log_size = log_size,
                .projected_first_column = projected_total_columns - column_count,
                .column_count = column_count,
            });
            mapped_fields[slot.claim_field_index] = true;
        }
        active_ordinal += 1;
    }
    for (bundle_by_field, mapped_fields) |entry_index, mapped| {
        if (entry_index != null and !mapped) return Error.MissingGeometry;
    }

    return .{
        .allocator = allocator,
        .components = try components.toOwnedSlice(allocator),
        .active_component_count = active_ordinal,
        .projected_total_columns = projected_total_columns,
    };
}

fn findField(name: []const u8) ?claim_registry.ClaimField {
    for (claim_registry.claim_fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field;
    }
    return null;
}

fn validateInstancePrefixes(
    geometry_by_slot: *const [claim_registry.enable_slot_count]?claim_generator.ComponentGeometry,
) Error!void {
    for (claim_registry.claim_fields) |field| {
        if (field.enable_slot_count == 1) continue;
        var missing_seen = false;
        for (0..field.enable_slot_count) |instance| {
            const slot = @as(usize, field.first_enable_slot) + instance;
            if (geometry_by_slot[slot] == null) {
                missing_seen = true;
            } else if (missing_seen) {
                return Error.NonCanonicalInstancePrefix;
            }
        }
    }
}

fn testEntry(label: []u8, columns: u32) witness_bundle.Entry {
    return .{
        .label = label,
        .semantic_hash = 1,
        .program = .{
            .insts = &.{},
            .n_regs = 1,
            .n_inputs = 0,
            .n_cols = columns,
            .n_mult_tables = 0,
            .n_lookup_words = 0,
            .n_sub_words = 0,
        },
    };
}

test "Cairo base trace layout: bundle order projects to pinned Rust order" {
    var entries = [_]witness_bundle.Entry{
        testEntry(@constCast("ret_opcode"), 16),
        testEntry(@constCast("add_ap_opcode"), 17),
        testEntry(@constCast("add_opcode"), 103),
    };
    const bundle = witness_bundle.Bundle{ .allocator = std.testing.allocator, .entries = &entries };
    const geometry = [_]claim_generator.ComponentGeometry{
        .{ .name = "ret_opcode", .log_size = .{ .known = 9 } },
        .{ .name = "range_check_6", .log_size = .{ .known = 6 } },
        .{ .name = "add_opcode", .log_size = .{ .known = 12 } },
        .{ .name = "add_ap_opcode", .log_size = .{ .known = 10 } },
    };

    var layout = try fromBundle(std.testing.allocator, &bundle, &geometry);
    defer layout.deinit();
    try std.testing.expectEqual(@as(usize, 3), layout.components.len);
    try std.testing.expectEqualStrings("add_opcode", layout.components[0].name);
    try std.testing.expectEqualStrings("add_ap_opcode", layout.components[1].name);
    try std.testing.expectEqualStrings("ret_opcode", layout.components[2].name);
    try std.testing.expectEqual(@as(u64, 120), layout.components[2].projected_first_column);
    try std.testing.expectEqual(@as(u32, 4), layout.active_component_count);
    try std.testing.expectEqual(@as(u64, 136), layout.projected_total_columns);
    try std.testing.expectEqual(@as(u32, 12), layout.find("add_opcode", 0).?.log_size);
}

test "Cairo base trace layout: memory big instances share one program in prefix order" {
    var entries = [_]witness_bundle.Entry{testEntry(@constCast("memory_id_to_big"), 29)};
    const bundle = witness_bundle.Bundle{ .allocator = std.testing.allocator, .entries = &entries };
    const geometry = [_]claim_generator.ComponentGeometry{
        .{ .name = "memory_id_to_big", .instance = 0, .log_size = .{ .known = 25 } },
        .{ .name = "memory_id_to_big", .instance = 1, .log_size = .{ .known = 24 } },
        .{ .name = "memory_id_to_big", .instance = 2, .log_size = .{ .known = 21 } },
    };

    var layout = try fromBundle(std.testing.allocator, &bundle, &geometry);
    defer layout.deinit();
    try std.testing.expectEqual(@as(usize, 3), layout.components.len);
    try std.testing.expectEqual(@as(u8, 2), layout.components[2].instance);
    try std.testing.expectEqual(@as(u32, 0), layout.components[2].bundle_entry_index);
    try std.testing.expectEqualStrings("memory_id_to_big[2]", layout.components[2].label);
    try std.testing.expectEqualStrings("memory_id_to_big", layout.components[2].name);
    try std.testing.expectEqual(@as(u64, 58), layout.components[2].projected_first_column);
    try std.testing.expectEqual(@as(u64, 87), layout.projected_total_columns);
}

test "Cairo base trace layout: Rust ordinal includes preceding unrecorded components" {
    var entries = [_]witness_bundle.Entry{testEntry(@constCast("ret_opcode"), 16)};
    const bundle = witness_bundle.Bundle{ .allocator = std.testing.allocator, .entries = &entries };
    const geometry = [_]claim_generator.ComponentGeometry{
        .{ .name = "add_opcode", .log_size = .{ .known = 12 } },
        .{ .name = "ret_opcode", .log_size = .{ .known = 9 } },
    };

    var layout = try fromBundle(std.testing.allocator, &bundle, &geometry);
    defer layout.deinit();
    try std.testing.expectEqual(@as(usize, 1), layout.components.len);
    try std.testing.expectEqual(@as(u32, 2), layout.active_component_count);
    try std.testing.expectEqual(@as(u32, 1), layout.components[0].ordinal);
    try std.testing.expectEqual(@as(u64, 0), layout.components[0].projected_first_column);
    try std.testing.expectEqual(@as(u64, 16), layout.projected_total_columns);
}

test "Cairo base trace layout: recorded SN2 programs have complete registry geometry" {
    var bundle = try witness_bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    );
    defer bundle.deinit();
    const geometry = try std.testing.allocator.alloc(
        claim_generator.ComponentGeometry,
        bundle.entries.len,
    );
    defer std.testing.allocator.free(geometry);
    for (bundle.entries, geometry) |entry, *component| {
        component.* = .{ .name = entry.label, .log_size = .{ .known = 4 } };
    }

    var layout = try fromBundle(std.testing.allocator, &bundle, geometry);
    defer layout.deinit();
    try std.testing.expectEqual(@as(usize, 33), layout.components.len);
    try std.testing.expectEqual(@as(u64, 3_054), layout.projected_total_columns);
    try std.testing.expectEqualStrings("add_opcode", layout.components[0].name);
    try std.testing.expectEqualStrings(
        "range_check_252_width_27",
        layout.components[layout.components.len - 1].name,
    );
    for (layout.components[1..], layout.components[0 .. layout.components.len - 1]) |current, previous| {
        try std.testing.expect(current.enable_slot > previous.enable_slot);
    }
}

test "Cairo base trace layout: malformed authority fails closed" {
    var duplicate_entries = [_]witness_bundle.Entry{
        testEntry(@constCast("ret_opcode"), 16),
        testEntry(@constCast("ret_opcode"), 16),
    };
    const duplicate_bundle = witness_bundle.Bundle{
        .allocator = std.testing.allocator,
        .entries = &duplicate_entries,
    };
    const ret_geometry = [_]claim_generator.ComponentGeometry{
        .{ .name = "ret_opcode", .log_size = .{ .known = 8 } },
    };
    try std.testing.expectError(
        Error.DuplicateBundleEntry,
        fromBundle(std.testing.allocator, &duplicate_bundle, &ret_geometry),
    );

    var unknown_entries = [_]witness_bundle.Entry{testEntry(@constCast("not_cairo"), 1)};
    const unknown_bundle = witness_bundle.Bundle{ .allocator = std.testing.allocator, .entries = &unknown_entries };
    try std.testing.expectError(
        Error.UnknownComponent,
        fromBundle(std.testing.allocator, &unknown_bundle, &ret_geometry),
    );

    var ret_entries = [_]witness_bundle.Entry{testEntry(@constCast("ret_opcode"), 16)};
    const ret_bundle = witness_bundle.Bundle{ .allocator = std.testing.allocator, .entries = &ret_entries };
    try std.testing.expectError(
        Error.MissingGeometry,
        fromBundle(std.testing.allocator, &ret_bundle, &.{}),
    );
    const duplicate_geometry = [_]claim_generator.ComponentGeometry{
        .{ .name = "ret_opcode", .log_size = .{ .known = 8 } },
        .{ .name = "ret_opcode", .log_size = .{ .known = 8 } },
    };
    try std.testing.expectError(
        Error.DuplicateGeometry,
        fromBundle(std.testing.allocator, &ret_bundle, &duplicate_geometry),
    );
    const deferred_geometry = [_]claim_generator.ComponentGeometry{
        .{ .name = "ret_opcode", .log_size = .{ .deferred = .witness_feed_cardinality } },
    };
    try std.testing.expectError(
        Error.IncompleteGeometry,
        fromBundle(std.testing.allocator, &ret_bundle, &deferred_geometry),
    );
}

test "Cairo base trace layout: memory big geometry must be a prefix" {
    var entries = [_]witness_bundle.Entry{testEntry(@constCast("memory_id_to_big"), 29)};
    const bundle = witness_bundle.Bundle{ .allocator = std.testing.allocator, .entries = &entries };
    const geometry = [_]claim_generator.ComponentGeometry{
        .{ .name = "memory_id_to_big", .instance = 1, .log_size = .{ .known = 24 } },
    };
    try std.testing.expectError(
        Error.NonCanonicalInstancePrefix,
        fromBundle(std.testing.allocator, &bundle, &geometry),
    );
}
