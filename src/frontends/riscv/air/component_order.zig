//! Canonical component order for the Sail-authoritative proof schema.
//!
//! The legacy sixteen-family block retains its order. New locally specified
//! families are appended before infrastructure so every proving phase shares
//! one explicit main/interaction/claim placement.

const std = @import("std");
const opcode_manifest = @import("../opcode_manifest.zig");
const composition_manifest = @import("lang/opcode_composition_manifest.zig");
const table_schema = @import("lookups/tables/schema.zig");
const transcript_claims = @import("transcript/claims.zig");

pub const OpcodeFamily = opcode_manifest.Family;
pub const TableKind = table_schema.Kind;
pub const TranscriptComponent = transcript_claims.Component;

pub const OPCODE_FAMILY_COUNT: usize = composition_manifest.FAMILY_COUNT;
pub const LOOKUP_TABLE_COUNT: usize = 6;
pub const LOOKUP_TABLE_COMPONENT_START: usize = 22;
pub const TRANSCRIPT_COMPONENT_COUNT: usize = 28;

pub const OPCODE_FAMILIES: [OPCODE_FAMILY_COUNT]OpcodeFamily =
    composition_manifest.TRANSCRIPT_ORDER;

pub const LOOKUP_TABLES = [LOOKUP_TABLE_COUNT]TableKind{
    .bitwise,
    .range_check_20,
    .range_check_8_11,
    .range_check_8_8_4,
    .range_check_8_8,
    .range_check_m31,
};

pub fn opcodeFamilies() []const OpcodeFamily {
    return &OPCODE_FAMILIES;
}

pub fn lookupTables() []const TableKind {
    return &LOOKUP_TABLES;
}

pub fn opcodeFamilyAt(index: usize) ?OpcodeFamily {
    return if (index < OPCODE_FAMILIES.len) OPCODE_FAMILIES[index] else null;
}

pub fn lookupTableAt(index: usize) ?TableKind {
    return if (index < LOOKUP_TABLES.len) LOOKUP_TABLES[index] else null;
}

pub fn opcodeFamilyIndex(family: OpcodeFamily) usize {
    return composition_manifest.compositionIndex(family);
}

pub fn lookupTableIndex(kind: TableKind) usize {
    return switch (kind) {
        .bitwise => 0,
        .range_check_20 => 1,
        .range_check_8_11 => 2,
        .range_check_8_8_4 => 3,
        .range_check_8_8 => 4,
        .range_check_m31 => 5,
    };
}

pub fn transcriptComponentForOpcodeFamily(family: OpcodeFamily) TranscriptComponent {
    return composition_manifest.transcriptComponent(family);
}

pub fn transcriptComponentForLookupTable(kind: TableKind) TranscriptComponent {
    return switch (kind) {
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
    };
}

comptime {
    const transcript_fields = @typeInfo(TranscriptComponent).@"enum".fields;
    if (transcript_fields.len != TRANSCRIPT_COMPONENT_COUNT)
        @compileError("canonical transcript component count drifted from pinned Stark-V");

    const family_fields = @typeInfo(OpcodeFamily).@"enum".fields;
    if (family_fields.len != OPCODE_FAMILIES.len)
        @compileError("canonical opcode order must cover every OpcodeFamily");
    var seen_families = [_]bool{false} ** OPCODE_FAMILIES.len;
    for (OPCODE_FAMILIES, 0..) |family, index| {
        const ordinal = @intFromEnum(family);
        if (ordinal >= seen_families.len or seen_families[ordinal])
            @compileError("canonical opcode order contains a duplicate or invalid family");
        seen_families[ordinal] = true;
        if (opcodeFamilyIndex(family) != index)
            @compileError("canonical opcode index mapping drifted");
        if (@intFromEnum(transcriptComponentForOpcodeFamily(family)) != index)
            @compileError("canonical opcode order drifted from the transcript registry");
    }
    for (seen_families) |seen| {
        if (!seen) @compileError("canonical opcode order omits an OpcodeFamily");
    }

    const table_fields = @typeInfo(TableKind).@"enum".fields;
    if (table_fields.len != LOOKUP_TABLES.len)
        @compileError("canonical table order must cover every lookup table kind");
    const table_component_start = @intFromEnum(TranscriptComponent.bitwise);
    if (table_component_start != LOOKUP_TABLE_COMPONENT_START)
        @compileError("canonical lookup table block moved in the transcript registry");
    var seen_tables = [_]bool{false} ** LOOKUP_TABLES.len;
    for (LOOKUP_TABLES, 0..) |kind, index| {
        const ordinal = @intFromEnum(kind);
        if (ordinal >= seen_tables.len or seen_tables[ordinal])
            @compileError("canonical table order contains a duplicate or invalid kind");
        seen_tables[ordinal] = true;
        if (lookupTableIndex(kind) != index)
            @compileError("canonical table index mapping drifted");
        if (@intFromEnum(transcriptComponentForLookupTable(kind)) != table_component_start + index)
            @compileError("canonical table order drifted from the transcript registry");
    }
    for (seen_tables) |seen| {
        if (!seen) @compileError("canonical table order omits a lookup table kind");
    }
}

test "component order: opcode families match the pinned transcript registry" {
    try std.testing.expectEqual(@as(usize, OPCODE_FAMILY_COUNT), opcodeFamilies().len);
    for (opcodeFamilies(), 0..) |family, index| {
        try std.testing.expectEqual(family, opcodeFamilyAt(index).?);
        try std.testing.expectEqual(index, opcodeFamilyIndex(family));
        try std.testing.expectEqual(
            @as(usize, @intFromEnum(transcriptComponentForOpcodeFamily(family))),
            index,
        );
    }
    try std.testing.expect(opcodeFamilyAt(OPCODE_FAMILY_COUNT) == null);
}

test "component order: lookup tables match the pinned transcript registry" {
    const transcript_start: usize = LOOKUP_TABLE_COMPONENT_START;
    try std.testing.expectEqual(@as(usize, LOOKUP_TABLE_COUNT), lookupTables().len);
    for (lookupTables(), 0..) |kind, index| {
        try std.testing.expectEqual(kind, lookupTableAt(index).?);
        try std.testing.expectEqual(index, lookupTableIndex(kind));
        try std.testing.expectEqual(
            transcript_start + index,
            @as(usize, @intFromEnum(transcriptComponentForLookupTable(kind))),
        );
    }
    try std.testing.expect(lookupTableAt(LOOKUP_TABLE_COUNT) == null);
}
