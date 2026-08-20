//! Single source of truth for the append-only 39-row resumed-segment V2
//! roster.
//!
//! Rows 0--9 reuse the exact transcript AIR programs driven by the V2 source,
//! rows 10--17 come only from their explicit V2 override tables, rows 18--35
//! retain their frozen universal identities, rows 36--37 are the appended
//! boundary AIRs, and row 38 is the committed verifier-input provider.  The
//! catalog is allocation-free and its identity commits to both that authority
//! partition and every proof-geometry field.

const std = @import("std");

const digest = @import("../../air/lang/digest.zig");
const base = @import("universal_adapter_manifest.zig");
const universal_manifest = @import("universal_manifest.zig");
const universal_roster = @import("universal_roster.zig");
const statement_v2 = @import("../segment_statement_outer_source_v2.zig");
const public_air_v2 = @import("segment_public_outer_air_v2.zig");
const row17_air_v2 = @import("vm_public_logup_control_v2.zig");
const row17_witness_v2 = @import("vm_public_logup_control_witness_v2.zig");
const boundary_v2 = @import("../segment_leaf_outer_authority_v2.zig");
const boundary_air_v2 = @import("../segment_leaf_outer_air_v2.zig");
const provider_air_v2 = @import("segment_publication_input_provider_v2.zig");
const provider_authority_v2 =
    @import("../segment_publication_input_provider_authority_v2.zig");

pub const FORMAT_VERSION: u16 = 3;
pub const COMPONENT_COUNT: usize = universal_roster.COMPONENT_COUNT + 3;
pub const UNIVERSAL_COMPONENT_COUNT: usize = universal_roster.COMPONENT_COUNT;
pub const STATEMENT_SOURCE_INDEX: u8 = UNIVERSAL_COMPONENT_COUNT;
pub const PUBLIC_LOGUP_SOURCE_INDEX: u8 = UNIVERSAL_COMPONENT_COUNT + 1;
pub const VERIFIER_INPUT_PROVIDER_INDEX: u8 = UNIVERSAL_COMPONENT_COUNT + 2;
pub const INACTIVE_STATEMENT_LOG_SIZE: u32 = 4;

pub const DOMAIN =
    "stwo-zig/typed-air/recursion-segment-v2-typed-catalog/v1\x00";

/// V2 source custody changes for these rows, even where (row 10) the dormant
/// equation geometry remains equal to V1.  This is an authority mask, not a
/// claim that every underlying SHA digest differs.
pub const V2_AUTHORITY_CHANGED_MASK: u64 = rangeMask(10, 18);
pub const V1_AUTHORITY_UNCHANGED_MASK: u64 =
    rangeMask(0, 10) | rangeMask(18, 36);
pub const APPENDED_SOURCE_MASK: u64 = rangeMask(36, 38);
pub const APPENDED_PROVIDER_MASK: u64 = componentBit(
    VERIFIER_INPUT_PROVIDER_INDEX,
);
pub const ALL_COMPONENT_MASK: u64 = rangeMask(0, COMPONENT_COUNT);

pub const Geometry = base.Geometry;

pub const Error = base.Error || universal_manifest.Error || error{
    CatalogIdentityMismatch,
    CatalogMaskMismatch,
    InvalidCatalogEntry,
    InvalidCatalogGeometry,
};

pub const Origin = enum(u8) {
    transcript_v2 = 1,
    statement_v2 = 2,
    public_v2 = 3,
    universal_v1 = 4,
    boundary_v2 = 5,
    verifier_input_provider_v2 = 6,
};

pub const Activation = enum(u8) {
    stable_active = 0,
    explicitly_inactive = 1,
    active_v2_override = 2,
    appended_boundary_source = 3,
    appended_committed_provider = 4,
};

pub const Entry = struct {
    component_index: u8,
    origin: Origin,
    activation: Activation,
    geometry: Geometry,
};

pub const Catalog = struct {
    format_version: u16 = FORMAT_VERSION,
    component_count: u8 = COMPONENT_COUNT,
    authority_changed_mask: u64 = V2_AUTHORITY_CHANGED_MASK,
    authority_unchanged_mask: u64 = V1_AUTHORITY_UNCHANGED_MASK,
    appended_source_mask: u64 = APPENDED_SOURCE_MASK,
    appended_provider_mask: u64 = APPENDED_PROVIDER_MASK,
    entries: [COMPONENT_COUNT]Entry,
    identity: digest.Digest,

    pub fn validate(self: *const Catalog) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.component_count != COMPONENT_COUNT or
            self.authority_changed_mask != V2_AUTHORITY_CHANGED_MASK or
            self.authority_unchanged_mask != V1_AUTHORITY_UNCHANGED_MASK or
            self.appended_source_mask != APPENDED_SOURCE_MASK or
            self.appended_provider_mask != APPENDED_PROVIDER_MASK or
            self.authority_changed_mask & self.authority_unchanged_mask != 0 or
            self.authority_changed_mask & self.appended_source_mask != 0 or
            self.authority_changed_mask & self.appended_provider_mask != 0 or
            self.authority_unchanged_mask & self.appended_source_mask != 0 or
            self.authority_unchanged_mask & self.appended_provider_mask != 0 or
            self.appended_source_mask & self.appended_provider_mask != 0 or
            self.authority_changed_mask | self.authority_unchanged_mask |
                self.appended_source_mask | self.appended_provider_mask !=
                ALL_COMPONENT_MASK)
        {
            return error.CatalogMaskMismatch;
        }

        var log_sizes: universal_manifest.LogSizes = undefined;
        for (self.entries, 0..) |entry, row| {
            if (entry.component_index != row or
                entry.origin != originFor(@intCast(row)) or
                entry.activation != activationFor(@intCast(row)) or
                entry.geometry.roster_row != row)
            {
                return error.InvalidCatalogEntry;
            }
            try entry.geometry.validateForComponentCount(COMPONENT_COUNT);
            if (row < UNIVERSAL_COMPONENT_COUNT)
                log_sizes[row] = entry.geometry.log_size;
        }

        // The universal builder remains the exact typed-AIR authority only for
        // rows explicitly classified as unchanged. Its V1 rows 10--17 are
        // constructed as inert temporaries and are never admitted or compared.
        const universal = try universal_manifest.build(log_sizes);
        for (0..UNIVERSAL_COMPONENT_COUNT) |row| {
            if ((V1_AUTHORITY_UNCHANGED_MASK & componentBit(row)) != 0 and
                !std.meta.eql(
                    self.entries[row].geometry,
                    universal.placements[row].?.geometry,
                ))
            {
                return error.InvalidCatalogGeometry;
            }
        }

        try validateStatementOverride(&self.entries[10], 0);
        try validateStatementOverride(&self.entries[11], 1);
        inline for (0..5) |index|
            try validatePublicOverride(&self.entries[12 + index], index);
        try validateRow17Override(&self.entries[17]);
        try validateSourceEntry(&self.entries[STATEMENT_SOURCE_INDEX]);
        try validateSourceEntry(&self.entries[PUBLIC_LOGUP_SOURCE_INDEX]);
        try validateProviderEntry(
            &self.entries[VERIFIER_INPUT_PROVIDER_INDEX],
        );

        if (!std.mem.eql(u8, &self.identity, &catalogDigest(self)))
            return error.CatalogIdentityMismatch;
    }
};

/// Build the complete catalog without accepting caller-authored component
/// geometry. The two boundary records must already come from their native V2
/// authority; all remaining rows, including the committed provider at row 38,
/// are projected from typed AIR declarations.
pub fn build(
    log_sizes: universal_manifest.LogSizes,
    boundary_components: [boundary_v2.COMPONENT_COUNT]boundary_v2.ComponentGeometryV2,
) Error!Catalog {
    for (boundary_components) |component|
        component.validate() catch return error.InvalidCatalogGeometry;

    const universal = try universal_manifest.build(log_sizes);
    var entries: [COMPONENT_COUNT]Entry = undefined;

    for (0..10) |row|
        entries[row] = stableEntry(
            @intCast(row),
            .transcript_v2,
            universal.placements[row].?.geometry,
        );

    entries[10] = try overrideEntry(
        statement_v2.COMPONENT_OVERRIDE_TABLE_V2[0],
        log_sizes[10],
        .statement_v2,
        .explicitly_inactive,
    );
    entries[11] = try overrideEntry(
        statement_v2.COMPONENT_OVERRIDE_TABLE_V2[1],
        log_sizes[11],
        .statement_v2,
        .active_v2_override,
    );
    inline for (0..5) |index| {
        entries[12 + index] = try overrideEntry(
            public_air_v2.COMPONENT_OVERRIDE_TABLE_V2[index],
            log_sizes[12 + index],
            .public_v2,
            .active_v2_override,
        );
    }
    entries[17] = try row17Entry(log_sizes[17]);
    for (18..UNIVERSAL_COMPONENT_COUNT) |row|
        entries[row] = stableEntry(
            @intCast(row),
            .universal_v1,
            universal.placements[row].?.geometry,
        );

    entries[STATEMENT_SOURCE_INDEX] = try boundaryEntry(
        STATEMENT_SOURCE_INDEX,
        boundary_components[0],
    );
    entries[PUBLIC_LOGUP_SOURCE_INDEX] = try boundaryEntry(
        PUBLIC_LOGUP_SOURCE_INDEX,
        boundary_components[1],
    );
    entries[VERIFIER_INPUT_PROVIDER_INDEX] = try providerEntry();

    var result = Catalog{
        .entries = entries,
        .identity = undefined,
    };
    result.identity = catalogDigest(&result);
    try result.validate();
    return result;
}

/// Reconstruct and validate the catalog committed by a compact manifest.
/// Classification is protocol-fixed; callers provide no origins or activation
/// flags that could weaken an admission decision.
pub fn validateGeometries(
    geometries: [COMPONENT_COUNT]Geometry,
    identity: digest.Digest,
) Error!void {
    var entries: [COMPONENT_COUNT]Entry = undefined;
    for (&entries, geometries, 0..) |*entry, geometry, row| {
        entry.* = .{
            .component_index = @intCast(row),
            .origin = originFor(@intCast(row)),
            .activation = activationFor(@intCast(row)),
            .geometry = geometry,
        };
    }
    const candidate = Catalog{
        .entries = entries,
        .identity = identity,
    };
    try candidate.validate();
}

fn stableEntry(row: u8, origin: Origin, geometry: Geometry) Entry {
    return .{
        .component_index = row,
        .origin = origin,
        .activation = .stable_active,
        .geometry = geometry,
    };
}

fn overrideEntry(
    item: anytype,
    log_size: u32,
    origin: Origin,
    activation: Activation,
) Error!Entry {
    if (@intFromEnum(item.activation) != sourceActivationValue(activation) or
        item.relation_events == 0 or
        item.interaction_batches != (item.relation_events + 1) / 2)
    {
        return error.InvalidCatalogGeometry;
    }
    const geometry = Geometry{
        .roster_row = item.component_index,
        .log_size = log_size,
        .preprocessed_columns = item.preprocessed_columns,
        .main_columns = item.main_columns,
        .interaction_columns = item.interaction_columns,
        .direct_constraints = item.direct_constraints,
        .interaction_batches = item.interaction_batches,
        .protocol_constraint_degree = item.protocol_constraint_degree,
        .profiled_constraint_degree = item.profiled_constraint_degree,
        .semantic_digest = item.semantic_digest,
    };
    try geometry.validateForComponentCount(COMPONENT_COUNT);
    return .{
        .component_index = item.component_index,
        .origin = origin,
        .activation = activation,
        .geometry = geometry,
    };
}

fn boundaryEntry(
    row: u8,
    source: boundary_v2.ComponentGeometryV2,
) Error!Entry {
    const profiled_degree = switch (row) {
        STATEMENT_SOURCE_INDEX => boundary_air_v2.Statement.MAXIMUM_CONSTRAINT_DEGREE,
        PUBLIC_LOGUP_SOURCE_INDEX => boundary_air_v2.PublicLogUp.MAXIMUM_CONSTRAINT_DEGREE,
        else => return error.InvalidCatalogEntry,
    };
    const geometry = Geometry{
        .roster_row = row,
        .log_size = source.trace_log_size,
        .preprocessed_columns = source.preprocessed_columns,
        .main_columns = source.main_columns,
        .interaction_columns = source.interaction_columns,
        .direct_constraints = source.direct_constraints,
        .interaction_batches = source.interaction_batches,
        .protocol_constraint_degree = source.protocol_constraint_degree,
        .profiled_constraint_degree = @intCast(profiled_degree),
        .semantic_digest = source.semantic_digest,
    };
    try geometry.validateForComponentCount(COMPONENT_COUNT);
    return .{
        .component_index = row,
        .origin = .boundary_v2,
        .activation = .appended_boundary_source,
        .geometry = geometry,
    };
}

fn validateStatementOverride(entry: *const Entry, table_index: usize) Error!void {
    const expected = try overrideEntry(
        statement_v2.COMPONENT_OVERRIDE_TABLE_V2[table_index],
        entry.geometry.log_size,
        .statement_v2,
        entry.activation,
    );
    if (!std.meta.eql(entry.*, expected))
        return error.InvalidCatalogGeometry;
}

fn validatePublicOverride(entry: *const Entry, table_index: usize) Error!void {
    const expected = try overrideEntry(
        public_air_v2.COMPONENT_OVERRIDE_TABLE_V2[table_index],
        entry.geometry.log_size,
        .public_v2,
        .active_v2_override,
    );
    if (!std.meta.eql(entry.*, expected))
        return error.InvalidCatalogGeometry;
}

/// Row 17 is no longer one instance of the generic public relay kernel. Its
/// schedule-consuming V2 AIR owns independent geometry and a distinct seal.
fn row17Entry(log_size: u32) Error!Entry {
    if (log_size != row17_witness_v2.TRACE_LOG_SIZE)
        return error.InvalidCatalogGeometry;
    const geometry = Geometry{
        .roster_row = 17,
        .log_size = log_size,
        .preprocessed_columns = row17_air_v2.PREPROCESSED_COLUMN_COUNT,
        .main_columns = row17_air_v2.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = row17_air_v2.INTERACTION_COLUMN_COUNT,
        .direct_constraints = row17_air_v2.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = row17_air_v2.INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = row17_air_v2.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
        .profiled_constraint_degree = row17_air_v2.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = row17_air_v2.SEMANTIC_DIGEST,
    };
    try geometry.validateForComponentCount(COMPONENT_COUNT);
    return .{
        .component_index = 17,
        .origin = .public_v2,
        .activation = .active_v2_override,
        .geometry = geometry,
    };
}

fn validateRow17Override(entry: *const Entry) Error!void {
    const expected = try row17Entry(entry.geometry.log_size);
    if (!std.meta.eql(entry.*, expected))
        return error.InvalidCatalogGeometry;
}

fn validateSourceEntry(entry: *const Entry) Error!void {
    switch (entry.component_index) {
        STATEMENT_SOURCE_INDEX => {
            try validateSourceAir(boundary_air_v2.Statement, entry.geometry);
            const expected = try overrideEntry(
                statement_v2.COMPONENT_OVERRIDE_TABLE_V2[2],
                entry.geometry.log_size,
                .statement_v2,
                .appended_boundary_source,
            );
            if (!std.meta.eql(expected.geometry, entry.geometry))
                return error.InvalidCatalogGeometry;
        },
        PUBLIC_LOGUP_SOURCE_INDEX => {
            if (entry.geometry.log_size != boundary_v2.PUBLIC_LOGUP_TRACE_LOG_SIZE)
                return error.InvalidCatalogGeometry;
            try validateSourceAir(boundary_air_v2.PublicLogUp, entry.geometry);
        },
        else => return error.InvalidCatalogEntry,
    }
}

fn validateSourceAir(comptime Air: type, geometry: Geometry) Error!void {
    if (geometry.preprocessed_columns != Air.PREPROCESSED_COLUMN_COUNT or
        geometry.main_columns != Air.PHYSICAL_MAIN_COLUMN_COUNT or
        geometry.interaction_columns != Air.INTERACTION_COLUMN_COUNT or
        geometry.direct_constraints != Air.DIRECT_CONSTRAINT_COUNT or
        geometry.interaction_batches != Air.INTERACTION_BATCH_COUNT or
        geometry.protocol_constraint_degree !=
            Air.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE or
        geometry.profiled_constraint_degree != Air.MAXIMUM_CONSTRAINT_DEGREE or
        !std.mem.eql(u8, &geometry.semantic_digest, &Air.SEMANTIC_DIGEST))
    {
        return error.InvalidCatalogGeometry;
    }
}

fn providerEntry() Error!Entry {
    const geometry = Geometry{
        .roster_row = VERIFIER_INPUT_PROVIDER_INDEX,
        .log_size = provider_authority_v2.TRACE_LOG_SIZE,
        .preprocessed_columns = provider_air_v2.PREPROCESSED_COLUMN_COUNT,
        .main_columns = provider_air_v2.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = provider_air_v2.INTERACTION_COLUMN_COUNT,
        .direct_constraints = provider_air_v2.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = provider_air_v2.INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = provider_air_v2.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
        .profiled_constraint_degree = provider_air_v2.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = provider_air_v2.SEMANTIC_DIGEST,
    };
    try geometry.validateForComponentCount(COMPONENT_COUNT);
    return .{
        .component_index = VERIFIER_INPUT_PROVIDER_INDEX,
        .origin = .verifier_input_provider_v2,
        .activation = .appended_committed_provider,
        .geometry = geometry,
    };
}

fn validateProviderEntry(entry: *const Entry) Error!void {
    const expected = try providerEntry();
    if (!std.meta.eql(entry.*, expected))
        return error.InvalidCatalogGeometry;
}

fn originFor(row: u8) Origin {
    return if (row < 10)
        .transcript_v2
    else if (row < 12)
        .statement_v2
    else if (row < 18)
        .public_v2
    else if (row < UNIVERSAL_COMPONENT_COUNT)
        .universal_v1
    else if (row < VERIFIER_INPUT_PROVIDER_INDEX)
        .boundary_v2
    else
        .verifier_input_provider_v2;
}

fn activationFor(row: u8) Activation {
    return if (row == 10)
        .explicitly_inactive
    else if (row >= 11 and row < 18)
        .active_v2_override
    else if (row >= UNIVERSAL_COMPONENT_COUNT and
        row < VERIFIER_INPUT_PROVIDER_INDEX)
        .appended_boundary_source
    else if (row == VERIFIER_INPUT_PROVIDER_INDEX)
        .appended_committed_provider
    else
        .stable_active;
}

fn sourceActivationValue(activation: Activation) u8 {
    return switch (activation) {
        .explicitly_inactive => 0,
        .active_v2_override => 1,
        .appended_boundary_source => 2,
        .appended_committed_provider => 3,
        .stable_active => std.math.maxInt(u8),
    };
}

fn catalogDigest(catalog: *const Catalog) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u16, catalog.format_version);
    hashInt(&hash, u8, catalog.component_count);
    hashInt(&hash, u64, catalog.authority_changed_mask);
    hashInt(&hash, u64, catalog.authority_unchanged_mask);
    hashInt(&hash, u64, catalog.appended_source_mask);
    hashInt(&hash, u64, catalog.appended_provider_mask);
    for (catalog.entries) |entry| {
        hashInt(&hash, u8, entry.component_index);
        hashInt(&hash, u8, @intFromEnum(entry.origin));
        hashInt(&hash, u8, @intFromEnum(entry.activation));
        hashGeometry(&hash, entry.geometry);
    }
    return hash.finalResult();
}

fn hashGeometry(hash: anytype, geometry: Geometry) void {
    hashInt(hash, u8, geometry.roster_row);
    hashInt(hash, u32, geometry.log_size);
    hashInt(hash, u16, geometry.preprocessed_columns);
    hashInt(hash, u16, geometry.main_columns);
    hashInt(hash, u16, geometry.interaction_columns);
    hashInt(hash, u16, geometry.direct_constraints);
    hashInt(hash, u16, geometry.interaction_batches);
    hashInt(hash, u8, geometry.protocol_constraint_degree);
    hashInt(hash, u8, geometry.profiled_constraint_degree);
    hash.update(&geometry.semantic_digest);
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn rangeMask(comptime first: usize, comptime end: usize) u64 {
    comptime {
        if (first > end or end > 64) @compileError("invalid catalog mask range");
    }
    var result: u64 = 0;
    inline for (first..end) |row| result |= componentBit(row);
    return result;
}

fn componentBit(row: anytype) u64 {
    return @as(u64, 1) << @intCast(row);
}

comptime {
    if (COMPONENT_COUNT != 39 or STATEMENT_SOURCE_INDEX != 36 or
        PUBLIC_LOGUP_SOURCE_INDEX != 37 or
        VERIFIER_INPUT_PROVIDER_INDEX != 38 or
        provider_authority_v2.PROPOSED_ROSTER_ROW !=
            VERIFIER_INPUT_PROVIDER_INDEX or
        statement_v2.COMPONENT_OVERRIDE_TABLE_V2.len != 3 or
        statement_v2.COMPONENT_OVERRIDE_TABLE_V2[0].component_index != 10 or
        statement_v2.COMPONENT_OVERRIDE_TABLE_V2[1].component_index != 11 or
        statement_v2.COMPONENT_OVERRIDE_TABLE_V2[2].component_index != 36 or
        public_air_v2.COMPONENT_OVERRIDE_TABLE_V2.len != 6 or
        public_air_v2.COMPONENT_OVERRIDE_TABLE_V2[0].component_index != 12 or
        public_air_v2.COMPONENT_OVERRIDE_TABLE_V2[4].component_index != 16 or
        row17_air_v2.RELATION_EVENT_COUNT != 2 or
        row17_air_v2.INTERACTION_BATCH_COUNT != 1 or
        row17_air_v2.INTERACTION_COLUMN_COUNT != 4 or
        row17_witness_v2.LOGICAL_ROW_COUNT != 71 or
        row17_witness_v2.TRACE_LOG_SIZE != 7 or
        V2_AUTHORITY_CHANGED_MASK | V1_AUTHORITY_UNCHANGED_MASK |
            APPENDED_SOURCE_MASK | APPENDED_PROVIDER_MASK !=
            ALL_COMPONENT_MASK)
    {
        @compileError("segment V2 typed catalog authority partition drifted");
    }
}
