//! Allocation-stable owner for temporal-parent universal roster row 35.
//!
//! The authority is borrowed exclusively from the authenticated statement
//! snapshot which also produced rows 10 and 11.  Cold construction allocates
//! one bounded inversion slab; all three tree writers and component admission
//! are allocation-free and reject before their first store.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const prefix_runtime = @import("recursive_temporal_parent_prefix_runtime.zig");
const manifest_mod = @import("recursive_temporal_parent_manifest_v3.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const range_bridge = recursion.air.range_check_8_8_bridge;
const lookup_interaction = frontend.air.lookups.tables.interaction;
const shared_provider = recursion.air.universal_shared_provider;
const universal = recursion.air.universal_challenges;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const ROW: usize = 35;
pub const LOG_SIZE: u32 = range_bridge.LOG_SIZE;
pub const TRACE_SIZE: usize = range_bridge.TABLE_SIZE;
pub const SCRATCH_ITEMS: usize = 2 * lookup_interaction.CHUNK_ROWS;
pub const HOT_HEAP_ALLOCATIONS: usize = 0;
pub const COLD_HEAP_ALLOCATIONS: usize = 1;
pub const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-parent-row35-owner/v1\x00";
pub const GENERATED_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-parent-row35-generated/v1\x00";

pub const Adapter = shared_provider.RangeCheck8x8AdapterForManifest(
    manifest_mod,
);

pub const Error = error{
    AliasedDestination,
    DestinationNotFresh,
    GeneratedIdentityMismatch,
    InvalidOwner,
    InvalidTraceShape,
};

pub const GeneratedV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    owner_identity: [32]u8,
    relation_registry_sha_id: [32]u8,
    provider_relations_sha_id: [32]u8,
    provider_snapshot_sha_id: [32]u8,
    claim: QM31,
    identity: [32]u8,

    pub fn validateAgainst(
        self: *const GeneratedV1,
        owner: *OwnerV1,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        try owner.validate();
        try relations.validate();
        try provider_relations.validateAgainst(relations);
        const provider_id = try provider_relations.identityDigest();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0) or
            !canonical(self.claim) or
            !std.mem.eql(u8, &self.owner_identity, &owner.identity) or
            !std.mem.eql(
                u8,
                &self.relation_registry_sha_id,
                &relations.registry_order_digest,
            ) or !std.mem.eql(
            u8,
            &self.provider_relations_sha_id,
            &provider_id,
        ) or !std.mem.eql(
            u8,
            &self.provider_snapshot_sha_id,
            &owner.authority.provider_snapshot_sha_id,
        ) or !std.mem.eql(u8, &self.identity, &generatedIdentity(self))) {
            return error.GeneratedIdentityMismatch;
        }
    }
};

pub const OwnerV1 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    prefix: *prefix_runtime.OwnerV1,
    authority: prefix_runtime.Row35AuthorityV1,
    scratch: []QM31,
    identity: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        prefix: *prefix_runtime.OwnerV1,
    ) !OwnerV1 {
        const authority = try prefix.row35Authority();
        const scratch = try allocator.alloc(QM31, SCRATCH_ITEMS);
        errdefer allocator.free(scratch);
        @memset(scratch, QM31.zero());
        var result = OwnerV1{
            .allocator = allocator,
            .prefix = prefix,
            .authority = authority,
            .scratch = scratch,
            .identity = undefined,
        };
        result.identity = ownerIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn deinit(self: *OwnerV1) void {
        self.allocator.free(self.scratch);
        self.* = undefined;
    }

    pub fn validate(self: *OwnerV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0) or
            self.scratch.len != SCRATCH_ITEMS or
            !std.mem.eql(u8, &self.identity, &ownerIdentity(self)))
        {
            return error.InvalidOwner;
        }
        try self.authority.validateAgainst(self.prefix);
    }

    pub fn fillPreprocessedInto(
        self: *OwnerV1,
        columns: *[range_bridge.FRAMEWORK_PREPROCESSED_COLUMN_COUNT][]M31,
    ) !void {
        try self.validate();
        try preflightFreshM31Columns(columns, TRACE_SIZE);
        errdefer clearM31Columns(columns);
        var tuples = [range_bridge.PREPROCESSED_COLUMN_COUNT][]M31{
            columns[1],
            columns[2],
        };
        try self.authority.executor.generatePreprocessedInto(
            self.authority.provider,
            &tuples,
        );
        columns[0][0] = M31.one();
    }

    pub fn fillMainInto(
        self: *OwnerV1,
        columns: *[range_bridge.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    ) !void {
        try self.validate();
        try preflightFreshM31Columns(columns, TRACE_SIZE);
        errdefer clearM31Columns(columns);
        try self.authority.executor.generateMainInto(
            self.authority.provider,
            columns,
        );
    }

    pub fn fillInteractionInto(
        self: *OwnerV1,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
        columns: *[lookup_interaction.N_COLUMNS][]M31,
    ) !GeneratedV1 {
        try self.validate();
        try relations.validate();
        try provider_relations.validateAgainst(relations);
        try preflightFreshM31Columns(columns, TRACE_SIZE);
        errdefer clearM31Columns(columns);
        const denominator_scratch =
            self.scratch[0..lookup_interaction.CHUNK_ROWS];
        const inverse_scratch =
            self.scratch[lookup_interaction.CHUNK_ROWS..];
        const claim = try self.authority.provider
            .generateNativeInteractionInto(
            &provider_relations.native,
            columns,
            denominator_scratch,
            inverse_scratch,
        );
        var result = GeneratedV1{
            .owner_identity = self.identity,
            .relation_registry_sha_id = relations.registry_order_digest,
            .provider_relations_sha_id = try provider_relations.identityDigest(),
            .provider_snapshot_sha_id = self.authority.provider_snapshot_sha_id,
            .claim = claim,
            .identity = undefined,
        };
        result.identity = generatedIdentity(&result);
        try result.validateAgainst(self, relations, provider_relations);
        try validateCommittedClaim(columns, claim);
        return result;
    }

    pub fn validateCommittedInteraction(
        self: *OwnerV1,
        generated: *const GeneratedV1,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
        columns: *const [lookup_interaction.N_COLUMNS][]M31,
    ) !void {
        try generated.validateAgainst(self, relations, provider_relations);
        try preflightM31Columns(columns, TRACE_SIZE);
        try validateCommittedClaim(columns, generated.claim);
    }

    pub fn initComponent(
        self: *OwnerV1,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
        generated: *const GeneratedV1,
    ) !Adapter {
        try generated.validateAgainst(self, relations, provider_relations);
        return Adapter.init(
            self.authority.definition,
            self.authority.executor,
            manifest,
            provider_relations,
            relations,
            generated.claim,
        );
    }
};

fn validateCommittedClaim(
    columns: *const [lookup_interaction.N_COLUMNS][]M31,
    claim: QM31,
) !void {
    const last = range_bridge.committedRow(TRACE_SIZE - 1);
    const actual = QM31.fromM31(
        columns[0][last],
        columns[1][last],
        columns[2][last],
        columns[3][last],
    );
    if (!actual.eql(claim)) return error.GeneratedIdentityMismatch;
}

fn preflightFreshM31Columns(columns: anytype, len: usize) !void {
    try preflightM31Columns(columns, len);
    for (columns) |column| for (column) |value|
        if (!value.isZero()) return error.DestinationNotFresh;
}

fn preflightM31Columns(columns: anytype, len: usize) !void {
    var starts: [8]usize = undefined;
    var ends: [8]usize = undefined;
    if (columns.len > starts.len) return error.InvalidTraceShape;
    for (columns, 0..) |column, index| {
        if (column.len != len) return error.InvalidTraceShape;
        starts[index] = @intFromPtr(column.ptr);
        const bytes = std.math.mul(usize, column.len, @sizeOf(M31)) catch
            return error.InvalidTraceShape;
        ends[index] = std.math.add(usize, starts[index], bytes) catch
            return error.InvalidTraceShape;
        for (0..index) |previous| if (starts[index] < ends[previous] and starts[previous] < ends[index]) return error.AliasedDestination;
    }
}

fn clearM31Columns(columns: anytype) void {
    for (columns) |column| @memset(column, M31.zero());
}

fn ownerIdentity(value: *const OwnerV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.padding);
    hash.update(&value.authority.identity);
    hashInt(&hash, usize, value.scratch.len);
    return hash.finalResult();
}

fn generatedIdentity(value: *const GeneratedV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(GENERATED_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.padding);
    hash.update(&value.owner_identity);
    hash.update(&value.relation_registry_sha_id);
    hash.update(&value.provider_relations_sha_id);
    hash.update(&value.provider_snapshot_sha_id);
    for (value.claim.toM31Array()) |word| hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

fn canonical(value: QM31) bool {
    for (value.toM31Array()) |word|
        if (word.toU32() >= stwo_core.fields.m31.Modulus) return false;
    return true;
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

comptime {
    if (ROW != 35 or LOG_SIZE != 16 or TRACE_SIZE != 1 << LOG_SIZE or
        SCRATCH_ITEMS != 2 * lookup_interaction.CHUNK_ROWS or
        COLD_HEAP_ALLOCATIONS != 1 or HOT_HEAP_ALLOCATIONS != 0)
    {
        @compileError("temporal row-35 owner contract drifted");
    }
}

test "temporal row-35 owner exposes an allocation-free hot contract" {
    std.testing.refAllDeclsRecursive(OwnerV1);
    std.testing.refAllDeclsRecursive(GeneratedV1);
    try std.testing.expectEqual(@as(usize, 1), COLD_HEAP_ALLOCATIONS);
    try std.testing.expectEqual(@as(usize, 0), HOT_HEAP_ALLOCATIONS);
    try std.testing.expectEqual(@as(usize, 35), ROW);
    try std.testing.expectEqual(@as(u32, 16), LOG_SIZE);
}
