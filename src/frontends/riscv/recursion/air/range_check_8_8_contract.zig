//! Verifier-owned range (8,8) source geometry, typed relation and binding seals.
//! Native writers and backend export reuse these contracts without owning them.
const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const lookup_layout = @import("../../air/lookups/tables/layout.zig");
const lookup_schema = @import("../../air/lookups/tables/schema_definition.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.range_check_8_8.shared.v1";
pub const TABLE_KIND = lookup_schema.Kind.range_check_8_8;
pub const LOG_SIZE: u32 = 16;
pub const TABLE_SIZE: usize = 1 << LOG_SIZE;
pub const TUPLE_ARITY: usize = 2;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1;
pub const PREPROCESSED_COLUMN_COUNT: usize = TUPLE_ARITY;
pub const FRAMEWORK_PREPROCESSED_COLUMN_COUNT: usize = 1 + TUPLE_ARITY;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 0;
pub const RELATION_EVENT_COUNT: usize = 1;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 4;
pub const FRAMEWORK_CONSTRAINT_COUNT: usize = 1;
pub const MAXIMUM_CONSTRAINT_LOG_DEGREE_BOUND: u32 = LOG_SIZE + 1;
/// Stark-V names the table-side occurrence a consume.  The frozen VM schema
/// predates that distinction and admits the numerically equivalent negative
/// `request` role only.  Keep the source role in the source receipt and bind
/// the typed effect through this explicit, recursion-local ABI adapter.
pub const SOURCE_RELATION_ROLE: relation.Role = .consume;
pub const BASE_ABI_RELATION_ROLE: relation.Role = .request;

pub const STARK_V_REVISION: [40]u8 =
    "59172a201bd01f2f4b699bc2f7d4442d8ee81597".*;
pub const STARK_V_SCHEMA_PATH = "crates/air/src/schema.rs";
pub const STARK_V_TABLE_PATH =
    "crates/air/src/preprocessed/range_check_8_8.rs";
pub const STARK_V_COMPONENT_MACRO_PATH =
    "crates/stwo-macros/src/components.rs";
pub const STARK_V_SCHEMA_SHA256 = hexDigest(
    "63db9536977b3cabe9591e0fb503c5586b99c568df6fe63d7c9a5b45f338300a",
    "invalid pinned Stark-V schema.rs digest",
);
pub const STARK_V_TABLE_SHA256 = hexDigest(
    "e247a338304623b1f3d667b4678a558c988ddcff8e05cb5f3bde6fc99170f933",
    "invalid pinned Stark-V range_check_8_8.rs digest",
);
pub const STARK_V_COMPONENT_MACRO_SHA256 = hexDigest(
    "f4e81780c1d03f3334b2132cd3685bf168aa4fe4c435924614ac3cbfd815a9ef",
    "invalid pinned Stark-V components.rs digest",
);

pub const SOURCE_AUTHORITY_FORMAT_VERSION: u16 = 1;
pub const SOURCE_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursion-range-check-8-8-source/v1\x00";
pub const SOURCE_AUTHORITY_DIGEST_HEX =
    "5cd192e942722048261703f614d86edfa4bb8109726ec50d55ec4c073e1ab596";
pub const SOURCE_AUTHORITY_DIGEST = hexDigest(
    SOURCE_AUTHORITY_DIGEST_HEX,
    "invalid recursion range-check source-authority digest",
);

/// Immutable source receipt for the existing shared primitive.  No source
/// pathname or human-readable label participates at runtime; the file bytes,
/// protocol geometry, relation id/version, and sign convention do.
pub const SourceAuthority = struct {
    format_version: u16,
    revision: [40]u8,
    schema_sha256: digest.Digest,
    table_sha256: digest.Digest,
    component_macro_sha256: digest.Digest,
    kind: lookup_schema.Kind,
    log_size: u32,
    tuple_arity: u8,
    main_columns: u8,
    preprocessed_columns: u8,
    interaction_columns: u8,
    framework_constraints: u8,
    relation_schema: types.RelationSchemaId,
    relation_schema_version: u16,
    relation_role: relation.Role,

    pub fn pinned() SourceAuthority {
        const schema = relation.get(.range_check_8_8);
        return .{
            .format_version = SOURCE_AUTHORITY_FORMAT_VERSION,
            .revision = STARK_V_REVISION,
            .schema_sha256 = STARK_V_SCHEMA_SHA256,
            .table_sha256 = STARK_V_TABLE_SHA256,
            .component_macro_sha256 = STARK_V_COMPONENT_MACRO_SHA256,
            .kind = TABLE_KIND,
            .log_size = LOG_SIZE,
            .tuple_arity = TUPLE_ARITY,
            .main_columns = PHYSICAL_MAIN_COLUMN_COUNT,
            .preprocessed_columns = FRAMEWORK_PREPROCESSED_COLUMN_COUNT,
            .interaction_columns = INTERACTION_COLUMN_COUNT,
            .framework_constraints = FRAMEWORK_CONSTRAINT_COUNT,
            .relation_schema = schema.id,
            .relation_schema_version = schema.version,
            // A typed `consume` applies the same leading minus as the Rust
            // component's `-EF::from(multiplicity)`.
            .relation_role = SOURCE_RELATION_ROLE,
        };
    }

    pub fn validate(self: SourceAuthority) error{AuthorityMismatch}!void {
        if (!std.meta.eql(self, pinned())) return error.AuthorityMismatch;
        const metadata = lookup_layout.ConstructionMetadata.forKind(TABLE_KIND);
        if (lookup_schema.logSize(TABLE_KIND) != LOG_SIZE or
            lookup_schema.size(TABLE_KIND) != TABLE_SIZE or
            lookup_schema.arity(TABLE_KIND) != TUPLE_ARITY or
            metadata.log_size != LOG_SIZE or
            metadata.tuple_columns != TUPLE_ARITY or
            metadata.preprocessed_columns != FRAMEWORK_PREPROCESSED_COLUMN_COUNT or
            metadata.main_columns != PHYSICAL_MAIN_COLUMN_COUNT or
            metadata.interaction_columns != INTERACTION_COLUMN_COUNT or
            metadata.previous_masks != INTERACTION_COLUMN_COUNT or
            metadata.constraints != FRAMEWORK_CONSTRAINT_COUNT)
        {
            return error.AuthorityMismatch;
        }
        const schema = relation.requireExactUniversalSchema(.range_check_8_8) catch
            return error.AuthorityMismatch;
        if (schema.id != self.relation_schema or
            schema.version != self.relation_schema_version or
            schema.fields.len != TUPLE_ARITY or
            !schema.allowed_roles.allows(BASE_ABI_RELATION_ROLE) or
            !rolesHaveSameLogupSign(self.relation_role, BASE_ABI_RELATION_ROLE))
        {
            return error.AuthorityMismatch;
        }
        const actual = self.identityDigest();
        if (!std.mem.eql(u8, &actual, &SOURCE_AUTHORITY_DIGEST))
            return error.AuthorityMismatch;
    }

    pub fn identityDigest(self: SourceAuthority) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(SOURCE_AUTHORITY_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hash.update(&self.revision);
        hashBytes(&hash, STARK_V_SCHEMA_PATH);
        hash.update(&self.schema_sha256);
        hashBytes(&hash, STARK_V_TABLE_PATH);
        hash.update(&self.table_sha256);
        hashBytes(&hash, STARK_V_COMPONENT_MACRO_PATH);
        hash.update(&self.component_macro_sha256);
        hashInt(&hash, u8, @intFromEnum(self.kind));
        hashInt(&hash, u32, self.log_size);
        hashInt(&hash, u8, self.tuple_arity);
        hashInt(&hash, u8, self.main_columns);
        hashInt(&hash, u8, self.preprocessed_columns);
        hashInt(&hash, u8, self.interaction_columns);
        hashInt(&hash, u8, self.framework_constraints);
        hashInt(&hash, u16, @intFromEnum(self.relation_schema));
        hashInt(&hash, u16, self.relation_schema_version);
        hashInt(&hash, u8, @intFromEnum(self.relation_role));
        return hash.finalResult();
    }
};

pub const SEMANTIC_DIGEST_HEX =
    "ec9693fbf2631f2c3d4035106d3f9bf6f1369bc5bccaf60f87114ef561840a58";
pub const SEMANTIC_DIGEST = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion range-check semantic digest",
);

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.range_check_8_8.signed_multiplicity",
};
pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "range_check_8_8_limb_0",
    "range_check_8_8_limb_1",
};

pub const MainColumns = struct {
    signed_multiplicity: types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{self.signed_multiplicity};
    }
};

pub const PreprocessedColumns = struct {
    limbs: [TUPLE_ARITY]types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return self.limbs;
    }
};

pub const DefinitionError = validate_mod.Error || relation_effect.Error || error{
    InvalidRangeCheckDefinition,
};

/// Relation-only typed program for row 35.  The framework recurrence remains
/// owned by the existing shared table component; this program authenticates
/// its exact tuple and signed multiplicity without transcribing that AIR.
pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    events: [RELATION_EVENT_COUNT]types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) DefinitionError!void {
        try validate_mod.validate(&self.arena);
        const actual = try digest.computeIdentity(&self.arena);
        if (actual.format_version != digest.typed_effect_format_version or
            !std.mem.eql(u8, &actual.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or
            self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or
            self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidRangeCheckDefinition;
        }
        try validateInput(
            &self.arena,
            self.main.signed_multiplicity,
            0,
            MAIN_COLUMN_NAMES[0],
            .felt,
        );
        for (self.preprocessed.limbs, PREPROCESSED_COLUMN_NAMES, 0..) |
            value,
            name,
            index,
        | try validateInput(
            &self.arena,
            value,
            PHYSICAL_MAIN_COLUMN_COUNT + index,
            name,
            .byte,
        );
        try validateEvent(self);
    }
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildDefinition(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn identity(allocator: std.mem.Allocator) !digest.Identity {
    var result = try buildDefinition(allocator);
    defer result.deinit();
    return digest.computeIdentity(&result.arena);
}

fn buildDefinition(allocator: std.mem.Allocator) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();
    const main = MainColumns{
        .signed_multiplicity = try arena.input(MAIN_COLUMN_NAMES[0], .felt, span),
    };
    var limbs: [TUPLE_ARITY]types.ValueId = undefined;
    for (&limbs, PREPROCESSED_COLUMN_NAMES) |*value, name|
        value.* = try arena.input(name, .byte, span);
    const preprocessed = PreprocessedColumns{ .limbs = limbs };
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{
            .domain = .range_check_8_8,
            .role = BASE_ABI_RELATION_ROLE,
            .values = &preprocessed.limbs,
            .weight = main.signed_multiplicity,
        },
    }, span);
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .events = events,
    };
}

pub const MainSource = enum(u8) {
    signed_multiplicity = 0,
};
pub const PreprocessedSource = enum(u8) {
    limb_0 = 0,
    limb_1 = 1,
};

pub fn Slot(comptime Source: type) type {
    return struct {
        column: u8,
        value: types.ValueId,
        source: Source,
    };
}

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-range-check-8-8-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "81ef06d735f1b34e56afe46740ba06c611edfce72d96d4bdd8bb35e4f25571ba";
pub const BINDING_DIGEST = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion range-check witness-binding digest",
);

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    semantic_digest: digest.Digest,
    source_authority_digest: digest.Digest,
    main: [PHYSICAL_MAIN_COLUMN_COUNT]Slot(MainSource),
    preprocessed: [PREPROCESSED_COLUMN_COUNT]Slot(PreprocessedSource),
    event: types.EffectId,

    pub fn canonical(definition: *const Definition) !Binding {
        try definition.validate();
        const authority = SourceAuthority.pinned();
        try authority.validate();
        return .{
            .format_version = BINDING_FORMAT_VERSION,
            .semantic_format_version = digest.typed_effect_format_version,
            .semantic_digest = SEMANTIC_DIGEST,
            .source_authority_digest = authority.identityDigest(),
            .main = .{.{
                .column = 0,
                .value = definition.main.signed_multiplicity,
                .source = .signed_multiplicity,
            }},
            .preprocessed = .{
                .{ .column = 0, .value = definition.preprocessed.limbs[0], .source = .limb_0 },
                .{ .column = 1, .value = definition.preprocessed.limbs[1], .source = .limb_1 },
            },
            .event = definition.events[0],
        };
    }

    pub fn identityDigest(self: *const Binding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(BINDING_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        hash.update(&self.semantic_digest);
        hash.update(&self.source_authority_digest);
        for (self.main) |slot| hashSlot(&hash, slot);
        for (self.preprocessed) |slot| hashSlot(&hash, slot);
        hashInt(&hash, u32, @intFromEnum(self.event));
        return hash.finalResult();
    }
};

fn validateInput(
    arena: *const ir.Arena,
    value: types.ValueId,
    index: usize,
    expected_name: []const u8,
    expected_type: types.Type,
) error{InvalidRangeCheckDefinition}!void {
    if (types.idIndex(value) != index) return error.InvalidRangeCheckDefinition;
    const node = arena.node(value) orelse return error.InvalidRangeCheckDefinition;
    if (!std.meta.eql(node.key.ty, expected_type))
        return error.InvalidRangeCheckDefinition;
    const name_id = switch (node.key.op) {
        .input => |name| name,
        else => return error.InvalidRangeCheckDefinition,
    };
    const actual_name = arena.name(name_id) orelse
        return error.InvalidRangeCheckDefinition;
    if (!std.mem.eql(u8, actual_name, expected_name))
        return error.InvalidRangeCheckDefinition;
}

fn validateEvent(
    definition: *const Definition,
) error{InvalidRangeCheckDefinition}!void {
    const effect_id = definition.events[0];
    if (types.idIndex(effect_id) != 0) return error.InvalidRangeCheckDefinition;
    const item = definition.arena.effect(effect_id) orelse
        return error.InvalidRangeCheckDefinition;
    const binding = item.binding orelse return error.InvalidRangeCheckDefinition;
    const schema = relation.get(.range_check_8_8);
    const values = definition.arena.effectValues(effect_id) orelse
        return error.InvalidRangeCheckDefinition;
    if (item.kind != .component_call or
        item.liveness != definition.main.signed_multiplicity or
        item.access_ordinal != null or
        binding.schema != schema.id or
        binding.schema_version != schema.version or
        binding.role != BASE_ABI_RELATION_ROLE or
        !std.mem.eql(types.ValueId, values, &definition.preprocessed.limbs))
    {
        return error.InvalidRangeCheckDefinition;
    }
}

fn rolesHaveSameLogupSign(lhs: relation.Role, rhs: relation.Role) bool {
    const lhs_is_positive = lhs == .emit;
    const rhs_is_positive = rhs == .emit;
    return lhs_is_positive == rhs_is_positive;
}

fn hashSlot(hash: anytype, slot: anytype) void {
    hashInt(hash, u8, slot.column);
    hashInt(hash, u32, @intFromEnum(slot.value));
    hashInt(hash, u8, @intFromEnum(slot.source));
}

fn hashBytes(hash: anytype, value: []const u8) void {
    hashInt(hash, u32, value.len);
    hash.update(value);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
