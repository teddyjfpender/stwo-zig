//! Canonical metadata and claim codec for candidate Ethereum leaf artifacts.

const std = @import("std");

const combined_authority =
    @import("../../isa/ethereum_candidate_combined_authority_v1.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const global_v3 = @import("../../recursion/segment_leaf_local_authority_v3.zig");
const base_types = @import("../types.zig");
const base_wire = @import("proof_artifact_wire.zig");
const ethereum_claim_wire = @import("ethereum_proof_artifact_wire.zig");
const ethereum_segment_wire = @import("ethereum_segment_proof_artifact_wire.zig");
const candidate_integration = @import("ethereum_candidate_leaf_integration_v1.zig");
const candidate_profile = @import("ethereum_candidate_leaf_profile_v1.zig");
const bulk_contract = @import("../../air/guest_precompile/bulk_memcpy_component_v1.zig");
const swap_contract = @import("../../air/guest_precompile/stack_swap_component_v1.zig");

pub const schema_version: u16 = 1;

pub const Metadata = struct {
    ethereum: ethereum_statement.Statement,
    global: global_v3.MetadataV3,
    profile: candidate_profile.Profile,
};

pub fn encodeMetadata(writer: anytype, value: Metadata) !void {
    try base_wire.writeInt(writer, u16, schema_version);
    try base_wire.writeInt(
        writer,
        u32,
        ethereum_segment_wire.extension_encoded_size,
    );
    try ethereum_segment_wire.encodeExtension(writer, .{
        .ethereum = value.ethereum,
        .global = value.global,
    });
    try encodeProfile(writer, value.profile);
}

pub fn decodeMetadata(bytes: []const u8) !Metadata {
    var cursor = base_wire.Cursor.init(bytes);
    if (try cursor.readInt(u16) != schema_version)
        return error.UnsupportedCandidateLeafMetadataVersion;
    if (try cursor.readInt(u32) != ethereum_segment_wire.extension_encoded_size)
        return error.InvalidCandidateLeafExtensionLength;
    const ordinary = try ethereum_segment_wire.decodeExtension(
        try cursor.take(ethereum_segment_wire.extension_encoded_size),
    );
    const profile = try decodeProfile(&cursor);
    try cursor.requireDone();
    return .{
        .ethereum = ordinary.ethereum,
        .global = ordinary.global,
        .profile = profile,
    };
}

pub const OwnedClaims = struct {
    base: *base_types.RiscVInteractionClaim,
    ethereum: @import("ethereum_types.zig").ExtensionClaim,
    candidate: candidate_integration.Claims,

    pub fn deinit(self: *OwnedClaims, allocator: std.mem.Allocator) void {
        allocator.destroy(self.base);
        self.* = undefined;
    }
};

pub fn encodeClaims(
    allocator: std.mem.Allocator,
    writer: anytype,
    projected: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    base: *const base_types.RiscVInteractionClaim,
    ethereum: *const @import("ethereum_types.zig").ExtensionClaim,
    candidate: candidate_integration.Claims,
) !void {
    var ordinary: std.ArrayList(u8) = .empty;
    defer ordinary.deinit(allocator);
    try ethereum_claim_wire.encodeClaim(
        ordinary.writer(allocator),
        &projected.core,
        extension,
        base,
        ethereum,
    );
    if (ordinary.items.len > std.math.maxInt(u32))
        return error.CandidateLeafClaimResourceLimitExceeded;
    try base_wire.writeInt(writer, u16, schema_version);
    try base_wire.writeInt(writer, u32, @intCast(ordinary.items.len));
    try writer.writeAll(ordinary.items);
    try encodeClaim(writer, candidate.bulk_memcpy_caller);
    try encodeClaim(writer, candidate.bulk_memcpy_words);
    try encodeClaim(writer, candidate.stack_swap_caller);
    try encodeClaim(writer, candidate.stack_swap_words);
}

pub fn decodeClaims(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    projected: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    profile: *const candidate_profile.Profile,
) !OwnedClaims {
    var cursor = base_wire.Cursor.init(bytes);
    if (try cursor.readInt(u16) != schema_version)
        return error.UnsupportedCandidateLeafClaimVersion;
    const ordinary_len = try cursor.readCount();
    var ordinary = try ethereum_claim_wire.decodeClaim(
        allocator,
        try cursor.take(ordinary_len),
        &projected.core,
        extension,
    );
    var ordinary_owned = true;
    errdefer if (ordinary_owned) ordinary.deinit(allocator);
    const candidate = candidate_integration.Claims{
        .bulk_memcpy_caller = try decodeClaim(bulk_contract.Caller, &cursor),
        .bulk_memcpy_words = try decodeClaim(bulk_contract.Word, &cursor),
        .stack_swap_caller = try decodeClaim(swap_contract.Caller, &cursor),
        .stack_swap_words = try decodeClaim(swap_contract.Word, &cursor),
    };
    try cursor.requireDone();
    try candidate.validate(profile);
    ordinary_owned = false;
    return .{
        .base = ordinary.base,
        .ethereum = ordinary.extension,
        .candidate = candidate,
    };
}

fn encodeProfile(writer: anytype, profile: candidate_profile.Profile) !void {
    try profile.authority.validate();
    try base_wire.writeInt(writer, u16, profile.format);
    try base_wire.writeInt(writer, u16, profile.schema);
    try writer.writeAll(&profile.authority.guest_elf_sha256);
    try base_wire.writeInt(writer, u32, profile.bulk_memcpy_call_count);
    try base_wire.writeInt(writer, u32, profile.bulk_memcpy_word_row_count);
    try base_wire.writeInt(writer, u32, profile.stack_swap_call_count);
    inline for (std.meta.fields(candidate_profile.PrefixGeometry)) |field|
        try base_wire.writeInt(writer, u32, @field(profile.prefix, field.name));
    for (profile.components) |component| try encodeDescriptor(writer, component);
    inline for (std.meta.fields(candidate_profile.Placements)) |field|
        try encodePlacement(writer, @field(profile.placements, field.name));
    inline for (std.meta.fields(candidate_profile.TreeTotals)) |field|
        try base_wire.writeInt(writer, u32, @field(profile.totals, field.name));
    try writer.writeAll(&profile.identity);
    try writer.writeByte(@intFromBool(profile.proof_fresh_verified));
    try writer.writeByte(@intFromBool(profile.production_eligible));
}

fn decodeProfile(cursor: *base_wire.Cursor) !candidate_profile.Profile {
    const format = try cursor.readInt(u16);
    const schema = try cursor.readInt(u16);
    var elf_sha256: [32]u8 = undefined;
    try cursor.readExact(&elf_sha256);
    const authority = try combined_authority.Authority.create(elf_sha256);
    const bulk_calls = try cursor.readInt(u32);
    const bulk_rows = try cursor.readInt(u32);
    const swap_calls = try cursor.readInt(u32);
    var prefix: candidate_profile.PrefixGeometry = undefined;
    inline for (std.meta.fields(candidate_profile.PrefixGeometry)) |field|
        @field(prefix, field.name) = try cursor.readInt(u32);
    var components: [candidate_profile.component_count]candidate_profile.ComponentDescriptor =
        undefined;
    for (&components) |*component| component.* = try decodeDescriptor(cursor);
    var placements: candidate_profile.Placements = undefined;
    inline for (std.meta.fields(candidate_profile.Placements)) |field|
        @field(placements, field.name) = try decodePlacement(cursor);
    var totals: candidate_profile.TreeTotals = undefined;
    inline for (std.meta.fields(candidate_profile.TreeTotals)) |field|
        @field(totals, field.name) = try cursor.readInt(u32);
    var identity: candidate_profile.Digest = undefined;
    try cursor.readExact(&identity);
    const fresh = try readBool(cursor);
    const production = try readBool(cursor);
    const result = candidate_profile.Profile{
        .format = format,
        .schema = schema,
        .authority = authority,
        .bulk_memcpy_call_count = bulk_calls,
        .bulk_memcpy_word_row_count = bulk_rows,
        .stack_swap_call_count = swap_calls,
        .prefix = prefix,
        .components = components,
        .placements = placements,
        .totals = totals,
        .identity = identity,
        .proof_fresh_verified = fresh,
        .production_eligible = production,
    };
    if (result.format != candidate_profile.format_version or
        result.schema != candidate_profile.schema_version or fresh or production)
    {
        return error.InvalidCandidateLeafProfile;
    }
    for (result.components) |component| try component.validate(
        result.bulk_memcpy_call_count,
        result.bulk_memcpy_word_row_count,
        result.stack_swap_call_count,
    );
    if (!std.meta.eql(
        result.placements,
        try candidate_profile.Placements.derive(result.prefix),
    ) or !std.meta.eql(
        result.totals,
        try candidate_profile.TreeTotals.derive(result.prefix),
    )) return error.InvalidCandidateLeafProfile;
    return result;
}

fn encodeDescriptor(
    writer: anytype,
    value: candidate_profile.ComponentDescriptor,
) !void {
    try writer.writeByte(@intFromEnum(value.kind));
    try base_wire.writeInt(writer, u32, value.n_rows);
    try base_wire.writeInt(writer, u32, value.log_size);
    try base_wire.writeInt(writer, u16, value.preprocessed_columns);
    try base_wire.writeInt(writer, u16, value.main_columns);
    try base_wire.writeInt(writer, u16, value.interaction_columns);
    try base_wire.writeInt(writer, u16, value.direct_constraints);
    try base_wire.writeInt(writer, u16, value.interaction_batches);
    try writer.writeByte(value.maximum_constraint_degree);
    try writer.writeByte(value.composition_log_split);
}

fn decodeDescriptor(
    cursor: *base_wire.Cursor,
) !candidate_profile.ComponentDescriptor {
    return .{
        .kind = try cursor.readKnownEnum(candidate_profile.ComponentKind),
        .n_rows = try cursor.readInt(u32),
        .log_size = try cursor.readInt(u32),
        .preprocessed_columns = try cursor.readInt(u16),
        .main_columns = try cursor.readInt(u16),
        .interaction_columns = try cursor.readInt(u16),
        .direct_constraints = try cursor.readInt(u16),
        .interaction_batches = try cursor.readInt(u16),
        .maximum_constraint_degree = try cursor.readByte(),
        .composition_log_split = try cursor.readByte(),
    };
}

fn encodePlacement(writer: anytype, value: candidate_profile.Placement) !void {
    try base_wire.writeInt(writer, u32, value.preprocessed_offset);
    try base_wire.writeInt(writer, u32, value.main_offset);
    try base_wire.writeInt(writer, u32, value.interaction_offset);
}

fn decodePlacement(cursor: *base_wire.Cursor) !candidate_profile.Placement {
    return .{
        .preprocessed_offset = try cursor.readInt(u32),
        .main_offset = try cursor.readInt(u32),
        .interaction_offset = try cursor.readInt(u32),
    };
}

fn encodeClaim(writer: anytype, claim: anytype) !void {
    try claim.validate();
    try base_wire.writeInt(writer, u32, claim.log_size);
    try base_wire.writeInt(writer, u32, claim.n_rows);
    for (claim.batch_sums) |sum| try base_wire.writeQm31(writer, sum);
    try base_wire.writeQm31(writer, claim.component_sum);
}

fn decodeClaim(
    comptime Config: type,
    cursor: *base_wire.Cursor,
) !ClaimType(Config) {
    const log_size = try cursor.readInt(u32);
    const n_rows = try cursor.readInt(u32);
    var sums: [Config.batch_count]@import("stwo_core").fields.qm31.QM31 = undefined;
    for (&sums) |*sum| sum.* = try cursor.readQm31();
    const encoded_total = try cursor.readQm31();
    const result = try ClaimType(Config).canonical(log_size, n_rows, sums);
    if (!result.component_sum.eql(encoded_total))
        return error.InvalidCandidateLeafClaim;
    return result;
}

fn ClaimType(comptime Config: type) type {
    return if (Config == bulk_contract.Caller or Config == bulk_contract.Word)
        bulk_contract.Claim(Config)
    else
        swap_contract.Claim(Config);
}

fn readBool(cursor: *base_wire.Cursor) !bool {
    return switch (try cursor.readByte()) {
        0 => false,
        1 => true,
        else => error.InvalidBoolean,
    };
}

comptime {
    if (candidate_profile.production_active or candidate_integration.production_active)
        @compileError("candidate leaf artifact wire became active");
}
