//! Corrected V3 leaf-link schedule: rows 40 and 45 consume one provider digest.
//!
//! V1 assumed 42 transcript claims, while the SegmentV2 native verifier owns
//! exactly 28. V1's final four provider digest kinds also had no AIR producer.
//! V2 uses the exact 28 claims and appends eight row-39 emitters for
//! `(0, PFD1, 0, limb, value)` with multiplicity two:
//! row 40 and row 45 each consume one copy. It replaces the 32 unbound row-40
//! projection rows with eight exact PFD1 joins. Its schedule identity is
//! distinct; the V1 compiler and any prior key remain unchanged.

const std = @import("std");
const old = @import("ethereum_leaf_link_program_v1.zig");
const source_air = @import("air/ethereum_leaf_link_source_v1.zig");
const field_hash = @import("segment_leaf_wrapper_field_hash_witness_v3.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 2;
pub const ID_DOMAIN = "stwo-zig/riscv-ethereum-leaf-link-program/v2\x00";
pub const SCHEDULE_ID_HEX = "ca7b1f5c3355072dd26a82a516a86c22b896213f0daefb9f467611f952fa7da0";
pub const SCHEDULE_ID: [32]u8 = blk: {
    var value: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&value, SCHEDULE_ID_HEX) catch @compileError("invalid V3 row-39/40 schedule ID");
    break :blk value;
};
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const TRANSCRIPT_CLAIM_COUNT: usize = @import("../air/transcript/claims.zig").COMPONENT_COUNT;
pub const SOURCE_ROW_COUNT = old.SOURCE_ROW_COUNT -
    (old.TRANSCRIPT_CLAIM_COUNT - TRANSCRIPT_CLAIM_COUNT) * old.SECURE_VALUE_WORD_COUNT +
    DIGEST_WORD_COUNT;
pub const DIGEST_WORD_COUNT = old.DIGEST_WORD_COUNT;
pub const METADATA_HASH_ROW_COUNT = old.METADATA_HASH_ROW_COUNT;
pub const LINK_HASH_ROW_COUNT = old.LINK_HASH_ROW_COUNT;
pub const METADATA_BASE_START = old.METADATA_BASE_START;
pub const METADATA_SEGMENT_INDEX_START = old.METADATA_SEGMENT_INDEX_START;
pub const METADATA_GLOBAL_START = old.METADATA_GLOBAL_START;
pub const METADATA_GLOBAL_END = old.METADATA_GLOBAL_END;
pub const METADATA_LOCAL_COUNT_START = old.METADATA_LOCAL_COUNT_START;
pub const METADATA_ENTRY_CONTINUATION_ROOT = old.METADATA_ENTRY_CONTINUATION_ROOT;
pub const METADATA_EXIT_CONTINUATION_ROOT = old.METADATA_EXIT_CONTINUATION_ROOT;
pub const METADATA_COMPLETION_START = old.METADATA_COMPLETION_START;
pub const PUBLIC_AUTHORITY_DIGEST_COUNT: usize = 4;
pub const PROJECTION_ROW_COUNT: usize = old.PROJECTION_ROW_COUNT - 3 * DIGEST_WORD_COUNT;
pub const SourceScheduleRowV1 = old.SourceScheduleRowV1;
pub const ProjectionScheduleRowV1 = old.ProjectionScheduleRowV1;

pub const ProgramV2 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    base: old.ProgramV1,
    source_log_size: u32,
    projection_log_size: u32,
    source_rows: []SourceScheduleRowV1,
    projection_rows: []ProjectionScheduleRowV1,
    metadata_hash: old.HashScheduleV1,
    link_hash: old.HashScheduleV1,
    schedule_id: [32]u8,

    pub fn init(allocator: std.mem.Allocator) !ProgramV2 {
        var base = try old.ProgramV1.init(allocator);
        errdefer base.deinit();
        const source_rows = try allocator.alloc(SourceScheduleRowV1, SOURCE_ROW_COUNT);
        errdefer allocator.free(source_rows);
        const projection_rows = try allocator.alloc(ProjectionScheduleRowV1, PROJECTION_ROW_COUNT);
        errdefer allocator.free(projection_rows);
        try fill(source_rows, projection_rows, &base);
        var result = ProgramV2{
            .allocator = allocator,
            .base = base,
            .source_log_size = base.source_log_size,
            .projection_log_size = base.projection_log_size,
            .source_rows = source_rows,
            .projection_rows = projection_rows,
            .metadata_hash = base.metadata_hash,
            .link_hash = base.link_hash,
            .schedule_id = digest(source_rows, projection_rows),
        };
        try result.validate();
        return result;
    }

    pub fn deinit(self: *ProgramV2) void {
        self.allocator.free(self.projection_rows);
        self.allocator.free(self.source_rows);
        self.base.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const ProgramV2) !void {
        try self.base.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.source_log_size != self.base.source_log_size or
            self.projection_log_size != self.base.projection_log_size or
            self.source_rows.len != SOURCE_ROW_COUNT or
            self.projection_rows.len != PROJECTION_ROW_COUNT or
            self.metadata_hash.rows.ptr != self.base.metadata_hash.rows.ptr or
            self.link_hash.rows.ptr != self.base.link_hash.rows.ptr)
            return error.InvalidV3LeafLinkProgramV2;
        const source_expected = try self.allocator.alloc(SourceScheduleRowV1, SOURCE_ROW_COUNT);
        defer self.allocator.free(source_expected);
        const projection_expected = try self.allocator.alloc(ProjectionScheduleRowV1, PROJECTION_ROW_COUNT);
        defer self.allocator.free(projection_expected);
        try fill(source_expected, projection_expected, &self.base);
        for (self.source_rows, source_expected) |actual, wanted|
            if (!std.meta.eql(actual, wanted)) return error.InvalidV3LeafLinkProgramV2;
        for (self.projection_rows, projection_expected) |actual, wanted|
            if (!std.meta.eql(actual, wanted)) return error.InvalidV3LeafLinkProgramV2;
        if (!std.meta.eql(self.schedule_id, SCHEDULE_ID) or
            !std.meta.eql(self.schedule_id, digest(source_expected, projection_expected)))
            return error.InvalidV3LeafLinkProgramV2;
    }
};

fn fill(source_destination: []SourceScheduleRowV1, destination: []ProjectionScheduleRowV1, base: *const old.ProgramV1) !void {
    if (source_destination.len != SOURCE_ROW_COUNT) return error.InvalidV3LeafLinkProgramV2;
    const raw_count = @import("segment_leaf_local_authority_v3.zig").METADATA_IDENTITY_WORDS +
        @import("segment_leaf_local_verified_link_v3.zig").IDENTITY_WORDS;
    const claim_words = TRANSCRIPT_CLAIM_COUNT * old.SECURE_VALUE_WORD_COUNT;
    const old_claim_words = old.TRANSCRIPT_CLAIM_COUNT * old.SECURE_VALUE_WORD_COUNT;
    const digest_words = 2 * DIGEST_WORD_COUNT;
    @memcpy(source_destination[0 .. raw_count + claim_words], base.source_rows[0 .. raw_count + claim_words]);
    @memcpy(
        source_destination[raw_count + claim_words ..][0..digest_words],
        base.source_rows[raw_count + old_claim_words ..][0..digest_words],
    );
    const provider_start = raw_count + claim_words + digest_words;
    for (0..DIGEST_WORD_COUNT) |limb| source_destination[provider_start + limb] = .{
        .active = 1,
        .raw_mask = 0,
        .verifier_mask = 1,
        .transcript_mask = 0,
        .statement_mask = 0,
        .scope = 0,
        .kind = field_hash.PROVIDER_FIELD_DIGEST_KIND,
        .index_0 = 0,
        .index_1 = @intCast(limb),
        .use_count = 2,
    };
    const public_start = base.projection_rows.len - old.PUBLIC_AUTHORITY_WORD_COUNT;
    const kept = public_start + 3 * DIGEST_WORD_COUNT;
    if (destination.len != PROJECTION_ROW_COUNT or
        base.projection_rows.len != old.PROJECTION_ROW_COUNT or
        kept + DIGEST_WORD_COUNT != destination.len)
        return error.InvalidV3LeafLinkProgramV2;
    @memcpy(destination[0..kept], base.projection_rows[0..kept]);
    for (0..DIGEST_WORD_COUNT) |limb| {
        var row = base.projection_rows[public_start + limb];
        if (row.verifier_kind != source_air.LINK_DIGEST_KIND or
            row.verifier_index_0 != 0 or row.verifier_index_1 != limb or
            row.statement_scope != source_air.LEAF_AUTHORITY_SCOPE)
            return error.InvalidV3LeafLinkProgramV2;
        row.verifier_kind = field_hash.PROVIDER_FIELD_DIGEST_KIND;
        row.statement_index = @intCast(3 * DIGEST_WORD_COUNT + limb);
        destination[kept + limb] = row;
    }
}

fn digest(source_rows: []const SourceScheduleRowV1, rows: []const ProjectionScheduleRowV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ID_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u32, SOURCE_ROW_COUNT);
    hashInt(&hash, u32, PROJECTION_ROW_COUNT);
    for (source_rows) |row| inline for (@typeInfo(SourceScheduleRowV1).@"struct".fields) |field|
        hashInt(&hash, u32, @field(row, field.name));
    for (rows) |row| inline for (@typeInfo(ProjectionScheduleRowV1).@"struct".fields) |field|
        hashInt(&hash, u32, @field(row, field.name));
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

test "V2 row 40 consumes only the emitted provider field digest" {
    var program = try ProgramV2.init(std.testing.allocator);
    defer program.deinit();
    try std.testing.expectEqualDeep(SCHEDULE_ID, program.schedule_id);
    try std.testing.expectEqual(@as(usize, 1093), program.projection_rows.len);
    try std.testing.expectEqual(@as(usize, 794), program.source_rows.len);
    for (program.source_rows[SOURCE_ROW_COUNT - DIGEST_WORD_COUNT ..], 0..) |row, limb| {
        try std.testing.expectEqual(field_hash.PROVIDER_FIELD_DIGEST_KIND, row.kind);
        try std.testing.expectEqual(@as(u32, @intCast(limb)), row.index_1);
        try std.testing.expectEqual(@as(u32, 2), row.use_count);
    }
    for (program.projection_rows[program.projection_rows.len - DIGEST_WORD_COUNT ..], 0..) |row, limb| {
        try std.testing.expectEqual(field_hash.PROVIDER_FIELD_DIGEST_KIND, row.verifier_kind);
        try std.testing.expectEqual(@as(u32, @intCast(limb)), row.verifier_index_1);
        try std.testing.expectEqual(@as(u32, @intCast(24 + limb)), row.statement_index);
    }
    const prior_id = program.schedule_id;
    program.projection_rows[program.projection_rows.len - 1].verifier_kind = source_air.PROVIDER_CANCELLATION_KIND;
    try std.testing.expectError(error.InvalidV3LeafLinkProgramV2, program.validate());
    program.projection_rows[program.projection_rows.len - 1].verifier_kind = field_hash.PROVIDER_FIELD_DIGEST_KIND;
    try program.validate();
    const provider_start = SOURCE_ROW_COUNT - DIGEST_WORD_COUNT;
    program.source_rows[provider_start].use_count = 1;
    try std.testing.expectError(error.InvalidV3LeafLinkProgramV2, program.validate());
    program.source_rows[provider_start].use_count = 2;
    program.source_rows[provider_start].active = 0;
    try std.testing.expectError(error.InvalidV3LeafLinkProgramV2, program.validate());
    program.source_rows[provider_start].active = 1;
    try program.validate();
    try std.testing.expectEqualDeep(prior_id, program.schedule_id);
}
