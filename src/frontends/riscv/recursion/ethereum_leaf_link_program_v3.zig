//! Direct native-verifier leaf link without post-challenge provider inputs.
//!
//! The wrapper's base rows already verify the native SegmentV2 proof. Row 39
//! therefore sources only fixed metadata/link words, the 28 native child
//! claims, two identity digests, and native ProgramV2/root verifier inputs.
//! Row 40 joins those against the three public pre-challenge authority digests:
//! link, native ProgramV2, and native preprocessed root. No PFD1 or outer
//! 39-row proof value appears in this schedule. The root input still needs an
//! AIR bridge to the native verifier's Tree0 tuple before proof activation.

const std = @import("std");
const old = @import("ethereum_leaf_link_program_v1.zig");
const metadata_mod = @import("segment_leaf_local_authority_v3.zig");
const link_mod = @import("segment_leaf_local_verified_link_v3.zig");
const direct_authority = @import("ethereum_leaf_direct_public_authority_v3.zig");
const source_air = @import("air/ethereum_leaf_link_source_v1.zig");

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 3;
pub const ID_DOMAIN = "stwo-zig/riscv-ethereum-leaf-link-program/v3-direct\x00";
pub const SCHEDULE_ID_HEX = "6563b6195a6e7e2e6825ca227b7585f70523f9bf79ffd3ac040447e567a15dbe";
pub const SCHEDULE_ID: [32]u8 = blk: {
    var value: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&value, SCHEDULE_ID_HEX) catch @compileError("invalid direct V3 row schedule ID");
    break :blk value;
};
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const TRANSCRIPT_CLAIM_COUNT: usize = @import("../air/transcript/claims.zig").COMPONENT_COUNT;
pub const DIGEST_WORD_COUNT: usize = old.DIGEST_WORD_COUNT;
pub const PUBLIC_AUTHORITY_DIGEST_COUNT: usize = 3;
pub const PUBLIC_AUTHORITY_WORD_COUNT: usize = direct_authority.WORD_COUNT;
pub const SOURCE_ROW_COUNT: usize = metadata_mod.METADATA_IDENTITY_WORDS +
    link_mod.IDENTITY_WORDS + TRANSCRIPT_CLAIM_COUNT * old.SECURE_VALUE_WORD_COUNT +
    4 * DIGEST_WORD_COUNT;
pub const PROJECTION_ROW_COUNT: usize = old.PROJECTION_ROW_COUNT -
    (old.PUBLIC_AUTHORITY_DIGEST_COUNT - PUBLIC_AUTHORITY_DIGEST_COUNT) * DIGEST_WORD_COUNT;
pub const METADATA_HASH_ROW_COUNT = old.METADATA_HASH_ROW_COUNT;
pub const LINK_HASH_ROW_COUNT = old.LINK_HASH_ROW_COUNT;
pub const SourceScheduleRowV1 = old.SourceScheduleRowV1;
pub const ProjectionScheduleRowV1 = old.ProjectionScheduleRowV1;

pub const ProgramV3 = struct {
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

    pub fn init(allocator: std.mem.Allocator) !ProgramV3 {
        var base = try old.ProgramV1.init(allocator);
        errdefer base.deinit();
        const source_rows = try allocator.alloc(SourceScheduleRowV1, SOURCE_ROW_COUNT);
        errdefer allocator.free(source_rows);
        const projection_rows = try allocator.alloc(ProjectionScheduleRowV1, PROJECTION_ROW_COUNT);
        errdefer allocator.free(projection_rows);
        try fill(source_rows, projection_rows, &base);
        var result = ProgramV3{
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

    pub fn deinit(self: *ProgramV3) void {
        self.allocator.free(self.projection_rows);
        self.allocator.free(self.source_rows);
        self.base.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const ProgramV3) !void {
        try self.base.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.source_log_size != self.base.source_log_size or
            self.projection_log_size != self.base.projection_log_size or
            self.source_rows.len != SOURCE_ROW_COUNT or
            self.projection_rows.len != PROJECTION_ROW_COUNT or
            self.metadata_hash.rows.ptr != self.base.metadata_hash.rows.ptr or
            self.link_hash.rows.ptr != self.base.link_hash.rows.ptr)
            return error.InvalidDirectLeafLinkProgramV3;
        const expected_source = try self.allocator.alloc(SourceScheduleRowV1, SOURCE_ROW_COUNT);
        defer self.allocator.free(expected_source);
        const expected_projection = try self.allocator.alloc(ProjectionScheduleRowV1, PROJECTION_ROW_COUNT);
        defer self.allocator.free(expected_projection);
        try fill(expected_source, expected_projection, &self.base);
        for (self.source_rows, expected_source) |actual, expected|
            if (!std.meta.eql(actual, expected)) return error.InvalidDirectLeafLinkProgramV3;
        for (self.projection_rows, expected_projection) |actual, expected|
            if (!std.meta.eql(actual, expected)) return error.InvalidDirectLeafLinkProgramV3;
        try direct_authority.validateProjectionSchedule(self.projection_rows);
        if (!std.meta.eql(self.schedule_id, SCHEDULE_ID) or
            !std.meta.eql(self.schedule_id, digest(expected_source, expected_projection)))
            return error.InvalidDirectLeafLinkProgramV3;
    }
};

fn fill(source: []SourceScheduleRowV1, projection: []ProjectionScheduleRowV1, base: *const old.ProgramV1) !void {
    const raw_count = metadata_mod.METADATA_IDENTITY_WORDS + link_mod.IDENTITY_WORDS;
    const claim_words = TRANSCRIPT_CLAIM_COUNT * old.SECURE_VALUE_WORD_COUNT;
    const old_claim_words = old.TRANSCRIPT_CLAIM_COUNT * old.SECURE_VALUE_WORD_COUNT;
    const digest_words = 2 * DIGEST_WORD_COUNT;
    const public_start = base.projection_rows.len - old.PUBLIC_AUTHORITY_DIGEST_COUNT * DIGEST_WORD_COUNT;
    if (source.len != raw_count + claim_words + 2 * digest_words or
        projection.len != public_start + PUBLIC_AUTHORITY_DIGEST_COUNT * DIGEST_WORD_COUNT or
        base.source_rows.len != raw_count + old_claim_words + digest_words)
        return error.InvalidDirectLeafLinkProgramV3;
    @memcpy(source[0 .. raw_count + claim_words], base.source_rows[0 .. raw_count + claim_words]);
    @memcpy(source[raw_count + claim_words ..][0..digest_words], base.source_rows[raw_count + old_claim_words ..]);
    const verifier_start = raw_count + claim_words + digest_words;
    for (0..DIGEST_WORD_COUNT) |limb| {
        source[verifier_start + limb] = verifierSource(source_air.PROGRAM_AUTHORITY_KIND, limb, 2);
        source[verifier_start + DIGEST_WORD_COUNT + limb] = verifierSource(source_air.PREPROCESSED_ROOT_KIND, limb, 1);
    }
    @memcpy(projection, base.projection_rows[0..projection.len]);
    for (projection[public_start..]) |*row| row.statement_scope = direct_authority.SCOPE;
}

fn verifierSource(kind: u32, limb: usize, use_count: u32) SourceScheduleRowV1 {
    return .{
        .active = 1,
        .raw_mask = 0,
        .verifier_mask = 1,
        .transcript_mask = 0,
        .statement_mask = 0,
        .scope = 0,
        .kind = kind,
        .index_0 = 0,
        .index_1 = @intCast(limb),
        .use_count = use_count,
    };
}

fn digest(source: []const SourceScheduleRowV1, projection: []const ProjectionScheduleRowV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ID_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u32, SOURCE_ROW_COUNT);
    hashInt(&hash, u32, PROJECTION_ROW_COUNT);
    for (source) |row| inline for (@typeInfo(SourceScheduleRowV1).@"struct".fields) |field|
        hashInt(&hash, u32, @field(row, field.name));
    for (projection) |row| inline for (@typeInfo(ProjectionScheduleRowV1).@"struct".fields) |field|
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

test "direct schedule contains no provider digest or post-challenge source" {
    const provider_kind = @import("segment_leaf_wrapper_field_hash_witness_v3.zig").PROVIDER_FIELD_DIGEST_KIND;
    var program = try ProgramV3.init(std.testing.allocator);
    defer program.deinit();
    try std.testing.expectEqualDeep(SCHEDULE_ID, program.schedule_id);
    try std.testing.expectEqual(@as(usize, 802), program.source_rows.len);
    try std.testing.expectEqual(@as(usize, 1085), program.projection_rows.len);
    for (program.source_rows) |row|
        try std.testing.expect(row.kind != provider_kind);
    const verifier_start = program.source_rows.len - 2 * DIGEST_WORD_COUNT;
    for (0..DIGEST_WORD_COUNT) |limb| {
        const program_row = program.source_rows[verifier_start + limb];
        const root_row = program.source_rows[verifier_start + DIGEST_WORD_COUNT + limb];
        try std.testing.expectEqual(source_air.PROGRAM_AUTHORITY_KIND, program_row.kind);
        try std.testing.expectEqual(@as(u32, 2), program_row.use_count);
        try std.testing.expectEqual(source_air.PREPROCESSED_ROOT_KIND, root_row.kind);
        try std.testing.expectEqual(@as(u32, 1), root_row.use_count);
    }
    for (program.projection_rows) |row| {
        try std.testing.expect(row.verifier_kind != provider_kind);
        try std.testing.expect(row.verifier_kind != source_air.PROVIDER_RELATION_CONTEXT_KIND);
        try std.testing.expect(row.verifier_kind != source_air.PROVIDER_CORE_CLAIM_KIND);
        try std.testing.expect(row.verifier_kind != source_air.PROVIDER_MANIFEST_KIND);
        try std.testing.expect(row.verifier_kind != source_air.PROVIDER_CANCELLATION_KIND);
    }
    const first_public = program.projection_rows.len - PUBLIC_AUTHORITY_DIGEST_COUNT * DIGEST_WORD_COUNT;
    try std.testing.expectEqual(source_air.LINK_DIGEST_KIND, program.projection_rows[first_public].verifier_kind);
    try std.testing.expectEqual(source_air.PROGRAM_AUTHORITY_KIND, program.projection_rows[first_public + DIGEST_WORD_COUNT].verifier_kind);
    try std.testing.expectEqual(source_air.PREPROCESSED_ROOT_KIND, program.projection_rows[first_public + 2 * DIGEST_WORD_COUNT].verifier_kind);
    program.projection_rows[first_public].verifier_kind = provider_kind;
    try std.testing.expectError(error.InvalidDirectLeafLinkProgramV3, program.validate());
    program.projection_rows[first_public].verifier_kind = source_air.LINK_DIGEST_KIND;
    program.projection_rows[first_public].statement_scope = source_air.LEAF_AUTHORITY_SCOPE;
    try std.testing.expectError(error.InvalidDirectLeafLinkProgramV3, program.validate());
}

test "direct schedule rejects row 39 multiplicity and typed row 40 mutation" {
    var program = try ProgramV3.init(std.testing.allocator);
    defer program.deinit();
    program.source_rows[0].use_count += 1;
    try std.testing.expectError(error.InvalidDirectLeafLinkProgramV3, program.validate());
    program.source_rows[0].use_count -= 1;
    const verifier_start = program.source_rows.len - 2 * DIGEST_WORD_COUNT;
    program.source_rows[verifier_start].use_count = 1;
    try std.testing.expectError(error.InvalidDirectLeafLinkProgramV3, program.validate());
    program.source_rows[verifier_start].use_count = 2;
    program.schedule_id[0] ^= 1;
    try std.testing.expectError(error.InvalidDirectLeafLinkProgramV3, program.validate());
    program.schedule_id[0] ^= 1;
    program.projection_rows[0].raw_join_index += 1;
    try std.testing.expectError(error.InvalidDirectLeafLinkProgramV3, program.validate());
}
