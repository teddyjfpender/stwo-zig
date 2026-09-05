//! Path-independent Stage-101 inventory for one sealed incremental V4 campaign.
//!
//! The table is durable custody, not verifier admission.  Each row contains
//! the exact seven ordered `InputRefV1` values accepted by the native-leaf V4
//! worker and the Zig-minted `RecipeV4` ref which occupies the profile slot.
//! Cardinality is decoded from the authenticated campaign manifests and is
//! bounded only by the V4 protocol maximum. The current Ethereum conformance
//! fixture is test/profile metadata, not transport admission.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const recipe_mod = @import("recursive_pipeline_incremental_leaf_recipe_v4.zig");
const support = @import("ethereum_block_leaf_support.zig");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");
const wire_publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 4;
pub const CAS_SCHEMA_VERSION: u16 = 0x0410;
pub const ARTIFACT_KIND = artifact_store.ArtifactKindV1.capture_transport;
pub const MAGIC = [8]u8{ 'S', 'T', 'W', 'C', 'I', 'T', '0', '4' };
pub const MIN_SEGMENT_COUNT: u32 = 2;
pub const MAX_SEGMENT_COUNT: u32 = publication.MAX_SEGMENT_COUNT;
pub const STAGE_INPUT_COUNT: usize = 7;

pub const COMPACT_MANIFEST_CAS_SCHEMA_VERSION: u16 = 0x0400;
pub const RECOVERY_MANIFEST_CAS_SCHEMA_VERSION: u16 = 0x0404;
pub const FULL_JOURNAL_CAS_SCHEMA_VERSION: u16 = 2;
pub const MATERIALIZATION_CAS_SCHEMA_VERSION: u16 = 2;

const table_domain =
    "stwo-zig/recursive-pipeline-incremental-campaign-table/v4\x00";
const global_ref_count: usize = 10;
const header_byte_count: usize = MAGIC.len + 2 * @sizeOf(u16) +
    3 * @sizeOf(u32);
const record_byte_count: usize = @sizeOf(u32) +
    artifact_store.BlobRefV1.canonical_size +
    STAGE_INPUT_COUNT * artifact_store.InputRefV1.canonical_size;

pub const Error = error{
    IncrementalCampaignTableCodecMismatchV4,
    IncrementalCampaignTableInputMismatchV4,
    IncrementalCampaignTableRecipeMismatchV4,
    InvalidIncrementalCampaignTableV4,
};

/// Complete binary-tree cardinality derived from the authenticated leaf
/// count.  Empty leaves and fold jobs are scheduling facts, not campaign
/// constants or caller-selected values.
pub const TopologyV4 = struct {
    leaf_count: u32,
    padded_leaf_count: u32,
    empty_leaf_count: u32,
    fold_count: u32,

    pub fn derive(segment_count: u32) Error!TopologyV4 {
        if (segment_count < MIN_SEGMENT_COUNT or
            segment_count > MAX_SEGMENT_COUNT)
        {
            return error.InvalidIncrementalCampaignTableV4;
        }
        const padded = std.math.ceilPowerOfTwo(u32, segment_count) catch
            return error.InvalidIncrementalCampaignTableV4;
        return .{
            .leaf_count = segment_count,
            .padded_leaf_count = padded,
            .empty_leaf_count = padded - segment_count,
            .fold_count = padded - 1,
        };
    }

    pub fn validate(self: TopologyV4) Error!void {
        if (!std.meta.eql(self, try derive(self.leaf_count)))
            return error.InvalidIncrementalCampaignTableV4;
    }
};

pub const GlobalRefsV4 = struct {
    capture_manifest: artifact_store.BlobRefV1,
    public_wire_manifest: artifact_store.BlobRefV1,
    compact_manifest: artifact_store.BlobRefV1,
    execution_profile_receipt: artifact_store.BlobRefV1,
    materialization_result: artifact_store.BlobRefV1,
    source_request: artifact_store.BlobRefV1,
    execution_journal: artifact_store.BlobRefV1,
    program: artifact_store.BlobRefV1,
    raw_input: artifact_store.BlobRefV1,
    expected_output: artifact_store.BlobRefV1,

    pub fn validate(self: GlobalRefsV4) Error!void {
        if (!codec(self.capture_manifest, .capture_transport, 4, false) or
            !codec(
                self.public_wire_manifest,
                .capture_transport,
                wire_publication.CAS_MANIFEST_SCHEMA_VERSION,
                false,
            ) or
            !auxiliaryManifestCodec(self.compact_manifest) or
            !codec(
                self.execution_profile_receipt,
                .profile_receipt,
                1,
                false,
            ) or
            !codec(
                self.materialization_result,
                .source,
                MATERIALIZATION_CAS_SCHEMA_VERSION,
                false,
            ) or
            !codec(self.source_request, .source, 1, false) or
            !codec(
                self.execution_journal,
                .journal,
                FULL_JOURNAL_CAS_SCHEMA_VERSION,
                false,
            ) or
            !codec(self.program, .program, 1, false) or
            !codec(self.raw_input, .raw, 1, true) or
            !codec(self.expected_output, .raw, 1, false))
        {
            return error.InvalidIncrementalCampaignTableV4;
        }
    }
};

pub const LeafRecordV4 = struct {
    segment_index: u32,
    recipe: artifact_store.BlobRefV1,
    stage_inputs: [STAGE_INPUT_COUNT]artifact_store.InputRefV1,

    pub fn validate(
        self: LeafRecordV4,
        expected_index: usize,
        globals: GlobalRefsV4,
    ) Error!void {
        if (self.segment_index != @as(u32, @intCast(expected_index)) or
            !codec(
                self.recipe,
                .capture_transport,
                recipe_mod.SCHEMA_VERSION,
                false,
            ) or self.recipe.byte_count != recipe_mod.ENCODED_BYTE_COUNT)
        {
            return error.InvalidIncrementalCampaignTableV4;
        }
        for (self.stage_inputs) |input| input.validate() catch
            return error.InvalidIncrementalCampaignTableV4;
        const values = self.stage_inputs;
        if (!inputCodec(values[0], .statement, 0, .statement, 1) or
            values[0].blob.byte_count != support.source_wire.encoded_size or
            !inputCodec(values[1], .program, 0, .program, 1) or
            !artifact_store.BlobRefV1.eql(values[1].blob, globals.program) or
            !inputCodec(values[2], .profile, 0, .capture_transport, 1) or
            !artifact_store.BlobRefV1.eql(values[2].blob, self.recipe) or
            !inputCodec(values[3], .witness, 0, .capture_transport, 1) or
            !inputCodec(values[4], .capture, 0, .capture_transport, 4) or
            !inputCodec(
                values[5],
                .capture,
                1,
                .capture_transport,
                wire_publication.CAS_REFERENCE_SCHEMA_VERSION,
            ) or values[5].blob.byte_count !=
            wire_publication.reference_byte_count or
            !inputCodec(values[6], .journal, 0, .journal, 1))
        {
            return error.IncrementalCampaignTableInputMismatchV4;
        }
    }
};

pub const CampaignTableV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    first_segment_index: u32 = 0,
    segment_count: u32,
    globals: GlobalRefsV4,
    records: []const LeafRecordV4,
    content_sha256: [32]u8,

    pub fn seal(value: CampaignTableV4) Error!CampaignTableV4 {
        var result = value;
        result.content_sha256 = tableIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const CampaignTableV4) Error!void {
        _ = try self.topology();
        const segment_count = std.math.cast(usize, self.segment_count) orelse
            return error.InvalidIncrementalCampaignTableV4;
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.first_segment_index != 0 or
            self.records.len != segment_count)
        {
            return error.InvalidIncrementalCampaignTableV4;
        }
        try self.globals.validate();
        for (self.records, 0..) |record, ordinal|
            try record.validate(ordinal, self.globals);
        if (!std.mem.eql(
            u8,
            &self.content_sha256,
            &tableIdentity(self),
        )) return error.InvalidIncrementalCampaignTableV4;
    }

    pub fn topology(self: *const CampaignTableV4) Error!TopologyV4 {
        return TopologyV4.derive(self.segment_count);
    }
};

pub const OwnedCampaignTableV4 = struct {
    allocator: std.mem.Allocator,
    value: CampaignTableV4,

    pub fn deinit(self: *OwnedCampaignTableV4) void {
        self.allocator.free(self.value.records);
        self.* = undefined;
    }
};

/// Fixed-prefix projection used to cold-open the two sealed manifests before
/// any variable record allocation. Its count is only a bounded claim until a
/// caller invokes `decodeAllocAgainstAuthenticatedCount` with the manifest-
/// derived value.
pub const HeaderV4 = struct {
    format_version: u16,
    schema_version: u16,
    first_segment_index: u32,
    segment_count: u32,
    globals: GlobalRefsV4,

    pub fn validate(self: HeaderV4) Error!void {
        _ = try TopologyV4.derive(self.segment_count);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.first_segment_index != 0)
        {
            return error.InvalidIncrementalCampaignTableV4;
        }
        try self.globals.validate();
    }
};

pub fn encodedByteCount(segment_count: u32) Error!usize {
    _ = try TopologyV4.derive(segment_count);
    const count = std.math.cast(usize, segment_count) orelse
        return error.IncrementalCampaignTableCodecMismatchV4;
    const records_byte_count = std.math.mul(
        usize,
        count,
        record_byte_count,
    ) catch return error.IncrementalCampaignTableCodecMismatchV4;
    return std.math.add(
        usize,
        header_byte_count +
            global_ref_count * artifact_store.BlobRefV1.canonical_size + 32,
        records_byte_count,
    ) catch return error.IncrementalCampaignTableCodecMismatchV4;
}

pub fn encodeAlloc(
    allocator: std.mem.Allocator,
    value: *const CampaignTableV4,
) ![]u8 {
    try value.validate();
    const bytes = try allocator.alloc(u8, try encodedByteCount(value.segment_count));
    errdefer allocator.free(bytes);
    var writer = Writer{ .bytes = bytes };
    writer.raw(&MAGIC);
    writer.int(u16, value.format_version);
    writer.int(u16, value.schema_version);
    writer.int(u32, 0);
    writer.int(u32, value.first_segment_index);
    writer.int(u32, value.segment_count);
    writeGlobals(&writer, value.globals);
    for (value.records) |record| {
        writer.int(u32, record.segment_index);
        writer.blob(record.recipe);
        for (record.stage_inputs) |input| writer.input(input);
    }
    writer.raw(&value.content_sha256);
    if (writer.failed or writer.at != bytes.len)
        return error.IncrementalCampaignTableCodecMismatchV4;
    return bytes;
}

pub fn decodeHeader(bytes: []const u8) !HeaderV4 {
    const minimum_byte_count = try encodedByteCount(MIN_SEGMENT_COUNT);
    if (bytes.len < minimum_byte_count)
        return error.IncrementalCampaignTableCodecMismatchV4;
    var reader = Reader{ .bytes = bytes };
    if (!std.mem.eql(u8, try reader.take(MAGIC.len), &MAGIC))
        return error.IncrementalCampaignTableCodecMismatchV4;
    const result = HeaderV4{
        .format_version = try reader.int(u16),
        .schema_version = try reader.int(u16),
        .first_segment_index = blk: {
            if (try reader.int(u32) != 0)
                return error.IncrementalCampaignTableCodecMismatchV4;
            break :blk try reader.int(u32);
        },
        .segment_count = try reader.int(u32),
        .globals = try readGlobals(&reader),
    };
    try result.validate();
    if (bytes.len != try encodedByteCount(result.segment_count))
        return error.IncrementalCampaignTableCodecMismatchV4;
    return result;
}

pub fn decodeAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !OwnedCampaignTableV4 {
    const minimum_byte_count = try encodedByteCount(MIN_SEGMENT_COUNT);
    if (bytes.len < minimum_byte_count)
        return error.IncrementalCampaignTableCodecMismatchV4;
    var reader = Reader{ .bytes = bytes };
    if (!std.mem.eql(u8, try reader.take(MAGIC.len), &MAGIC))
        return error.IncrementalCampaignTableCodecMismatchV4;
    const format_version = try reader.int(u16);
    const schema_version = try reader.int(u16);
    if (try reader.int(u32) != 0)
        return error.IncrementalCampaignTableCodecMismatchV4;
    const first_segment_index = try reader.int(u32);
    const segment_count = try reader.int(u32);
    if (bytes.len != (encodedByteCount(segment_count) catch
        return error.IncrementalCampaignTableCodecMismatchV4))
    {
        return error.IncrementalCampaignTableCodecMismatchV4;
    }
    const globals = try readGlobals(&reader);
    const records = try allocator.alloc(
        LeafRecordV4,
        @intCast(segment_count),
    );
    errdefer allocator.free(records);
    for (records) |*record| {
        record.* = .{
            .segment_index = try reader.int(u32),
            .recipe = try reader.blob(),
            .stage_inputs = undefined,
        };
        for (&record.stage_inputs) |*input| input.* = try reader.input();
    }
    const content_sha256 = try reader.array(32);
    if (reader.failed or reader.at != bytes.len)
        return error.IncrementalCampaignTableCodecMismatchV4;
    const result = OwnedCampaignTableV4{
        .allocator = allocator,
        .value = .{
            .format_version = format_version,
            .schema_version = schema_version,
            .first_segment_index = first_segment_index,
            .segment_count = segment_count,
            .globals = globals,
            .records = records,
            .content_sha256 = content_sha256,
        },
    };
    try result.value.validate();
    const canonical = try encodeAlloc(allocator, &result.value);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, bytes, canonical))
        return error.IncrementalCampaignTableCodecMismatchV4;
    return result;
}

pub fn decodeAllocAgainstAuthenticatedCount(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    authenticated_segment_count: u32,
) !OwnedCampaignTableV4 {
    _ = try TopologyV4.derive(authenticated_segment_count);
    const header = try decodeHeader(bytes);
    if (header.segment_count != authenticated_segment_count)
        return error.IncrementalCampaignTableCodecMismatchV4;
    return decodeAlloc(allocator, bytes);
}

/// Reopens every Zig-minted recipe and replays its exact seven-input binding.
/// This deliberately does not imply proof verification or a fresh lease.
pub fn coldValidateRecipeBindings(
    store: *artifact_store.Store,
    table: *const CampaignTableV4,
) !void {
    try table.validate();
    for (table.records) |record| {
        var owned = try store.openBlob(
            record.recipe,
            .capture_transport,
            recipe_mod.SCHEMA_VERSION,
            recipe_mod.ENCODED_BYTE_COUNT,
        );
        defer owned.deinit(store.allocator);
        const recipe = try recipe_mod.decode(owned.bytes);
        try recipe.validateStageInputs(&record.stage_inputs, record.recipe);
        recipe.validateAgainstCampaignCount(table.segment_count) catch
            return error.IncrementalCampaignTableRecipeMismatchV4;
        if (recipe.segment_index != record.segment_index or
            !artifact_store.BlobRefV1.eql(recipe.program, table.globals.program) or
            !artifact_store.BlobRefV1.eql(
                recipe.raw_input,
                table.globals.raw_input,
            ) or !artifact_store.BlobRefV1.eql(
            recipe.expected_output,
            table.globals.expected_output,
        ) or !artifact_store.BlobRefV1.eql(
            recipe.boundary_manifest_v4,
            table.globals.capture_manifest,
        ) or !artifact_store.BlobRefV1.eql(
            recipe.public_wire_manifest_v4,
            table.globals.public_wire_manifest,
        )) return error.IncrementalCampaignTableRecipeMismatchV4;
    }
}

fn tableIdentity(
    value: *const CampaignTableV4,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(table_domain);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.first_segment_index);
    hashInt(&hash, u32, value.segment_count);
    hashGlobals(&hash, value.globals);
    for (value.records) |record| {
        hashInt(&hash, u32, record.segment_index);
        hashBlob(&hash, record.recipe);
        for (record.stage_inputs) |input| {
            hashInt(&hash, u32, @intFromEnum(input.role));
            hashInt(&hash, u32, input.ordinal);
            hashBlob(&hash, input.blob);
        }
    }
    return hash.finalResult();
}

fn inputCodec(
    input: artifact_store.InputRefV1,
    role: artifact_store.InputRoleV1,
    ordinal: u32,
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
) bool {
    return input.role == role and input.ordinal == ordinal and
        codec(input.blob, kind, schema_version, false);
}

fn codec(
    reference: artifact_store.BlobRefV1,
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
    allow_empty: bool,
) bool {
    reference.validate() catch return false;
    return reference.kind == kind and reference.format_version == 1 and
        reference.schema_version == schema_version and
        (allow_empty or reference.byte_count != 0);
}

fn auxiliaryManifestCodec(reference: artifact_store.BlobRefV1) bool {
    return codec(
        reference,
        .capture_transport,
        COMPACT_MANIFEST_CAS_SCHEMA_VERSION,
        false,
    ) or codec(
        reference,
        .capture_transport,
        RECOVERY_MANIFEST_CAS_SCHEMA_VERSION,
        false,
    );
}

fn writeGlobals(writer: *Writer, value: GlobalRefsV4) void {
    inline for (globalValues(value)) |reference| writer.blob(reference);
}

fn readGlobals(reader: *Reader) !GlobalRefsV4 {
    return .{
        .capture_manifest = try reader.blob(),
        .public_wire_manifest = try reader.blob(),
        .compact_manifest = try reader.blob(),
        .execution_profile_receipt = try reader.blob(),
        .materialization_result = try reader.blob(),
        .source_request = try reader.blob(),
        .execution_journal = try reader.blob(),
        .program = try reader.blob(),
        .raw_input = try reader.blob(),
        .expected_output = try reader.blob(),
    };
}

fn hashGlobals(hash: *std.crypto.hash.sha2.Sha256, value: GlobalRefsV4) void {
    inline for (globalValues(value)) |reference| hashBlob(hash, reference);
}

fn globalValues(value: GlobalRefsV4) [global_ref_count]artifact_store.BlobRefV1 {
    return .{
        value.capture_manifest,
        value.public_wire_manifest,
        value.compact_manifest,
        value.execution_profile_receipt,
        value.materialization_result,
        value.source_request,
        value.execution_journal,
        value.program,
        value.raw_input,
        value.expected_output,
    };
}

fn hashBlob(
    hash: *std.crypto.hash.sha2.Sha256,
    reference: artifact_store.BlobRefV1,
) void {
    hashInt(hash, u32, @intFromEnum(reference.kind));
    hashInt(hash, u16, reference.format_version);
    hashInt(hash, u16, reference.schema_version);
    hashInt(hash, u64, reference.byte_count);
    hash.update(&reference.sha256);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,
    failed: bool = false,

    fn raw(self: *Writer, value: []const u8) void {
        const end = std.math.add(usize, self.at, value.len) catch {
            self.failed = true;
            return;
        };
        if (end > self.bytes.len) {
            self.failed = true;
            return;
        }
        @memcpy(self.bytes[self.at..end], value);
        self.at = end;
    }

    fn int(self: *Writer, comptime T: type, value: T) void {
        var encoded: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &encoded, value, .little);
        self.raw(&encoded);
    }

    fn blob(self: *Writer, value: artifact_store.BlobRefV1) void {
        const bytes = value.canonicalBytes() catch {
            self.failed = true;
            return;
        };
        self.raw(&bytes);
    }

    fn input(self: *Writer, value: artifact_store.InputRefV1) void {
        self.int(u32, @intFromEnum(value.role));
        self.int(u32, value.ordinal);
        self.blob(value.blob);
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    failed: bool = false,

    fn take(self: *Reader, count: usize) ![]const u8 {
        const end = std.math.add(usize, self.at, count) catch
            return error.IncrementalCampaignTableCodecMismatchV4;
        if (end > self.bytes.len) {
            self.failed = true;
            return error.IncrementalCampaignTableCodecMismatchV4;
        }
        defer self.at = end;
        return self.bytes[self.at..end];
    }

    fn int(self: *Reader, comptime T: type) !T {
        const bytes = try self.take(@sizeOf(T));
        const fixed: *const [@sizeOf(T)]u8 = @ptrCast(bytes.ptr);
        return std.mem.readInt(T, fixed, .little);
    }

    fn array(self: *Reader, comptime count: usize) ![count]u8 {
        var result: [count]u8 = undefined;
        @memcpy(&result, try self.take(count));
        return result;
    }

    fn blob(self: *Reader) !artifact_store.BlobRefV1 {
        return artifact_store.BlobRefV1.decodeCanonical(
            try self.take(artifact_store.BlobRefV1.canonical_size),
        );
    }

    fn input(self: *Reader) !artifact_store.InputRefV1 {
        const result = artifact_store.InputRefV1{
            .role = @enumFromInt(try self.int(u32)),
            .ordinal = try self.int(u32),
            .blob = try self.blob(),
        };
        try result.validate();
        return result;
    }
};
