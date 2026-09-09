//! Canonical stage-101 replay recipe for one incremental Ethereum V4 leaf.
//!
//! The recipe binds every per-leaf transport consumed by native proving plus
//! the raw input/output objects and the two seal-last campaign manifests. It
//! is durable custody only: decoding it never verifies a proof, authenticates
//! a VM execution, or mints a live capture.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const publication = @import("ethereum_incremental_capture_publication_v4.zig");
const public_wire = @import("ethereum_incremental_public_wire_publication_v4.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const ARTIFACT_KIND = artifact_store.ArtifactKindV1.capture_transport;
pub const MIN_SEGMENT_COUNT: u32 = 2;
pub const MAX_SEGMENT_COUNT: u32 = publication.MAX_SEGMENT_COUNT;
/// Default bytes remain the current Ethereum conformance fixture. Generic
/// custody validation below accepts every authenticated protocol-bounded
/// campaign count and does not grant this fixture production authority.
pub const CURRENT_ETHEREUM_CONFORMANCE_SEGMENT_COUNT: u32 =
    publication.CANONICAL_SEGMENT_COUNT;
pub const MAGIC = [8]u8{ 'S', 'T', 'W', 'R', 'P', '1', '0', '1' };

const CONTENT_DOMAIN =
    "stwo-zig/recursive-pipeline-incremental-leaf-recipe/v1\x00";
const HEADER_BYTE_COUNT: usize = MAGIC.len + 2 * @sizeOf(u16) +
    @sizeOf(u32) + 2 * @sizeOf(u32);
const BLOB_REF_COUNT: usize = 10;
pub const ENCODED_BYTE_COUNT: usize = HEADER_BYTE_COUNT +
    BLOB_REF_COUNT * artifact_store.BlobRefV1.canonical_size + 32;

pub const Error = error{
    IncrementalLeafRecipeCodecMismatchV4,
    IncrementalLeafRecipeInputMismatchV4,
    InvalidIncrementalLeafRecipeV4,
};

/// `profile` input role 4 points to these bytes. The six other direct stage
/// inputs are repeated here so a recipe cannot be spliced across coordinates.
pub const RecipeV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    segment_index: u32,
    segment_count: u32 = CURRENT_ETHEREUM_CONFORMANCE_SEGMENT_COUNT,
    statement: artifact_store.BlobRefV1,
    program: artifact_store.BlobRefV1,
    compact_witness: artifact_store.BlobRefV1,
    boundary_v4: artifact_store.BlobRefV1,
    public_wire_reference_v4: artifact_store.BlobRefV1,
    journal_record: artifact_store.BlobRefV1,
    raw_input: artifact_store.BlobRefV1,
    expected_output: artifact_store.BlobRefV1,
    boundary_manifest_v4: artifact_store.BlobRefV1,
    public_wire_manifest_v4: artifact_store.BlobRefV1,
    content_sha256: [32]u8,

    pub fn seal(value: RecipeV4) Error!RecipeV4 {
        var result = value;
        result.content_sha256 = contentIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const RecipeV4) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.segment_count < MIN_SEGMENT_COUNT or
            self.segment_count > MAX_SEGMENT_COUNT or
            self.segment_index >= self.segment_count)
        {
            return error.InvalidIncrementalLeafRecipeV4;
        }
        inline for (.{
            self.statement,
            self.program,
            self.compact_witness,
            self.boundary_v4,
            self.public_wire_reference_v4,
            self.journal_record,
            self.raw_input,
            self.expected_output,
            self.boundary_manifest_v4,
            self.public_wire_manifest_v4,
        }) |reference| reference.validate() catch
            return error.InvalidIncrementalLeafRecipeV4;
        if (!codec(self.statement, .statement, 1) or
            !codec(self.program, .program, 1) or
            !codec(self.compact_witness, .capture_transport, 1) or
            !codec(self.boundary_v4, .capture_transport, 4) or
            !codec(
                self.public_wire_reference_v4,
                .capture_transport,
                public_wire.CAS_REFERENCE_SCHEMA_VERSION,
            ) or
            !codec(self.journal_record, .journal, 1) or
            !codec(self.raw_input, .raw, 1) or
            !codec(self.expected_output, .raw, 1) or
            !codec(self.boundary_manifest_v4, .capture_transport, 4) or
            !codec(
                self.public_wire_manifest_v4,
                .capture_transport,
                public_wire.CAS_MANIFEST_SCHEMA_VERSION,
            ) or
            !std.mem.eql(u8, &self.content_sha256, &contentIdentity(self)))
        {
            return error.InvalidIncrementalLeafRecipeV4;
        }
    }

    pub fn validateStageInputs(
        self: *const RecipeV4,
        inputs: []const artifact_store.InputRefV1,
        recipe_ref: artifact_store.BlobRefV1,
    ) Error!void {
        try self.validate();
        if (inputs.len != 7 or
            !inputEquals(inputs[0], .statement, 0, self.statement) or
            !inputEquals(inputs[1], .program, 0, self.program) or
            !inputEquals(inputs[2], .profile, 0, recipe_ref) or
            !inputEquals(inputs[3], .witness, 0, self.compact_witness) or
            !inputEquals(inputs[4], .capture, 0, self.boundary_v4) or
            !inputEquals(
                inputs[5],
                .capture,
                1,
                self.public_wire_reference_v4,
            ) or
            !inputEquals(inputs[6], .journal, 0, self.journal_record))
        {
            return error.IncrementalLeafRecipeInputMismatchV4;
        }
    }

    pub fn validateAgainstCampaignCount(
        self: *const RecipeV4,
        segment_count: u32,
    ) Error!void {
        try self.validate();
        if (self.segment_count != segment_count)
            return error.InvalidIncrementalLeafRecipeV4;
    }
};

pub fn encode(value: *const RecipeV4) Error![ENCODED_BYTE_COUNT]u8 {
    try value.validate();
    var bytes: [ENCODED_BYTE_COUNT]u8 = undefined;
    var writer = Writer{ .bytes = &bytes };
    writer.raw(&MAGIC);
    writer.int(u16, value.format_version);
    writer.int(u16, value.schema_version);
    writer.int(u32, 0);
    writer.int(u32, value.segment_index);
    writer.int(u32, value.segment_count);
    inline for (.{
        value.statement,
        value.program,
        value.compact_witness,
        value.boundary_v4,
        value.public_wire_reference_v4,
        value.journal_record,
        value.raw_input,
        value.expected_output,
        value.boundary_manifest_v4,
        value.public_wire_manifest_v4,
    }) |reference| writer.blob(reference);
    writer.raw(&value.content_sha256);
    if (writer.failed or writer.at != bytes.len)
        return error.IncrementalLeafRecipeCodecMismatchV4;
    return bytes;
}

pub fn decode(bytes: []const u8) Error!RecipeV4 {
    if (bytes.len != ENCODED_BYTE_COUNT)
        return error.IncrementalLeafRecipeCodecMismatchV4;
    var reader = Reader{ .bytes = bytes };
    if (!std.mem.eql(u8, reader.take(MAGIC.len), &MAGIC))
        return error.IncrementalLeafRecipeCodecMismatchV4;
    const format_version = reader.int(u16);
    const schema_version = reader.int(u16);
    if (reader.int(u32) != 0)
        return error.IncrementalLeafRecipeCodecMismatchV4;
    const result = RecipeV4{
        .format_version = format_version,
        .schema_version = schema_version,
        .segment_index = reader.int(u32),
        .segment_count = reader.int(u32),
        .statement = reader.blob(),
        .program = reader.blob(),
        .compact_witness = reader.blob(),
        .boundary_v4 = reader.blob(),
        .public_wire_reference_v4 = reader.blob(),
        .journal_record = reader.blob(),
        .raw_input = reader.blob(),
        .expected_output = reader.blob(),
        .boundary_manifest_v4 = reader.blob(),
        .public_wire_manifest_v4 = reader.blob(),
        .content_sha256 = reader.array(32),
    };
    if (reader.failed or reader.at != bytes.len)
        return error.IncrementalLeafRecipeCodecMismatchV4;
    try result.validate();
    const canonical = try encode(&result);
    if (!std.mem.eql(u8, bytes, &canonical))
        return error.IncrementalLeafRecipeCodecMismatchV4;
    return result;
}

fn contentIdentity(value: *const RecipeV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CONTENT_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.segment_index);
    hashInt(&hash, u32, value.segment_count);
    inline for (.{
        value.statement,
        value.program,
        value.compact_witness,
        value.boundary_v4,
        value.public_wire_reference_v4,
        value.journal_record,
        value.raw_input,
        value.expected_output,
        value.boundary_manifest_v4,
        value.public_wire_manifest_v4,
    }) |reference| hashBlob(&hash, reference);
    return hash.finalResult();
}

fn codec(
    reference: artifact_store.BlobRefV1,
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
) bool {
    return reference.kind == kind and reference.format_version == 1 and
        reference.schema_version == schema_version and reference.byte_count != 0;
}

fn inputEquals(
    input: artifact_store.InputRefV1,
    role: artifact_store.InputRoleV1,
    ordinal: u32,
    blob: artifact_store.BlobRefV1,
) bool {
    return input.role == role and input.ordinal == ordinal and
        artifact_store.BlobRefV1.eql(input.blob, blob);
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

    fn int(self: *Writer, comptime T: type, value: anytype) void {
        var encoded: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &encoded, @intCast(value), .little);
        self.raw(&encoded);
    }

    fn blob(self: *Writer, value: artifact_store.BlobRefV1) void {
        self.int(u32, @intFromEnum(value.kind));
        self.int(u16, value.format_version);
        self.int(u16, value.schema_version);
        self.int(u64, value.byte_count);
        self.raw(&value.sha256);
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    failed: bool = false,

    fn take(self: *Reader, count: usize) []const u8 {
        const end = std.math.add(usize, self.at, count) catch {
            self.failed = true;
            return &.{};
        };
        if (end > self.bytes.len) {
            self.failed = true;
            return &.{};
        }
        const result = self.bytes[self.at..end];
        self.at = end;
        return result;
    }

    fn int(self: *Reader, comptime T: type) T {
        const value = self.take(@sizeOf(T));
        if (value.len != @sizeOf(T)) return 0;
        return std.mem.readInt(T, value[0..@sizeOf(T)], .little);
    }

    fn array(self: *Reader, comptime count: usize) [count]u8 {
        var result: [count]u8 = .{0} ** count;
        const value = self.take(count);
        if (value.len == count) @memcpy(&result, value);
        return result;
    }

    fn blob(self: *Reader) artifact_store.BlobRefV1 {
        return .{
            .kind = @enumFromInt(self.int(u32)),
            .format_version = self.int(u16),
            .schema_version = self.int(u16),
            .byte_count = self.int(u64),
            .sha256 = self.array(32),
        };
    }
};

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 1 or
        CURRENT_ETHEREUM_CONFORMANCE_SEGMENT_COUNT !=
            publication.CANONICAL_SEGMENT_COUNT or
        MAX_SEGMENT_COUNT != publication.MAX_SEGMENT_COUNT or
        ENCODED_BYTE_COUNT != 536 or
        @intFromEnum(ARTIFACT_KIND) != 9 or
        public_wire.CAS_REFERENCE_SCHEMA_VERSION != 0x0402 or
        public_wire.CAS_MANIFEST_SCHEMA_VERSION != 0x0403)
    {
        @compileError("stage101 incremental leaf recipe drifted");
    }
}
