//! Durable companion custody for the canonical SegmentV2 public wire.
//!
//! STWIMT04 authenticates the wire identity but deliberately does not embed
//! the variable-length canonical words. This transport retains those exact
//! M31 words without changing any STWIMT04/STWIMR04 byte. Each STWIPR04 binds
//! its wire to the corresponding V4 segment reference, STWESG31 source, and
//! journal record. STWIPF04 is published only after the V4 manifest exists.
//!
//! This is replay transport only. Authentication reconstructs PublicDataV2;
//! it never serializes proof freshness or activates native/recursive proving.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");

const M31 = core.fields.m31.M31;
const m31 = core.fields.m31;
const public_data_v2 = frontend.air.public_data_v2;
const global_v3 = frontend.recursion.segment_leaf_local_authority_v3;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 4;
pub const CANONICAL_SEGMENT_COUNT = publication.CANONICAL_SEGMENT_COUNT;
pub const PRODUCTION_ACTIVE = false;
pub const PROOF_ADMISSIBLE = false;
pub const RECURSIVE_ADMISSIBLE = false;
/// Unique shared-CAS codecs. All three are replay/input transport (kind 9),
/// while the native file header remains schema 4.
pub const CAS_ARTIFACT_KIND: u32 = 9;
pub const CAS_WIRE_SCHEMA_VERSION: u16 = 0x0401;
pub const CAS_REFERENCE_SCHEMA_VERSION: u16 = 0x0402;
pub const CAS_MANIFEST_SCHEMA_VERSION: u16 = 0x0403;

pub const WIRE_MAGIC = [8]u8{ 'S', 'T', 'W', 'I', 'P', 'W', '0', '4' };
pub const REF_MAGIC = [8]u8{ 'S', 'T', 'W', 'I', 'P', 'R', '0', '4' };
pub const MANIFEST_MAGIC = [8]u8{ 'S', 'T', 'W', 'I', 'P', 'F', '0', '4' };
pub const manifest_basename = "incremental-public-wire-manifest.stwipf04";

const wire_domain = "stwo.ethereum.incremental-public-wire.v4\x00";
const ref_domain = "stwo.ethereum.incremental-public-wire-ref.v4\x00";
const manifest_domain = "stwo.ethereum.incremental-public-wire-manifest.v4\x00";
const header_bytes: usize = 8 + 2 + 2 + 4;
const identity_bytes: usize = 8 + 32;
const seal_bytes: usize = 32;
const wire_fixed_bytes: usize = header_bytes + 2 * 4 + 8 + 8 * 4 + seal_bytes;
const ref_fields_bytes: usize = 2 * 4 + 8 * 4 + 3 * identity_bytes + 32;
const reference_wire_bytes: usize = header_bytes + ref_fields_bytes + seal_bytes;
const execution_bytes: usize = 3 * identity_bytes + 32 + 4 + 8 + 4 + 4;
const final_bindings_bytes: usize = 5 * identity_bytes;
const committed_bytes: usize = ref_fields_bytes + identity_bytes;
const manifest_fixed_bytes: usize = header_bytes + execution_bytes +
    final_bindings_bytes + identity_bytes + 4 + 4 + seal_bytes;

pub const max_wire_bytes: usize = 768 * 1024 * 1024;
pub const max_wire_words: usize = (max_wire_bytes - wire_fixed_bytes) / 4;
pub const reference_byte_count = reference_wire_bytes;
pub const manifest_max_byte_count = manifest_fixed_bytes +
    committed_bytes * publication.MAX_SEGMENT_COUNT;

pub const CoordinateV4 = struct {
    segment_index: u32,
    segment_count: u32,

    pub fn validate(self: CoordinateV4) !void {
        if (self.segment_count < 2 or
            self.segment_count > publication.MAX_SEGMENT_COUNT or
            self.segment_index >= self.segment_count)
        {
            return error.InvalidIncrementalPublicWireCoordinateV4;
        }
    }
};

pub const OwnedWireV4 = struct {
    allocator: std.mem.Allocator,
    coordinate: CoordinateV4,
    words: []M31,
    data: public_data_v2.PublicDataV2,
    content_sha256: [32]u8,

    pub fn deinit(self: *OwnedWireV4) void {
        self.allocator.free(self.words);
        self.* = undefined;
    }

    pub fn validate(self: *const OwnedWireV4) !void {
        try self.coordinate.validate();
        if (self.data.words().ptr != self.words.ptr or
            self.data.words().len != self.words.len)
        {
            return error.IncrementalPublicWireBackingMismatchV4;
        }
        try self.data.validate();
        const encoded = try encodeWireAlloc(
            self.allocator,
            self.coordinate,
            &self.data,
        );
        defer self.allocator.free(encoded);
        if (!std.mem.eql(
            u8,
            encoded[encoded.len - seal_bytes ..],
            &self.content_sha256,
        )) return error.IncrementalPublicWireContentMismatchV4;
    }
};

pub const SegmentRefV4 = struct {
    coordinate: CoordinateV4,
    wire_id: public_data_v2.Digest,
    wire_artifact: publication.ArtifactIdentityV4,
    v4_segment_reference: publication.ArtifactIdentityV4,
    source: publication.ArtifactIdentityV4,
    journal_record_sha256: [32]u8,

    pub fn validate(self: SegmentRefV4) !void {
        try self.coordinate.validate();
        try self.wire_artifact.validate(false);
        try self.v4_segment_reference.validate(false);
        try self.source.validate(false);
        for (self.wire_id) |word| if (word >= m31.Modulus)
            return error.InvalidIncrementalPublicWireRefV4;
        if (allZero(std.mem.asBytes(&self.wire_id)) or
            allZero(&self.journal_record_sha256))
        {
            return error.InvalidIncrementalPublicWireRefV4;
        }
    }
};

pub const CommittedSegmentV4 = struct {
    segment: SegmentRefV4,
    reference: publication.ArtifactIdentityV4,

    pub fn validate(self: CommittedSegmentV4) !void {
        try self.segment.validate();
        try self.reference.validate(false);
    }
};

pub const ManifestV4 = struct {
    execution: publication.ExecutionAuthorityV4,
    final_bindings: publication.FinalBindingsV4,
    v4_manifest: publication.ArtifactIdentityV4,
    segment_count: u32,
    segments: []const CommittedSegmentV4,
    content_sha256: [32]u8,

    pub fn validate(self: ManifestV4) !void {
        try self.execution.validate();
        try self.final_bindings.validate();
        try self.v4_manifest.validate(false);
        if (self.segment_count != self.execution.segment_count or
            self.segments.len != self.segment_count or
            allZero(&self.content_sha256))
        {
            return error.InvalidIncrementalPublicWireManifestV4;
        }
        for (self.segments, 0..) |committed, ordinal| {
            try committed.validate();
            if (committed.segment.coordinate.segment_index != ordinal or
                committed.segment.coordinate.segment_count != self.segment_count)
            {
                return error.InvalidIncrementalPublicWireManifestOrderV4;
            }
        }
    }

    pub fn validateAgainst(
        self: ManifestV4,
        execution: publication.ExecutionAuthorityV4,
        final_bindings: publication.FinalBindingsV4,
        v4_manifest: publication.ArtifactIdentityV4,
    ) !void {
        try self.validate();
        if (!std.meta.eql(self.execution, execution) or
            !std.meta.eql(self.final_bindings, final_bindings) or
            !std.meta.eql(self.v4_manifest, v4_manifest))
        {
            return error.IncrementalPublicWireManifestBindingsMismatchV4;
        }
    }
};

pub const OwnedManifestV4 = struct {
    allocator: std.mem.Allocator,
    value: ManifestV4,
    file: publication.ArtifactIdentityV4,

    pub fn deinit(self: *OwnedManifestV4) void {
        self.allocator.free(self.value.segments);
        self.* = undefined;
    }
};

pub const OpenedSegmentV4 = struct {
    allocator: std.mem.Allocator,
    wire_bytes: []u8,
    wire: OwnedWireV4,
    reference: CommittedSegmentV4,

    pub fn deinit(self: *OpenedSegmentV4) void {
        self.wire.deinit();
        self.allocator.free(self.wire_bytes);
        self.* = undefined;
    }
};

pub fn encodeWireAlloc(
    allocator: std.mem.Allocator,
    coordinate: CoordinateV4,
    data: *const public_data_v2.PublicDataV2,
) ![]u8 {
    try coordinate.validate();
    try data.validate();
    const words = data.words();
    if (words.len == 0 or words.len > max_wire_words)
        return error.InvalidIncrementalPublicWireLengthV4;
    const byte_count = try wireByteCount(words.len);
    const bytes = try allocator.alloc(u8, byte_count);
    errdefer allocator.free(bytes);
    var writer = Writer{ .bytes = bytes };
    writeHeader(&writer, WIRE_MAGIC);
    writer.int(u32, coordinate.segment_index);
    writer.int(u32, coordinate.segment_count);
    writer.int(u64, words.len);
    for (data.wireId()) |word| writer.int(u32, word);
    for (words) |word| writer.int(u32, word.toU32());
    writer.raw(&contentIdentity(wire_domain, bytes[0..writer.at]));
    if (writer.failed or writer.at != bytes.len)
        return error.InvalidIncrementalPublicWireLengthV4;
    return bytes;
}

pub fn decodeWireAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !OwnedWireV4 {
    return decodeWireAllocWithRetained(allocator, bytes, null);
}

/// Cold-open the public wire while reusing the two continuation roots from
/// its independently authenticated STWESG31 metadata. The wire still replays
/// all sparse tuple IDs/counts, clock maps, fixed statement fields, and its
/// complete content/wire identities.
pub fn decodeWireAllocAgainstRetainedMetadata(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    retained: *const global_v3.MetadataV3,
) !OwnedWireV4 {
    try retained.validate();
    return decodeWireAllocWithRetained(allocator, bytes, retained);
}

fn decodeWireAllocWithRetained(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    retained_metadata: ?*const global_v3.MetadataV3,
) !OwnedWireV4 {
    if (bytes.len < wire_fixed_bytes or bytes.len > max_wire_bytes)
        return error.InvalidIncrementalPublicWireLengthV4;
    var reader = Reader{ .bytes = bytes };
    try readHeader(&reader, WIRE_MAGIC);
    const coordinate = CoordinateV4{
        .segment_index = reader.int(u32),
        .segment_count = reader.int(u32),
    };
    try coordinate.validate();
    const word_count_u64 = reader.int(u64);
    const word_count = std.math.cast(usize, word_count_u64) orelse
        return error.InvalidIncrementalPublicWireLengthV4;
    if (word_count == 0 or word_count > max_wire_words or
        try wireByteCount(word_count) != bytes.len)
    {
        return error.InvalidIncrementalPublicWireLengthV4;
    }
    var retained_wire_id: public_data_v2.Digest = undefined;
    for (&retained_wire_id) |*word| word.* = reader.int(u32);
    const words = try allocator.alloc(M31, word_count);
    errdefer allocator.free(words);
    for (words) |*word| {
        const raw = reader.int(u32);
        if (raw >= m31.Modulus) return error.NonCanonicalIncrementalPublicWireM31;
        word.* = M31.fromCanonical(raw);
    }
    const expected = contentIdentity(wire_domain, bytes[0..reader.at]);
    const retained = reader.array(32);
    if (reader.failed or reader.at != bytes.len or
        !std.mem.eql(u8, &expected, &retained))
    {
        return error.IncrementalPublicWireContentMismatchV4;
    }
    if (retained_metadata) |metadata| {
        if (coordinate.segment_index != metadata.segment_index or
            coordinate.segment_count != metadata.segment_count)
        {
            return error.InvalidIncrementalPublicWireCoordinateV4;
        }
    }
    const data = if (retained_metadata) |metadata|
        try public_data_v2.PublicDataV2.authenticateReusingRoots(words, .{
            .entry = .{
                .id = metadata.entry.snapshot_id,
                .count = metadata.entry.snapshot_count,
                .root = metadata.entry.continuation_root,
            },
            .exit = .{
                .id = metadata.exit.snapshot_id,
                .count = metadata.exit.snapshot_count,
                .root = metadata.exit.continuation_root,
            },
        })
    else
        try public_data_v2.PublicDataV2.authenticate(words);
    if (!std.meta.eql(data.wireId(), retained_wire_id))
        return error.IncrementalPublicWireIdentityMismatchV4;
    return .{
        .allocator = allocator,
        .coordinate = coordinate,
        .words = words,
        .data = data,
        .content_sha256 = retained,
    };
}

pub fn encodeSegmentRefAlloc(
    allocator: std.mem.Allocator,
    value: SegmentRefV4,
) ![]u8 {
    try value.validate();
    const bytes = try allocator.alloc(u8, reference_wire_bytes);
    errdefer allocator.free(bytes);
    var writer = Writer{ .bytes = bytes };
    writeHeader(&writer, REF_MAGIC);
    writeRefFields(&writer, value);
    writer.raw(&contentIdentity(ref_domain, bytes[0..writer.at]));
    if (writer.failed or writer.at != bytes.len)
        return error.InvalidIncrementalPublicWireRefV4;
    return bytes;
}

pub fn decodeSegmentRef(bytes: []const u8) !SegmentRefV4 {
    if (bytes.len != reference_wire_bytes)
        return error.InvalidIncrementalPublicWireRefV4;
    var reader = Reader{ .bytes = bytes };
    try readHeader(&reader, REF_MAGIC);
    const value = readRefFields(&reader);
    const expected = contentIdentity(ref_domain, bytes[0..reader.at]);
    const retained = reader.array(32);
    if (reader.failed or reader.at != bytes.len or
        !std.mem.eql(u8, &expected, &retained))
    {
        return error.IncrementalPublicWireRefContentMismatchV4;
    }
    try value.validate();
    return value;
}

pub fn encodeManifestAlloc(
    allocator: std.mem.Allocator,
    execution: publication.ExecutionAuthorityV4,
    final_bindings: publication.FinalBindingsV4,
    v4_manifest: publication.ArtifactIdentityV4,
    segments: []const CommittedSegmentV4,
) ![]u8 {
    const placeholder = ManifestV4{
        .execution = execution,
        .final_bindings = final_bindings,
        .v4_manifest = v4_manifest,
        .segment_count = execution.segment_count,
        .segments = segments,
        .content_sha256 = [_]u8{1} ** 32,
    };
    try placeholder.validate();
    const byte_count = try manifestByteCount(execution.segment_count);
    const bytes = try allocator.alloc(u8, byte_count);
    errdefer allocator.free(bytes);
    var writer = Writer{ .bytes = bytes };
    writeHeader(&writer, MANIFEST_MAGIC);
    writeExecution(&writer, execution);
    writeFinalBindings(&writer, final_bindings);
    writeIdentity(&writer, v4_manifest);
    writer.int(u32, execution.segment_count);
    writer.int(u32, 0);
    for (segments) |committed| {
        writeRefFields(&writer, committed.segment);
        writeIdentity(&writer, committed.reference);
    }
    writer.raw(&contentIdentity(manifest_domain, bytes[0..writer.at]));
    if (writer.failed or writer.at != bytes.len)
        return error.InvalidIncrementalPublicWireManifestV4;
    return bytes;
}

pub fn decodeManifestAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !OwnedManifestV4 {
    if (bytes.len < try manifestByteCount(2) or
        bytes.len > manifest_max_byte_count)
    {
        return error.InvalidIncrementalPublicWireManifestV4;
    }
    var reader = Reader{ .bytes = bytes };
    try readHeader(&reader, MANIFEST_MAGIC);
    const execution = readExecution(&reader);
    const final_bindings = readFinalBindings(&reader);
    const v4_manifest = readIdentity(&reader);
    const segment_count = reader.int(u32);
    if (reader.int(u32) != 0 or segment_count < 2 or
        segment_count > publication.MAX_SEGMENT_COUNT or
        try manifestByteCount(segment_count) != bytes.len)
    {
        return error.InvalidIncrementalPublicWireManifestV4;
    }
    const segments = try allocator.alloc(CommittedSegmentV4, segment_count);
    errdefer allocator.free(segments);
    for (segments) |*committed| committed.* = .{
        .segment = readRefFields(&reader),
        .reference = readIdentity(&reader),
    };
    const expected = contentIdentity(manifest_domain, bytes[0..reader.at]);
    const retained = reader.array(32);
    if (reader.failed or reader.at != bytes.len or
        !std.mem.eql(u8, &expected, &retained))
    {
        return error.IncrementalPublicWireManifestContentMismatchV4;
    }
    var result = OwnedManifestV4{
        .allocator = allocator,
        .value = .{
            .execution = execution,
            .final_bindings = final_bindings,
            .v4_manifest = v4_manifest,
            .segment_count = segment_count,
            .segments = segments,
            .content_sha256 = retained,
        },
        .file = publication.ArtifactIdentityV4.fromBytes(bytes),
    };
    errdefer result.deinit();
    try result.value.validate();
    return result;
}

pub fn coldOpenSegment(
    allocator: std.mem.Allocator,
    root: []const u8,
    segment_index: u32,
    expected_v4: publication.CommittedSegmentV4,
) !OpenedSegmentV4 {
    try expected_v4.validate();
    if (expected_v4.segment.segment_index != segment_index)
        return error.SegmentIndexMismatch;
    const v4_ref_path = try publication.segmentReferencePathAlloc(
        allocator,
        root,
        segment_index,
    );
    defer allocator.free(v4_ref_path);
    const v4_ref_bytes = try artifact_io.readFileBounded(
        allocator,
        v4_ref_path,
        publication.segment_ref_byte_count,
    );
    defer allocator.free(v4_ref_bytes);
    const reopened_v4 = publication.CommittedSegmentV4{
        .segment = try publication.decodeSegmentRef(v4_ref_bytes),
        .reference = publication.ArtifactIdentityV4.fromBytes(v4_ref_bytes),
    };
    if (!std.meta.eql(reopened_v4, expected_v4))
        return error.IncrementalPublicWireV4SegmentReferenceMismatch;
    const wire_path = try wirePathAlloc(allocator, root, segment_index);
    defer allocator.free(wire_path);
    const wire_bytes = try artifact_io.readFileBounded(
        allocator,
        wire_path,
        max_wire_bytes,
    );
    errdefer allocator.free(wire_bytes);
    var wire = try decodeWireAlloc(allocator, wire_bytes);
    errdefer wire.deinit();
    const ref_path = try referencePathAlloc(allocator, root, segment_index);
    defer allocator.free(ref_path);
    const retained_ref = try artifact_io.readFileBounded(
        allocator,
        ref_path,
        reference_wire_bytes,
    );
    defer allocator.free(retained_ref);
    const reference = CommittedSegmentV4{
        .segment = try decodeSegmentRef(retained_ref),
        .reference = publication.ArtifactIdentityV4.fromBytes(retained_ref),
    };
    try reference.validate();
    if (!std.meta.eql(reference.segment.coordinate, wire.coordinate) or
        !std.meta.eql(reference.segment.wire_id, wire.data.wireId()) or
        !std.meta.eql(
            reference.segment.wire_artifact,
            publication.ArtifactIdentityV4.fromBytes(wire_bytes),
        ) or !std.meta.eql(
        reference.segment.v4_segment_reference,
        reopened_v4.reference,
    ) or !std.meta.eql(
        reference.segment.source,
        reopened_v4.segment.source,
    ) or !std.mem.eql(
        u8,
        &reference.segment.journal_record_sha256,
        &reopened_v4.segment.journal_record_sha256,
    ) or !std.meta.eql(
        reference.segment.wire_id,
        reopened_v4.segment.segment_public_wire_id,
    )) return error.IncrementalPublicWireSegmentBindingMismatchV4;
    return .{
        .allocator = allocator,
        .wire_bytes = wire_bytes,
        .wire = wire,
        .reference = reference,
    };
}

pub fn coldOpenPublication(
    allocator: std.mem.Allocator,
    root: []const u8,
    execution: publication.ExecutionAuthorityV4,
    final_bindings: publication.FinalBindingsV4,
    v4_manifest_identity: publication.ArtifactIdentityV4,
) !OwnedManifestV4 {
    const v4_path = try publication.manifestPathAlloc(allocator, root);
    defer allocator.free(v4_path);
    const v4_bytes = try artifact_io.readFileBounded(
        allocator,
        v4_path,
        publication.manifest_max_byte_count,
    );
    defer allocator.free(v4_bytes);
    if (!std.meta.eql(
        publication.ArtifactIdentityV4.fromBytes(v4_bytes),
        v4_manifest_identity,
    )) return error.IncrementalPublicWireV4ManifestIdentityMismatch;
    var v4_manifest = try publication.decodeManifestAlloc(allocator, v4_bytes);
    defer v4_manifest.deinit();
    try v4_manifest.value.validateAgainst(execution, final_bindings);

    const path = try manifestPathAlloc(allocator, root);
    defer allocator.free(path);
    const bytes = try artifact_io.readFileBounded(
        allocator,
        path,
        manifest_max_byte_count,
    );
    defer allocator.free(bytes);
    var manifest = try decodeManifestAlloc(allocator, bytes);
    errdefer manifest.deinit();
    try manifest.value.validateAgainst(
        execution,
        final_bindings,
        v4_manifest_identity,
    );
    for (manifest.value.segments, v4_manifest.value.segments) |
        committed,
        expected_v4,
    | {
        var opened = try coldOpenSegment(
            allocator,
            root,
            committed.segment.coordinate.segment_index,
            expected_v4,
        );
        defer opened.deinit();
        if (!std.meta.eql(opened.reference, committed))
            return error.IncrementalPublicWireManifestReferenceMismatchV4;
    }
    return manifest;
}

pub fn wirePathAlloc(
    allocator: std.mem.Allocator,
    root: []const u8,
    index: u32,
) ![]u8 {
    return indexedPathAlloc(allocator, root, index, "stwipw04");
}

pub fn referencePathAlloc(
    allocator: std.mem.Allocator,
    root: []const u8,
    index: u32,
) ![]u8 {
    return indexedPathAlloc(allocator, root, index, "stwipr04");
}

pub fn manifestPathAlloc(
    allocator: std.mem.Allocator,
    root: []const u8,
) ![]u8 {
    return std.fs.path.join(allocator, &.{ root, manifest_basename });
}

fn indexedPathAlloc(
    allocator: std.mem.Allocator,
    root: []const u8,
    index: u32,
    suffix: []const u8,
) ![]u8 {
    const basename = try std.fmt.allocPrint(
        allocator,
        "segment-{d:0>6}.{s}",
        .{ index, suffix },
    );
    defer allocator.free(basename);
    return std.fs.path.join(allocator, &.{ root, basename });
}

fn wireByteCount(word_count: usize) !usize {
    return std.math.add(
        usize,
        wire_fixed_bytes,
        try std.math.mul(usize, word_count, 4),
    );
}

fn manifestByteCount(segment_count: u32) !usize {
    if (segment_count < 2 or segment_count > publication.MAX_SEGMENT_COUNT)
        return error.InvalidIncrementalPublicWireManifestV4;
    return std.math.add(
        usize,
        manifest_fixed_bytes,
        try std.math.mul(usize, segment_count, committed_bytes),
    );
}

fn writeHeader(writer: *Writer, magic: [8]u8) void {
    writer.raw(&magic);
    writer.int(u16, FORMAT_VERSION);
    writer.int(u16, SCHEMA_VERSION);
    writer.int(u32, 0);
}

fn readHeader(reader: *Reader, magic: [8]u8) !void {
    if (!std.mem.eql(u8, reader.bytesSlice(8), &magic) or
        reader.int(u16) != FORMAT_VERSION or
        reader.int(u16) != SCHEMA_VERSION or
        reader.int(u32) != 0 or reader.failed)
    {
        return error.InvalidIncrementalPublicWireHeaderV4;
    }
}

fn writeRefFields(writer: *Writer, value: SegmentRefV4) void {
    writer.int(u32, value.coordinate.segment_index);
    writer.int(u32, value.coordinate.segment_count);
    for (value.wire_id) |word| writer.int(u32, word);
    writeIdentity(writer, value.wire_artifact);
    writeIdentity(writer, value.v4_segment_reference);
    writeIdentity(writer, value.source);
    writer.raw(&value.journal_record_sha256);
}

fn readRefFields(reader: *Reader) SegmentRefV4 {
    var value = SegmentRefV4{
        .coordinate = .{
            .segment_index = reader.int(u32),
            .segment_count = reader.int(u32),
        },
        .wire_id = undefined,
        .wire_artifact = undefined,
        .v4_segment_reference = undefined,
        .source = undefined,
        .journal_record_sha256 = undefined,
    };
    for (&value.wire_id) |*word| word.* = reader.int(u32);
    value.wire_artifact = readIdentity(reader);
    value.v4_segment_reference = readIdentity(reader);
    value.source = readIdentity(reader);
    value.journal_record_sha256 = reader.array(32);
    return value;
}

fn writeExecution(
    writer: *Writer,
    value: publication.ExecutionAuthorityV4,
) void {
    writeIdentity(writer, value.elf);
    writeIdentity(writer, value.input);
    writeIdentity(writer, value.expected_output);
    writer.raw(&value.execution_profile_semantic_sha256);
    writer.int(u32, value.segment_count);
    writer.int(u64, value.segment_step_budget);
    writer.int(u32, value.clock_frame);
    writer.int(u32, value.strict_completion);
}

fn readExecution(reader: *Reader) publication.ExecutionAuthorityV4 {
    return .{
        .elf = readIdentity(reader),
        .input = readIdentity(reader),
        .expected_output = readIdentity(reader),
        .execution_profile_semantic_sha256 = reader.array(32),
        .segment_count = reader.int(u32),
        .segment_step_budget = reader.int(u64),
        .clock_frame = reader.int(u32),
        .strict_completion = reader.int(u32),
    };
}

fn writeFinalBindings(
    writer: *Writer,
    value: publication.FinalBindingsV4,
) void {
    inline for (.{
        value.compact_manifest,
        value.materialization_result,
        value.source_request,
        value.journal,
        value.execution_profile_receipt,
    }) |identity| writeIdentity(writer, identity);
}

fn readFinalBindings(reader: *Reader) publication.FinalBindingsV4 {
    return .{
        .compact_manifest = readIdentity(reader),
        .materialization_result = readIdentity(reader),
        .source_request = readIdentity(reader),
        .journal = readIdentity(reader),
        .execution_profile_receipt = readIdentity(reader),
    };
}

fn writeIdentity(
    writer: *Writer,
    value: publication.ArtifactIdentityV4,
) void {
    writer.int(u64, value.byte_count);
    writer.raw(&value.sha256);
}

fn readIdentity(reader: *Reader) publication.ArtifactIdentityV4 {
    return .{ .byte_count = reader.int(u64), .sha256 = reader.array(32) };
}

fn contentIdentity(domain: []const u8, bytes: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    hash.update(bytes);
    return hash.finalResult();
}

fn allZero(bytes: []const u8) bool {
    var merged: u8 = 0;
    for (bytes) |value| merged |= value;
    return merged == 0;
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
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    failed: bool = false,

    fn bytesSlice(self: *Reader, count: usize) []const u8 {
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
        const bytes = self.bytesSlice(@sizeOf(T));
        if (bytes.len != @sizeOf(T)) return 0;
        return std.mem.readInt(T, bytes[0..@sizeOf(T)], .little);
    }

    fn array(self: *Reader, comptime count: usize) [count]u8 {
        var result: [count]u8 = .{0} ** count;
        const bytes = self.bytesSlice(count);
        if (bytes.len == count) @memcpy(&result, bytes);
        return result;
    }
};

comptime {
    if (reference_wire_bytes != 240 or
        manifest_max_byte_count != 49_188 or
        @sizeOf(public_data_v2.Digest) != 32)
    {
        @compileError("incremental public-wire V4 wire geometry drifted");
    }
}
