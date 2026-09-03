//! Create-only custody for one canonical 210-segment incremental capture.
//!
//! Segment transports are published as STWIMT02 followed by a small sealed
//! reference.  The session manifest is published only after every ordered
//! segment has been cold-reopened.  This module never turns those transports
//! into native-proof or recursion authority.

const std = @import("std");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const artifact_mod = @import("ethereum_incremental_boundary_artifact_v2.zig");

pub const SCHEMA = "stwo.ethereum.incremental-capture-publication.v1";
pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const CANONICAL_SEGMENT_COUNT: u32 = 210;
pub const PRODUCTION_ACTIVE = false;
pub const NATIVE_PROOF_ADMISSIBLE = false;
pub const RECURSIVE_ADMISSIBLE = false;

pub const SEGMENT_REF_MAGIC = [8]u8{ 'S', 'T', 'W', 'I', 'M', 'R', '0', '1' };
pub const MANIFEST_MAGIC = [8]u8{ 'S', 'T', 'W', 'I', 'M', 'F', '0', '1' };
pub const manifest_basename = "incremental-capture-manifest.stwimf01";

const segment_ref_domain =
    "stwo.ethereum.incremental-capture-segment-ref.v1\x00";
const manifest_domain =
    "stwo.ethereum.incremental-capture-manifest.v1\x00";
const session_domain =
    "stwo.ethereum.incremental-capture-session.v1\x00";
const wire_header_bytes: usize = 8 + 2 + 2 + 4;
const identity_bytes: usize = 8 + 32;
const segment_fields_bytes: usize = 192;
const segment_ref_bytes: usize = wire_header_bytes + segment_fields_bytes + 32;
const committed_segment_bytes: usize = segment_fields_bytes + identity_bytes;
const manifest_prefix_bytes: usize = wire_header_bytes + 4 * 4 + 32 * 3 +
    identity_bytes * 6;
const manifest_max_bytes: usize = manifest_prefix_bytes +
    committed_segment_bytes * CANONICAL_SEGMENT_COUNT + 32;
pub const segment_ref_byte_count = segment_ref_bytes;
pub const manifest_max_byte_count = manifest_max_bytes;

pub const ArtifactIdentityV1 = struct {
    byte_count: u64,
    sha256: [32]u8,

    pub fn fromBytes(bytes: []const u8) ArtifactIdentityV1 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        return .{ .byte_count = bytes.len, .sha256 = digest };
    }

    pub fn validate(self: ArtifactIdentityV1) !void {
        if (allZero(&self.sha256)) return error.InvalidPublicationIdentity;
    }
};

/// Immutable authorities common to every segment. Paths are deliberately not
/// authority: callers reopen these byte identities in their own custody root.
pub const SessionBindingsV1 = struct {
    compact_tape: ArtifactIdentityV1,
    source: ArtifactIdentityV1,
    journal: ArtifactIdentityV1,
    elf: ArtifactIdentityV1,
    input: ArtifactIdentityV1,
    output: ArtifactIdentityV1,

    pub fn validate(self: SessionBindingsV1) !void {
        inline for (.{
            self.compact_tape,
            self.source,
            self.journal,
            self.elf,
            self.input,
            self.output,
        }) |identity| try identity.validate();
    }

    /// This must be supplied to `SessionCaptureV2.init`; the publication owner
    /// later binds the capture's genesis predecessor and every transition.
    pub fn sessionIdentity(self: SessionBindingsV1) ![32]u8 {
        try self.validate();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(session_domain);
        hash.update(SCHEMA);
        putIntHash(&hash, u32, 0);
        putIntHash(&hash, u32, CANONICAL_SEGMENT_COUNT);
        inline for (.{
            self.compact_tape,
            self.source,
            self.journal,
            self.elf,
            self.input,
            self.output,
        }, 0..) |identity, role| {
            putIntHash(&hash, u32, @intCast(role));
            putIntHash(&hash, u64, identity.byte_count);
            hash.update(&identity.sha256);
        }
        var result: [32]u8 = undefined;
        hash.final(&result);
        return result;
    }
};

pub const SegmentRefV1 = struct {
    segment_index: u32,
    entry_root: u32,
    exit_root: u32,
    changed_word_count: u32,
    touched_word_count: u32,
    frontier_node_count: u32,
    entry_hash_calls: u64,
    exit_hash_calls: u64,
    total_hash_calls: u64,
    max_shard_log: u8,
    artifact: ArtifactIdentityV1,
    artifact_content_sha256: [32]u8,
    prior_authority_id: [32]u8,
    authority_id: [32]u8,

    pub fn validate(self: SegmentRefV1) !void {
        try self.artifact.validate();
        const expected_total = std.math.add(
            u64,
            self.entry_hash_calls,
            self.exit_hash_calls,
        ) catch return error.InvalidIncrementalSegmentRef;
        if (self.segment_index >= CANONICAL_SEGMENT_COUNT or
            self.touched_word_count < self.changed_word_count or
            expected_total != self.total_hash_calls or
            allZero(&self.artifact_content_sha256) or
            allZero(&self.prior_authority_id) or
            allZero(&self.authority_id))
        {
            return error.InvalidIncrementalSegmentRef;
        }
        if (self.touched_word_count == 0 and
            (self.frontier_node_count != 0 or self.changed_word_count != 0 or
                self.entry_root != self.exit_root or
                self.total_hash_calls != 0 or self.max_shard_log != 0))
        {
            return error.InvalidIncrementalSegmentRef;
        }
    }
};

pub const CommittedSegmentV1 = struct {
    segment: SegmentRefV1,
    reference: ArtifactIdentityV1,

    pub fn validate(self: CommittedSegmentV1) !void {
        try self.segment.validate();
        try self.reference.validate();
    }
};

pub const ManifestV1 = struct {
    bindings: SessionBindingsV1,
    session_identity: [32]u8,
    first_segment_index: u32,
    segment_count: u32,
    initial_root: u32,
    initial_prior_authority_id: [32]u8,
    final_root: u32,
    final_authority_id: [32]u8,
    segments: []const CommittedSegmentV1,
    content_sha256: [32]u8,

    pub fn validate(self: ManifestV1) !void {
        try self.bindings.validate();
        const expected_session = try self.bindings.sessionIdentity();
        if (!std.mem.eql(u8, &expected_session, &self.session_identity) or
            self.first_segment_index != 0 or
            self.segment_count != CANONICAL_SEGMENT_COUNT or
            self.segments.len != CANONICAL_SEGMENT_COUNT or
            allZero(&self.initial_prior_authority_id) or
            allZero(&self.final_authority_id) or
            allZero(&self.content_sha256))
        {
            return error.InvalidIncrementalCaptureManifest;
        }
        var expected_root = self.initial_root;
        var expected_prior = self.initial_prior_authority_id;
        for (self.segments, 0..) |committed, ordinal| {
            try committed.validate();
            const expected_index = std.math.cast(u32, ordinal) orelse
                return error.InvalidIncrementalCaptureManifest;
            if (committed.segment.segment_index != expected_index or
                committed.segment.entry_root != expected_root or
                !std.mem.eql(
                    u8,
                    &committed.segment.prior_authority_id,
                    &expected_prior,
                ))
            {
                return error.InvalidIncrementalCaptureChain;
            }
            expected_root = committed.segment.exit_root;
            expected_prior = committed.segment.authority_id;
        }
        if (expected_root != self.final_root or
            !std.mem.eql(u8, &expected_prior, &self.final_authority_id))
        {
            return error.InvalidIncrementalCaptureChain;
        }
    }

    pub fn validateAgainst(
        self: ManifestV1,
        expected: SessionBindingsV1,
    ) !void {
        try self.validate();
        if (!std.meta.eql(self.bindings, expected))
            return error.IncrementalCaptureBindingsMismatch;
    }
};

pub const OwnedManifestV1 = struct {
    allocator: std.mem.Allocator,
    value: ManifestV1,
    file: ArtifactIdentityV1,

    pub fn deinit(self: *OwnedManifestV1) void {
        self.allocator.free(self.value.segments);
        self.* = undefined;
    }
};

pub const OpenedSegmentV1 = struct {
    allocator: std.mem.Allocator,
    artifact_bytes: []u8,
    artifact: artifact_mod.OwnedArtifactV2,
    reference: CommittedSegmentV1,

    pub fn deinit(self: *OpenedSegmentV1) void {
        self.artifact.deinit();
        self.allocator.free(self.artifact_bytes);
        self.* = undefined;
    }
};

pub fn coldOpenPublication(
    allocator: std.mem.Allocator,
    root: []const u8,
    expected_bindings: SessionBindingsV1,
) !OwnedManifestV1 {
    const path = try manifestPathAlloc(allocator, root);
    defer allocator.free(path);
    const bytes = try artifact_io.readFileBounded(
        allocator,
        path,
        manifest_max_bytes,
    );
    defer allocator.free(bytes);
    var manifest = try decodeManifestAlloc(allocator, bytes);
    errdefer manifest.deinit();
    manifest.file = ArtifactIdentityV1.fromBytes(bytes);
    try manifest.value.validateAgainst(expected_bindings);
    for (manifest.value.segments) |committed| {
        var opened = try coldOpenSegment(
            allocator,
            root,
            committed.segment.segment_index,
            false,
        );
        defer opened.deinit();
        if (!std.meta.eql(opened.reference, committed))
            return error.IncrementalCaptureManifestReferenceMismatch;
    }
    return manifest;
}

pub fn encodeSegmentRefAlloc(
    allocator: std.mem.Allocator,
    value: SegmentRefV1,
) ![]u8 {
    try value.validate();
    const bytes = try allocator.alloc(u8, segment_ref_bytes);
    errdefer allocator.free(bytes);
    var writer = Writer{ .bytes = bytes };
    writeHeader(&writer, SEGMENT_REF_MAGIC);
    writeSegmentFields(&writer, value);
    const seal = contentIdentity(segment_ref_domain, bytes[0..writer.at]);
    writer.writeBytes(&seal);
    if (writer.at != bytes.len) return error.InvalidIncrementalSegmentRef;
    return bytes;
}

pub fn decodeSegmentRef(bytes: []const u8) !SegmentRefV1 {
    if (bytes.len != segment_ref_bytes)
        return error.InvalidIncrementalSegmentRef;
    var reader = Reader{ .bytes = bytes };
    try readHeader(&reader, SEGMENT_REF_MAGIC);
    const value = readSegmentFields(&reader);
    const expected = contentIdentity(segment_ref_domain, bytes[0..reader.at]);
    const retained = reader.readArray(32);
    if (reader.failed or reader.at != bytes.len or
        !std.mem.eql(u8, &expected, &retained))
    {
        return error.IncrementalSegmentRefContentMismatch;
    }
    try value.validate();
    return value;
}

pub fn encodeManifestAlloc(
    allocator: std.mem.Allocator,
    bindings: SessionBindingsV1,
    initial_root: u32,
    initial_prior_authority_id: [32]u8,
    final_root: u32,
    final_authority_id: [32]u8,
    segments: []const CommittedSegmentV1,
) ![]u8 {
    const session_identity = try bindings.sessionIdentity();
    const placeholder = ManifestV1{
        .bindings = bindings,
        .session_identity = session_identity,
        .first_segment_index = 0,
        .segment_count = CANONICAL_SEGMENT_COUNT,
        .initial_root = initial_root,
        .initial_prior_authority_id = initial_prior_authority_id,
        .final_root = final_root,
        .final_authority_id = final_authority_id,
        .segments = segments,
        .content_sha256 = [_]u8{1} ** 32,
    };
    try placeholder.validate();
    const bytes = try allocator.alloc(u8, manifest_max_bytes);
    errdefer allocator.free(bytes);
    var writer = Writer{ .bytes = bytes };
    writeHeader(&writer, MANIFEST_MAGIC);
    writer.writeInt(u32, 0);
    writer.writeInt(u32, CANONICAL_SEGMENT_COUNT);
    writer.writeInt(u32, initial_root);
    writer.writeInt(u32, final_root);
    writer.writeBytes(&session_identity);
    writer.writeBytes(&initial_prior_authority_id);
    writer.writeBytes(&final_authority_id);
    writeBindings(&writer, bindings);
    for (segments) |committed| {
        writeSegmentFields(&writer, committed.segment);
        writeIdentity(&writer, committed.reference);
    }
    const seal = contentIdentity(manifest_domain, bytes[0..writer.at]);
    writer.writeBytes(&seal);
    if (writer.at != bytes.len)
        return error.InvalidIncrementalCaptureManifest;
    return bytes;
}

pub fn decodeManifestAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !OwnedManifestV1 {
    if (bytes.len != manifest_max_bytes)
        return error.InvalidIncrementalCaptureManifest;
    var reader = Reader{ .bytes = bytes };
    try readHeader(&reader, MANIFEST_MAGIC);
    const first_segment_index = reader.readInt(u32);
    const segment_count = reader.readInt(u32);
    const initial_root = reader.readInt(u32);
    const final_root = reader.readInt(u32);
    const session_identity = reader.readArray(32);
    const initial_prior_authority_id = reader.readArray(32);
    const final_authority_id = reader.readArray(32);
    const bindings = readBindings(&reader);
    if (segment_count != CANONICAL_SEGMENT_COUNT)
        return error.InvalidIncrementalCaptureManifest;
    const segments = try allocator.alloc(CommittedSegmentV1, segment_count);
    errdefer allocator.free(segments);
    for (segments) |*committed| committed.* = .{
        .segment = readSegmentFields(&reader),
        .reference = readIdentity(&reader),
    };
    const expected = contentIdentity(manifest_domain, bytes[0..reader.at]);
    const retained = reader.readArray(32);
    if (reader.failed or reader.at != bytes.len or
        !std.mem.eql(u8, &expected, &retained))
    {
        return error.IncrementalCaptureManifestContentMismatch;
    }
    var result = OwnedManifestV1{
        .allocator = allocator,
        .value = .{
            .bindings = bindings,
            .session_identity = session_identity,
            .first_segment_index = first_segment_index,
            .segment_count = segment_count,
            .initial_root = initial_root,
            .initial_prior_authority_id = initial_prior_authority_id,
            .final_root = final_root,
            .final_authority_id = final_authority_id,
            .segments = segments,
            .content_sha256 = retained,
        },
        .file = ArtifactIdentityV1.fromBytes(bytes),
    };
    errdefer result.deinit();
    try result.value.validate();
    return result;
}

pub fn segmentArtifactPathAlloc(
    allocator: std.mem.Allocator,
    root: []const u8,
    index: u32,
) ![]u8 {
    const basename = try std.fmt.allocPrint(
        allocator,
        "segment-{d:0>6}.stwimt02",
        .{index},
    );
    defer allocator.free(basename);
    return std.fs.path.join(allocator, &.{ root, basename });
}

pub fn segmentReferencePathAlloc(
    allocator: std.mem.Allocator,
    root: []const u8,
    index: u32,
) ![]u8 {
    const basename = try std.fmt.allocPrint(
        allocator,
        "segment-{d:0>6}.stwimr01",
        .{index},
    );
    defer allocator.free(basename);
    return std.fs.path.join(allocator, &.{ root, basename });
}

pub fn manifestPathAlloc(
    allocator: std.mem.Allocator,
    root: []const u8,
) ![]u8 {
    return std.fs.path.join(allocator, &.{ root, manifest_basename });
}

pub fn coldOpenSegment(
    allocator: std.mem.Allocator,
    root: []const u8,
    segment_index: u32,
    publish_missing_ref: bool,
) !OpenedSegmentV1 {
    const artifact_path = try segmentArtifactPathAlloc(
        allocator,
        root,
        segment_index,
    );
    defer allocator.free(artifact_path);
    const artifact_bytes = try artifact_io.readFileBounded(
        allocator,
        artifact_path,
        artifact_mod.default_limits.max_bytes,
    );
    errdefer allocator.free(artifact_bytes);
    var artifact = try artifact_mod.decodeAlloc(
        allocator,
        artifact_bytes,
        artifact_mod.default_limits,
    );
    errdefer artifact.deinit();
    if (artifact.authority.segment_index != segment_index)
        return error.SegmentIndexMismatch;
    const expected_ref = segmentRefFromArtifact(
        &artifact,
        ArtifactIdentityV1.fromBytes(artifact_bytes),
    );
    const expected_encoded = try encodeSegmentRefAlloc(allocator, expected_ref);
    defer allocator.free(expected_encoded);
    const reference_path = try segmentReferencePathAlloc(
        allocator,
        root,
        segment_index,
    );
    defer allocator.free(reference_path);
    const retained_ref = artifact_io.readFileBounded(
        allocator,
        reference_path,
        segment_ref_bytes,
    ) catch |err| switch (err) {
        error.FileNotFound => if (publish_missing_ref) missing: {
            try artifact_io.publishCreateOnlyDurable(
                reference_path,
                expected_encoded,
            );
            break :missing try allocator.dupe(u8, expected_encoded);
        } else return err,
        else => return err,
    };
    defer allocator.free(retained_ref);
    if (!std.mem.eql(u8, retained_ref, expected_encoded))
        return error.IncrementalCaptureSegmentRefMismatch;
    const decoded_ref = try decodeSegmentRef(retained_ref);
    if (!std.meta.eql(decoded_ref, expected_ref))
        return error.IncrementalCaptureSegmentRefMismatch;
    return .{
        .allocator = allocator,
        .artifact_bytes = artifact_bytes,
        .artifact = artifact,
        .reference = .{
            .segment = decoded_ref,
            .reference = ArtifactIdentityV1.fromBytes(retained_ref),
        },
    };
}

fn segmentRefFromArtifact(
    artifact: *const artifact_mod.OwnedArtifactV2,
    file: ArtifactIdentityV1,
) SegmentRefV1 {
    const authority = artifact.authority;
    return .{
        .segment_index = authority.segment_index,
        .entry_root = authority.entry_root,
        .exit_root = authority.exit_root,
        .changed_word_count = authority.changed_word_count,
        .touched_word_count = @intCast(authority.touched_words.len),
        .frontier_node_count = @intCast(authority.frontier_nodes.len),
        .entry_hash_calls = authority.work.entry_hash_calls,
        .exit_hash_calls = authority.work.exit_hash_calls,
        .total_hash_calls = authority.work.total_hash_calls,
        .max_shard_log = authority.work.max_shard_log,
        .artifact = file,
        .artifact_content_sha256 = artifact.content_sha256,
        .prior_authority_id = authority.prior_authority_id,
        .authority_id = authority.authority_id,
    };
}

fn writeHeader(writer: *Writer, magic: [8]u8) void {
    writer.writeBytes(&magic);
    writer.writeInt(u16, FORMAT_VERSION);
    writer.writeInt(u16, SCHEMA_VERSION);
    writer.writeInt(u32, 0);
}

fn readHeader(reader: *Reader, magic: [8]u8) !void {
    if (!std.mem.eql(u8, reader.readBytes(8), &magic) or
        reader.readInt(u16) != FORMAT_VERSION or
        reader.readInt(u16) != SCHEMA_VERSION or
        reader.readInt(u32) != 0 or reader.failed)
    {
        return error.InvalidIncrementalCaptureWireHeader;
    }
}

fn writeSegmentFields(writer: *Writer, value: SegmentRefV1) void {
    writer.writeInt(u32, value.segment_index);
    writer.writeInt(u32, value.entry_root);
    writer.writeInt(u32, value.exit_root);
    writer.writeInt(u32, value.changed_word_count);
    writer.writeInt(u32, value.touched_word_count);
    writer.writeInt(u32, value.frontier_node_count);
    writer.writeInt(u64, value.entry_hash_calls);
    writer.writeInt(u64, value.exit_hash_calls);
    writer.writeInt(u64, value.total_hash_calls);
    writer.writeByte(value.max_shard_log);
    writer.writeBytes(&([_]u8{0} ** 7));
    writeIdentity(writer, value.artifact);
    writer.writeBytes(&value.artifact_content_sha256);
    writer.writeBytes(&value.prior_authority_id);
    writer.writeBytes(&value.authority_id);
}

fn readSegmentFields(reader: *Reader) SegmentRefV1 {
    const result = SegmentRefV1{
        .segment_index = reader.readInt(u32),
        .entry_root = reader.readInt(u32),
        .exit_root = reader.readInt(u32),
        .changed_word_count = reader.readInt(u32),
        .touched_word_count = reader.readInt(u32),
        .frontier_node_count = reader.readInt(u32),
        .entry_hash_calls = reader.readInt(u64),
        .exit_hash_calls = reader.readInt(u64),
        .total_hash_calls = reader.readInt(u64),
        .max_shard_log = reader.readByte(),
        .artifact = undefined,
        .artifact_content_sha256 = undefined,
        .prior_authority_id = undefined,
        .authority_id = undefined,
    };
    if (!allZero(reader.readBytes(7))) reader.failed = true;
    var mutable = result;
    mutable.artifact = readIdentity(reader);
    mutable.artifact_content_sha256 = reader.readArray(32);
    mutable.prior_authority_id = reader.readArray(32);
    mutable.authority_id = reader.readArray(32);
    return mutable;
}

fn writeBindings(writer: *Writer, value: SessionBindingsV1) void {
    inline for (.{
        value.compact_tape,
        value.source,
        value.journal,
        value.elf,
        value.input,
        value.output,
    }) |identity| writeIdentity(writer, identity);
}

fn readBindings(reader: *Reader) SessionBindingsV1 {
    return .{
        .compact_tape = readIdentity(reader),
        .source = readIdentity(reader),
        .journal = readIdentity(reader),
        .elf = readIdentity(reader),
        .input = readIdentity(reader),
        .output = readIdentity(reader),
    };
}

fn writeIdentity(writer: *Writer, value: ArtifactIdentityV1) void {
    writer.writeInt(u64, value.byte_count);
    writer.writeBytes(&value.sha256);
}

fn readIdentity(reader: *Reader) ArtifactIdentityV1 {
    return .{
        .byte_count = reader.readInt(u64),
        .sha256 = reader.readArray(32),
    };
}

pub fn pathExists(path: []const u8, max_bytes: usize) !bool {
    _ = max_bytes;
    if (std.fs.accessAbsolute(path, .{})) |_| return true else |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    }
}

pub fn requireAbsent(path: []const u8, max_bytes: usize) !void {
    if (try pathExists(path, max_bytes)) return error.PathAlreadyExists;
}

fn contentIdentity(domain: []const u8, bytes: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    hash.update(bytes);
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn allZero(bytes: []const u8) bool {
    var merged: u8 = 0;
    for (bytes) |value| merged |= value;
    return merged == 0;
}

fn putIntHash(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn writeByte(self: *Writer, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }

    fn writeBytes(self: *Writer, values: []const u8) void {
        @memcpy(self.bytes[self.at..][0..values.len], values);
        self.at += values.len;
    }

    fn writeInt(self: *Writer, comptime T: type, value: T) void {
        std.mem.writeInt(T, self.bytes[self.at..][0..@sizeOf(T)], value, .little);
        self.at += @sizeOf(T);
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

    fn readByte(self: *Reader) u8 {
        const bytes = self.take(1);
        return if (bytes.len == 1) bytes[0] else 0;
    }

    fn readBytes(self: *Reader, count: usize) []const u8 {
        return self.take(count);
    }

    fn readArray(self: *Reader, comptime count: usize) [count]u8 {
        var result = [_]u8{0} ** count;
        const bytes = self.take(count);
        if (bytes.len == count) @memcpy(&result, bytes);
        return result;
    }

    fn readInt(self: *Reader, comptime T: type) T {
        const bytes = self.take(@sizeOf(T));
        return if (bytes.len == @sizeOf(T))
            std.mem.readInt(T, bytes[0..@sizeOf(T)], .little)
        else
            0;
    }
};

comptime {
    if (segment_ref_bytes != 240 or manifest_max_bytes != 49_120)
        @compileError("incremental capture publication wire size drifted");
}
