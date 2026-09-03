//! Canonical create-only custody for one retained-authority incremental run.
//! Each segment is published in the strict order STWEMT01, STWIMT04, then
//! STWIMR04.  The fixed manifest is sealed only after all ordered segment
//! transports have been independently reopened.  The retained materialization
//! and source files remain the global-position authority; none of these
//! transport seals constitutes native-proof or recursive admission.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const artifact_v4 = @import("ethereum_incremental_boundary_artifact_v4.zig");

pub const SCHEMA = "stwo.ethereum.incremental-capture-publication.v4";
pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 4;
pub const CANONICAL_SEGMENT_COUNT: u32 = 210;
pub const MAX_SEGMENT_COUNT: u32 = CANONICAL_SEGMENT_COUNT;
pub const PRODUCTION_ACTIVE = false;
pub const NATIVE_PROOF_ADMISSIBLE = false;
pub const RECURSIVE_ADMISSIBLE = false;
pub const DURABLE_VM_RESTORE_AVAILABLE = false;
pub const PREFIX_VM_REEXECUTION_REQUIRED = true;
pub const SEGMENT_REF_MAGIC = [8]u8{ 'S', 'T', 'W', 'I', 'M', 'R', '0', '4' };
pub const MANIFEST_MAGIC = [8]u8{ 'S', 'T', 'W', 'I', 'M', 'F', '0', '4' };
pub const manifest_basename = "incremental-capture-manifest.stwimf04";

const segment_ref_domain =
    "stwo.ethereum.incremental-capture-segment-ref.v4\x00";
const manifest_domain =
    "stwo.ethereum.incremental-capture-manifest.v4\x00";
const session_domain =
    "stwo.ethereum.incremental-capture-session.v4\x00";
const wire_header_bytes: usize = 8 + 2 + 2 + 4;
const identity_bytes: usize = 8 + 32;
const segment_fields_bytes: usize = 372;
const segment_ref_bytes: usize = wire_header_bytes + segment_fields_bytes + 32;
const committed_segment_bytes: usize = segment_fields_bytes + identity_bytes;
const execution_fields_bytes: usize = identity_bytes * 3 + 32 + 4 + 8 + 4 + 4;
const final_binding_fields_bytes: usize = identity_bytes * 5;
const manifest_prefix_bytes: usize = wire_header_bytes + execution_fields_bytes +
    final_binding_fields_bytes + 6 * 4 + 32 * 2;
const manifest_max_bytes: usize = manifest_prefix_bytes +
    committed_segment_bytes * MAX_SEGMENT_COUNT + 32;
pub const segment_ref_byte_count = segment_ref_bytes;
pub const manifest_max_byte_count = manifest_max_bytes;
pub const ArtifactIdentityV4 = struct {
    byte_count: u64,
    sha256: [32]u8,

    pub fn fromBytes(bytes: []const u8) ArtifactIdentityV4 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        return .{ .byte_count = bytes.len, .sha256 = digest };
    }

    pub fn validate(self: ArtifactIdentityV4, allow_empty: bool) !void {
        if ((!allow_empty and self.byte_count == 0) or allZero(&self.sha256))
            return error.InvalidIncrementalPublicationIdentity;
    }
};

/// Immutable authorities known before the one deterministic execution starts.
/// Paths, timestamps, and host power state deliberately are not authority.
pub const ExecutionAuthorityV4 = struct {
    elf: ArtifactIdentityV4,
    input: ArtifactIdentityV4,
    expected_output: ArtifactIdentityV4,
    execution_profile_semantic_sha256: [32]u8,
    segment_count: u32,
    segment_step_budget: u64,
    clock_frame: u32 = @intFromEnum(frontend.runner.SegmentClockFrame.leaf_local),
    strict_completion: u32 = 1,

    pub fn validate(self: ExecutionAuthorityV4) !void {
        try self.elf.validate(false);
        try self.input.validate(true);
        try self.expected_output.validate(false);
        if (allZero(&self.execution_profile_semantic_sha256) or
            self.segment_count < 2 or self.segment_count > MAX_SEGMENT_COUNT or
            self.segment_step_budget == 0 or
            self.clock_frame != @intFromEnum(
                frontend.runner.SegmentClockFrame.leaf_local,
            ) or self.strict_completion != 1)
        {
            return error.InvalidIncrementalExecutionAuthority;
        }
    }

    pub fn sessionIdentity(self: ExecutionAuthorityV4) ![32]u8 {
        try self.validate();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(session_domain);
        hash.update(SCHEMA);
        writeIdentityHash(&hash, 0, self.elf);
        writeIdentityHash(&hash, 1, self.input);
        writeIdentityHash(&hash, 2, self.expected_output);
        hash.update(&self.execution_profile_semantic_sha256);
        putIntHash(&hash, u32, self.segment_count);
        putIntHash(&hash, u64, self.segment_step_budget);
        putIntHash(&hash, u32, self.clock_frame);
        putIntHash(&hash, u32, self.strict_completion);
        return hash.finalResult();
    }
};

/// Authorities available only after the execution journal, compact receipt,
/// and terminal materialization have been cold-reopened.
pub const FinalBindingsV4 = struct {
    compact_manifest: ArtifactIdentityV4,
    materialization_result: ArtifactIdentityV4,
    source_request: ArtifactIdentityV4,
    journal: ArtifactIdentityV4,
    execution_profile_receipt: ArtifactIdentityV4,

    pub fn validate(self: FinalBindingsV4) !void {
        inline for (.{
            self.compact_manifest,
            self.materialization_result,
            self.source_request,
            self.journal,
            self.execution_profile_receipt,
        }) |identity| try identity.validate(false);
    }
};

pub const SegmentRefV4 = struct {
    segment_index: u32,
    segment_count: u32,
    entry_root: u32,
    exit_root: u32,
    touched_word_count: u32,
    changed_word_count: u32,
    frontier_node_count: u32,
    entry_hash_calls: u64,
    exit_hash_calls: u64,
    total_hash_calls: u64,
    max_shard_log: u8,
    artifact: ArtifactIdentityV4,
    compact_tape: ArtifactIdentityV4,
    source: ArtifactIdentityV4,
    artifact_content_sha256: [32]u8,
    transition_v2_content_sha256: [32]u8,
    segment_public_wire_id: [8]u32,
    journal_record_sha256: [32]u8,
    prior_authority_id: [32]u8,
    authority_id: [32]u8,

    pub fn validate(self: SegmentRefV4) !void {
        try self.artifact.validate(false);
        try self.compact_tape.validate(false);
        try self.source.validate(false);
        const expected_total = std.math.add(
            u64,
            self.entry_hash_calls,
            self.exit_hash_calls,
        ) catch return error.InvalidIncrementalSegmentRefV4;
        if (self.segment_count < 2 or self.segment_count > MAX_SEGMENT_COUNT or
            self.segment_index >= self.segment_count or
            self.touched_word_count < self.changed_word_count or
            expected_total != self.total_hash_calls or
            allZero(&self.artifact_content_sha256) or
            allZero(&self.transition_v2_content_sha256) or
            allZero(std.mem.asBytes(&self.segment_public_wire_id)) or
            allZero(&self.journal_record_sha256) or
            allZero(&self.prior_authority_id) or allZero(&self.authority_id))
        {
            return error.InvalidIncrementalSegmentRefV4;
        }
        if (self.touched_word_count == 0 and
            (self.changed_word_count != 0 or self.frontier_node_count != 0 or
                self.entry_root != self.exit_root or
                self.total_hash_calls != 0 or self.max_shard_log != 0))
        {
            return error.InvalidIncrementalSegmentRefV4;
        }
    }
};

pub const CommittedSegmentV4 = struct {
    segment: SegmentRefV4,
    reference: ArtifactIdentityV4,

    pub fn validate(self: CommittedSegmentV4) !void {
        try self.segment.validate();
        try self.reference.validate(false);
    }
};

pub const ManifestV4 = struct {
    execution: ExecutionAuthorityV4,
    final_bindings: FinalBindingsV4,
    session_identity: [32]u8,
    first_segment_index: u32,
    segment_count: u32,
    initial_root: u32,
    final_root: u32,
    initial_prior_authority_id: [32]u8,
    final_authority_id: [32]u8,
    durable_vm_restore_available: u32,
    prefix_vm_reexecution_required: u32,
    segments: []const CommittedSegmentV4,
    content_sha256: [32]u8,

    pub fn validate(self: ManifestV4) !void {
        try self.execution.validate();
        try self.final_bindings.validate();
        const session = try self.execution.sessionIdentity();
        if (!std.mem.eql(u8, &session, &self.session_identity) or
            self.first_segment_index != 0 or
            self.segment_count != self.execution.segment_count or
            self.segments.len != self.segment_count or
            self.durable_vm_restore_available != 0 or
            self.prefix_vm_reexecution_required != 1 or
            allZero(&self.initial_prior_authority_id) or
            allZero(&self.final_authority_id) or
            allZero(&self.content_sha256))
        {
            return error.InvalidIncrementalCaptureManifestV4;
        }
        var expected_root = self.initial_root;
        var expected_prior = self.initial_prior_authority_id;
        for (self.segments, 0..) |committed, ordinal| {
            try committed.validate();
            if (committed.segment.segment_index != ordinal or
                committed.segment.segment_count != self.segment_count or
                committed.segment.entry_root != expected_root or
                !std.mem.eql(
                    u8,
                    &committed.segment.prior_authority_id,
                    &expected_prior,
                ))
            {
                return error.InvalidIncrementalCaptureChainV4;
            }
            expected_root = committed.segment.exit_root;
            expected_prior = committed.segment.authority_id;
        }
        if (expected_root != self.final_root or
            !std.mem.eql(u8, &expected_prior, &self.final_authority_id))
        {
            return error.InvalidIncrementalCaptureChainV4;
        }
    }

    pub fn validateAgainst(
        self: ManifestV4,
        execution: ExecutionAuthorityV4,
        final_bindings: FinalBindingsV4,
    ) !void {
        try self.validate();
        if (!std.meta.eql(self.execution, execution) or
            !std.meta.eql(self.final_bindings, final_bindings))
        {
            return error.IncrementalCaptureBindingsMismatchV4;
        }
    }
};

pub const OwnedManifestV4 = struct {
    allocator: std.mem.Allocator,
    value: ManifestV4,
    file: ArtifactIdentityV4,

    pub fn deinit(self: *OwnedManifestV4) void {
        self.allocator.free(self.value.segments);
        self.* = undefined;
    }
};

pub const OpenedSegmentV4 = struct {
    allocator: std.mem.Allocator,
    compact_bytes: []u8,
    artifact_bytes: []u8,
    artifact: artifact_v4.OwnedArtifactV4,
    reference: CommittedSegmentV4,

    pub fn deinit(self: *OpenedSegmentV4) void {
        self.artifact.deinit();
        self.allocator.free(self.artifact_bytes);
        self.allocator.free(self.compact_bytes);
        self.* = undefined;
    }
};

pub fn encodeSegmentRefAlloc(
    allocator: std.mem.Allocator,
    value: SegmentRefV4,
) ![]u8 {
    try value.validate();
    const bytes = try allocator.alloc(u8, segment_ref_bytes);
    errdefer allocator.free(bytes);
    var writer = Writer{ .bytes = bytes };
    writeHeader(&writer, SEGMENT_REF_MAGIC);
    writeSegmentFields(&writer, value);
    writer.writeBytes(&contentIdentity(segment_ref_domain, bytes[0..writer.at]));
    if (writer.at != bytes.len) return error.InvalidIncrementalSegmentRefV4;
    return bytes;
}

pub fn decodeSegmentRef(bytes: []const u8) !SegmentRefV4 {
    if (bytes.len != segment_ref_bytes)
        return error.InvalidIncrementalSegmentRefV4;
    var reader = Reader{ .bytes = bytes };
    try readHeader(&reader, SEGMENT_REF_MAGIC);
    const result = readSegmentFields(&reader);
    const expected = contentIdentity(segment_ref_domain, bytes[0..reader.at]);
    const retained = reader.readArray(32);
    if (reader.failed or reader.at != bytes.len or
        !std.mem.eql(u8, &expected, &retained))
    {
        return error.IncrementalSegmentRefContentMismatchV4;
    }
    try result.validate();
    return result;
}

pub fn encodeManifestAlloc(
    allocator: std.mem.Allocator,
    execution: ExecutionAuthorityV4,
    final_bindings: FinalBindingsV4,
    initial_root: u32,
    initial_prior_authority_id: [32]u8,
    final_root: u32,
    final_authority_id: [32]u8,
    segments: []const CommittedSegmentV4,
) ![]u8 {
    const session_identity = try execution.sessionIdentity();
    const placeholder = ManifestV4{
        .execution = execution,
        .final_bindings = final_bindings,
        .session_identity = session_identity,
        .first_segment_index = 0,
        .segment_count = execution.segment_count,
        .initial_root = initial_root,
        .final_root = final_root,
        .initial_prior_authority_id = initial_prior_authority_id,
        .final_authority_id = final_authority_id,
        .durable_vm_restore_available = 0,
        .prefix_vm_reexecution_required = 1,
        .segments = segments,
        .content_sha256 = [_]u8{1} ** 32,
    };
    try placeholder.validate();
    const byte_count = manifestByteCount(execution.segment_count) catch
        return error.InvalidIncrementalCaptureManifestV4;
    const bytes = try allocator.alloc(u8, byte_count);
    errdefer allocator.free(bytes);
    var writer = Writer{ .bytes = bytes };
    writeHeader(&writer, MANIFEST_MAGIC);
    writeExecution(&writer, execution);
    writeFinalBindings(&writer, final_bindings);
    writer.writeInt(u32, 0);
    writer.writeInt(u32, execution.segment_count);
    writer.writeInt(u32, initial_root);
    writer.writeInt(u32, final_root);
    writer.writeBytes(&initial_prior_authority_id);
    writer.writeBytes(&final_authority_id);
    writer.writeInt(u32, 0);
    writer.writeInt(u32, 1);
    for (segments) |committed| {
        writeSegmentFields(&writer, committed.segment);
        writeIdentity(&writer, committed.reference);
    }
    writer.writeBytes(&contentIdentity(manifest_domain, bytes[0..writer.at]));
    if (writer.at != bytes.len)
        return error.InvalidIncrementalCaptureManifestV4;
    return bytes;
}

pub fn decodeManifestAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !OwnedManifestV4 {
    if (bytes.len < manifestByteCount(2) catch unreachable or
        bytes.len > manifest_max_bytes)
    {
        return error.InvalidIncrementalCaptureManifestV4;
    }
    var reader = Reader{ .bytes = bytes };
    try readHeader(&reader, MANIFEST_MAGIC);
    const execution = readExecution(&reader);
    const final_bindings = readFinalBindings(&reader);
    const first_segment_index = reader.readInt(u32);
    const segment_count = reader.readInt(u32);
    const initial_root = reader.readInt(u32);
    const final_root = reader.readInt(u32);
    const initial_prior_authority_id = reader.readArray(32);
    const final_authority_id = reader.readArray(32);
    const durable_vm_restore_available = reader.readInt(u32);
    const prefix_vm_reexecution_required = reader.readInt(u32);
    if (segment_count < 2 or segment_count > MAX_SEGMENT_COUNT or
        manifestByteCount(segment_count) catch 0 != bytes.len)
    {
        return error.InvalidIncrementalCaptureManifestV4;
    }
    const segments = try allocator.alloc(CommittedSegmentV4, segment_count);
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
        return error.IncrementalCaptureManifestContentMismatchV4;
    }
    var result = OwnedManifestV4{
        .allocator = allocator,
        .value = .{
            .execution = execution,
            .final_bindings = final_bindings,
            .session_identity = try execution.sessionIdentity(),
            .first_segment_index = first_segment_index,
            .segment_count = segment_count,
            .initial_root = initial_root,
            .final_root = final_root,
            .initial_prior_authority_id = initial_prior_authority_id,
            .final_authority_id = final_authority_id,
            .durable_vm_restore_available = durable_vm_restore_available,
            .prefix_vm_reexecution_required = prefix_vm_reexecution_required,
            .segments = segments,
            .content_sha256 = retained,
        },
        .file = ArtifactIdentityV4.fromBytes(bytes),
    };
    errdefer result.deinit();
    try result.value.validate();
    return result;
}

pub fn coldOpenPublication(
    allocator: std.mem.Allocator,
    root: []const u8,
    execution: ExecutionAuthorityV4,
    final_bindings: FinalBindingsV4,
) !OwnedManifestV4 {
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
    manifest.file = ArtifactIdentityV4.fromBytes(bytes);
    try manifest.value.validateAgainst(execution, final_bindings);
    for (manifest.value.segments) |committed| {
        var opened = try coldOpenSegment(
            allocator,
            root,
            committed.segment.segment_index,
            false,
        );
        defer opened.deinit();
        if (!std.meta.eql(opened.reference, committed))
            return error.IncrementalCaptureManifestReferenceMismatchV4;
    }
    return manifest;
}

pub fn coldOpenSegment(
    allocator: std.mem.Allocator,
    root: []const u8,
    segment_index: u32,
    publish_missing_ref: bool,
) !OpenedSegmentV4 {
    const compact_path = try compactTapePathAlloc(allocator, root, segment_index);
    defer allocator.free(compact_path);
    const compact_bytes = try artifact_io.readFileBounded(
        allocator,
        compact_path,
        frontend.runner.minimal_trace.ethereum_wire.MAX_ENCODED_BYTES,
    );
    errdefer allocator.free(compact_bytes);
    var compact = try frontend.runner.minimal_trace
        .decodeEthereumMinimalArtifactAlloc(allocator, compact_bytes);
    defer compact.deinit();
    if (compact.leaf.segment_index != segment_index)
        return error.SegmentIndexMismatch;
    const artifact_path = try segmentArtifactPathAlloc(allocator, root, segment_index);
    defer allocator.free(artifact_path);
    const artifact_bytes = try artifact_io.readFileBounded(
        allocator,
        artifact_path,
        artifact_v4.default_limits.max_bytes,
    );
    errdefer allocator.free(artifact_bytes);
    var artifact = try artifact_v4.decodeAlloc(
        allocator,
        artifact_bytes,
        artifact_v4.default_limits,
    );
    errdefer artifact.deinit();
    if (artifact.coordinate.segment_index != segment_index)
        return error.SegmentIndexMismatch;

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
        error.FileNotFound => if (publish_missing_ref)
            return error.IncrementalCaptureRefNeedsExpectedAuthorityV4
        else
            return err,
        else => return err,
    };
    defer allocator.free(retained_ref);
    const decoded_ref = try decodeSegmentRef(retained_ref);
    if (!std.meta.eql(
        decoded_ref.artifact,
        ArtifactIdentityV4.fromBytes(artifact_bytes),
    ) or !std.meta.eql(
        decoded_ref.compact_tape,
        ArtifactIdentityV4.fromBytes(compact_bytes),
    ) or !std.mem.eql(
        u8,
        &decoded_ref.artifact_content_sha256,
        &artifact.content_sha256,
    ) or !std.mem.eql(
        u8,
        &decoded_ref.transition_v2_content_sha256,
        &artifact.transition_v2.content_sha256,
    ) or !std.meta.eql(
        decoded_ref.segment_public_wire_id,
        artifact.segment_public_wire_id,
    )) return error.IncrementalCaptureSegmentRefMismatchV4;
    return .{
        .allocator = allocator,
        .compact_bytes = compact_bytes,
        .artifact_bytes = artifact_bytes,
        .artifact = artifact,
        .reference = .{
            .segment = decoded_ref,
            .reference = ArtifactIdentityV4.fromBytes(retained_ref),
        },
    };
}

pub fn compactTapePathAlloc(
    allocator: std.mem.Allocator,
    root: []const u8,
    index: u32,
) ![]u8 {
    return indexedPathAlloc(allocator, root, index, "stwemt01");
}

pub fn segmentArtifactPathAlloc(
    allocator: std.mem.Allocator,
    root: []const u8,
    index: u32,
) ![]u8 {
    return indexedPathAlloc(allocator, root, index, "stwimt04");
}

pub fn segmentReferencePathAlloc(
    allocator: std.mem.Allocator,
    root: []const u8,
    index: u32,
) ![]u8 {
    return indexedPathAlloc(allocator, root, index, "stwimr04");
}

pub fn manifestPathAlloc(
    allocator: std.mem.Allocator,
    root: []const u8,
) ![]u8 {
    return std.fs.path.join(allocator, &.{ root, manifest_basename });
}

pub fn pathExists(path: []const u8) !bool {
    if (std.fs.accessAbsolute(path, .{})) |_| return true else |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    }
}

pub fn requireAbsent(path: []const u8) !void {
    if (try pathExists(path)) return error.PathAlreadyExists;
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

fn manifestByteCount(segment_count: u32) !usize {
    if (segment_count < 2 or segment_count > MAX_SEGMENT_COUNT)
        return error.InvalidIncrementalCaptureManifestV4;
    return std.math.add(
        usize,
        manifest_prefix_bytes + 32,
        try std.math.mul(
            usize,
            committed_segment_bytes,
            @intCast(segment_count),
        ),
    );
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
        return error.InvalidIncrementalCaptureWireHeaderV4;
    }
}

fn writeExecution(writer: *Writer, value: ExecutionAuthorityV4) void {
    writeIdentity(writer, value.elf);
    writeIdentity(writer, value.input);
    writeIdentity(writer, value.expected_output);
    writer.writeBytes(&value.execution_profile_semantic_sha256);
    writer.writeInt(u32, value.segment_count);
    writer.writeInt(u64, value.segment_step_budget);
    writer.writeInt(u32, value.clock_frame);
    writer.writeInt(u32, value.strict_completion);
}

fn readExecution(reader: *Reader) ExecutionAuthorityV4 {
    return .{
        .elf = readIdentity(reader),
        .input = readIdentity(reader),
        .expected_output = readIdentity(reader),
        .execution_profile_semantic_sha256 = reader.readArray(32),
        .segment_count = reader.readInt(u32),
        .segment_step_budget = reader.readInt(u64),
        .clock_frame = reader.readInt(u32),
        .strict_completion = reader.readInt(u32),
    };
}

fn writeFinalBindings(writer: *Writer, value: FinalBindingsV4) void {
    inline for (.{
        value.compact_manifest,
        value.materialization_result,
        value.source_request,
        value.journal,
        value.execution_profile_receipt,
    }) |identity| writeIdentity(writer, identity);
}

fn readFinalBindings(reader: *Reader) FinalBindingsV4 {
    return .{
        .compact_manifest = readIdentity(reader),
        .materialization_result = readIdentity(reader),
        .source_request = readIdentity(reader),
        .journal = readIdentity(reader),
        .execution_profile_receipt = readIdentity(reader),
    };
}

fn writeSegmentFields(writer: *Writer, value: SegmentRefV4) void {
    writer.writeInt(u32, value.segment_index);
    writer.writeInt(u32, value.segment_count);
    writer.writeInt(u32, value.entry_root);
    writer.writeInt(u32, value.exit_root);
    writer.writeInt(u32, value.touched_word_count);
    writer.writeInt(u32, value.changed_word_count);
    writer.writeInt(u32, value.frontier_node_count);
    writer.writeInt(u64, value.entry_hash_calls);
    writer.writeInt(u64, value.exit_hash_calls);
    writer.writeInt(u64, value.total_hash_calls);
    writer.writeByte(value.max_shard_log);
    writer.writeBytes(&([_]u8{0} ** 7));
    writeIdentity(writer, value.artifact);
    writeIdentity(writer, value.compact_tape);
    writeIdentity(writer, value.source);
    writer.writeBytes(&value.artifact_content_sha256);
    writer.writeBytes(&value.transition_v2_content_sha256);
    for (value.segment_public_wire_id) |word| writer.writeInt(u32, word);
    writer.writeBytes(&value.journal_record_sha256);
    writer.writeBytes(&value.prior_authority_id);
    writer.writeBytes(&value.authority_id);
}

fn readSegmentFields(reader: *Reader) SegmentRefV4 {
    var result = SegmentRefV4{
        .segment_index = reader.readInt(u32),
        .segment_count = reader.readInt(u32),
        .entry_root = reader.readInt(u32),
        .exit_root = reader.readInt(u32),
        .touched_word_count = reader.readInt(u32),
        .changed_word_count = reader.readInt(u32),
        .frontier_node_count = reader.readInt(u32),
        .entry_hash_calls = reader.readInt(u64),
        .exit_hash_calls = reader.readInt(u64),
        .total_hash_calls = reader.readInt(u64),
        .max_shard_log = reader.readByte(),
        .artifact = undefined,
        .compact_tape = undefined,
        .source = undefined,
        .artifact_content_sha256 = undefined,
        .transition_v2_content_sha256 = undefined,
        .segment_public_wire_id = undefined,
        .journal_record_sha256 = undefined,
        .prior_authority_id = undefined,
        .authority_id = undefined,
    };
    if (!allZero(reader.readBytes(7))) reader.failed = true;
    result.artifact = readIdentity(reader);
    result.compact_tape = readIdentity(reader);
    result.source = readIdentity(reader);
    result.artifact_content_sha256 = reader.readArray(32);
    result.transition_v2_content_sha256 = reader.readArray(32);
    for (&result.segment_public_wire_id) |*word| word.* = reader.readInt(u32);
    result.journal_record_sha256 = reader.readArray(32);
    result.prior_authority_id = reader.readArray(32);
    result.authority_id = reader.readArray(32);
    return result;
}

fn writeIdentity(writer: *Writer, value: ArtifactIdentityV4) void {
    writer.writeInt(u64, value.byte_count);
    writer.writeBytes(&value.sha256);
}

fn readIdentity(reader: *Reader) ArtifactIdentityV4 {
    return .{
        .byte_count = reader.readInt(u64),
        .sha256 = reader.readArray(32),
    };
}

fn writeIdentityHash(
    hash: *std.crypto.hash.sha2.Sha256,
    role: u32,
    identity: ArtifactIdentityV4,
) void {
    putIntHash(hash, u32, role);
    putIntHash(hash, u64, identity.byte_count);
    hash.update(&identity.sha256);
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
    if (segment_ref_bytes != 420 or manifest_max_bytes != 87_028)
        @compileError("incremental V4 publication wire size drifted");
}
