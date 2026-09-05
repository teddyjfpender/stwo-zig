//! Durable schema-2 recursive node envelope for the field-native public ABI.
//!
//! Poseidon digests are the recursive proof semantics. SHA-256 authenticates
//! canonical transport bytes and CAS references only; no SHA digest in this
//! envelope is presented to a recursive AIR as a proved relation.

const std = @import("std");

const v1 = @import("recursive_node_artifact_v1.zig");
const field_public = @import("recursive_field_node_public_v2.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 2;
pub const PRODUCTION_ACTIVATION = false;
pub const RECURSIVE_NODE_ARTIFACT_KIND = v1.RECURSIVE_NODE_ARTIFACT_KIND;
pub const MAX_CHILD_COUNT = v1.MAX_CHILD_COUNT;
pub const IDENTITY_COUNT: usize = 9;
pub const ENCODED_BYTE_COUNT: usize = 2380;

const SEMANTIC_INPUTS_DOMAIN =
    "stwo-zig/recursive-node-semantic-inputs/v2\x00";
const CONTENT_IDENTITY_DOMAIN =
    "stwo-zig/recursive-node-artifact-content/v2\x00";

pub const ArtifactRefV1 = v1.ArtifactRefV1;
pub const NodeKindV1 = v1.NodeKindV1;
pub const StageKindV1 = v1.StageKindV1;
pub const TaskCoordinateV1 = v1.TaskCoordinateV1;
pub const NodePublicV2 = field_public.NodePublicV2;

pub const Error = v1.Error || field_public.Error || error{
    InvalidFieldPublicTransport,
};

pub const SemanticInputsV2 = struct {
    campaign_namespace_sha256: [32]u8,
    stage_kind: StageKindV1,
    node_kind: NodeKindV1,
    coordinate: TaskCoordinateV1,
    circuit_identity_sha256: [32]u8,
    program_identity_sha256: [32]u8,
    profile_identity_sha256: [32]u8,
    pcs_identity_sha256: [32]u8,
    padding_layout_identity_sha256: [32]u8,
    registry_identity_sha256: [32]u8,
    node_public_abi_sha256: [32]u8,
    proof_shape_identity_sha256: [32]u8,
    statement_digest: [field_public.DIGEST_WORD_COUNT]u32,
    source_digest: [field_public.DIGEST_WORD_COUNT]u32,
    subtree_digest: [field_public.DIGEST_WORD_COUNT]u32,
    output_digest: [field_public.DIGEST_WORD_COUNT]u32,
    child_count: u8,
    ordered_children: [MAX_CHILD_COUNT]ArtifactRefV1,
    preprocessed_root: [v1.DIGEST_WORD_COUNT]u32,
    identity_sha256: [32]u8,

    pub fn validate(self: *const SemanticInputsV2) Error!void {
        inline for (.{
            self.campaign_namespace_sha256,
            self.circuit_identity_sha256,
            self.program_identity_sha256,
            self.profile_identity_sha256,
            self.pcs_identity_sha256,
            self.padding_layout_identity_sha256,
            self.registry_identity_sha256,
            self.proof_shape_identity_sha256,
        }) |identity| if (std.mem.allEqual(u8, &identity, 0))
            return error.InvalidArtifactIdentity;
        if (!std.mem.eql(
            u8,
            &self.node_public_abi_sha256,
            &field_public.abiIdentitySha256(),
        ) or allWordsZero(self.statement_digest) or
            allWordsZero(self.source_digest) or
            allWordsZero(self.subtree_digest) or
            allWordsZero(self.output_digest) or
            allWordsZero(self.preprocessed_root))
        {
            return error.InvalidArtifactIdentity;
        }
        try self.coordinate.validate();
        try validateStageCoordinate(self.stage_kind, self.coordinate);
        if (self.node_kind != try v1.expectedNodeKind(self.coordinate))
            return error.InvalidNodeKind;
        try validateChildRefs(
            self.stage_kind,
            self.child_count,
            &self.ordered_children,
        );
        if (!std.mem.eql(
            u8,
            &self.identity_sha256,
            &semanticInputsIdentity(self),
        )) return error.InvalidArtifactIdentity;
    }
};

pub const RecursiveNodeArtifactV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    stage_kind: StageKindV1,
    node_kind: NodeKindV1,
    child_count: u8,
    coordinate: TaskCoordinateV1,
    node_public: NodePublicV2,
    campaign_namespace_sha256: [32]u8,
    circuit_identity_sha256: [32]u8,
    program_identity_sha256: [32]u8,
    profile_identity_sha256: [32]u8,
    pcs_identity_sha256: [32]u8,
    padding_layout_identity_sha256: [32]u8,
    registry_identity_sha256: [32]u8,
    node_public_abi_sha256: [32]u8,
    proof_shape_identity_sha256: [32]u8,
    ordered_children: [MAX_CHILD_COUNT]ArtifactRefV1,
    proof_ref: ArtifactRefV1,
    preprocessed_root: [v1.DIGEST_WORD_COUNT]u32,
    semantic_inputs_identity_sha256: [32]u8,
    field_public_transport_sha256: [32]u8,
    content_identity_sha256: [32]u8,

    pub fn seal(
        value: RecursiveNodeArtifactV2,
    ) Error!RecursiveNodeArtifactV2 {
        var result = value;
        result.semantic_inputs_identity_sha256 =
            result.semanticInputsUnchecked().identity_sha256;
        result.field_public_transport_sha256 = try fieldPublicTransportSha256(
            &result.node_public,
        );
        result.content_identity_sha256 = contentIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const RecursiveNodeArtifactV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation)
        {
            return error.UnsupportedFormat;
        }
        try self.coordinate.validate();
        try validateStageCoordinate(self.stage_kind, self.coordinate);
        if (self.node_kind != try v1.expectedNodeKind(self.coordinate))
            return error.InvalidNodeKind;
        try self.node_public.validate();
        if (!std.meta.eql(self.coordinate, self.node_public.coordinate) or
            self.node_kind != self.node_public.node_kind)
        {
            return error.InvalidNodePublic;
        }
        try self.proof_ref.validate();
        try validateChildRefs(
            self.stage_kind,
            self.child_count,
            &self.ordered_children,
        );
        if (!std.mem.eql(
            u8,
            &self.node_public_abi_sha256,
            &field_public.abiIdentitySha256(),
        ) or !std.mem.eql(
            u8,
            &self.field_public_transport_sha256,
            &try fieldPublicTransportSha256(&self.node_public),
        )) return error.InvalidFieldPublicTransport;
        var semantic = self.semanticInputsUnchecked();
        try semantic.validate();
        if (!std.mem.eql(
            u8,
            &semantic.identity_sha256,
            &self.semantic_inputs_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.content_identity_sha256,
            &contentIdentity(self),
        )) return error.InvalidArtifactIdentity;
    }

    pub fn semanticInputs(
        self: *const RecursiveNodeArtifactV2,
    ) Error!SemanticInputsV2 {
        try self.validate();
        return self.semanticInputsUnchecked();
    }

    pub fn encodeCanonical(
        self: *const RecursiveNodeArtifactV2,
    ) Error![ENCODED_BYTE_COUNT]u8 {
        try self.validate();
        var result: [ENCODED_BYTE_COUNT]u8 = undefined;
        var writer = Writer{ .bytes = &result };
        writeArtifact(&writer, self, true);
        std.debug.assert(writer.at == result.len);
        return result;
    }

    pub fn decodeCanonical(bytes: []const u8) Error!RecursiveNodeArtifactV2 {
        if (bytes.len != ENCODED_BYTE_COUNT)
            return error.NonCanonicalEncoding;
        var reader = Reader{ .bytes = bytes };
        const result = RecursiveNodeArtifactV2{
            .format_version = try reader.u16Value(),
            .schema_version = try reader.u16Value(),
            .production_activation = try reader.boolValue(),
            .stage_kind = std.meta.intToEnum(
                StageKindV1,
                try reader.u8Value(),
            ) catch return error.NonCanonicalEncoding,
            .node_kind = std.meta.intToEnum(
                NodeKindV1,
                try reader.u8Value(),
            ) catch return error.NonCanonicalEncoding,
            .child_count = try reader.u8Value(),
            .coordinate = try readCoordinate(&reader),
            .node_public = try field_public.NodePublicV2.decodeCanonical(
                try reader.take(field_public.ENCODED_BYTE_COUNT),
            ),
            .campaign_namespace_sha256 = try reader.array(32),
            .circuit_identity_sha256 = try reader.array(32),
            .program_identity_sha256 = try reader.array(32),
            .profile_identity_sha256 = try reader.array(32),
            .pcs_identity_sha256 = try reader.array(32),
            .padding_layout_identity_sha256 = try reader.array(32),
            .registry_identity_sha256 = try reader.array(32),
            .node_public_abi_sha256 = try reader.array(32),
            .proof_shape_identity_sha256 = try reader.array(32),
            .ordered_children = .{
                try readArtifactRef(&reader),
                try readArtifactRef(&reader),
            },
            .proof_ref = try readArtifactRef(&reader),
            .preprocessed_root = try reader.words(v1.DIGEST_WORD_COUNT),
            .semantic_inputs_identity_sha256 = try reader.array(32),
            .field_public_transport_sha256 = try reader.array(32),
            .content_identity_sha256 = try reader.array(32),
        };
        if (reader.at != bytes.len) return error.NonCanonicalEncoding;
        try result.validate();
        const canonical = try result.encodeCanonical();
        if (!std.mem.eql(u8, bytes, &canonical))
            return error.NonCanonicalEncoding;
        return result;
    }

    pub fn artifactRef(
        self: *const RecursiveNodeArtifactV2,
    ) Error!ArtifactRefV1 {
        const bytes = try self.encodeCanonical();
        return .{
            .kind = RECURSIVE_NODE_ARTIFACT_KIND,
            .format_version = v1.ARTIFACT_REF_FORMAT_VERSION,
            .schema_version = SCHEMA_VERSION,
            .byte_count = bytes.len,
            .sha256 = sha256(&bytes),
        };
    }

    fn semanticInputsUnchecked(
        self: *const RecursiveNodeArtifactV2,
    ) SemanticInputsV2 {
        var result = SemanticInputsV2{
            .campaign_namespace_sha256 = self.campaign_namespace_sha256,
            .stage_kind = self.stage_kind,
            .node_kind = self.node_kind,
            .coordinate = self.coordinate,
            .circuit_identity_sha256 = self.circuit_identity_sha256,
            .program_identity_sha256 = self.program_identity_sha256,
            .profile_identity_sha256 = self.profile_identity_sha256,
            .pcs_identity_sha256 = self.pcs_identity_sha256,
            .padding_layout_identity_sha256 = self.padding_layout_identity_sha256,
            .registry_identity_sha256 = self.registry_identity_sha256,
            .node_public_abi_sha256 = self.node_public_abi_sha256,
            .proof_shape_identity_sha256 = self.proof_shape_identity_sha256,
            .statement_digest = self.node_public.statement_digest,
            .source_digest = self.node_public.source_digest,
            .subtree_digest = self.node_public.subtree_digest,
            .output_digest = self.node_public.output_digest,
            .child_count = self.child_count,
            .ordered_children = self.ordered_children,
            .preprocessed_root = self.preprocessed_root,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = semanticInputsIdentity(&result);
        return result;
    }
};

fn fieldPublicTransportSha256(value: *const NodePublicV2) Error![32]u8 {
    const bytes = try value.encodeCanonical();
    return sha256(&bytes);
}

fn validateStageCoordinate(
    stage: StageKindV1,
    coordinate: TaskCoordinateV1,
) Error!void {
    switch (stage) {
        .leaf_wrapper => if (coordinate.height != 0) return error.InvalidStage,
        .fold => if (coordinate.height == 0 or
            coordinate.height == v1.ROOT_HEIGHT) return error.InvalidStage,
        .root => if (coordinate.height != v1.ROOT_HEIGHT or
            coordinate.index != 0) return error.InvalidStage,
    }
}

fn validateChildRefs(
    stage: StageKindV1,
    child_count: u8,
    children: *const [MAX_CHILD_COUNT]ArtifactRefV1,
) Error!void {
    const expected: u8 = if (stage == .leaf_wrapper) 1 else 2;
    if (child_count != expected) return error.InvalidChildCount;
    for (children[0..child_count]) |child| try child.validate();
    for (children[child_count..]) |child|
        if (!child.isZero()) return error.InvalidChildCount;
}

fn semanticInputsIdentity(value: *const SemanticInputsV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(SEMANTIC_INPUTS_DOMAIN);
    hash.update(&value.campaign_namespace_sha256);
    hashInt(&hash, u8, @intFromEnum(value.stage_kind));
    hashInt(&hash, u8, @intFromEnum(value.node_kind));
    hashCoordinate(&hash, value.coordinate);
    inline for (.{
        value.circuit_identity_sha256,
        value.program_identity_sha256,
        value.profile_identity_sha256,
        value.pcs_identity_sha256,
        value.padding_layout_identity_sha256,
        value.registry_identity_sha256,
        value.node_public_abi_sha256,
        value.proof_shape_identity_sha256,
    }) |identity| hash.update(&identity);
    inline for (.{
        value.statement_digest,
        value.source_digest,
        value.subtree_digest,
        value.output_digest,
    }) |digest| for (digest) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u8, value.child_count);
    for (value.ordered_children) |child| hashArtifactRef(&hash, child);
    for (value.preprocessed_root) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn contentIdentity(value: *const RecursiveNodeArtifactV2) [32]u8 {
    var bytes: [ENCODED_BYTE_COUNT - 32]u8 = undefined;
    var writer = Writer{ .bytes = &bytes };
    writeArtifact(&writer, value, false);
    std.debug.assert(writer.at == bytes.len);
    var hash = Sha256.init(.{});
    hash.update(CONTENT_IDENTITY_DOMAIN);
    hash.update(&bytes);
    return hash.finalResult();
}

fn writeArtifact(
    writer: *Writer,
    value: *const RecursiveNodeArtifactV2,
    include_content_identity: bool,
) void {
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u8Value(@intFromBool(value.production_activation));
    writer.u8Value(@intFromEnum(value.stage_kind));
    writer.u8Value(@intFromEnum(value.node_kind));
    writer.u8Value(value.child_count);
    writeCoordinate(writer, value.coordinate);
    const public_bytes = value.node_public.encodeCanonical() catch unreachable;
    writer.bytesValue(&public_bytes);
    inline for (.{
        value.campaign_namespace_sha256,
        value.circuit_identity_sha256,
        value.program_identity_sha256,
        value.profile_identity_sha256,
        value.pcs_identity_sha256,
        value.padding_layout_identity_sha256,
        value.registry_identity_sha256,
        value.node_public_abi_sha256,
        value.proof_shape_identity_sha256,
    }) |identity| writer.bytesValue(&identity);
    for (value.ordered_children) |child| writeArtifactRef(writer, child);
    writeArtifactRef(writer, value.proof_ref);
    for (value.preprocessed_root) |word| writer.u32Value(word);
    writer.bytesValue(&value.semantic_inputs_identity_sha256);
    writer.bytesValue(&value.field_public_transport_sha256);
    if (include_content_identity)
        writer.bytesValue(&value.content_identity_sha256);
}

fn writeCoordinate(writer: *Writer, value: TaskCoordinateV1) void {
    writer.u8Value(value.height);
    writer.bytesValue(&value.reserved);
    writer.u32Value(value.index);
    writer.u32Value(value.global_ordinal);
}

fn readCoordinate(reader: *Reader) Error!TaskCoordinateV1 {
    return .{
        .height = try reader.u8Value(),
        .reserved = try reader.array(3),
        .index = try reader.u32Value(),
        .global_ordinal = try reader.u32Value(),
    };
}

fn writeArtifactRef(writer: *Writer, value: ArtifactRefV1) void {
    writer.u32Value(value.kind);
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u64Value(value.byte_count);
    writer.bytesValue(&value.sha256);
}

fn readArtifactRef(reader: *Reader) Error!ArtifactRefV1 {
    return .{
        .kind = try reader.u32Value(),
        .format_version = try reader.u16Value(),
        .schema_version = try reader.u16Value(),
        .byte_count = try reader.u64Value(),
        .sha256 = try reader.array(32),
    };
}

fn hashArtifactRef(hash: *Sha256, value: ArtifactRefV1) void {
    hashInt(hash, u32, value.kind);
    hashInt(hash, u16, value.format_version);
    hashInt(hash, u16, value.schema_version);
    hashInt(hash, u64, value.byte_count);
    hash.update(&value.sha256);
}

fn hashCoordinate(hash: *Sha256, value: TaskCoordinateV1) void {
    hashInt(hash, u8, value.height);
    hash.update(&value.reserved);
    hashInt(hash, u32, value.index);
    hashInt(hash, u32, value.global_ordinal);
}

fn allWordsZero(words: [v1.DIGEST_WORD_COUNT]u32) bool {
    var aggregate: u32 = 0;
    for (words) |word| aggregate |= word;
    return aggregate == 0;
}

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn bytesValue(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.at..][0..value.len], value);
        self.at += value.len;
    }
    fn u8Value(self: *Writer, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }
    fn u16Value(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.at..][0..2], value, .little);
        self.at += 2;
    }
    fn u32Value(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.at..][0..4], value, .little);
        self.at += 4;
    }
    fn u64Value(self: *Writer, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.at..][0..8], value, .little);
        self.at += 8;
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(self: *Reader, count: usize) Error![]const u8 {
        const end = std.math.add(usize, self.at, count) catch
            return error.NonCanonicalEncoding;
        if (end > self.bytes.len) return error.NonCanonicalEncoding;
        const result = self.bytes[self.at..end];
        self.at = end;
        return result;
    }
    fn array(self: *Reader, comptime count: usize) Error![count]u8 {
        return (try self.take(count))[0..count].*;
    }
    fn words(self: *Reader, comptime count: usize) Error![count]u32 {
        var result: [count]u32 = undefined;
        for (&result) |*word| word.* = try self.u32Value();
        return result;
    }
    fn u8Value(self: *Reader) Error!u8 {
        return (try self.take(1))[0];
    }
    fn boolValue(self: *Reader) Error!bool {
        return switch (try self.u8Value()) {
            0 => false,
            1 => true,
            else => error.NonCanonicalEncoding,
        };
    }
    fn u16Value(self: *Reader) Error!u16 {
        const bytes = try self.take(2);
        return std.mem.readInt(u16, @ptrCast(bytes.ptr), .little);
    }
    fn u32Value(self: *Reader) Error!u32 {
        const bytes = try self.take(4);
        return std.mem.readInt(u32, @ptrCast(bytes.ptr), .little);
    }
    fn u64Value(self: *Reader) Error!u64 {
        const bytes = try self.take(8);
        return std.mem.readInt(u64, @ptrCast(bytes.ptr), .little);
    }
};

comptime {
    if (SCHEMA_VERSION != 2 or ENCODED_BYTE_COUNT != 2380 or
        field_public.ENCODED_BYTE_COUNT != 1800 or
        RECURSIVE_NODE_ARTIFACT_KIND != 10 or PRODUCTION_ACTIVATION)
    {
        @compileError("recursive node artifact V2 constants drifted");
    }
}
