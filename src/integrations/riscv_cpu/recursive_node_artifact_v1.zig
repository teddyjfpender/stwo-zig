//! Canonical durable ABI for one node in the 210-to-256 recursive tree.
//!
//! This envelope contains only persisted proof semantics.  In particular it
//! contains no path, timing, host observation, verifier lease, or borrowed
//! proof capture.  A digest identifies bytes; a consumer must still cold-open
//! `proof_ref` with the circuit selected by the typed registry.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const REAL_LEAF_COUNT: u16 = 210;
pub const PADDED_LEAF_COUNT: u16 = 256;
pub const ROOT_HEIGHT: u8 = 8;
pub const TOTAL_NODE_COUNT: u16 = 511;
pub const PARENT_NODE_COUNT: u16 = 255;
pub const STATEMENT_WORD_COUNT: usize = 412;
pub const DIGEST_WORD_COUNT: usize = 8;
pub const MAX_CHILD_COUNT: usize = 2;
pub const RECURSIVE_NODE_ARTIFACT_KIND: u32 = 10;
pub const ARTIFACT_REF_FORMAT_VERSION: u16 = 1;

pub const ARTIFACT_REF_BYTE_COUNT: usize = 48;
pub const NODE_PUBLIC_BYTE_COUNT: usize = 1816;
pub const TASK_COORDINATE_BYTE_COUNT: usize = 12;
pub const ENCODED_BYTE_COUNT: usize = 2396;

const NODE_PUBLIC_IDENTITY_DOMAIN =
    "stwo-zig/recursive-node-public/v1\x00";
const NODE_PUBLIC_ABI_DOMAIN =
    "stwo-zig/recursive-node-public-abi/v1\x00";
const SEMANTIC_INPUTS_DOMAIN =
    "stwo-zig/recursive-node-semantic-inputs/v1\x00";
const CONTENT_IDENTITY_DOMAIN =
    "stwo-zig/recursive-node-artifact-content/v1\x00";

pub const Error = error{
    ArithmeticOverflow,
    ChildArtifactMismatch,
    InvalidArtifactIdentity,
    InvalidArtifactReference,
    InvalidChildCount,
    InvalidChildOrder,
    InvalidNodeKind,
    InvalidNodePublic,
    InvalidStage,
    InvalidTaskCoordinate,
    NonCanonicalEncoding,
    ProductionActivationUnavailable,
    UnsupportedFormat,
};

/// Narrow host-neutral adapter for the root CAS reference.  Format and schema
/// are distinct: changing either makes the reference a different typed blob.
pub const ArtifactRefV1 = struct {
    kind: u32,
    format_version: u16,
    schema_version: u16,
    byte_count: u64,
    sha256: [32]u8,

    pub fn zero() ArtifactRefV1 {
        return std.mem.zeroes(ArtifactRefV1);
    }

    pub fn isZero(self: *const ArtifactRefV1) bool {
        return self.kind == 0 and self.format_version == 0 and
            self.schema_version == 0 and self.byte_count == 0 and
            std.mem.allEqual(u8, &self.sha256, 0);
    }

    pub fn validate(self: *const ArtifactRefV1) Error!void {
        if (self.kind == 0 or
            self.format_version != ARTIFACT_REF_FORMAT_VERSION or
            self.schema_version == 0 or self.byte_count == 0 or
            std.mem.allEqual(u8, &self.sha256, 0))
        {
            return error.InvalidArtifactReference;
        }
    }

    /// Deliberately field-wise so Lane C does not depend on a CAS module's
    /// ownership or filesystem representation.
    pub fn fromTransport(value: anytype) Error!ArtifactRefV1 {
        const result = ArtifactRefV1{
            .kind = value.kind,
            .format_version = value.format_version,
            .schema_version = value.schema_version,
            .byte_count = value.byte_count,
            .sha256 = value.sha256,
        };
        try result.validate();
        return result;
    }
};

pub const NodeKindV1 = enum(u8) {
    real = 0,
    empty = 1,
    mixed = 2,
};

pub const StageKindV1 = enum(u8) {
    leaf_wrapper = 1,
    fold = 2,
    root = 3,
};

/// A unified coordinate covers all 511 nodes.  Height-zero leaves occupy
/// ordinals 0..255.  Parent ordinals occupy 256..510 breadth-wise by height;
/// subtracting 256 yields the existing parent-task ordinal 0..254.
pub const TaskCoordinateV1 = struct {
    height: u8,
    reserved: [3]u8 = .{ 0, 0, 0 },
    index: u32,
    global_ordinal: u32,

    pub fn init(height: u8, index: u32) Error!TaskCoordinateV1 {
        const result = TaskCoordinateV1{
            .height = height,
            .index = index,
            .global_ordinal = try globalOrdinal(height, index),
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: *const TaskCoordinateV1) Error!void {
        if (!std.mem.allEqual(u8, &self.reserved, 0) or
            self.height > ROOT_HEIGHT or
            self.index >= try nodeCount(self.height) or
            self.global_ordinal != try globalOrdinal(
                self.height,
                self.index,
            ))
        {
            return error.InvalidTaskCoordinate;
        }
    }

    pub fn parentTaskOrdinal(self: *const TaskCoordinateV1) Error!u32 {
        try self.validate();
        if (self.height == 0) return error.InvalidTaskCoordinate;
        return self.global_ordinal - PADDED_LEAF_COUNT;
    }
};

pub fn nodeCount(height: u8) Error!u32 {
    if (height > ROOT_HEIGHT) return error.InvalidTaskCoordinate;
    return @as(u32, PADDED_LEAF_COUNT) >> @intCast(height);
}

pub fn levelOffset(height: u8) Error!u32 {
    if (height > ROOT_HEIGHT) return error.InvalidTaskCoordinate;
    var result: u32 = 0;
    var cursor: u8 = 0;
    while (cursor < height) : (cursor += 1)
        result = std.math.add(u32, result, try nodeCount(cursor)) catch
            return error.ArithmeticOverflow;
    return result;
}

pub fn globalOrdinal(height: u8, index: u32) Error!u32 {
    if (index >= try nodeCount(height)) return error.InvalidTaskCoordinate;
    return std.math.add(u32, try levelOffset(height), index) catch
        return error.ArithmeticOverflow;
}

pub fn expectedNodeKind(coordinate: TaskCoordinateV1) Error!NodeKindV1 {
    try coordinate.validate();
    const width = @as(u32, 1) << @intCast(coordinate.height);
    const first = std.math.mul(u32, coordinate.index, width) catch
        return error.ArithmeticOverflow;
    const end = std.math.add(u32, first, width) catch
        return error.ArithmeticOverflow;
    if (end <= REAL_LEAF_COUNT) return .real;
    if (first >= REAL_LEAF_COUNT) return .empty;
    return .mixed;
}

/// Fixed public result of every recursive circuit.  The 412 words are the
/// canonical SpanStatement authority.  The remaining fields are the exact
/// NodeReferenceV2 authority/subtree projection plus a self-authenticating
/// output identity.  Existing M31 words adapt by their canonical u32 values.
pub const NodePublicV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    reserved: [4]u8 = .{ 0, 0, 0, 0 },
    statement_words: [STATEMENT_WORD_COUNT]u32,
    statement_identity_sha256: [32]u8,
    node_authority_sha256: [32]u8,
    subtree_sha256: [32]u8,
    subtree_digest: [DIGEST_WORD_COUNT]u32,
    output_identity_sha256: [32]u8,

    pub fn seal(value: NodePublicV1) Error!NodePublicV1 {
        var result = value;
        result.output_identity_sha256 = nodePublicIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const NodePublicV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            std.mem.allEqual(u8, &self.statement_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.node_authority_sha256, 0) or
            std.mem.allEqual(u8, &self.subtree_sha256, 0) or
            allWordsZero(self.subtree_digest) or
            !std.mem.eql(
                u8,
                &self.output_identity_sha256,
                &nodePublicIdentity(self),
            ))
        {
            return error.InvalidNodePublic;
        }
    }
};

pub fn nodePublicAbiIdentity() [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(NODE_PUBLIC_ABI_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u32, STATEMENT_WORD_COUNT);
    hashInt(&hash, u32, DIGEST_WORD_COUNT);
    hashInt(&hash, u32, NODE_PUBLIC_BYTE_COUNT);
    return hash.finalResult();
}

/// Exact proof-semantic inputs.  This projection is Zig-owned; a controller
/// stores its sealed identity and ordered refs but never independently hashes
/// production node semantics.  A whole leaf-inventory digest is intentionally
/// absent so a proof blob remains branch-local reusable.
pub const SemanticInputsV1 = struct {
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
    statement_identity_sha256: [32]u8,
    output_identity_sha256: [32]u8,
    child_count: u8,
    ordered_children: [MAX_CHILD_COUNT]ArtifactRefV1,
    preprocessed_root: [DIGEST_WORD_COUNT]u32,
    identity_sha256: [32]u8,

    pub fn validate(self: *const SemanticInputsV1) Error!void {
        if (std.mem.allEqual(u8, &self.campaign_namespace_sha256, 0) or
            std.mem.allEqual(u8, &self.circuit_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.program_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.profile_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.pcs_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.padding_layout_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.registry_identity_sha256, 0) or
            !std.mem.eql(
                u8,
                &self.node_public_abi_sha256,
                &nodePublicAbiIdentity(),
            ) or std.mem.allEqual(u8, &self.statement_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.output_identity_sha256, 0) or
            allWordsZero(self.preprocessed_root))
        {
            return error.InvalidArtifactIdentity;
        }
        try self.coordinate.validate();
        try validateStageCoordinate(self.stage_kind, self.coordinate);
        if (self.node_kind != try expectedNodeKind(self.coordinate))
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

pub const RecursiveNodeArtifactV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    stage_kind: StageKindV1,
    node_kind: NodeKindV1,
    child_count: u8,
    coordinate: TaskCoordinateV1,
    node_public: NodePublicV1,
    campaign_namespace_sha256: [32]u8,
    circuit_identity_sha256: [32]u8,
    program_identity_sha256: [32]u8,
    profile_identity_sha256: [32]u8,
    pcs_identity_sha256: [32]u8,
    padding_layout_identity_sha256: [32]u8,
    registry_identity_sha256: [32]u8,
    node_public_abi_sha256: [32]u8,
    statement_identity_sha256: [32]u8,
    output_identity_sha256: [32]u8,
    ordered_children: [MAX_CHILD_COUNT]ArtifactRefV1,
    proof_ref: ArtifactRefV1,
    preprocessed_root: [DIGEST_WORD_COUNT]u32,
    semantic_inputs_identity_sha256: [32]u8,
    content_identity_sha256: [32]u8,

    pub fn seal(value: RecursiveNodeArtifactV1) Error!RecursiveNodeArtifactV1 {
        var result = value;
        result.semantic_inputs_identity_sha256 =
            result.semanticInputsUnchecked().identity_sha256;
        result.content_identity_sha256 = contentIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const RecursiveNodeArtifactV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation)
        {
            return error.UnsupportedFormat;
        }
        try self.coordinate.validate();
        try validateStageCoordinate(self.stage_kind, self.coordinate);
        if (self.node_kind != try expectedNodeKind(self.coordinate))
            return error.InvalidNodeKind;
        try self.node_public.validate();
        try self.proof_ref.validate();
        try validateChildRefs(
            self.stage_kind,
            self.child_count,
            &self.ordered_children,
        );
        if (!std.mem.eql(
            u8,
            &self.node_public_abi_sha256,
            &nodePublicAbiIdentity(),
        ) or !std.mem.eql(
            u8,
            &self.statement_identity_sha256,
            &self.node_public.statement_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.output_identity_sha256,
            &self.node_public.output_identity_sha256,
        )) return error.InvalidArtifactIdentity;
        var semantic = self.semanticInputsUnchecked();
        try semantic.validate();
        if (!std.mem.eql(
            u8,
            &self.semantic_inputs_identity_sha256,
            &semantic.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.content_identity_sha256,
            &contentIdentity(self),
        )) return error.InvalidArtifactIdentity;
    }

    pub fn semanticInputs(self: *const RecursiveNodeArtifactV1) Error!SemanticInputsV1 {
        try self.validate();
        return self.semanticInputsUnchecked();
    }

    pub fn artifactRef(self: *const RecursiveNodeArtifactV1) Error!ArtifactRefV1 {
        const bytes = try self.encodeCanonical();
        var result = ArtifactRefV1{
            .kind = RECURSIVE_NODE_ARTIFACT_KIND,
            .format_version = FORMAT_VERSION,
            .schema_version = SCHEMA_VERSION,
            .byte_count = bytes.len,
            .sha256 = hashBytes(&bytes),
        };
        try result.validate();
        return result;
    }

    pub fn validateAgainstChildren(
        self: *const RecursiveNodeArtifactV1,
        left: *const RecursiveNodeArtifactV1,
        right: *const RecursiveNodeArtifactV1,
    ) Error!void {
        try self.validate();
        try left.validate();
        try right.validate();
        if (self.stage_kind == .leaf_wrapper or self.coordinate.height == 0)
            return error.InvalidStage;
        const child_height = self.coordinate.height - 1;
        const left_index = self.coordinate.index * 2;
        const right_index = left_index + 1;
        if (left.coordinate.height != child_height or
            right.coordinate.height != child_height or
            left.coordinate.index != left_index or
            right.coordinate.index != right_index or
            !std.meta.eql(self.ordered_children[0], try left.artifactRef()) or
            !std.meta.eql(self.ordered_children[1], try right.artifactRef()))
        {
            return error.InvalidChildOrder;
        }
    }

    pub fn encodeCanonical(self: *const RecursiveNodeArtifactV1) Error![ENCODED_BYTE_COUNT]u8 {
        try self.validate();
        var result: [ENCODED_BYTE_COUNT]u8 = undefined;
        var writer = Writer{ .bytes = &result };
        writeArtifact(&writer, self, true);
        std.debug.assert(writer.at == result.len);
        return result;
    }

    pub fn decodeCanonical(bytes: []const u8) Error!RecursiveNodeArtifactV1 {
        if (bytes.len != ENCODED_BYTE_COUNT) return error.UnsupportedFormat;
        var reader = Reader{ .bytes = bytes };
        const result = RecursiveNodeArtifactV1{
            .format_version = try reader.u16Value(),
            .schema_version = try reader.u16Value(),
            .production_activation = try reader.boolValue(),
            .stage_kind = std.meta.intToEnum(
                StageKindV1,
                try reader.u8Value(),
            ) catch return error.UnsupportedFormat,
            .node_kind = std.meta.intToEnum(
                NodeKindV1,
                try reader.u8Value(),
            ) catch return error.UnsupportedFormat,
            .child_count = try reader.u8Value(),
            .coordinate = try readCoordinate(&reader),
            .node_public = try readNodePublic(&reader),
            .campaign_namespace_sha256 = try reader.array(32),
            .circuit_identity_sha256 = try reader.array(32),
            .program_identity_sha256 = try reader.array(32),
            .profile_identity_sha256 = try reader.array(32),
            .pcs_identity_sha256 = try reader.array(32),
            .padding_layout_identity_sha256 = try reader.array(32),
            .registry_identity_sha256 = try reader.array(32),
            .node_public_abi_sha256 = try reader.array(32),
            .statement_identity_sha256 = try reader.array(32),
            .output_identity_sha256 = try reader.array(32),
            .ordered_children = .{
                try readArtifactRef(&reader),
                try readArtifactRef(&reader),
            },
            .proof_ref = try readArtifactRef(&reader),
            .preprocessed_root = try reader.words(DIGEST_WORD_COUNT),
            .semantic_inputs_identity_sha256 = try reader.array(32),
            .content_identity_sha256 = try reader.array(32),
        };
        if (reader.at != bytes.len) return error.NonCanonicalEncoding;
        try result.validate();
        const canonical = try result.encodeCanonical();
        if (!std.mem.eql(u8, bytes, &canonical))
            return error.NonCanonicalEncoding;
        return result;
    }

    fn semanticInputsUnchecked(self: *const RecursiveNodeArtifactV1) SemanticInputsV1 {
        var result = SemanticInputsV1{
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
            .statement_identity_sha256 = self.statement_identity_sha256,
            .output_identity_sha256 = self.output_identity_sha256,
            .child_count = self.child_count,
            .ordered_children = self.ordered_children,
            .preprocessed_root = self.preprocessed_root,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = semanticInputsIdentity(&result);
        return result;
    }
};

fn validateStageCoordinate(
    stage: StageKindV1,
    coordinate: TaskCoordinateV1,
) Error!void {
    switch (stage) {
        .leaf_wrapper => if (coordinate.height != 0) return error.InvalidStage,
        .fold => if (coordinate.height == 0 or coordinate.height >= ROOT_HEIGHT)
            return error.InvalidStage,
        .root => if (coordinate.height != ROOT_HEIGHT or coordinate.index != 0)
            return error.InvalidStage,
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
    for (children[child_count..]) |child| {
        if (!child.isZero()) return error.InvalidChildCount;
    }
}

fn nodePublicIdentity(value: *const NodePublicV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(NODE_PUBLIC_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.reserved);
    for (value.statement_words) |word| hashInt(&hash, u32, word);
    hash.update(&value.statement_identity_sha256);
    hash.update(&value.node_authority_sha256);
    hash.update(&value.subtree_sha256);
    for (value.subtree_digest) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn semanticInputsIdentity(value: *const SemanticInputsV1) [32]u8 {
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
        value.statement_identity_sha256,
        value.output_identity_sha256,
    }) |identity| hash.update(&identity);
    hashInt(&hash, u8, value.child_count);
    for (value.ordered_children) |child| hashArtifactRef(&hash, child);
    for (value.preprocessed_root) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn contentIdentity(value: *const RecursiveNodeArtifactV1) [32]u8 {
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
    value: *const RecursiveNodeArtifactV1,
    include_content_identity: bool,
) void {
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u8Value(@intFromBool(value.production_activation));
    writer.u8Value(@intFromEnum(value.stage_kind));
    writer.u8Value(@intFromEnum(value.node_kind));
    writer.u8Value(value.child_count);
    writeCoordinate(writer, value.coordinate);
    writeNodePublic(writer, &value.node_public);
    inline for (.{
        value.campaign_namespace_sha256,
        value.circuit_identity_sha256,
        value.program_identity_sha256,
        value.profile_identity_sha256,
        value.pcs_identity_sha256,
        value.padding_layout_identity_sha256,
        value.registry_identity_sha256,
        value.node_public_abi_sha256,
        value.statement_identity_sha256,
        value.output_identity_sha256,
    }) |identity| writer.bytesValue(&identity);
    for (value.ordered_children) |child| writeArtifactRef(writer, child);
    writeArtifactRef(writer, value.proof_ref);
    for (value.preprocessed_root) |word| writer.u32Value(word);
    writer.bytesValue(&value.semantic_inputs_identity_sha256);
    if (include_content_identity)
        writer.bytesValue(&value.content_identity_sha256);
}

fn writeNodePublic(writer: *Writer, value: *const NodePublicV1) void {
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.bytesValue(&value.reserved);
    for (value.statement_words) |word| writer.u32Value(word);
    writer.bytesValue(&value.statement_identity_sha256);
    writer.bytesValue(&value.node_authority_sha256);
    writer.bytesValue(&value.subtree_sha256);
    for (value.subtree_digest) |word| writer.u32Value(word);
    writer.bytesValue(&value.output_identity_sha256);
}

fn readNodePublic(reader: *Reader) Error!NodePublicV1 {
    return .{
        .format_version = try reader.u16Value(),
        .schema_version = try reader.u16Value(),
        .reserved = try reader.array(4),
        .statement_words = try reader.words(STATEMENT_WORD_COUNT),
        .statement_identity_sha256 = try reader.array(32),
        .node_authority_sha256 = try reader.array(32),
        .subtree_sha256 = try reader.array(32),
        .subtree_digest = try reader.words(DIGEST_WORD_COUNT),
        .output_identity_sha256 = try reader.array(32),
    };
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

fn allWordsZero(words: [DIGEST_WORD_COUNT]u32) bool {
    var aggregate: u32 = 0;
    for (words) |word| aggregate |= word;
    return aggregate == 0;
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn hashBytes(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
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
    if (PADDED_LEAF_COUNT != 256 or REAL_LEAF_COUNT != 210 or
        ROOT_HEIGHT != 8 or TOTAL_NODE_COUNT != 511 or
        PARENT_NODE_COUNT != 255 or STATEMENT_WORD_COUNT != 412 or
        @sizeOf(@TypeOf(@as(NodePublicV1, undefined).statement_words)) !=
            STATEMENT_WORD_COUNT * @sizeOf(u32) or
        PRODUCTION_ACTIVATION)
    {
        @compileError("recursive node V1 frozen constants drifted");
    }
}
