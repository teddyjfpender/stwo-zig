//! Internal fri merkle leaf witness authority shard; use fri_merkle_leaf_witness.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const digest = @import("../../air/lang/digest.zig");
pub const direct = @import("../../air/lang/direct_witness_executor.zig");
pub const types = @import("../../air/lang/types.zig");
pub const poseidon2 = @import("../../air/memory_commitment/poseidon2.zig");
pub const component = @import("fri_merkle_leaf.zig");
pub const merkle_root = @import("merkle_root_witness.zig");
pub const proof_kind_mod = @import("proof_kind.zig");
pub const query_mapping = @import("query_mapping_witness.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const PACKED_LEAF_SIZE: u32 = 4;
pub const SECURE_WORD_COUNT: u32 = 4;
pub const LEAF_TAG: u32 = 1;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = proof_kind_mod.ProofKind;
pub const SEGMENT_VERIFIER_ID = merkle_root.SEGMENT_VERIFIER_ID;
pub const LEFT_RECURSION_VERIFIER_ID = merkle_root.LEFT_RECURSION_VERIFIER_ID;
pub const RIGHT_RECURSION_VERIFIER_ID = merkle_root.RIGHT_RECURSION_VERIFIER_ID;

pub const BINDING_FORMAT_VERSION: u16 = 2;
pub const BINDING_DOMAIN = "stwo-zig/typed-air/recursion-fri-merkle-leaf-witness/v2\x00";
pub const BINDING_DIGEST_HEX =
    "65432c3d395c052ed97acd3d35ed597e0126acc19d68e0ba22b439f648a359f2";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion FRI-Merkle-leaf witness-binding digest",
);
pub const REFERENCE_FORMAT_VERSION: u16 = 1;
pub const REFERENCE_DOMAIN = "stwo-zig/typed-air/recursion-fri-merkle-leaf-reference/v1\x00";
pub const ROWS_DOMAIN = "stwo-zig/typed-air/recursion-fri-merkle-leaf-rows/v1\x00";

pub const Error = direct.Error || std.mem.Allocator.Error || query_mapping.Error ||
    merkle_root.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    InvalidProfile,
    InvalidWitness,
    InvalidWitnessBinding,
    LogSizeOutOfRange,
};

pub const MainSource = enum(u8) {
    enabler = 0,
    position = 1,
    leaf_index = 2,
    previous_0 = 3,
    previous_1 = 4,
    previous_2 = 5,
    previous_3 = 6,
    previous_4 = 7,
    previous_5 = 8,
    previous_6 = 9,
    previous_7 = 10,
    previous_8 = 11,
    previous_9 = 12,
    previous_10 = 13,
    previous_11 = 14,
    previous_12 = 15,
    previous_13 = 16,
    previous_14 = 17,
    previous_15 = 18,
    chunk_0 = 19,
    chunk_1 = 20,
    chunk_2 = 21,
    chunk_3 = 22,
    chunk_4 = 23,
    chunk_5 = 24,
    chunk_6 = 25,
    chunk_7 = 26,
    output_0 = 27,
    output_1 = 28,
    output_2 = 29,
    output_3 = 30,
    output_4 = 31,
    output_5 = 32,
    output_6 = 33,
    output_7 = 34,
    output_8 = 35,
    output_9 = 36,
    output_10 = 37,
    output_11 = 38,
    output_12 = 39,
    output_13 = 40,
    output_14 = 41,
    output_15 = 42,
};

pub const PreprocessedSource = enum(u8) {
    row_mask = 0,
    segment_mask = 1,
    binary_mask = 2,
    verifier_id = 3,
    layer = 4,
    query = 5,
    packed_index = 6,
    leaf_count = 7,
    local_root_mask = 8,
    tree_id = 9,
    tree_height = 10,
    step = 11,
    first = 12,
    last = 13,
    chunk_0_source_mask = 14,
    chunk_0_offset = 15,
    chunk_0_word = 16,
    chunk_0_constant = 17,
    chunk_1_source_mask = 18,
    chunk_1_offset = 19,
    chunk_1_word = 20,
    chunk_1_constant = 21,
    chunk_2_source_mask = 22,
    chunk_2_offset = 23,
    chunk_2_word = 24,
    chunk_2_constant = 25,
    chunk_3_source_mask = 26,
    chunk_3_offset = 27,
    chunk_3_word = 28,
    chunk_3_constant = 29,
    chunk_4_source_mask = 30,
    chunk_4_offset = 31,
    chunk_4_word = 32,
    chunk_4_constant = 33,
    chunk_5_source_mask = 34,
    chunk_5_offset = 35,
    chunk_5_word = 36,
    chunk_5_constant = 37,
    chunk_6_source_mask = 38,
    chunk_6_offset = 39,
    chunk_6_word = 40,
    chunk_6_constant = 41,
    chunk_7_source_mask = 42,
    chunk_7_offset = 43,
    chunk_7_word = 44,
    chunk_7_constant = 45,
    merkle_endpoint_mask = 46,
    local_root_endpoint_mask = 47,
};

pub fn Slot(comptime SourceType: type) type {
    return struct { column: u8, value: types.ValueId, source: SourceType };
}

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    semantic_digest: digest.Digest,
    main: [MAIN_COLUMN_COUNT]Slot(MainSource),
    preprocessed: [PREPROCESSED_COLUMN_COUNT]Slot(PreprocessedSource),
    parameters: [component.PARAMETER_COUNT]types.ValueId,

    pub fn canonical(definition: *const component.Definition) !Binding {
        try definition.validate();
        var main: [MAIN_COLUMN_COUNT]Slot(MainSource) = undefined;
        for (&main, definition.main.physical(), std.enums.values(MainSource), 0..) |
            *slot,
            value,
            source_value,
            column,
        | slot.* = .{ .column = @intCast(column), .value = value, .source = source_value };
        var preprocessed: [PREPROCESSED_COLUMN_COUNT]Slot(PreprocessedSource) = undefined;
        for (
            &preprocessed,
            definition.preprocessed.physical(),
            std.enums.values(PreprocessedSource),
            0..,
        ) |*slot, value, source_value, column| {
            slot.* = .{ .column = @intCast(column), .value = value, .source = source_value };
        }
        return .{
            .format_version = BINDING_FORMAT_VERSION,
            .semantic_format_version = digest.typed_effect_format_version,
            .semantic_digest = component.SEMANTIC_DIGEST,
            .main = main,
            .preprocessed = preprocessed,
            .parameters = definition.parameters.physical(),
        };
    }

    pub fn identityDigest(self: *const Binding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(BINDING_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        hash.update(&self.semantic_digest);
        hashInt(&hash, u16, self.main.len);
        for (self.main) |slot| hashSlot(&hash, slot);
        hashInt(&hash, u16, self.preprocessed.len);
        for (self.preprocessed) |slot| hashSlot(&hash, slot);
        hashInt(&hash, u16, self.parameters.len);
        for (self.parameters) |value| hashInt(&hash, u32, @intFromEnum(value));
        return hash.finalResult();
    }
};

pub const LayerProfile = struct {
    width: u32,
    tree_height: u32,
};

pub const LaneProfile = struct {
    query_count: u32,
    lifting_log_size: u32,
    layers: []const LayerProfile,

    pub fn foldWidths(self: LaneProfile, destination: []u32) Error![]u32 {
        if (destination.len < self.layers.len) return error.InvalidProfile;
        for (self.layers, destination) |layer, *width| width.* = layer.width;
        return destination[0..self.layers.len];
    }
};

pub const Reference = struct {
    vm: LaneProfile,
    recursion: LaneProfile,
    authority_digest: digest.Digest,

    pub fn seal(vm: LaneProfile, recursion: LaneProfile) Error!Reference {
        try validateProfiles(vm, recursion);
        return .{
            .vm = vm,
            .recursion = recursion,
            .authority_digest = referenceDigest(vm, recursion),
        };
    }

    pub fn validate(self: Reference) Error!void {
        try validateProfiles(self.vm, self.recursion);
        if (!std.mem.eql(
            u8,
            &self.authority_digest,
            &referenceDigest(self.vm, self.recursion),
        )) return error.AuthorityMismatch;
    }

    pub fn validateQueryMapping(
        self: Reference,
        mapping: query_mapping.Reference,
    ) Error!void {
        try self.validate();
        try mapping.validate();
        try laneMatchesMapping(self.vm, mapping.vm);
        try laneMatchesMapping(self.recursion, mapping.recursion);
    }

    pub fn validateMerkleRoots(
        self: Reference,
        roots: merkle_root.Reference,
    ) Error!void {
        try self.validate();
        try roots.validate();
        if (self.vm.query_count != roots.vm.query_count or
            self.recursion.query_count != roots.recursion.query_count or
            self.vm.layers.len != roots.vm.fri_layer_count or
            self.recursion.layers.len != roots.recursion.fri_layer_count)
        {
            return error.AuthorityMismatch;
        }
    }
};

pub const Chunk = struct {
    source_mask: u32,
    offset: u32,
    word: u32,
    constant: u32,
};

pub const Row = struct {
    row_mask: u32,
    segment_mask: u32,
    binary_mask: u32,
    verifier_id: u32,
    layer: u32,
    query: u32,
    packed_index: u32,
    leaf_count: u32,
    local_root_mask: u32,
    tree_id: u32,
    tree_height: u32,
    step: u32,
    first: u32,
    last: u32,
    chunks: [component.RATE]Chunk,
    merkle_endpoint_mask: u32,
    local_root_endpoint_mask: u32,
    /// Exact query-position bit window, retained in sealed verifier metadata.
    position_shift: u32,
    position_bits: u32,

    pub fn values(self: Row) [PREPROCESSED_COLUMN_COUNT]M31 {
        var result: [PREPROCESSED_COLUMN_COUNT]M31 = undefined;
        result[0..14].* = .{
            M31.fromCanonical(self.row_mask),
            M31.fromCanonical(self.segment_mask),
            M31.fromCanonical(self.binary_mask),
            M31.fromCanonical(self.verifier_id),
            M31.fromCanonical(self.layer),
            M31.fromCanonical(self.query),
            M31.fromCanonical(self.packed_index),
            M31.fromCanonical(self.leaf_count),
            M31.fromCanonical(self.local_root_mask),
            M31.fromCanonical(self.tree_id),
            M31.fromCanonical(self.tree_height),
            M31.fromCanonical(self.step),
            M31.fromCanonical(self.first),
            M31.fromCanonical(self.last),
        };
        for (self.chunks, 0..) |chunk, index| result[14 + 4 * index ..][0..4].* = .{
            M31.fromCanonical(chunk.source_mask),
            M31.fromCanonical(chunk.offset),
            M31.fromCanonical(chunk.word),
            M31.fromCanonical(chunk.constant),
        };
        result[46] = M31.fromCanonical(self.merkle_endpoint_mask);
        result[47] = M31.fromCanonical(self.local_root_endpoint_mask);
        return result;
    }
};

pub const LayerOpening = struct {
    width: u32,
    /// Query-major, then secure value, then four M31 words.
    values: []const M31,
};

pub const OpeningSet = struct {
    raw_queries: []const M31,
    layers: []const LayerOpening,
};

pub const OpeningWitness = union(ProofKind) {
    segment_leaf: OpeningSet,
    binary_node: struct { left: OpeningSet, right: OpeningSet },
    empty_leaf: void,

    pub fn proofKind(self: OpeningWitness) ProofKind {
        return std.meta.activeTag(self);
    }
};

pub const MainRow = struct {
    enabler: M31,
    position: M31,
    leaf_index: M31,
    previous: [component.STATE_WIDTH]M31,
    chunks: [component.RATE]M31,
    output: [component.STATE_WIDTH]M31,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{ self.enabler, self.position, self.leaf_index } ++
            self.previous ++ self.chunks ++ self.output;
    }
};

pub fn materialize(row: Row, opening: OpeningSet, previous: [component.STATE_WIDTH]M31) MainRow {
    const layer = opening.layers[row.layer];
    var chunks: [component.RATE]M31 = undefined;
    for (&chunks, row.chunks) |*value, chunk| value.* = if (chunk.source_mask == 1)
        layer.values[
            (@as(usize, row.query) * layer.width + chunk.offset) * SECURE_WORD_COUNT +
                chunk.word
        ]
    else
        M31.fromCanonical(chunk.constant);
    var permutation_input = previous;
    for (chunks, 0..) |chunk, index| permutation_input[index] =
        permutation_input[index].add(chunk);
    poseidon2.permute(&permutation_input);
    const position = if (row.last == 1)
        routePosition(opening.raw_queries[row.query], row.position_shift, row.position_bits)
    else
        M31.zero();
    return .{
        .enabler = M31.one(),
        .position = position,
        .leaf_index = position.mul(M31.fromCanonical(row.leaf_count)).add(
            M31.fromCanonical(row.packed_index),
        ),
        .previous = previous,
        .chunks = chunks,
        .output = permutation_input,
    };
}

pub fn routePosition(raw: M31, shift: u32, bits: u32) M31 {
    const mask: u32 = if (bits == 31) std.math.maxInt(u31) else (@as(u32, 1) << @intCast(bits)) - 1;
    return M31.fromCanonical((raw.toU32() >> @intCast(shift)) & mask);
}

pub fn fillLaneRows(
    rows: []Row,
    cursor: *usize,
    profile: LaneProfile,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    var folded_bits: u32 = 0;
    for (profile.layers, 0..) |layer, layer_index| {
        const geometry = try layerGeometry(profile.lifting_log_size, folded_bits, layer);
        folded_bits += geometry.fold_step;
        const tree_id = try merkle_root.friTreeId(verifier_id, layer_index);
        const semantic_words = geometry.leaf_size * SECURE_WORD_COUNT;
        const hash_steps = std.math.divCeil(u32, semantic_words + 1, component.RATE) catch
            return error.ArithmeticOverflow;
        for (0..profile.query_count) |query| for (0..geometry.leaf_count) |packed_index| {
            for (0..hash_steps) |step| {
                var chunks = [_]Chunk{.{
                    .source_mask = 0,
                    .offset = 0,
                    .word = 0,
                    .constant = 0,
                }} ** component.RATE;
                for (&chunks, 0..) |*chunk, slot| {
                    const stream_index = step * component.RATE + slot;
                    if (stream_index < semantic_words) {
                        chunk.* = .{
                            .source_mask = 1,
                            .offset = @intCast(packed_index * geometry.leaf_size +
                                stream_index / SECURE_WORD_COUNT),
                            .word = @intCast(stream_index % SECURE_WORD_COUNT),
                            .constant = 0,
                        };
                    } else if (stream_index == semantic_words) {
                        chunk.constant = 1;
                    }
                }
                const last = step + 1 == hash_steps;
                rows[cursor.*] = .{
                    .row_mask = 1,
                    .segment_mask = segment_mask,
                    .binary_mask = binary_mask,
                    .verifier_id = verifier_id,
                    .layer = @intCast(layer_index),
                    .query = @intCast(query),
                    .packed_index = @intCast(packed_index),
                    .leaf_count = geometry.leaf_count,
                    .local_root_mask = @intFromBool(geometry.leaf_count == 1),
                    .tree_id = tree_id,
                    .tree_height = layer.tree_height,
                    .step = @intCast(step),
                    .first = @intFromBool(step == 0),
                    .last = @intFromBool(last),
                    .chunks = chunks,
                    .merkle_endpoint_mask = @intFromBool(last and geometry.leaf_count != 1),
                    .local_root_endpoint_mask = @intFromBool(last and geometry.leaf_count == 1),
                    .position_shift = folded_bits,
                    .position_bits = profile.lifting_log_size - folded_bits,
                };
                cursor.* += 1;
            }
        };
    }
}

pub const Geometry = struct {
    fold_step: u32,
    leaf_size: u32,
    leaf_count: u32,
    subtree_height: u32,
};

pub fn layerGeometry(lifting: u32, folded_before: u32, layer: LayerProfile) Error!Geometry {
    if (layer.width < 2 or layer.width > 16 or !std.math.isPowerOfTwo(layer.width))
        return error.InvalidProfile;
    const fold_step = std.math.log2_int(u32, layer.width);
    const folded_after = std.math.add(u32, folded_before, fold_step) catch
        return error.ArithmeticOverflow;
    if (folded_after >= lifting) return error.InvalidProfile;
    const leaf_size: u32 = if (fold_step > 1) PACKED_LEAF_SIZE else 1;
    const leaf_count = layer.width / leaf_size;
    const subtree_height = std.math.log2_int(u32, leaf_count);
    const expected_height = lifting - folded_after + subtree_height;
    if (layer.tree_height != expected_height) return error.InvalidProfile;
    return .{
        .fold_step = fold_step,
        .leaf_size = leaf_size,
        .leaf_count = leaf_count,
        .subtree_height = subtree_height,
    };
}

pub fn validateProfiles(vm: LaneProfile, recursion: LaneProfile) Error!void {
    try validateProfile(vm);
    try validateProfile(recursion);
}

pub fn validateProfile(profile: LaneProfile) Error!void {
    if (profile.query_count == 0 or profile.query_count >= m31.Modulus or
        profile.lifting_log_size <= 1 or profile.lifting_log_size > MAX_LOG_SIZE or
        profile.layers.len == 0 or profile.layers.len >= merkle_root.TREE_INDEX_LIMIT)
    {
        return error.InvalidProfile;
    }
    var folded: u32 = 0;
    for (profile.layers) |layer| {
        const geometry = try layerGeometry(profile.lifting_log_size, folded, layer);
        folded += geometry.fold_step;
    }
}

pub fn rowsForLane(profile: LaneProfile) Error!usize {
    var count: usize = 0;
    var folded: u32 = 0;
    for (profile.layers) |layer| {
        const geometry = try layerGeometry(profile.lifting_log_size, folded, layer);
        folded += geometry.fold_step;
        const semantic_words = geometry.leaf_size * SECURE_WORD_COUNT;
        const hash_steps = std.math.divCeil(u32, semantic_words + 1, component.RATE) catch
            return error.ArithmeticOverflow;
        var layer_rows = std.math.mul(usize, profile.query_count, geometry.leaf_count) catch
            return error.ArithmeticOverflow;
        layer_rows = std.math.mul(usize, layer_rows, hash_steps) catch
            return error.ArithmeticOverflow;
        count = std.math.add(usize, count, layer_rows) catch return error.ArithmeticOverflow;
    }
    return count;
}

pub fn laneMatchesMapping(profile: LaneProfile, mapping: query_mapping.LaneProfile) Error!void {
    if (profile.query_count != mapping.query_count or
        profile.lifting_log_size != mapping.lifting_log_size or
        profile.layers.len != mapping.fri_fold_widths.len)
    {
        return error.AuthorityMismatch;
    }
    for (profile.layers, mapping.fri_fold_widths) |layer, width| {
        if (layer.width != width) return error.AuthorityMismatch;
    }
}

pub fn referenceDigest(vm: LaneProfile, recursion: LaneProfile) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(REFERENCE_DOMAIN);
    hashInt(&hash, u16, REFERENCE_FORMAT_VERSION);
    hashLane(&hash, vm);
    hashLane(&hash, recursion);
    return hash.finalResult();
}

pub fn hashLane(hash: anytype, profile: LaneProfile) void {
    hashInt(hash, u32, profile.query_count);
    hashInt(hash, u32, profile.lifting_log_size);
    hashInt(hash, u32, profile.layers.len);
    for (profile.layers) |layer| {
        hashInt(hash, u32, layer.width);
        hashInt(hash, u32, layer.tree_height);
    }
}

pub fn hashSlot(hash: anytype, slot: anytype) void {
    hashInt(hash, u8, slot.column);
    hashInt(hash, u32, @intFromEnum(slot.value));
    hashInt(hash, u8, @intFromEnum(slot.source));
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
