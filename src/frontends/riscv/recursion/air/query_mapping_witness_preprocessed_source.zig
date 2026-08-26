//! Internal query mapping witness authority shard; use query_mapping_witness.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const digest = @import("../../air/lang/digest.zig");
pub const direct = @import("../../air/lang/direct_witness_executor.zig");
pub const types = @import("../../air/lang/types.zig");
pub const component = @import("query_mapping.zig");
pub const query_bits_witness = @import("query_bits_witness.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const SEGMENT_VERIFIER_ID = query_bits_witness.SEGMENT_VERIFIER_ID;
pub const LEFT_RECURSION_VERIFIER_ID = query_bits_witness.LEFT_RECURSION_VERIFIER_ID;
pub const RIGHT_RECURSION_VERIFIER_ID = query_bits_witness.RIGHT_RECURSION_VERIFIER_ID;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = query_bits_witness.ProofKind;
pub const QueryWitness = query_bits_witness.QueryWitness;

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN = "stwo-zig/typed-air/recursion-query-mapping-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "07e9a873c4d15166bc0a836967ef19f2ca28970efa3539dac03fce651f89bd19";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion query-mapping witness-binding digest",
);
pub const REFERENCE_FORMAT_VERSION: u16 = 1;
pub const REFERENCE_DOMAIN = "stwo-zig/typed-air/recursion-query-mapping-reference/v1\x00";

pub const Error = direct.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    BitRangeOutOfBounds,
    InvalidFriFoldWidth,
    InvalidProfile,
    InvalidWitnessBinding,
    LogSizeOutOfRange,
    PositionNotCanonical,
    QueryCountMismatch,
};

pub const MainSource = enum(u8) {
    enabler = 0,
    position = 1,
    offset = 2,
    bit_0 = 3,
    bit_1 = 4,
    bit_2 = 5,
    bit_3 = 6,
    bit_4 = 7,
    bit_5 = 8,
    bit_6 = 9,
    bit_7 = 10,
    bit_8 = 11,
    bit_9 = 12,
    bit_10 = 13,
    bit_11 = 14,
    bit_12 = 15,
    bit_13 = 16,
    bit_14 = 17,
    bit_15 = 18,
    bit_16 = 19,
    bit_17 = 20,
    bit_18 = 21,
    bit_19 = 22,
    bit_20 = 23,
    bit_21 = 24,
    bit_22 = 25,
    bit_23 = 26,
    bit_24 = 27,
    bit_25 = 28,
    bit_26 = 29,
    bit_27 = 30,
    bit_28 = 31,
    bit_29 = 32,
    bit_30 = 33,
};

pub const PreprocessedSource = enum(u8) {
    row_mask = 0,
    segment_mask = 1,
    binary_mask = 2,
    verifier_id = 3,
    kind = 4,
    item = 5,
    query = 6,
    position_weight_0 = 7,
    position_weight_1 = 8,
    position_weight_2 = 9,
    position_weight_3 = 10,
    position_weight_4 = 11,
    position_weight_5 = 12,
    position_weight_6 = 13,
    position_weight_7 = 14,
    position_weight_8 = 15,
    position_weight_9 = 16,
    position_weight_10 = 17,
    position_weight_11 = 18,
    position_weight_12 = 19,
    position_weight_13 = 20,
    position_weight_14 = 21,
    position_weight_15 = 22,
    position_weight_16 = 23,
    position_weight_17 = 24,
    position_weight_18 = 25,
    position_weight_19 = 26,
    position_weight_20 = 27,
    position_weight_21 = 28,
    position_weight_22 = 29,
    position_weight_23 = 30,
    position_weight_24 = 31,
    position_weight_25 = 32,
    position_weight_26 = 33,
    position_weight_27 = 34,
    position_weight_28 = 35,
    position_weight_29 = 36,
    position_weight_30 = 37,
    offset_weight_0 = 38,
    offset_weight_1 = 39,
    offset_weight_2 = 40,
    offset_weight_3 = 41,
    offset_weight_4 = 42,
    offset_weight_5 = 43,
    offset_weight_6 = 44,
    offset_weight_7 = 45,
    offset_weight_8 = 46,
    offset_weight_9 = 47,
    offset_weight_10 = 48,
    offset_weight_11 = 49,
    offset_weight_12 = 50,
    offset_weight_13 = 51,
    offset_weight_14 = 52,
    offset_weight_15 = 53,
    offset_weight_16 = 54,
    offset_weight_17 = 55,
    offset_weight_18 = 56,
    offset_weight_19 = 57,
    offset_weight_20 = 58,
    offset_weight_21 = 59,
    offset_weight_22 = 60,
    offset_weight_23 = 61,
    offset_weight_24 = 62,
    offset_weight_25 = 63,
    offset_weight_26 = 64,
    offset_weight_27 = 65,
    offset_weight_28 = 66,
    offset_weight_29 = 67,
    offset_weight_30 = 68,
};

pub fn Slot(comptime SourceType: type) type {
    return struct {
        column: u8,
        value: types.ValueId,
        source: SourceType,
    };
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

pub const QueryPositionKind = enum(u32) {
    trace_tree = 1,
    deep = 2,
    fri_fold = 3,
    fri_merkle = 4,
    last_layer = 5,
};

pub const LaneProfile = struct {
    query_count: u32,
    lifting_log_size: u32,
    tree_heights: []const u32,
    fri_fold_widths: []const u32,

    pub fn useCount(self: LaneProfile) Error!u32 {
        const fri_uses = std.math.mul(u32, @intCast(self.fri_fold_widths.len), 2) catch
            return error.ArithmeticOverflow;
        const with_trees = std.math.add(u32, @intCast(self.tree_heights.len), fri_uses) catch
            return error.ArithmeticOverflow;
        return std.math.add(u32, with_trees, 2) catch return error.ArithmeticOverflow;
    }

    pub fn queryBitsProfile(self: LaneProfile) query_bits_witness.LaneProfile {
        return .{
            .query_count = self.query_count,
            .lifting_log_size = self.lifting_log_size,
            .trace_tree_count = @intCast(self.tree_heights.len),
            .fri_layer_count = @intCast(self.fri_fold_widths.len),
        };
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

    pub fn queryBitsReference(self: Reference) !query_bits_witness.Reference {
        try self.validate();
        return query_bits_witness.Reference.seal(
            self.vm.queryBitsProfile(),
            self.recursion.queryBitsProfile(),
        );
    }
};

pub const Row = struct {
    row_mask: u32,
    segment_mask: u32,
    binary_mask: u32,
    verifier_id: u32,
    kind: QueryPositionKind,
    item: u32,
    query: u32,
    position_weights: [component.M31_BIT_COUNT]u32,
    offset_weights: [component.M31_BIT_COUNT]u32,

    pub fn values(self: Row) [PREPROCESSED_COLUMN_COUNT]M31 {
        var result: [PREPROCESSED_COLUMN_COUNT]M31 = undefined;
        result[0] = M31.fromCanonical(self.row_mask);
        result[1] = M31.fromCanonical(self.segment_mask);
        result[2] = M31.fromCanonical(self.binary_mask);
        result[3] = M31.fromCanonical(self.verifier_id);
        result[4] = M31.fromCanonical(@intFromEnum(self.kind));
        result[5] = M31.fromCanonical(self.item);
        result[6] = M31.fromCanonical(self.query);
        for (self.position_weights, 0..) |weight, bit|
            result[7 + bit] = M31.fromCanonical(weight);
        for (self.offset_weights, 0..) |weight, bit|
            result[7 + component.M31_BIT_COUNT + bit] = M31.fromCanonical(weight);
        return result;
    }
};

pub fn shiftedWeights(start: u32, count: u32) Error![component.M31_BIT_COUNT]u32 {
    const end = std.math.add(u32, start, count) catch return error.BitRangeOutOfBounds;
    if (end > component.M31_BIT_COUNT) return error.BitRangeOutOfBounds;
    var weights = [_]u32{0} ** component.M31_BIT_COUNT;
    for (start..end) |source| {
        weights[source] = @as(u32, 1) << @intCast(source - start);
    }
    return weights;
}

pub fn preprocessedTreeWeights(
    lifting_log_size: u32,
    tree_height: u32,
) Error![component.M31_BIT_COUNT]u32 {
    if (lifting_log_size > MAX_LOG_SIZE or tree_height > MAX_LOG_SIZE)
        return error.BitRangeOutOfBounds;
    var weights = [_]u32{0} ** component.M31_BIT_COUNT;
    if (tree_height == 0) return weights;
    weights[0] = 1;
    if (lifting_log_size < tree_height) {
        for (1..lifting_log_size) |source| {
            const target = source + tree_height - lifting_log_size;
            weights[source] = @as(u32, 1) << @intCast(target);
        }
    } else {
        const source_start = lifting_log_size - tree_height + 1;
        for (source_start..lifting_log_size) |source| {
            const target = source + tree_height - lifting_log_size;
            weights[source] = @as(u32, 1) << @intCast(target);
        }
    }
    return weights;
}

pub fn validateProfiles(vm: LaneProfile, recursion: LaneProfile) Error!void {
    for ([_]LaneProfile{ vm, recursion }) |profile| {
        if (profile.query_count == 0 or profile.query_count >= m31.Modulus or
            profile.lifting_log_size < MIN_LOG_SIZE or profile.lifting_log_size > MAX_LOG_SIZE or
            profile.tree_heights.len == 0 or profile.tree_heights.len >= m31.Modulus or
            profile.fri_fold_widths.len == 0 or profile.fri_fold_widths.len >= m31.Modulus or
            try profile.useCount() >= m31.Modulus)
        {
            return error.InvalidProfile;
        }
        for (profile.tree_heights) |height| if (height > MAX_LOG_SIZE)
            return error.InvalidProfile;
        var folded_bits: u32 = 0;
        for (profile.fri_fold_widths) |width| {
            if (width < 2 or !std.math.isPowerOfTwo(width))
                return error.InvalidFriFoldWidth;
            const fold_step = std.math.log2_int(u32, width);
            folded_bits = std.math.add(u32, folded_bits, fold_step) catch
                return error.ArithmeticOverflow;
            if (folded_bits > profile.lifting_log_size) return error.InvalidProfile;
        }
    }
    _ = try totalRows(vm, recursion);
}

pub fn rowsPerQuery(profile: LaneProfile) Error!usize {
    const fri_rows = std.math.mul(usize, profile.fri_fold_widths.len, 2) catch
        return error.ArithmeticOverflow;
    const with_trees = std.math.add(usize, profile.tree_heights.len, fri_rows) catch
        return error.ArithmeticOverflow;
    return std.math.add(usize, with_trees, 2) catch return error.ArithmeticOverflow;
}

pub fn laneRows(profile: LaneProfile) Error!usize {
    return std.math.mul(usize, profile.query_count, try rowsPerQuery(profile)) catch
        return error.ArithmeticOverflow;
}

pub fn totalRows(vm: LaneProfile, recursion: LaneProfile) Error!usize {
    const recursion_rows = std.math.mul(usize, try laneRows(recursion), 2) catch
        return error.ArithmeticOverflow;
    return std.math.add(usize, try laneRows(vm), recursion_rows) catch
        return error.ArithmeticOverflow;
}

pub fn fillProfileRows(
    rows: []Row,
    cursor: *usize,
    profile: LaneProfile,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    for (0..profile.query_count) |query| {
        for (profile.tree_heights, 0..) |height, tree| {
            const weights = if (tree == 0)
                try preprocessedTreeWeights(profile.lifting_log_size, height)
            else
                try shiftedWeights(0, height);
            rows[cursor.*] = routeRow(
                verifier_id,
                segment_mask,
                binary_mask,
                .trace_tree,
                @intCast(tree),
                @intCast(query),
                weights,
                [_]u32{0} ** component.M31_BIT_COUNT,
            );
            cursor.* += 1;
        }
        rows[cursor.*] = routeRow(
            verifier_id,
            segment_mask,
            binary_mask,
            .deep,
            0,
            @intCast(query),
            try shiftedWeights(0, profile.lifting_log_size),
            [_]u32{0} ** component.M31_BIT_COUNT,
        );
        cursor.* += 1;
        var folded_bits: u32 = 0;
        for (profile.fri_fold_widths, 0..) |width, layer| {
            const fold_step = std.math.log2_int(u32, width);
            const remaining = profile.lifting_log_size - folded_bits;
            rows[cursor.*] = routeRow(
                verifier_id,
                segment_mask,
                binary_mask,
                .fri_fold,
                @intCast(layer),
                @intCast(query),
                try shiftedWeights(folded_bits, remaining),
                try shiftedWeights(folded_bits, fold_step),
            );
            cursor.* += 1;
            folded_bits += fold_step;
            rows[cursor.*] = routeRow(
                verifier_id,
                segment_mask,
                binary_mask,
                .fri_merkle,
                @intCast(layer),
                @intCast(query),
                try shiftedWeights(
                    folded_bits,
                    profile.lifting_log_size - folded_bits,
                ),
                [_]u32{0} ** component.M31_BIT_COUNT,
            );
            cursor.* += 1;
        }
        rows[cursor.*] = routeRow(
            verifier_id,
            segment_mask,
            binary_mask,
            .last_layer,
            0,
            @intCast(query),
            try shiftedWeights(
                folded_bits,
                profile.lifting_log_size - folded_bits,
            ),
            [_]u32{0} ** component.M31_BIT_COUNT,
        );
        cursor.* += 1;
    }
}

pub fn routeRow(
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
    kind: QueryPositionKind,
    item: u32,
    query: u32,
    position_weights: [component.M31_BIT_COUNT]u32,
    offset_weights: [component.M31_BIT_COUNT]u32,
) Row {
    return .{
        .row_mask = 1,
        .segment_mask = segment_mask,
        .binary_mask = binary_mask,
        .verifier_id = verifier_id,
        .kind = kind,
        .item = item,
        .query = query,
        .position_weights = position_weights,
        .offset_weights = offset_weights,
    };
}

pub fn expectRow(actual: Row, expected: Row) Error!void {
    if (!std.meta.eql(actual, expected)) return error.AuthorityMismatch;
}

pub fn referenceDigest(vm: LaneProfile, recursion: LaneProfile) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(REFERENCE_DOMAIN);
    hashInt(&hash, u16, REFERENCE_FORMAT_VERSION);
    hashProfile(&hash, vm);
    hashProfile(&hash, recursion);
    return hash.finalResult();
}

pub fn hashProfile(hash: anytype, profile: LaneProfile) void {
    hashInt(hash, u32, profile.query_count);
    hashInt(hash, u32, profile.lifting_log_size);
    hashInt(hash, u32, profile.tree_heights.len);
    for (profile.tree_heights) |height| hashInt(hash, u32, height);
    hashInt(hash, u32, profile.fri_fold_widths.len);
    for (profile.fri_fold_widths) |width| hashInt(hash, u32, width);
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
