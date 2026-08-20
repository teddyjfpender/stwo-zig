//! Internal pcs deep input witness authority shard; use pcs_deep_input_witness.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const digest = @import("../../air/lang/digest.zig");
pub const direct = @import("../../air/lang/direct_witness_executor.zig");
pub const types = @import("../../air/lang/types.zig");
pub const circuit = @import("composition_circuit.zig");
pub const component = @import("pcs_deep_input.zig");
pub const merkle_root = @import("merkle_root_witness.zig");
pub const proof_kind_mod = @import("proof_kind.zig");
pub const trace_merkle = @import("trace_merkle_witness.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const SECURE_WORD_COUNT: u32 = 4;
pub const M31_BIT_COUNT: u32 = 31;
pub const SAMPLED_VALUE_KIND: u32 = 6;
pub const OODS_POINT_KIND: u32 = 2;
pub const DEEP_RANDOMNESS_KIND: u32 = 3;
pub const DEEP_POSITION_KIND: u32 = 2;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = proof_kind_mod.ProofKind;
pub const SEGMENT_VERIFIER_ID = merkle_root.SEGMENT_VERIFIER_ID;
pub const LEFT_RECURSION_VERIFIER_ID = merkle_root.LEFT_RECURSION_VERIFIER_ID;
pub const RIGHT_RECURSION_VERIFIER_ID = merkle_root.RIGHT_RECURSION_VERIFIER_ID;

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN = "stwo-zig/typed-air/recursion-pcs-deep-input-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "9efd26d505f7f4990f31aae6a6db396007b5c4a31d90f83418c14db14d3bb0dc";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion PCS-DEEP-input witness-binding digest",
);
pub const REFERENCE_FORMAT_VERSION: u16 = 1;
pub const REFERENCE_DOMAIN = "stwo-zig/typed-air/recursion-pcs-deep-reference/v1\x00";
pub const SCHEDULE_FORMAT_VERSION: u16 = 1;
pub const SCHEDULE_DOMAIN = "stwo-zig/typed-air/recursion-pcs-deep-schedule/v1\x00";

pub const Error = direct.Error || std.mem.Allocator.Error || circuit.Error ||
    trace_merkle.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    CircuitIdNotCanonical,
    DuplicateCircuitId,
    InputBindingCountMismatch,
    InputBindingNodeMismatch,
    InputBindingTargetsNonInput,
    InvalidProfile,
    InvalidSource,
    InvalidWitness,
    InvalidWitnessBinding,
    LogSizeOutOfRange,
    VerifierLaneOrderMismatch,
};

pub const MainSource = enum(u8) {
    enabler = 0,
    value = 1,
};

pub const PreprocessedSource = enum(u8) {
    row_mask = 0,
    segment_mask = 1,
    binary_mask = 2,
    sampled_value_mask = 3,
    queried_value_mask = 4,
    oods_seed_mask = 5,
    deep_randomness_mask = 6,
    query_bit_mask = 7,
    query_position_mask = 8,
    answer_mask = 9,
    selector_mask = 10,
    verifier_id = 11,
    circuit_id = 12,
    node_id = 13,
    use_count = 14,
    source_index_0 = 15,
    source_index_1 = 16,
    source_index_2 = 17,
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

pub const TreeProfile = struct {
    column_log_sizes: []const u32,
};

pub const LaneProfile = struct {
    sample_count: u32,
    query_count: u32,
    lifting_log_size: u32,
    trees: []const TreeProfile,

    pub fn columnCount(self: LaneProfile) Error!usize {
        var count: usize = 0;
        for (self.trees) |tree| count = std.math.add(
            usize,
            count,
            tree.column_log_sizes.len,
        ) catch return error.ArithmeticOverflow;
        return count;
    }

    pub fn inputCount(self: LaneProfile) Error!usize {
        var count: usize = 1;
        count = try addProduct(count, self.sample_count, SECURE_WORD_COUNT);
        count = try addProduct(count, try self.columnCount(), self.query_count);
        count = std.math.add(usize, count, 2 * SECURE_WORD_COUNT) catch
            return error.ArithmeticOverflow;
        count = try addProduct(count, self.query_count, M31_BIT_COUNT);
        count = std.math.add(usize, count, self.query_count) catch
            return error.ArithmeticOverflow;
        return addProduct(count, self.query_count, SECURE_WORD_COUNT);
    }
};

pub const Source = union(enum) {
    active_selector,
    sampled_value_word: struct { sample: u32, word: u32 },
    queried_value: struct { tree: u32, column: u32, query: u32 },
    oods_seed_word: u32,
    deep_randomness_word: u32,
    query_bit: struct { query: u32, bit: u32 },
    query_position: u32,
    answer_word: struct { query: u32, word: u32 },
};

pub const InputBinding = struct {
    node_id: u32,
    source: Source,
};

pub const Lane = struct {
    verifier_id: u32,
    circuit_id: u32,
    profile: LaneProfile,
    graph: circuit.CircuitGraph,
    bindings: []const InputBinding,
};

pub const Reference = struct {
    lanes: [3]Lane,
    authority_digest: digest.Digest,

    pub fn authenticate(
        lanes: [3]Lane,
        expected_digest: digest.Digest,
    ) Error!Reference {
        const candidate = Reference{
            .lanes = lanes,
            .authority_digest = expected_digest,
        };
        try candidate.validateStructure();
        const actual = referenceDigest(lanes);
        if (!std.mem.eql(u8, &actual, &expected_digest))
            return error.AuthorityMismatch;
        return .{ .lanes = lanes, .authority_digest = actual };
    }

    pub fn validate(self: Reference) Error!void {
        try self.validateStructure();
        const actual = referenceDigest(self.lanes);
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthorityMismatch;
    }

    pub fn validateTraceMerkle(
        self: Reference,
        trace_reference: trace_merkle.Reference,
    ) Error!void {
        try self.validate();
        try trace_reference.validate();
        try profileMatchesTrace(self.lanes[0].profile, trace_reference.vm);
        try profileMatchesTrace(self.lanes[1].profile, trace_reference.recursion);
        try profileMatchesTrace(self.lanes[2].profile, trace_reference.recursion);
    }

    fn validateStructure(self: Reference) Error!void {
        const expected_ids = [_]u32{
            SEGMENT_VERIFIER_ID,
            LEFT_RECURSION_VERIFIER_ID,
            RIGHT_RECURSION_VERIFIER_ID,
        };
        for (self.lanes, expected_ids, 0..) |lane, expected_id, lane_index| {
            if (lane.verifier_id != expected_id)
                return error.VerifierLaneOrderMismatch;
            if (lane.circuit_id >= m31.Modulus) return error.CircuitIdNotCanonical;
            for (self.lanes[0..lane_index]) |previous| if (previous.circuit_id == lane.circuit_id)
                return error.DuplicateCircuitId;
            try validateProfile(lane.profile);
            try lane.graph.validate();
            try validateBindings(lane);
        }
    }
};

pub const Row = struct {
    source: Source,
    lane: u32,
    binding: u32,
    verifier_id: u32,
    circuit_id: u32,
    node_id: u32,
    use_count: u32,

    pub fn values(self: Row) [PREPROCESSED_COLUMN_COUNT]M31 {
        const tag = std.meta.activeTag(self.source);
        const indices = sourceIndices(self.source);
        const segment = self.verifier_id == SEGMENT_VERIFIER_ID;
        return .{
            M31.one(),
            boolM31(segment),
            boolM31(!segment),
            boolM31(tag == .sampled_value_word),
            boolM31(tag == .queried_value),
            boolM31(tag == .oods_seed_word),
            boolM31(tag == .deep_randomness_word),
            boolM31(tag == .query_bit),
            boolM31(tag == .query_position),
            boolM31(tag == .answer_word),
            boolM31(tag == .active_selector),
            M31.fromCanonical(self.verifier_id),
            M31.fromCanonical(self.circuit_id),
            M31.fromCanonical(self.node_id),
            M31.fromCanonical(self.use_count),
            M31.fromCanonical(indices[0]),
            M31.fromCanonical(indices[1]),
            M31.fromCanonical(indices[2]),
        };
    }
};

pub const LaneWitness = struct {
    verifier_id: u32,
    circuit_id: u32,
    graph_digest: digest.Digest,
    input_values: []const M31,
};

pub const InputWitness = struct {
    lanes: [3]LaneWitness,
};

pub fn expectedSource(profile: LaneProfile, source_index: usize) Error!?Source {
    if (source_index == 0) return .active_selector;
    var index = source_index - 1;
    const sampled_words = std.math.mul(usize, profile.sample_count, SECURE_WORD_COUNT) catch
        return error.ArithmeticOverflow;
    if (index < sampled_words) return .{ .sampled_value_word = .{
        .sample = @intCast(index / SECURE_WORD_COUNT),
        .word = @intCast(index % SECURE_WORD_COUNT),
    } };
    index -= sampled_words;
    const queried_values = std.math.mul(usize, try profile.columnCount(), profile.query_count) catch
        return error.ArithmeticOverflow;
    if (index < queried_values) {
        const flat_column = index / profile.query_count;
        const query: u32 = @intCast(index % profile.query_count);
        var remaining = flat_column;
        for (profile.trees, 0..) |tree, tree_index| {
            if (remaining < tree.column_log_sizes.len) return .{ .queried_value = .{
                .tree = @intCast(tree_index),
                .column = @intCast(remaining),
                .query = query,
            } };
            remaining -= tree.column_log_sizes.len;
        }
        unreachable;
    }
    index -= queried_values;
    if (index < SECURE_WORD_COUNT) return .{ .oods_seed_word = @intCast(index) };
    index -= SECURE_WORD_COUNT;
    if (index < SECURE_WORD_COUNT) return .{ .deep_randomness_word = @intCast(index) };
    index -= SECURE_WORD_COUNT;
    const query_coordinates = @as(usize, profile.query_count) * (M31_BIT_COUNT + 1);
    if (index < query_coordinates) {
        const query: u32 = @intCast(index / (M31_BIT_COUNT + 1));
        const coordinate = index % (M31_BIT_COUNT + 1);
        if (coordinate < M31_BIT_COUNT) return .{ .query_bit = .{
            .query = query,
            .bit = @intCast(coordinate),
        } };
        return .{ .query_position = query };
    }
    index -= query_coordinates;
    const answer_words = @as(usize, profile.query_count) * SECURE_WORD_COUNT;
    if (index < answer_words) return .{ .answer_word = .{
        .query = @intCast(index / SECURE_WORD_COUNT),
        .word = @intCast(index % SECURE_WORD_COUNT),
    } };
    return null;
}

pub fn validateProfile(profile: LaneProfile) Error!void {
    if (profile.query_count == 0 or profile.query_count >= m31.Modulus or
        profile.sample_count >= m31.Modulus or profile.lifting_log_size == 0 or
        profile.lifting_log_size > MAX_LOG_SIZE or profile.trees.len == 0 or
        profile.trees.len >= m31.Modulus)
    {
        return error.InvalidProfile;
    }
    for (profile.trees) |tree| {
        if (tree.column_log_sizes.len == 0 or tree.column_log_sizes.len >= m31.Modulus)
            return error.InvalidProfile;
        for (tree.column_log_sizes) |log_size| if (log_size == 0 or
            log_size > profile.lifting_log_size)
        {
            return error.InvalidProfile;
        };
    }
    const count = try profile.inputCount();
    if (count == 0 or count >= m31.Modulus) return error.InvalidProfile;
}

pub fn validateBindings(lane: Lane) Error!void {
    const count = try lane.profile.inputCount();
    if (lane.bindings.len != count) return error.InputBindingCountMismatch;
    var cursor: usize = 0;
    for (lane.graph.nodes, 0..) |node, node_index| switch (node.op) {
        .input => {
            if (cursor >= lane.bindings.len) return error.InputBindingCountMismatch;
            const binding = lane.bindings[cursor];
            if (binding.node_id != node_index) return error.InputBindingNodeMismatch;
            const expected = (try expectedSource(lane.profile, cursor)) orelse
                return error.InvalidSource;
            if (!std.meta.eql(expected, binding.source)) return error.InvalidSource;
            cursor += 1;
        },
        else => {},
    };
    if (cursor != lane.bindings.len) return error.InputBindingTargetsNonInput;
}

pub fn validateWitness(
    reference: Reference,
    input_witness: InputWitness,
    proof_kind: ProofKind,
) Error!void {
    const expected_ids = [_]u32{
        SEGMENT_VERIFIER_ID,
        LEFT_RECURSION_VERIFIER_ID,
        RIGHT_RECURSION_VERIFIER_ID,
    };
    for (reference.lanes, input_witness.lanes, expected_ids) |
        lane,
        supplied,
        verifier_id,
    | {
        if (supplied.verifier_id != verifier_id or
            supplied.circuit_id != lane.circuit_id or
            !std.mem.eql(u8, &supplied.graph_digest, &lane.graph.identity_digest) or
            supplied.input_values.len != lane.bindings.len)
        {
            return error.InvalidWitness;
        }
        const active = switch (verifier_id) {
            SEGMENT_VERIFIER_ID => proof_kind == .segment_leaf,
            LEFT_RECURSION_VERIFIER_ID, RIGHT_RECURSION_VERIFIER_ID => proof_kind == .binary_node,
            else => unreachable,
        };
        for (lane.bindings, supplied.input_values) |binding, value| {
            if (std.meta.activeTag(binding.source) == .active_selector) {
                if (!value.eql(boolM31(active))) return error.InvalidWitness;
            } else if (!active and !value.isZero()) {
                return error.InvalidWitness;
            }
        }
    }
}

pub fn profileMatchesTrace(
    profile: LaneProfile,
    trace_profile: trace_merkle.LaneProfile,
) Error!void {
    if (profile.query_count != trace_profile.query_count or
        profile.lifting_log_size != trace_profile.lifting_log_size or
        profile.trees.len != trace_profile.trees.len)
    {
        return error.AuthorityMismatch;
    }
    for (profile.trees, trace_profile.trees) |lhs, rhs| {
        if (!std.mem.eql(u32, lhs.column_log_sizes, rhs.column_log_sizes))
            return error.AuthorityMismatch;
    }
}

pub fn totalRows(reference: Reference) Error!usize {
    var count: usize = 0;
    for (reference.lanes) |lane| count = std.math.add(
        usize,
        count,
        lane.bindings.len,
    ) catch return error.ArithmeticOverflow;
    return count;
}

pub fn traceLogSize(row_count: usize) Error!u32 {
    const padded = std.math.ceilPowerOfTwo(usize, @max(row_count, @as(usize, 1) << MIN_LOG_SIZE)) catch
        return error.ArithmeticOverflow;
    const log_size = std.math.log2_int(usize, padded);
    if (log_size > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
    return @intCast(log_size);
}

pub fn maximumNodeCount(reference: Reference) usize {
    var count: usize = 0;
    for (reference.lanes) |lane| count = @max(count, lane.graph.nodes.len);
    return count;
}

pub fn computeUseCounts(graph: circuit.CircuitGraph, scratch: []u32) Error!void {
    const uses = scratch[0..graph.nodes.len];
    @memset(uses, 0);
    for (graph.nodes) |node| switch (node.op) {
        .add, .sub, .mul => |operands| {
            try incrementUse(&uses[operands.lhs]);
            try incrementUse(&uses[operands.rhs]);
        },
        .neg, .inverse => |operand| try incrementUse(&uses[operand]),
        .input, .constant => {},
    };
    for (graph.outputs) |output| try incrementUse(&uses[output]);
}

pub fn incrementUse(value: *u32) Error!void {
    value.* = std.math.add(u32, value.*, 1) catch return error.ArithmeticOverflow;
    if (value.* >= m31.Modulus) return error.InvalidProfile;
}

pub fn validateRow(row: Row) Error!void {
    if (row.lane >= 3 or row.binding >= m31.Modulus or
        row.verifier_id != row.lane or row.circuit_id >= m31.Modulus or
        row.node_id >= m31.Modulus or row.use_count >= m31.Modulus)
    {
        return error.InvalidProfile;
    }
    const indices = sourceIndices(row.source);
    for (indices) |value| if (value >= m31.Modulus) return error.InvalidProfile;
}

pub fn validateRowDirect(row: Row) direct.Error!void {
    validateRow(row) catch return error.InvalidTraceRow;
}

pub fn writePreprocessedRow(
    columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    logical_row: usize,
    row: Row,
) void {
    const values = row.values();
    for (columns, values) |column, value| column[logical_row] = value;
}

pub const AddressRange = struct {
    start: usize,
    end: usize,
    pub fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

pub fn sliceRange(comptime T: type, values: []const T) direct.Error!AddressRange {
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    return .{ .start = start, .end = std.math.add(usize, start, byte_len) catch
        return error.AddressOverflow };
}

pub fn objectRange(value: anytype) direct.Error!AddressRange {
    const T = @TypeOf(value.*);
    const start = @intFromPtr(value);
    return .{ .start = start, .end = std.math.add(usize, start, @sizeOf(T)) catch
        return error.AddressOverflow };
}

pub fn sourceIndices(source_value: Source) [3]u32 {
    return switch (source_value) {
        .active_selector => .{ 0, 0, 0 },
        .sampled_value_word => |item| .{ item.sample, item.word, 0 },
        .queried_value => |item| .{ item.tree, item.column, item.query },
        .oods_seed_word, .deep_randomness_word => |word| .{ 0, word, 0 },
        .query_bit => |item| .{ item.query, item.bit, 0 },
        .query_position => |query| .{ query, 0, 0 },
        .answer_word => |item| .{ item.query, item.word, 0 },
    };
}

pub fn referenceDigest(lanes: [3]Lane) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(REFERENCE_DOMAIN);
    hashInt(&hash, u16, REFERENCE_FORMAT_VERSION);
    hashInt(&hash, u8, lanes.len);
    for (lanes) |lane| {
        hashInt(&hash, u32, lane.verifier_id);
        hashInt(&hash, u32, lane.circuit_id);
        hash.update(&lane.graph.identity_digest);
        hashProfile(&hash, lane.profile);
        hashInt(&hash, u32, lane.bindings.len);
        for (lane.bindings) |binding| {
            hashInt(&hash, u32, binding.node_id);
            hashSource(&hash, binding.source);
        }
    }
    return hash.finalResult();
}

pub fn hashProfile(hash: anytype, profile: LaneProfile) void {
    hashInt(hash, u32, profile.sample_count);
    hashInt(hash, u32, profile.query_count);
    hashInt(hash, u32, profile.lifting_log_size);
    hashInt(hash, u32, profile.trees.len);
    for (profile.trees) |tree| {
        hashInt(hash, u32, tree.column_log_sizes.len);
        for (tree.column_log_sizes) |log_size| hashInt(hash, u32, log_size);
    }
}

pub fn hashSource(hash: anytype, source_value: Source) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(source_value)));
    for (sourceIndices(source_value)) |value| hashInt(hash, u32, value);
}

pub fn addProduct(base: usize, lhs: anytype, rhs: anytype) Error!usize {
    const product = std.math.mul(usize, @intCast(lhs), @intCast(rhs)) catch
        return error.ArithmeticOverflow;
    return std.math.add(usize, base, product) catch return error.ArithmeticOverflow;
}

pub fn boolM31(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
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
