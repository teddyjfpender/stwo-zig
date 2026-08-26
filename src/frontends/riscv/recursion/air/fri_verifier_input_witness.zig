//! Verifier-owned row-29 schedule and allocation-free FRI-circuit input writer.
//!
//! Cold admission authenticates the exact fixed FRI arithmetic circuits and
//! derives every input row and graph use count. Proof-time emission consumes
//! evaluated circuit nodes only after allocation-free operation replay and
//! active-lane zeroing checks. The immutable row seal, not caller-provided
//! input inventory, remains the schedule authority.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const digest = @import("../../air/lang/digest.zig");
const direct = @import("../../air/lang/direct_witness_executor.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("fri_verifier_input.zig");
const circuit_mod = @import("fri_verifier_circuit.zig");
const proof_kind_mod = @import("proof_kind.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = proof_kind_mod.ProofKind;
pub const Circuit = circuit_mod.Circuit;
pub const Evaluation = circuit_mod.Evaluation;
pub const Source = circuit_mod.InputSource;

pub const SEGMENT_VERIFIER_ID: u32 = 0;
pub const LEFT_RECURSION_VERIFIER_ID: u32 = 1;
pub const RIGHT_RECURSION_VERIFIER_ID: u32 = 2;
pub const FRI_ALPHA_KIND: u32 = 4;
pub const FRI_FOLD_KIND: u32 = 3;
pub const LAST_LAYER_KIND: u32 = 5;
pub const POSITION_FIELD: u32 = 1;
pub const OFFSET_FIELD: u32 = 2;
pub const COEFFICIENT_KIND: u32 = 8;

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-fri-verifier-input-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "335f4a819c6ed2f9b8e4b6fac930fb403b121e7206739c05e55c4d1f1f36dd21";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion FRI-verifier-input witness-binding digest",
);
pub const REFERENCE_DOMAIN =
    "stwo-zig/typed-air/recursion-fri-verifier-input-reference/v1\x00";
pub const ROWS_DOMAIN =
    "stwo-zig/typed-air/recursion-fri-verifier-input-rows/v1\x00";

pub const Error = direct.Error || std.mem.Allocator.Error || circuit_mod.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    CircuitIdNotCanonical,
    DuplicateCircuitId,
    InputIsNotBaseField,
    InvalidCircuitLane,
    InvalidSource,
    InvalidWitness,
    InvalidWitnessBinding,
    LogSizeOutOfRange,
    NodeIdNotCanonical,
    UseCountNotCanonical,
};

pub const MainSource = enum(u8) {
    enabler = 0,
    value = 1,
};

pub const PreprocessedSource = enum(u8) {
    row_mask = 0,
    segment_mask = 1,
    binary_mask = 2,
    deep_answer_mask = 3,
    authenticated_value_mask = 4,
    alpha_mask = 5,
    query_bit_mask = 6,
    fri_position_mask = 7,
    fri_offset_mask = 8,
    last_position_mask = 9,
    coefficient_mask = 10,
    selector_mask = 11,
    verifier_id = 12,
    circuit_id = 13,
    node_id = 14,
    use_count = 15,
    source_index_0 = 16,
    source_index_1 = 17,
    source_index_2 = 18,
    source_index_3 = 19,
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

pub const Executor = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(definition: *const component.Definition, supplied: *const Binding) !Executor {
        const expected = try Binding.canonical(definition);
        if (!std.meta.eql(expected, supplied.*)) return error.InvalidWitnessBinding;
        const binding_digest = supplied.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        return .{ .binding = supplied.*, .binding_digest = binding_digest };
    }

    pub fn generatePreprocessedInto(
        self: *const Executor,
        preprocessing: *const Preprocessed,
        reference: Reference,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    ) Error!void {
        return preprocessing.generatePreprocessedInto(reference, columns, self);
    }

    pub fn generateMainInto(
        self: *const Executor,
        preprocessing: *const Preprocessed,
        reference: Reference,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        evaluations: Evaluations,
        kind: ProofKind,
    ) Error!void {
        return preprocessing.generateMainInto(reference, columns, evaluations, kind, self);
    }
};

pub const Lane = struct {
    verifier_id: u32,
    circuit_id: u32,
    circuit: *const Circuit,
};

pub const Reference = struct {
    lanes: [3]Lane,
    circuit_identities: [3]digest.Digest,
    authority_digest: digest.Digest,

    pub fn seal(lanes: [3]Lane) Error!Reference {
        try validateLaneOrder(lanes);
        var identities: [3]digest.Digest = undefined;
        for (lanes, 0..) |lane, index| {
            try lane.circuit.validate();
            identities[index] = lane.circuit.identity_digest;
        }
        return .{
            .lanes = lanes,
            .circuit_identities = identities,
            .authority_digest = referenceDigest(lanes, identities),
        };
    }

    /// Allocation-free proof-path identity check. Full graph hashing and
    /// structural validation remain at the cold admission boundary.
    pub fn validate(self: Reference) Error!void {
        try validateLaneOrder(self.lanes);
        for (self.lanes, self.circuit_identities) |lane, identity| {
            if (!std.mem.eql(u8, &lane.circuit.identity_digest, &identity))
                return error.AuthorityMismatch;
        }
        if (!std.mem.eql(
            u8,
            &self.authority_digest,
            &referenceDigest(self.lanes, self.circuit_identities),
        )) return error.AuthorityMismatch;
    }

    pub fn validateAuthority(self: Reference) Error!void {
        try self.validate();
        for (self.lanes) |lane| try lane.circuit.validate();
    }
};

pub const Evaluations = struct {
    segment: *const Evaluation,
    left: *const Evaluation,
    right: *const Evaluation,

    pub fn at(self: Evaluations, lane: usize) *const Evaluation {
        return switch (lane) {
            0 => self.segment,
            1 => self.left,
            2 => self.right,
            else => unreachable,
        };
    }
};

pub const Row = struct {
    source: Source,
    lane: u8,
    binding: u32,
    row_mask: u32,
    segment_mask: u32,
    binary_mask: u32,
    source_masks: [9]u32,
    verifier_id: u32,
    circuit_id: u32,
    node_id: u32,
    use_count: u32,
    source_indices: [4]u32,

    pub fn values(self: Row) [PREPROCESSED_COLUMN_COUNT]M31 {
        return .{
            M31.fromCanonical(self.row_mask),
            M31.fromCanonical(self.segment_mask),
            M31.fromCanonical(self.binary_mask),
            M31.fromCanonical(self.source_masks[0]),
            M31.fromCanonical(self.source_masks[1]),
            M31.fromCanonical(self.source_masks[2]),
            M31.fromCanonical(self.source_masks[3]),
            M31.fromCanonical(self.source_masks[4]),
            M31.fromCanonical(self.source_masks[5]),
            M31.fromCanonical(self.source_masks[6]),
            M31.fromCanonical(self.source_masks[7]),
            M31.fromCanonical(self.source_masks[8]),
            M31.fromCanonical(self.verifier_id),
            M31.fromCanonical(self.circuit_id),
            M31.fromCanonical(self.node_id),
            M31.fromCanonical(self.use_count),
            M31.fromCanonical(self.source_indices[0]),
            M31.fromCanonical(self.source_indices[1]),
            M31.fromCanonical(self.source_indices[2]),
            M31.fromCanonical(self.source_indices[3]),
        };
    }
};

pub const MainRow = struct {
    enabler: M31,
    value: M31,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{ self.enabler, self.value };
    }
};

pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []Row,
    reference_digest: digest.Digest,
    authority_digest: digest.Digest,

    pub fn init(allocator: std.mem.Allocator, reference: Reference) Error!Preprocessed {
        try reference.validateAuthority();
        const row_count = try totalRows(reference);
        const rows = try allocator.alloc(Row, row_count);
        errdefer allocator.free(rows);
        const max_nodes = maximumNodeCount(reference);
        const use_scratch = try allocator.alloc(u32, max_nodes);
        defer allocator.free(use_scratch);
        var cursor: usize = 0;
        for (reference.lanes, 0..) |lane, lane_index| {
            const uses = try circuit_mod.computeUseCountsInto(lane.circuit, use_scratch);
            try fillLaneRows(rows, &cursor, lane, @intCast(lane_index), uses);
        }
        if (cursor != rows.len) return error.AuthorityMismatch;
        return .{
            .allocator = allocator,
            .log_size = try traceLogSize(rows.len),
            .rows = rows,
            .reference_digest = reference.authority_digest,
            .authority_digest = rowsDigest(rows),
        };
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(self: *const Preprocessed, reference: Reference) Error!void {
        try reference.validate();
        if (self.rows.len != try totalRows(reference) or
            self.log_size != try traceLogSize(self.rows.len) or
            !std.mem.eql(u8, &self.reference_digest, &reference.authority_digest) or
            !std.mem.eql(u8, &self.authority_digest, &rowsDigest(self.rows)))
        {
            return error.AuthorityMismatch;
        }
    }

    pub fn validateAgainstAuthority(
        self: *const Preprocessed,
        allocator: std.mem.Allocator,
        reference: Reference,
    ) Error!void {
        try reference.validateAuthority();
        try self.validateAgainst(reference);
        const scratch = try allocator.alloc(u32, maximumNodeCount(reference));
        defer allocator.free(scratch);
        var cursor: usize = 0;
        for (reference.lanes, 0..) |lane, lane_index| {
            const uses = try circuit_mod.computeUseCountsInto(lane.circuit, scratch);
            try validateLaneRows(self.rows, &cursor, lane, @intCast(lane_index), uses);
        }
        if (cursor != self.rows.len) return error.AuthorityMismatch;
    }

    fn generatePreprocessedInto(
        self: *const Preprocessed,
        reference: Reference,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
        executor: *const Executor,
    ) Error!void {
        try self.validateAgainst(reference);
        return direct.generateMainInto(
            M31,
            Row,
            PREPROCESSED_COLUMN_COUNT,
            columns,
            self.rows,
            self.log_size,
            M31.zero(),
            executor,
            validateRowDirect,
            writePreprocessedRow,
        );
    }

    fn generateMainInto(
        self: *const Preprocessed,
        reference: Reference,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        evaluations: Evaluations,
        kind: ProofKind,
        executor: *const Executor,
    ) Error!void {
        try self.validateAgainst(reference);
        try validateEvaluationsHot(reference, evaluations, kind);
        _ = try preflightMain(columns, self, reference, evaluations, executor);
        for (columns) |column| @memset(column, M31.zero());
        for (self.rows, 0..) |row, row_index| {
            const value = evaluations.at(row.lane).values[row.node_id].tryIntoM31() catch
                unreachable;
            writeMainRow(columns, row_index, .{ .enabler = M31.one(), .value = value });
        }
    }
};

pub fn logicalRow(
    reference: Reference,
    preprocessing: *const Preprocessed,
    row_index: usize,
    evaluations: Evaluations,
    kind: ProofKind,
) Error![component.LOGICAL_INPUT_COUNT]M31 {
    try preprocessing.validateAgainst(reference);
    try validateEvaluationsHot(reference, evaluations, kind);
    if (row_index >= preprocessing.rows.len) return error.InvalidWitness;
    const row = preprocessing.rows[row_index];
    const value = evaluations.at(row.lane).values[row.node_id].tryIntoM31() catch
        return error.InputIsNotBaseField;
    return logicalInputs(
        (MainRow{ .enabler = M31.one(), .value = value }).values(),
        row.values(),
        kind,
    );
}

/// Allocation-free assembly used after the preprocessing/reference and the
/// complete evaluation set have passed their bulk admission checks. This
/// avoids an accidental O(rows * graph) validation loop in outer proving.
pub fn logicalInputs(
    main: [MAIN_COLUMN_COUNT]M31,
    preprocessed: [PREPROCESSED_COLUMN_COUNT]M31,
    kind: ProofKind,
) [component.LOGICAL_INPUT_COUNT]M31 {
    const selectors = kind.selectors();
    return main ++ preprocessed ++ .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(FRI_ALPHA_KIND),
        M31.fromCanonical(FRI_FOLD_KIND),
        M31.fromCanonical(LAST_LAYER_KIND),
        M31.fromCanonical(POSITION_FIELD),
        M31.fromCanonical(OFFSET_FIELD),
        M31.fromCanonical(COEFFICIENT_KIND),
    };
}

pub fn validateEvaluationsHot(
    reference: Reference,
    evaluations: Evaluations,
    kind: ProofKind,
) Error!void {
    for (reference.lanes, 0..) |lane, lane_index| {
        const evaluation = evaluations.at(lane_index);
        try lane.circuit.validateEvaluationHot(evaluation);
        const active = laneIsActive(lane.verifier_id, kind);
        for (lane.circuit.bindings) |binding| {
            const value = evaluation.values[binding.node_id].tryIntoM31() catch
                return error.InputIsNotBaseField;
            const selector = std.meta.activeTag(binding.source) == .active_selector;
            if (selector) {
                if (!value.eql(M31.fromCanonical(@intFromBool(active))))
                    return error.InvalidWitness;
            } else if (!active and !value.isZero()) {
                return error.InvalidWitness;
            }
        }
    }
}

fn fillLaneRows(
    rows: []Row,
    cursor: *usize,
    lane: Lane,
    lane_index: u8,
    uses: []const u32,
) Error!void {
    const masks = try laneMasks(lane.verifier_id);
    for (lane.circuit.bindings, 0..) |binding, binding_index| {
        if (cursor.* >= rows.len or binding.node_id >= uses.len)
            return error.AuthorityMismatch;
        const use_count = uses[binding.node_id];
        if (binding.node_id >= m31.Modulus) return error.NodeIdNotCanonical;
        if (use_count >= m31.Modulus) return error.UseCountNotCanonical;
        rows[cursor.*] = .{
            .source = binding.source,
            .lane = lane_index,
            .binding = std.math.cast(u32, binding_index) orelse
                return error.ArithmeticOverflow,
            .row_mask = 1,
            .segment_mask = masks[0],
            .binary_mask = masks[1],
            .source_masks = sourceMasks(binding.source),
            .verifier_id = lane.verifier_id,
            .circuit_id = lane.circuit_id,
            .node_id = binding.node_id,
            .use_count = use_count,
            .source_indices = sourceIndices(binding.source),
        };
        cursor.* += 1;
    }
}

fn validateLaneRows(
    rows: []const Row,
    cursor: *usize,
    lane: Lane,
    lane_index: u8,
    uses: []const u32,
) Error!void {
    const start = cursor.*;
    if (start > rows.len or lane.circuit.bindings.len > rows.len - start)
        return error.AuthorityMismatch;
    for (lane.circuit.bindings, 0..) |binding, binding_index| {
        const use_count = if (binding.node_id < uses.len) uses[binding.node_id] else return error.AuthorityMismatch;
        const masks = try laneMasks(lane.verifier_id);
        const expected = Row{
            .source = binding.source,
            .lane = lane_index,
            .binding = @intCast(binding_index),
            .row_mask = 1,
            .segment_mask = masks[0],
            .binary_mask = masks[1],
            .source_masks = sourceMasks(binding.source),
            .verifier_id = lane.verifier_id,
            .circuit_id = lane.circuit_id,
            .node_id = binding.node_id,
            .use_count = use_count,
            .source_indices = sourceIndices(binding.source),
        };
        if (!std.meta.eql(expected, rows[cursor.*])) return error.AuthorityMismatch;
        cursor.* += 1;
    }
}

fn validateLaneOrder(lanes: [3]Lane) Error!void {
    const expected_ids = [_]u32{
        SEGMENT_VERIFIER_ID,
        LEFT_RECURSION_VERIFIER_ID,
        RIGHT_RECURSION_VERIFIER_ID,
    };
    for (lanes, expected_ids) |lane, expected| {
        if (lane.verifier_id != expected) return error.InvalidCircuitLane;
        if (lane.circuit_id >= m31.Modulus) return error.CircuitIdNotCanonical;
    }
    inline for (0..3) |lhs| inline for (lhs + 1..3) |rhs| {
        if (lanes[lhs].circuit_id == lanes[rhs].circuit_id)
            return error.DuplicateCircuitId;
    };
}

fn laneMasks(verifier_id: u32) Error![2]u32 {
    return switch (verifier_id) {
        SEGMENT_VERIFIER_ID => .{ 1, 0 },
        LEFT_RECURSION_VERIFIER_ID, RIGHT_RECURSION_VERIFIER_ID => .{ 0, 1 },
        else => error.InvalidCircuitLane,
    };
}

fn laneIsActive(verifier_id: u32, kind: ProofKind) bool {
    return switch (verifier_id) {
        SEGMENT_VERIFIER_ID => kind == .segment_leaf,
        LEFT_RECURSION_VERIFIER_ID, RIGHT_RECURSION_VERIFIER_ID => kind == .binary_node,
        else => unreachable,
    };
}

fn sourceMasks(source: Source) [9]u32 {
    var result = [_]u32{0} ** 9;
    result[
        switch (std.meta.activeTag(source)) {
            .deep_answer_word => 0,
            .authenticated_value_word => 1,
            .fri_alpha_word => 2,
            .query_bit => 3,
            .fri_position => 4,
            .fri_offset => 5,
            .last_layer_position => 6,
            .last_layer_coefficient_word => 7,
            .active_selector => 8,
        }
    ] = 1;
    return result;
}

fn sourceIndices(source: Source) [4]u32 {
    return switch (source) {
        .active_selector => .{ 0, 0, 0, 0 },
        .deep_answer_word => |item| .{ item.query, item.word, 0, 0 },
        .authenticated_value_word => |item| .{ item.layer, item.query, item.offset, item.word },
        .fri_alpha_word => |item| .{ item.layer, item.word, 0, 0 },
        .query_bit => |item| .{ item.query, item.bit, 0, 0 },
        .fri_position => |item| .{ item.layer, item.query, 0, 0 },
        .fri_offset => |item| .{ item.layer, item.query, 0, 0 },
        .last_layer_position => |item| .{ item.query, 0, 0, 0 },
        .last_layer_coefficient_word => |item| .{ item.coefficient, item.word, 0, 0 },
    };
}

fn validateRow(row: Row) Error!void {
    if (row.row_mask != 1 or row.lane > 2 or row.verifier_id != row.lane or
        row.circuit_id >= m31.Modulus or row.node_id >= m31.Modulus or
        row.use_count >= m31.Modulus)
    {
        return error.InvalidSource;
    }
    const masks = try laneMasks(row.verifier_id);
    if (row.segment_mask != masks[0] or row.binary_mask != masks[1] or
        !std.meta.eql(row.source_masks, sourceMasks(row.source)) or
        !std.meta.eql(row.source_indices, sourceIndices(row.source)))
    {
        return error.InvalidSource;
    }
}

fn validateRowDirect(row: Row) direct.Error!void {
    validateRow(row) catch return error.InvalidTraceRow;
}

fn writePreprocessedRow(
    columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    logical_row: usize,
    row: Row,
) void {
    const values = row.values();
    for (columns, values) |column, value| column[logical_row] = value;
}

fn writeMainRow(columns: *[MAIN_COLUMN_COUNT][]M31, logical_row: usize, row: MainRow) void {
    const values = row.values();
    for (columns, values) |column, value| column[logical_row] = value;
}

const AddressRange = struct {
    start: usize,
    end: usize,

    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn preflightMain(
    columns: *const [MAIN_COLUMN_COUNT][]M31,
    preprocessing: *const Preprocessed,
    reference: Reference,
    evaluations: Evaluations,
    executor: *const Executor,
) direct.Error!usize {
    if (preprocessing.log_size >= @bitSizeOf(usize)) return error.InvalidTraceShape;
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);
    var destinations: [MAIN_COLUMN_COUNT]AddressRange = undefined;
    for (columns, 0..) |column, index| {
        if (column.len != size) return error.InvalidTraceShape;
        destinations[index] = try sliceRange(M31, column);
        for (destinations[0..index]) |previous| if (destinations[index].overlaps(previous))
            return error.AliasedDestination;
    }
    const objects = [_]AddressRange{
        try objectRange(columns),
        try objectRange(preprocessing),
        try objectRange(executor),
    };
    const rows = try sliceRange(Row, preprocessing.rows);
    for (destinations) |destination| {
        for (objects) |object| if (destination.overlaps(object)) return error.AliasedDestination;
        if (destination.overlaps(rows)) return error.AliasedInput;
        for (reference.lanes, 0..) |lane, lane_index| {
            const evaluation = evaluations.at(lane_index);
            if (destination.overlaps(try sliceRange(@TypeOf(evaluation.values[0]), evaluation.values)) or
                destination.overlaps(try sliceRange(@TypeOf(lane.circuit.nodes[0]), lane.circuit.nodes)) or
                destination.overlaps(try sliceRange(@TypeOf(lane.circuit.bindings[0]), lane.circuit.bindings)))
            {
                return error.AliasedInput;
            }
        }
    }
    return size;
}

fn totalRows(reference: Reference) Error!usize {
    var result: usize = 0;
    for (reference.lanes) |lane| result = std.math.add(
        usize,
        result,
        lane.circuit.bindings.len,
    ) catch return error.ArithmeticOverflow;
    return result;
}

fn maximumNodeCount(reference: Reference) usize {
    var result: usize = 0;
    for (reference.lanes) |lane| result = @max(result, lane.circuit.nodes.len);
    return result;
}

fn traceLogSize(row_count: usize) Error!u32 {
    const result: u32 = @max(
        MIN_LOG_SIZE,
        @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(row_count, 1)))),
    );
    if (result > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
    return result;
}

fn referenceDigest(lanes: [3]Lane, identities: [3]digest.Digest) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(REFERENCE_DOMAIN);
    hashInt(&hash, u32, lanes.len);
    for (lanes, identities) |lane, identity| {
        hashInt(&hash, u32, lane.verifier_id);
        hashInt(&hash, u32, lane.circuit_id);
        hash.update(&identity);
    }
    return hash.finalResult();
}

fn rowsDigest(rows: []const Row) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ROWS_DOMAIN);
    hashInt(&hash, u32, rows.len);
    for (rows) |row| {
        hashInt(&hash, u8, row.lane);
        hashInt(&hash, u32, row.binding);
        hashSource(&hash, row.source);
        for (row.values()) |value| hashInt(&hash, u32, value.toU32());
    }
    return hash.finalResult();
}

fn hashSource(hash: anytype, source: Source) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(source)));
    for (sourceIndices(source)) |value| hashInt(hash, u32, value);
}

fn sliceRange(comptime T: type, values: []const T) direct.Error!AddressRange {
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    return .{ .start = start, .end = std.math.add(usize, start, byte_len) catch
        return error.AddressOverflow };
}

fn objectRange(value: anytype) direct.Error!AddressRange {
    const T = @TypeOf(value.*);
    const start = @intFromPtr(value);
    return .{ .start = start, .end = std.math.add(usize, start, @sizeOf(T)) catch
        return error.AddressOverflow };
}

fn hashSlot(hash: anytype, slot: anytype) void {
    hashInt(hash, u8, slot.column);
    hashInt(hash, u32, @intFromEnum(slot.value));
    hashInt(hash, u8, @intFromEnum(slot.source));
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
