//! Sealed row-18 schedule and allocation-free direct SoA witness emission.
//!
//! The schedule is verifier authority. Admission is deliberately cold and
//! fail-closed; the trace-writing loop is contiguous, allocation-free, and has
//! no hashing or dynamic dispatch.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const direct = @import("../../air/lang/direct_witness_executor.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("vm_air_composition_input.zig");
const circuit = @import("composition_circuit.zig");
const relation = @import("../../air/lang/relation.zig");
const statement = @import("statement_input.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const SECURE_VALUE_WORD_COUNT: u32 = 4;
pub const RELATION_CHALLENGE_WORD_COUNT: u32 = 8;
pub const SAMPLED_VALUE_KIND: u32 = 6;
pub const VM_CLAIMED_SUM_KIND: u32 = 12;
pub const RECURSION_CLAIMED_SUM_KIND: u32 = 5;
pub const TRANSCRIPT_CLAIMED_SUM_KIND: u32 = 5;
pub const CHALLENGE_SCOPE: u32 = 1;
pub const COMPOSITION_RANDOMNESS_KIND: u32 = 1;
pub const OODS_POINT_KIND: u32 = 2;
pub const SEGMENT_VERIFIER_ID: u32 = 0;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = circuit.ProofKind;

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-vm-air-composition-input-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "571fe988c6e85fb473691fe62b0bb27681773d46f86db41dba662ec5beb46a32";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion VM AIR-composition-input witness-binding digest",
);
pub const SCHEDULE_FORMAT_VERSION: u16 = 1;
pub const SCHEDULE_DOMAIN =
    "stwo-zig/typed-air/recursion-vm-air-composition-input-schedule/v1\x00";

pub const Error = direct.Error || std.mem.Allocator.Error || error{
    AnchorModeMismatch,
    AuthorityMismatch,
    CircuitIdNotCanonical,
    DuplicateInputCoordinate,
    DuplicateInputSource,
    FixedValueNotCanonical,
    InputCountMismatch,
    InvalidAnchor,
    InvalidInputSource,
    InvalidScheduleOrder,
    InvalidWitnessBinding,
    InvalidWitnessValue,
    LogSizeOutOfRange,
    MissingCircuitAnchor,
    NodeIdNotCanonical,
    RecursionSelectorCountMismatch,
    SegmentSelectorCountMismatch,
    StatementScopeNotCanonical,
    UseCountNotCanonical,
    VerifierIdNotCanonical,
};

pub const MainSource = enum(u8) {
    enabler = 0,
    value = 1,
};

pub const PreprocessedSource = enum(u8) {
    row_mask = 0,
    sampled_value_mask = 1,
    claimed_sum_mask = 2,
    challenge_mask = 3,
    composition_randomness_mask = 4,
    oods_point_mask = 5,
    selector_mask = 6,
    circuit_id = 7,
    node_id = 8,
    use_count = 9,
    source_index_0 = 10,
    source_index_1 = 11,
    anchor_row_mask = 12,
    input_segment_mask = 13,
    input_binary_mask = 14,
    parent_binary_selector_mask = 15,
    child_kind_selector_mask = 16,
    statement_word_mask = 17,
    verifier_id = 18,
    statement_scope = 19,
    recursion_claimed_sum_mask = 20,
    transcript_claimed_sum_mask = 21,
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

    pub fn init(
        definition: *const component.Definition,
        supplied: *const Binding,
    ) !Executor {
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
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    ) Error!void {
        return preprocessing.generatePreprocessedInto(columns, self);
    }

    pub fn generateMainInto(
        self: *const Executor,
        preprocessing: *const Preprocessed,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        values: []const M31,
        kind: ProofKind,
    ) Error!void {
        return preprocessing.generateMainInto(columns, values, kind, self);
    }
};

pub const ModeSet = circuit.ModeSet;
pub const VmSource = circuit.VmSource;
pub const RecursionSource = circuit.RecursionSource;
pub const SecureCoordinate = circuit.SecureCoordinate;
pub const ChallengeCoordinate = circuit.ChallengeCoordinate;
pub const RecursionInput = circuit.RecursionInput;
pub const Classification = circuit.Classification;
pub const Row = circuit.Row;

pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []Row,
    source: Source,
    reference_digest: ?digest.Digest,
    authority_digest: digest.Digest,

    pub const Source = enum(u8) {
        /// Test-only compatibility path for explicit malformed-schedule gates.
        raw_schedule = 0,
        authenticated_graph = 1,
    };

    /// Compatibility constructor retained only for negative schedule tests.
    /// Production callers must use `initFromReference`.
    pub fn initForTesting(allocator: std.mem.Allocator, schedule: []const Row) Error!Preprocessed {
        try validateSchedule(schedule);
        const log_size = try traceLogSize(schedule.len);
        const rows = try allocator.dupe(Row, schedule);
        errdefer allocator.free(rows);
        return .{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .source = .raw_schedule,
            .reference_digest = null,
            .authority_digest = scheduleDigest(rows),
        };
    }

    /// Preferred authority path: compile exact bindings, use counts, constants,
    /// and outputs from an independently authenticated circuit graph.
    pub fn initFromReference(
        allocator: std.mem.Allocator,
        reference: *const circuit.Reference,
    ) (Error || circuit.Error)!Preprocessed {
        var compiled = try circuit.compile(allocator, reference);
        errdefer compiled.deinit();
        const log_size = try traceLogSize(compiled.rows.len);
        const reference_digest = compiled.reference_digest;
        const authority_digest = compiled.authority_digest;
        const rows = compiled.releaseRows();
        return .{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .source = .authenticated_graph,
            .reference_digest = reference_digest,
            .authority_digest = authority_digest,
        };
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validate(self: *const Preprocessed) Error!void {
        if (self.log_size != try traceLogSize(self.rows.len))
            return error.AuthorityMismatch;
        switch (self.source) {
            .raw_schedule => {
                if (self.reference_digest != null or
                    !std.mem.eql(u8, &self.authority_digest, &scheduleDigest(self.rows)))
                {
                    return error.AuthorityMismatch;
                }
            },
            .authenticated_graph => {
                const reference_digest = self.reference_digest orelse
                    return error.AuthorityMismatch;
                const expected = circuit.computeScheduleDigest(reference_digest, self.rows);
                if (!std.mem.eql(u8, &self.authority_digest, &expected))
                    return error.AuthorityMismatch;
            },
        }
        switch (self.source) {
            .raw_schedule => validateSchedule(self.rows) catch
                return error.AuthorityMismatch,
            .authenticated_graph => circuit.validateCompiledRows(self.rows) catch
                return error.AuthorityMismatch,
        }
    }

    fn generatePreprocessedInto(
        self: *const Preprocessed,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
        executor: *const Executor,
    ) Error!void {
        try self.validate();
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
        columns: *[MAIN_COLUMN_COUNT][]M31,
        values: []const M31,
        kind: ProofKind,
        executor: *const Executor,
    ) Error!void {
        try self.validate();
        if (values.len != self.rows.len) return error.InputCountMismatch;
        const size = try preflightMain(columns, self, values, executor);
        for (self.rows, values) |row, value| try validateValue(row, value, kind);
        for (columns) |column| @memset(column, M31.zero());
        for (self.rows, values, 0..) |row, value, logical_row| {
            const main = mainRowAssumeValid(row, value, kind);
            inline for (0..MAIN_COLUMN_COUNT) |column| {
                columns[column][logical_row] = main[column];
            }
        }
        std.debug.assert(size == columns[0].len);
    }
};

pub fn mainRow(row: Row, value: M31, kind: ProofKind) Error![MAIN_COLUMN_COUNT]M31 {
    try validateRow(row);
    try validateValue(row, value, kind);
    return mainRowAssumeValid(row, value, kind);
}

pub fn logicalRow(
    row: Row,
    value: M31,
    kind: ProofKind,
) Error![component.LOGICAL_INPUT_COUNT]M31 {
    const main = try mainRow(row, value, kind);
    const selectors = kind.selectors();
    return main ++ row.values() ++ .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(SAMPLED_VALUE_KIND),
        M31.fromCanonical(VM_CLAIMED_SUM_KIND),
        M31.fromCanonical(RECURSION_CLAIMED_SUM_KIND),
        M31.fromCanonical(CHALLENGE_SCOPE),
        M31.fromCanonical(COMPOSITION_RANDOMNESS_KIND),
        M31.fromCanonical(OODS_POINT_KIND),
        M31.fromCanonical(TRANSCRIPT_CLAIMED_SUM_KIND),
    };
}

pub fn inputCount(rows: []const Row) usize {
    var count: usize = 0;
    for (rows) |row| count += @intFromBool(isInput(row.classification));
    return count;
}

fn validateSchedule(rows: []const Row) Error!void {
    var phase: enum { vm, recursion, anchors } = .vm;
    var vm_circuit: ?u32 = null;
    var segment_selector_count: usize = 0;
    for (rows, 0..) |row, index| {
        try validateRow(row);
        switch (row.classification) {
            .vm_input => |source_value| {
                if (phase != .vm) return error.InvalidScheduleOrder;
                if (vm_circuit) |circuit_id| {
                    if (circuit_id != row.circuit_id) return error.InvalidInputSource;
                } else vm_circuit = row.circuit_id;
                segment_selector_count += @intFromBool(std.meta.activeTag(source_value) == .segment_selector);
            },
            .recursion_input => {
                if (phase == .anchors) return error.InvalidScheduleOrder;
                phase = .recursion;
            },
            .constant_anchor, .output_anchor => {
                if (phase != .anchors) {
                    if (vm_circuit == null or row.circuit_id != vm_circuit.?)
                        return error.InvalidScheduleOrder;
                    phase = .anchors;
                }
            },
        }
        if (index != 0 and !sameScheduleGroup(row, rows[index - 1])) {
            for (rows[0 .. index - 1]) |previous| {
                if (sameScheduleGroup(row, previous)) return error.InvalidScheduleOrder;
            }
        }
        for (rows[0..index]) |previous| {
            if (isInput(row.classification) and isInput(previous.classification) and
                row.circuit_id == previous.circuit_id and row.node_id == previous.node_id)
            {
                return error.DuplicateInputCoordinate;
            }
            if (sameInputLane(row, previous) and sameInputSource(row.classification, previous.classification))
                return error.DuplicateInputSource;
            if (std.meta.activeTag(row.classification) == .constant_anchor and
                std.meta.activeTag(previous.classification) == .output_anchor and
                row.circuit_id == previous.circuit_id)
            {
                return error.InvalidScheduleOrder;
            }
            if (anchorModes(row.classification) != null and
                anchorModes(previous.classification) != null and
                row.circuit_id == previous.circuit_id and
                !std.meta.eql(anchorModes(row.classification).?, anchorModes(previous.classification).?))
            {
                return error.AnchorModeMismatch;
            }
        }
    }
    if (segment_selector_count != 1) return error.SegmentSelectorCountMismatch;

    // Each distinct recursive lane owns exactly one parent selector and the
    // three canonical child-kind selectors. Counting is cold and allocation-free.
    for (rows, 0..) |row, index| switch (row.classification) {
        .recursion_input => |input| {
            var seen_lane = false;
            for (rows[0..index]) |previous| if (sameRecursionLane(row, previous)) {
                seen_lane = true;
                break;
            };
            if (seen_lane) continue;
            var parent_count: usize = 0;
            var child_count: usize = 0;
            var child_bits: u3 = 0;
            for (rows) |candidate| if (sameRecursionLane(row, candidate)) switch (candidate.classification) {
                .recursion_input => |candidate_input| switch (candidate_input.source) {
                    .parent_binary_selector => parent_count += 1,
                    .child_kind_selector => |kind| {
                        child_count += 1;
                        child_bits |= @as(u3, 1) << @as(u2, @intCast(@intFromEnum(kind)));
                    },
                    else => {},
                },
                else => unreachable,
            };
            _ = input;
            if (parent_count != 1 or child_count != 3 or child_bits != 0b111)
                return error.RecursionSelectorCountMismatch;
        },
        else => {},
    };

    // Every input circuit must be closed by at least one anchor row active in
    // that lane's mode. This is weaker than reconstructing the absent circuit
    // graph, but prevents accepting a visibly open supplied schedule.
    for (rows) |row| if (isInput(row.classification)) {
        const required: ProofKind = switch (row.classification) {
            .vm_input => .segment_leaf,
            .recursion_input => .binary_node,
            else => unreachable,
        };
        var found = false;
        for (rows) |candidate| if (candidate.circuit_id == row.circuit_id) {
            if (anchorModes(candidate.classification)) |modes| {
                const expected = switch (required) {
                    .segment_leaf => ModeSet.SEGMENT,
                    .binary_node => ModeSet.BINARY,
                    .empty_leaf => unreachable,
                };
                if (!std.meta.eql(modes, expected)) return error.AnchorModeMismatch;
                found = true;
            }
        };
        if (!found) return error.MissingCircuitAnchor;
    };
}

fn validateRow(row: Row) Error!void {
    if (row.circuit_id >= m31.Modulus) return error.CircuitIdNotCanonical;
    if (row.node_id >= m31.Modulus) return error.NodeIdNotCanonical;
    if (row.use_count >= m31.Modulus) return error.UseCountNotCanonical;
    for (row.fixed_value) |limb| if (limb >= m31.Modulus)
        return error.FixedValueNotCanonical;
    switch (row.classification) {
        .vm_input => |source_value| {
            if (!allZero(row.fixed_value)) return error.InvalidInputSource;
            try validateVmSource(source_value);
        },
        .recursion_input => |input| {
            if (!allZero(row.fixed_value)) return error.InvalidInputSource;
            if (input.verifier_id >= m31.Modulus) return error.VerifierIdNotCanonical;
            if (input.statement_scope >= m31.Modulus) return error.StatementScopeNotCanonical;
            try validateRecursionSource(input.source);
        },
        .constant_anchor => |modes| modes.validate() catch
            return error.AnchorModeMismatch,
        .output_anchor => |modes| {
            modes.validate() catch return error.AnchorModeMismatch;
            if (row.use_count != 0 or !allZero(row.fixed_value))
                return error.InvalidAnchor;
        },
    }
}

fn validateVmSource(source_value: VmSource) Error!void {
    switch (source_value) {
        .sampled_value, .claimed_sum, .transcript_claimed_sum => |coordinate| try validateSecure(coordinate),
        .relation_challenge => |coordinate| try validateChallenge(coordinate),
        .composition_randomness, .oods_point => |word_index| if (word_index >= SECURE_VALUE_WORD_COUNT)
            return error.InvalidInputSource,
        .segment_selector => {},
    }
}

fn validateRecursionSource(source_value: RecursionSource) Error!void {
    switch (source_value) {
        .sampled_value, .claimed_sum, .public_wire_boundary => |coordinate| try validateSecure(coordinate),
        .relation_challenge => |coordinate| try validateChallenge(coordinate),
        .composition_randomness, .oods_point => |word_index| if (word_index >= SECURE_VALUE_WORD_COUNT)
            return error.InvalidInputSource,
        .statement_word => |word_index| if (word_index >= statement.CANONICAL_WORD_COUNT)
            return error.InvalidInputSource,
        .parent_binary_selector, .child_kind_selector => {},
    }
}

fn validateSecure(coordinate: SecureCoordinate) Error!void {
    if (coordinate.item_index >= m31.Modulus or coordinate.word_index >= SECURE_VALUE_WORD_COUNT)
        return error.InvalidInputSource;
}

fn validateChallenge(coordinate: ChallengeCoordinate) Error!void {
    if (coordinate.challenge >= relation.UNIVERSAL_RELATION_COUNT or
        coordinate.word_index >= RELATION_CHALLENGE_WORD_COUNT)
    {
        return error.InvalidInputSource;
    }
}

fn validateValue(row: Row, value: M31, kind: ProofKind) Error!void {
    switch (row.classification) {
        .vm_input => |source_value| {
            const active = kind == .segment_leaf;
            switch (source_value) {
                .segment_selector => if (value.toU32() != @intFromBool(active))
                    return error.InvalidWitnessValue,
                else => if (!active and !value.isZero()) return error.InvalidWitnessValue,
            }
        },
        .recursion_input => |input| {
            const active = kind == .binary_node;
            switch (input.source) {
                .parent_binary_selector => if (value.toU32() != @intFromBool(active))
                    return error.InvalidWitnessValue,
                .child_kind_selector => if (!active and !value.isZero())
                    return error.InvalidWitnessValue,
                else => if (!active and !value.isZero()) return error.InvalidWitnessValue,
            }
        },
        .constant_anchor, .output_anchor => if (!value.isZero())
            return error.InvalidWitnessValue,
    }
}

fn mainRowAssumeValid(_: Row, value: M31, _: ProofKind) [MAIN_COLUMN_COUNT]M31 {
    return .{ M31.one(), value };
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

fn anchorModes(classification: Classification) ?ModeSet {
    return switch (classification) {
        .constant_anchor, .output_anchor => |modes| modes,
        else => null,
    };
}

fn isInput(classification: Classification) bool {
    return switch (classification) {
        .vm_input, .recursion_input => true,
        else => false,
    };
}

fn sameInputLane(lhs: Row, rhs: Row) bool {
    if (lhs.circuit_id != rhs.circuit_id) return false;
    return switch (lhs.classification) {
        .vm_input => switch (rhs.classification) {
            .vm_input => true,
            else => false,
        },
        .recursion_input => |left| switch (rhs.classification) {
            .recursion_input => |right| left.verifier_id == right.verifier_id and
                left.statement_scope == right.statement_scope,
            else => false,
        },
        else => false,
    };
}

fn sameRecursionLane(lhs: Row, rhs: Row) bool {
    return switch (lhs.classification) {
        .recursion_input => |left| switch (rhs.classification) {
            .recursion_input => |right| lhs.circuit_id == rhs.circuit_id and
                left.verifier_id == right.verifier_id and
                left.statement_scope == right.statement_scope,
            else => false,
        },
        else => false,
    };
}

fn sameScheduleGroup(lhs: Row, rhs: Row) bool {
    return switch (lhs.classification) {
        .vm_input => switch (rhs.classification) {
            .vm_input => true,
            else => false,
        },
        .recursion_input => sameRecursionLane(lhs, rhs),
        .constant_anchor, .output_anchor => switch (rhs.classification) {
            .constant_anchor, .output_anchor => lhs.circuit_id == rhs.circuit_id,
            else => false,
        },
    };
}

fn sameInputSource(lhs: Classification, rhs: Classification) bool {
    return switch (lhs) {
        .vm_input => |left| switch (rhs) {
            .vm_input => |right| std.meta.eql(left, right),
            else => false,
        },
        .recursion_input => |left| switch (rhs) {
            .recursion_input => |right| std.meta.eql(left.source, right.source),
            else => false,
        },
        else => false,
    };
}

fn allZero(values: [4]u32) bool {
    return values[0] == 0 and values[1] == 0 and values[2] == 0 and values[3] == 0;
}

fn traceLogSize(row_count: usize) Error!u32 {
    const result: u32 = @max(
        MIN_LOG_SIZE,
        @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(row_count, 1)))),
    );
    if (result > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
    return result;
}

fn scheduleDigest(rows: []const Row) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(SCHEDULE_DOMAIN);
    hashInt(&hash, u16, SCHEDULE_FORMAT_VERSION);
    hashInt(&hash, u32, rows.len);
    for (rows) |row| {
        hashInt(&hash, u8, @intFromEnum(std.meta.activeTag(row.classification)));
        switch (row.classification) {
            .vm_input => |source_value| hashVmSource(&hash, source_value),
            .recursion_input => |input| {
                hashInt(&hash, u32, input.verifier_id);
                hashInt(&hash, u32, input.statement_scope);
                hashRecursionSource(&hash, input.source);
            },
            .constant_anchor, .output_anchor => |modes| {
                hashInt(&hash, u8, @as(u8, @bitCast(modes)));
            },
        }
        hashInt(&hash, u32, row.circuit_id);
        hashInt(&hash, u32, row.node_id);
        hashInt(&hash, u32, row.use_count);
        for (row.fixed_value) |limb| hashInt(&hash, u32, limb);
    }
    return hash.finalResult();
}

fn hashVmSource(hash: anytype, source_value: VmSource) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(source_value)));
    const indices = circuit.vmSourceIndices(source_value);
    hashInt(hash, u32, indices[0]);
    hashInt(hash, u32, indices[1]);
}

fn hashRecursionSource(hash: anytype, source_value: RecursionSource) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(source_value)));
    const indices = circuit.recursionSourceIndices(source_value);
    hashInt(hash, u32, indices[0]);
    hashInt(hash, u32, indices[1]);
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
    values: []const M31,
    executor: *const Executor,
) direct.Error!usize {
    if (preprocessing.log_size >= @bitSizeOf(usize))
        return error.InvalidTraceShape;
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);
    if (preprocessing.rows.len > size) return error.InvalidTraceShape;
    var destinations: [MAIN_COLUMN_COUNT]AddressRange = undefined;
    for (columns, 0..) |column, index| {
        if (column.len != size) return error.InvalidTraceShape;
        destinations[index] = try sliceRange(M31, column);
    }
    const descriptors = try objectRange(columns);
    const protected = try objectRange(preprocessing);
    const binding = try objectRange(executor);
    const row_source = try sliceRange(Row, preprocessing.rows);
    const value_source = try sliceRange(M31, values);
    for (destinations, 0..) |destination, index| {
        if (destination.overlaps(descriptors) or destination.overlaps(protected) or
            destination.overlaps(binding))
            return error.AliasedDestination;
        if (destination.overlaps(row_source) or destination.overlaps(value_source))
            return error.AliasedInput;
        for (destinations[0..index]) |previous| if (destination.overlaps(previous))
            return error.AliasedDestination;
    }
    return size;
}

fn sliceRange(comptime T: type, values: []const T) direct.Error!AddressRange {
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    const end = std.math.add(usize, start, byte_len) catch return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

fn objectRange(pointer: anytype) direct.Error!AddressRange {
    const info = @typeInfo(@TypeOf(pointer));
    if (info != .pointer or info.pointer.size != .one)
        @compileError("protected storage must be a single-item pointer");
    const start = @intFromPtr(pointer);
    const end = std.math.add(usize, start, @sizeOf(info.pointer.child)) catch
        return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn hashSlot(hash: anytype, slot: anytype) void {
    hashInt(hash, u8, slot.column);
    hashInt(hash, u32, @intFromEnum(slot.value));
    hashInt(hash, u8, @intFromEnum(slot.source));
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
