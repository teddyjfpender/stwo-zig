//! Verifier-owned row-11 schedule and allocation-free direct SoA witness.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const direct = @import("../../air/lang/direct_witness_executor.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("statement_semantics_input.zig");
const statement = @import("statement_input.zig");
const proof_kind_mod = @import("proof_kind.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = proof_kind_mod.ProofKind;
pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-statement-semantics-input-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "35f31bae2a6522fbeaab9170c987bbcd9ed5174a5e64022f0ab8377bbf46448b";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion statement-semantics-input witness-binding digest",
);

pub const Error = direct.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    CircuitIdNotCanonical,
    DuplicateOrUnorderedNode,
    InputCountMismatch,
    IntegerWordOutOfRange,
    InvalidActiveKinds,
    InvalidInputBinding,
    InvalidSelectorValue,
    InvalidWitnessBinding,
    LogSizeOutOfRange,
};

pub const MainSource = enum(u8) {
    enabler = 0,
    value = 1,
    low_byte = 2,
    high_byte = 3,
};

pub const PreprocessedSource = enum(u8) {
    row_mask = 0,
    statement_mask = 1,
    selector_mask = 2,
    private_mask = 3,
    integer_mask = 4,
    segment_enabled = 5,
    binary_enabled = 6,
    empty_enabled = 7,
    circuit_id = 8,
    node_id = 9,
    use_count = 10,
    statement_scope = 11,
    word_index = 12,
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

pub const ProofKindSet = packed struct(u8) {
    segment: bool = false,
    binary: bool = false,
    empty: bool = false,
    reserved: u5 = 0,

    pub const SEGMENT = ProofKindSet{ .segment = true };
    pub const BINARY = ProofKindSet{ .binary = true };
    pub const EMPTY = ProofKindSet{ .empty = true };
    pub const LEAVES = ProofKindSet{ .segment = true, .empty = true };
    pub const ALL = ProofKindSet{ .segment = true, .binary = true, .empty = true };

    pub fn contains(self: ProofKindSet, kind: ProofKind) bool {
        return switch (kind) {
            .segment_leaf => self.segment,
            .binary_node => self.binary,
            .empty_leaf => self.empty,
        };
    }

    pub fn selectors(self: ProofKindSet) [3]u32 {
        return .{ @intFromBool(self.segment), @intFromBool(self.binary), @intFromBool(self.empty) };
    }

    fn validate(self: ProofKindSet) Error!void {
        if (self.reserved != 0 or (!self.segment and !self.binary and !self.empty))
            return error.InvalidActiveKinds;
    }
};

pub const InputSource = enum(u8) {
    statement = 0,
    selector = 1,
    private = 2,
};

pub const Source = union(InputSource) {
    statement: struct {
        scope: u32,
        index: u32,
        active_kinds: ProofKindSet,
    },
    selector: ProofKind,
    private: ProofKindSet,
};

pub const InputBinding = struct {
    node_id: u32,
    use_count: u32,
    source: Source,
};

pub const Row = struct {
    source: InputSource,
    integer: bool,
    active_kinds: ProofKindSet,
    circuit_id: u32,
    node_id: u32,
    use_count: u32,
    statement_scope: u32,
    word_index: u32,

    pub fn values(self: Row) [PREPROCESSED_COLUMN_COUNT]M31 {
        const active = self.active_kinds.selectors();
        return .{
            M31.one(),
            M31.fromU64(@intFromBool(self.source == .statement)),
            M31.fromU64(@intFromBool(self.source == .selector)),
            M31.fromU64(@intFromBool(self.source == .private)),
            M31.fromU64(@intFromBool(self.integer)),
            M31.fromU64(active[0]),
            M31.fromU64(active[1]),
            M31.fromU64(active[2]),
            M31.fromU64(self.circuit_id),
            M31.fromU64(self.node_id),
            M31.fromU64(self.use_count),
            M31.fromU64(self.statement_scope),
            M31.fromU64(self.word_index),
        };
    }
};

pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []Row,
    circuit_id: u32,
    authority_digest: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        circuit_id: u32,
        bindings: []const InputBinding,
    ) Error!Preprocessed {
        if (circuit_id >= m31.Modulus) return error.CircuitIdNotCanonical;
        try validateBindings(circuit_id, bindings);
        const log_size: u32 = @max(
            MIN_LOG_SIZE,
            @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(bindings.len, 1)))),
        );
        if (log_size > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
        const rows = try allocator.alloc(Row, bindings.len);
        errdefer allocator.free(rows);
        for (rows, bindings) |*row, binding| row.* = rowFrom(circuit_id, binding);
        return .{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .circuit_id = circuit_id,
            .authority_digest = rowsDigest(circuit_id, rows),
        };
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validate(self: *const Preprocessed) Error!void {
        if (self.circuit_id >= m31.Modulus or self.log_size > MAX_LOG_SIZE or
            self.log_size != @max(
                MIN_LOG_SIZE,
                @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(self.rows.len, 1)))),
            ) or
            !std.meta.eql(
                self.authority_digest,
                rowsDigest(self.circuit_id, self.rows),
            ))
        {
            return error.AuthorityMismatch;
        }
        var previous_node: ?u32 = null;
        for (self.rows) |row| {
            try validateRow(row);
            if (row.circuit_id != self.circuit_id)
                return error.AuthorityMismatch;
            if (previous_node) |previous| if (row.node_id <= previous)
                return error.DuplicateOrUnorderedNode;
            previous_node = row.node_id;
        }
    }

    pub fn activeStatementCount(self: *const Preprocessed, kind: ProofKind) usize {
        var count: usize = 0;
        for (self.rows) |row| {
            count += @intFromBool(row.source == .statement and row.active_kinds.contains(kind));
        }
        return count;
    }

    pub fn activeIntegerCount(self: *const Preprocessed, kind: ProofKind) usize {
        var count: usize = 0;
        for (self.rows) |row| {
            count += @intFromBool(row.integer and row.active_kinds.contains(kind));
        }
        return count;
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

    /// Writes exact circuit input values and byte decompositions into final
    /// SoA columns. The hot loop performs no allocation or dynamic dispatch.
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
        selectors[2],
        M31.zero(),
    };
}

fn rowFrom(circuit_id: u32, binding: InputBinding) Row {
    return switch (binding.source) {
        .statement => |item| .{
            .source = .statement,
            .integer = isIntegerWord(item.index),
            .active_kinds = item.active_kinds,
            .circuit_id = circuit_id,
            .node_id = binding.node_id,
            .use_count = binding.use_count,
            .statement_scope = item.scope,
            .word_index = item.index,
        },
        .selector => |kind| .{
            .source = .selector,
            .integer = false,
            .active_kinds = kindSet(kind),
            .circuit_id = circuit_id,
            .node_id = binding.node_id,
            .use_count = binding.use_count,
            .statement_scope = 0,
            .word_index = 0,
        },
        .private => |active_kinds| .{
            .source = .private,
            .integer = false,
            .active_kinds = active_kinds,
            .circuit_id = circuit_id,
            .node_id = binding.node_id,
            .use_count = binding.use_count,
            .statement_scope = 0,
            .word_index = 0,
        },
    };
}

fn validateBindings(circuit_id: u32, bindings: []const InputBinding) Error!void {
    var previous_node: ?u32 = null;
    for (bindings) |binding| {
        const row = rowFrom(circuit_id, binding);
        try validateRow(row);
        if (previous_node) |previous| if (binding.node_id <= previous)
            return error.DuplicateOrUnorderedNode;
        previous_node = binding.node_id;
    }
}

fn validateRow(row: Row) Error!void {
    try row.active_kinds.validate();
    if (row.circuit_id >= m31.Modulus or row.node_id >= m31.Modulus or
        row.use_count >= m31.Modulus or row.statement_scope >= m31.Modulus or
        row.word_index >= m31.Modulus)
    {
        return error.InvalidInputBinding;
    }
    switch (row.source) {
        .statement => {
            if (row.statement_scope > statement.PARENT_STATEMENT_SCOPE or
                row.word_index >= statement.CANONICAL_WORD_COUNT or
                row.integer != isIntegerWord(row.word_index))
            {
                return error.InvalidInputBinding;
            }
        },
        .selector => {
            const selectors = row.active_kinds.selectors();
            if (selectors[0] + selectors[1] + selectors[2] != 1 or row.integer or
                row.statement_scope != 0 or row.word_index != 0)
            {
                return error.InvalidInputBinding;
            }
        },
        .private => if (row.integer or row.statement_scope != 0 or row.word_index != 0)
            return error.InvalidInputBinding,
    }
}

fn validateRowDirect(row: Row) direct.Error!void {
    validateRow(row) catch return error.InvalidTraceRow;
}

fn validateValue(row: Row, value: M31, kind: ProofKind) Error!void {
    const active = row.active_kinds.contains(kind);
    switch (row.source) {
        .selector => if (value.toU32() != @intFromBool(active))
            return error.InvalidSelectorValue,
        .statement, .private => if (!active and !value.isZero())
            return error.InvalidTraceRow,
    }
    if (row.integer and active and value.toU32() > std.math.maxInt(u16))
        return error.IntegerWordOutOfRange;
}

fn mainRowAssumeValid(row: Row, value: M31, kind: ProofKind) [MAIN_COLUMN_COUNT]M31 {
    const active_integer = row.integer and row.active_kinds.contains(kind);
    return .{
        M31.one(),
        value,
        if (active_integer) M31.fromCanonical(value.toU32() & 0xff) else M31.zero(),
        if (active_integer) M31.fromCanonical(value.toU32() >> 8) else M31.zero(),
    };
}

fn writePreprocessedRow(
    columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    logical_row: usize,
    row: Row,
) void {
    const values = row.values();
    for (columns, values) |column, value| column[logical_row] = value;
}

fn kindSet(kind: ProofKind) ProofKindSet {
    return switch (kind) {
        .segment_leaf => .SEGMENT,
        .binary_node => .BINARY,
        .empty_leaf => .EMPTY,
    };
}

/// Exact raw-integer classification from Stark-V's canonical statement ABI.
pub fn isIntegerWord(index_value: anytype) bool {
    const index: usize = @intCast(index_value);
    const machine_starts = [_]usize{ 19, 102, 228, 311 };
    for (machine_starts) |start| {
        if (index >= start + 1 and index < start + 67) return true;
    }
    return inRange(index, 201, 4) or inRange(index, 205, 2) or index == 207 or
        inRange(index, 209, 4) or index == 213 or inRange(index, 216, 2) or
        inRange(index, 218, 2) or inRange(index, 220, 4) or inRange(index, 224, 4);
}

fn inRange(index: usize, start: usize, len: usize) bool {
    return index >= start and index < start + len;
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
    const end = std.math.add(usize, start, byte_len) catch
        return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

fn objectRange(pointer: anytype) direct.Error!AddressRange {
    const info = @typeInfo(@TypeOf(pointer)).pointer;
    const start = @intFromPtr(pointer);
    const end = std.math.add(usize, start, @sizeOf(info.child)) catch
        return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

fn rowsDigest(circuit_id: u32, rows: []const Row) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursion-statement-semantics-input-preprocessing/v1\x00");
    hashInt(&hash, u32, circuit_id);
    hashInt(&hash, u32, rows.len);
    for (rows) |row| {
        hashInt(&hash, u8, @intFromEnum(row.source));
        hashInt(&hash, u8, @intFromBool(row.integer));
        hashInt(&hash, u8, @as(u8, @bitCast(row.active_kinds)));
        hashInt(&hash, u32, row.circuit_id);
        hashInt(&hash, u32, row.node_id);
        hashInt(&hash, u32, row.use_count);
        hashInt(&hash, u32, row.statement_scope);
        hashInt(&hash, u32, row.word_index);
    }
    return hash.finalResult();
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
