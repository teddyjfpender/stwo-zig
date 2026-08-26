//! Verifier-owned row-10 preprocessing and allocation-free direct SoA writer.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const direct = @import("../../air/lang/direct_witness_executor.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("statement_input.zig");
const proof_kind_mod = @import("proof_kind.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const SEGMENT_VERIFIER_ID: u32 = 0;
pub const LEFT_RECURSION_VERIFIER_ID: u32 = 1;
pub const RIGHT_RECURSION_VERIFIER_ID: u32 = 2;
pub const DERIVED_PARENT_SOURCE_ID: u32 = 3;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const StatementWords = [component.CANONICAL_WORD_COUNT]M31;
pub const ProofKind = proof_kind_mod.ProofKind;
pub const BINDING_FORMAT_VERSION: u16 = 2;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-statement-input-witness/v2\x00";
pub const BINDING_DIGEST_HEX =
    "aae526b44405610ed7ae277f2c483862a21d5b98c8950db41fa166d70274828b";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion statement-input witness-binding digest",
);

pub const Error = direct.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    InvalidStatementWitness,
    InvalidWitnessBinding,
    LogSizeOutOfRange,
};

pub const MainSource = enum(u8) {
    enabler = 0,
    value = 1,
};

pub const PreprocessedSource = enum(u8) {
    row_mask = 0,
    segment_mask = 1,
    binary_mask = 2,
    derived_parent_mask = 3,
    verifier_id = 4,
    statement_scope = 5,
    word_index = 6,
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
        statement_value: StatementWitness,
    ) Error!void {
        return preprocessing.generateMainInto(columns, statement_value, self);
    }
};

pub const Row = struct {
    row_mask: u32,
    segment_mask: u32,
    binary_mask: u32,
    derived_parent_mask: u32,
    verifier_id: u32,
    statement_scope: u32,
    word_index: u32,

    pub fn values(self: Row) [PREPROCESSED_COLUMN_COUNT]M31 {
        return .{
            M31.fromU64(self.row_mask),
            M31.fromU64(self.segment_mask),
            M31.fromU64(self.binary_mask),
            M31.fromU64(self.derived_parent_mask),
            M31.fromU64(self.verifier_id),
            M31.fromU64(self.statement_scope),
            M31.fromU64(self.word_index),
        };
    }
};

pub const StatementWitness = union(ProofKind) {
    segment_leaf: *const StatementWords,
    binary_node: struct {
        left: *const StatementWords,
        right: *const StatementWords,
        parent: *const StatementWords,
    },
    empty_leaf: void,

    pub fn proofKind(self: StatementWitness) ProofKind {
        return std.meta.activeTag(self);
    }
};

pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []Row,
    authority_digest: [32]u8,

    pub fn init(allocator: std.mem.Allocator) Error!Preprocessed {
        const row_count = std.math.mul(
            usize,
            component.CANONICAL_WORD_COUNT,
            component.STATEMENT_LANE_COUNT,
        ) catch return error.ArithmeticOverflow;
        const log_size: u32 = @max(
            MIN_LOG_SIZE,
            @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(row_count, 1)))),
        );
        if (log_size > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
        const rows = try allocator.alloc(Row, row_count);
        errdefer allocator.free(rows);
        for (rows, 0..) |*row, index| row.* = expectedRow(index);
        return .{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .authority_digest = rowsDigest(rows),
        };
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validate(self: *const Preprocessed) Error!void {
        const expected_len = std.math.mul(
            usize,
            component.CANONICAL_WORD_COUNT,
            component.STATEMENT_LANE_COUNT,
        ) catch return error.ArithmeticOverflow;
        if (self.rows.len != expected_len or
            self.log_size != @max(
                MIN_LOG_SIZE,
                @as(u32, @intCast(std.math.log2_int_ceil(usize, expected_len))),
            ) or
            !std.meta.eql(self.authority_digest, rowsDigest(self.rows)))
        {
            return error.AuthorityMismatch;
        }
        for (self.rows, 0..) |row, index| {
            if (!std.meta.eql(row, expectedRow(index)))
                return error.AuthorityMismatch;
        }
    }

    pub fn activeWordCount(_: *const Preprocessed, kind: ProofKind) usize {
        return switch (kind) {
            .segment_leaf => component.CANONICAL_WORD_COUNT,
            .binary_node => 3 * component.CANONICAL_WORD_COUNT,
            .empty_leaf => 0,
        };
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
            validateRow,
            writePreprocessedRow,
        );
    }

    /// Writes the selected statement directly into final column-major storage.
    /// All authority, shape, alias, and source checks complete before mutation.
    fn generateMainInto(
        self: *const Preprocessed,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        statement: StatementWitness,
        executor: *const Executor,
    ) Error!void {
        try self.validate();
        const size = try preflightMain(columns, self, statement, executor);
        for (columns) |column| @memset(column, M31.zero());
        for (self.rows, 0..) |row, logical_row| {
            columns[0][logical_row] = M31.one();
            columns[1][logical_row] = valueFor(row, statement);
        }
        std.debug.assert(size == columns[0].len);
    }
};

pub fn mainRow(row: Row, statement: StatementWitness) Error![MAIN_COLUMN_COUNT]M31 {
    try validateRow(row);
    return .{ M31.one(), valueFor(row, statement) };
}

pub fn logicalRow(
    row: Row,
    statement: StatementWitness,
) Error![component.LOGICAL_INPUT_COUNT]M31 {
    const main = try mainRow(row, statement);
    const selectors = statement.proofKind().selectors();
    return main ++ row.values() ++ .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(component.STATEMENT_INPUT_KIND),
        M31.fromCanonical(component.STATEMENT_INPUT_ITEM),
        M31.fromCanonical(component.VM_CLAIM_STATEMENT_SCOPE),
    };
}

fn expectedRow(index: usize) Row {
    const lane = index / component.CANONICAL_WORD_COUNT;
    const word_index: u32 = @intCast(index % component.CANONICAL_WORD_COUNT);
    return switch (lane) {
        0 => .{
            .row_mask = 1,
            .segment_mask = 1,
            .binary_mask = 0,
            .derived_parent_mask = 0,
            .verifier_id = SEGMENT_VERIFIER_ID,
            .statement_scope = component.SEGMENT_STATEMENT_SCOPE,
            .word_index = word_index,
        },
        1 => .{
            .row_mask = 1,
            .segment_mask = 0,
            .binary_mask = 1,
            .derived_parent_mask = 0,
            .verifier_id = LEFT_RECURSION_VERIFIER_ID,
            .statement_scope = component.LEFT_STATEMENT_SCOPE,
            .word_index = word_index,
        },
        2 => .{
            .row_mask = 1,
            .segment_mask = 0,
            .binary_mask = 1,
            .derived_parent_mask = 0,
            .verifier_id = RIGHT_RECURSION_VERIFIER_ID,
            .statement_scope = component.RIGHT_STATEMENT_SCOPE,
            .word_index = word_index,
        },
        3 => .{
            .row_mask = 1,
            .segment_mask = 0,
            .binary_mask = 0,
            .derived_parent_mask = 1,
            .verifier_id = DERIVED_PARENT_SOURCE_ID,
            .statement_scope = component.PARENT_STATEMENT_SCOPE,
            .word_index = word_index,
        },
        else => unreachable,
    };
}

fn valueFor(row: Row, statement: StatementWitness) M31 {
    const index: usize = @intCast(row.word_index);
    return switch (statement) {
        .segment_leaf => |words| if (row.verifier_id == SEGMENT_VERIFIER_ID)
            words[index]
        else
            M31.zero(),
        .binary_node => |words| switch (row.verifier_id) {
            LEFT_RECURSION_VERIFIER_ID => words.left[index],
            RIGHT_RECURSION_VERIFIER_ID => words.right[index],
            DERIVED_PARENT_SOURCE_ID => words.parent[index],
            else => M31.zero(),
        },
        .empty_leaf => M31.zero(),
    };
}

fn validateRow(row: Row) direct.Error!void {
    if (row.row_mask != 1 or row.segment_mask > 1 or row.binary_mask > 1 or
        row.derived_parent_mask > 1 or
        row.segment_mask + row.binary_mask + row.derived_parent_mask != 1 or
        row.verifier_id > DERIVED_PARENT_SOURCE_ID or
        row.statement_scope > component.PARENT_STATEMENT_SCOPE or
        row.word_index >= component.CANONICAL_WORD_COUNT or
        row.verifier_id >= m31.Modulus or row.statement_scope >= m31.Modulus or
        !canonicalLane(row))
    {
        return error.InvalidTraceRow;
    }
}

fn writePreprocessedRow(
    columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    logical_row: usize,
    row: Row,
) void {
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
    statement: StatementWitness,
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
    if (destinations[0].overlaps(destinations[1]))
        return error.AliasedDestination;
    const descriptors = try objectRange(columns);
    const protected = try objectRange(preprocessing);
    const binding = try objectRange(executor);
    const rows = try sliceRange(Row, preprocessing.rows);
    for (destinations) |destination| {
        if (destination.overlaps(descriptors) or destination.overlaps(protected) or
            destination.overlaps(binding))
            return error.AliasedDestination;
        if (destination.overlaps(rows)) return error.AliasedInput;
    }
    switch (statement) {
        .segment_leaf => |words| try rejectSourceAlias(destinations, words),
        .binary_node => |words| {
            try rejectSourceAlias(destinations, words.left);
            try rejectSourceAlias(destinations, words.right);
            try rejectSourceAlias(destinations, words.parent);
        },
        .empty_leaf => {},
    }
    return size;
}

fn canonicalLane(row: Row) bool {
    if (row.segment_mask == 1) {
        return row.verifier_id == SEGMENT_VERIFIER_ID and
            row.statement_scope == component.SEGMENT_STATEMENT_SCOPE;
    }
    if (row.binary_mask == 1) {
        return (row.verifier_id == LEFT_RECURSION_VERIFIER_ID and
            row.statement_scope == component.LEFT_STATEMENT_SCOPE) or
            (row.verifier_id == RIGHT_RECURSION_VERIFIER_ID and
                row.statement_scope == component.RIGHT_STATEMENT_SCOPE);
    }
    return row.derived_parent_mask == 1 and
        row.verifier_id == DERIVED_PARENT_SOURCE_ID and
        row.statement_scope == component.PARENT_STATEMENT_SCOPE;
}

fn rejectSourceAlias(
    destinations: [MAIN_COLUMN_COUNT]AddressRange,
    words: *const StatementWords,
) direct.Error!void {
    const source = try objectRange(words);
    for (destinations) |destination| if (destination.overlaps(source))
        return error.AliasedInput;
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

fn rowsDigest(rows: []const Row) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursion-statement-input-preprocessing/v1\x00");
    hashInt(&hash, u32, component.CANONICAL_WORD_COUNT);
    hashInt(&hash, u32, rows.len);
    for (rows) |row| inline for (std.meta.fields(Row)) |field| {
        hashInt(&hash, u32, @field(row, field.name));
    };
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
