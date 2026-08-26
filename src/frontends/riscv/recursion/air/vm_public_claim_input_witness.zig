//! Canonical shape admission and direct SoA witness generation for row 12.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const digest = @import("../../air/lang/digest.zig");
const direct = @import("../../air/lang/direct_witness_executor.zig");
const types = @import("../../air/lang/types.zig");
const air = @import("vm_public_claim_input.zig");
const proof_kind_mod = @import("proof_kind.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const FIXED_CLAIM_WORDS: usize = 259;
pub const INPUT_SLOT_WORDS: usize = 3;
pub const OUTPUT_SLOT_WORDS: usize = 7;
pub const MAIN_COLUMN_COUNT = air.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = air.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = proof_kind_mod.ProofKind;

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-vm-public-claim-input-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "aada6002e86382de0e220972a05d5d7bbb6c7af2495287838f8565cfbb66779f";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion VM public-claim input witness-binding digest",
);
pub const PREPROCESSING_DOMAIN =
    "stwo-zig/typed-air/recursion-vm-public-claim-input-preprocessing/v1\x00";

pub const Error = direct.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    ConstantMismatch,
    InactiveClaimProvided,
    IntegerWordOutOfRange,
    InvalidBooleanWord,
    InvalidShape,
    InvalidWitnessBinding,
    LogSizeOutOfRange,
    SegmentClaimMissing,
    WordCountMismatch,
};

pub const Shape = struct {
    max_input_words: u32,
    max_output_words: u32,

    pub fn init(max_input_words: u32, max_output_words: u32) Error!Shape {
        const result = Shape{
            .max_input_words = max_input_words,
            .max_output_words = max_output_words,
        };
        _ = try result.wordCount();
        return result;
    }

    pub fn wordCount(self: Shape) Error!usize {
        if (self.max_input_words >= m31.Modulus or
            self.max_output_words >= m31.Modulus)
        {
            return error.InvalidShape;
        }
        const input = std.math.mul(
            usize,
            self.max_input_words,
            INPUT_SLOT_WORDS,
        ) catch return error.ArithmeticOverflow;
        const output = std.math.mul(
            usize,
            self.max_output_words,
            OUTPUT_SLOT_WORDS,
        ) catch return error.ArithmeticOverflow;
        const count = std.math.add(
            usize,
            std.math.add(usize, FIXED_CLAIM_WORDS, input) catch
                return error.ArithmeticOverflow,
            output,
        ) catch return error.ArithmeticOverflow;
        if (count == 0 or count > (@as(usize, 1) << MAX_LOG_SIZE) or
            count - 1 >= m31.Modulus)
        {
            return error.LogSizeOutOfRange;
        }
        return count;
    }
};

pub const WordKind = union(enum) {
    constant: u32,
    boolean,
    u16,
    field,
};

pub const MainSource = enum(u8) {
    enabler = 0,
    value = 1,
    low_byte = 2,
    high_byte = 3,
};

pub const PreprocessedSource = enum(u8) {
    row_mask = 0,
    word_index = 1,
    constant_mask = 2,
    boolean_mask = 3,
    u16_mask = 4,
    constant_value = 5,
    input_io_mask = 6,
    input_io_index = 7,
    output_io_mask = 8,
    output_io_index = 9,
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
    parameters: [air.PARAMETER_COUNT]types.ValueId,

    pub fn canonical(definition: *const air.Definition) !Binding {
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
            .semantic_digest = air.SEMANTIC_DIGEST,
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
        definition: *const air.Definition,
        supplied: *const Binding,
    ) !Executor {
        const expected = try Binding.canonical(definition);
        if (!std.meta.eql(expected, supplied.*)) return error.InvalidWitnessBinding;
        const actual = supplied.identityDigest();
        if (!std.mem.eql(u8, &actual, &BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        return .{ .binding = supplied.*, .binding_digest = actual };
    }
};

pub const PreprocessedRow = struct {
    word_index: u32,
    kind: WordKind,
    input_io_index: ?u32,
    output_io_index: ?u32,

    pub fn values(self: PreprocessedRow) [PREPROCESSED_COLUMN_COUNT]M31 {
        return .{
            M31.one(),
            M31.fromU64(self.word_index),
            M31.fromU64(@intFromBool(std.meta.activeTag(self.kind) == .constant)),
            M31.fromU64(@intFromBool(std.meta.activeTag(self.kind) == .boolean)),
            M31.fromU64(@intFromBool(std.meta.activeTag(self.kind) == .u16)),
            M31.fromU64(switch (self.kind) {
                .constant => |value| value,
                else => 0,
            }),
            M31.fromU64(@intFromBool(self.input_io_index != null)),
            M31.fromU64(self.input_io_index orelse 0),
            M31.fromU64(@intFromBool(self.output_io_index != null)),
            M31.fromU64(self.output_io_index orelse 0),
        };
    }
};

pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    shape: Shape,
    log_size: u32,
    rows: []PreprocessedRow,
    authority_digest: digest.Digest,

    pub fn init(allocator: std.mem.Allocator, shape: Shape) Error!Preprocessed {
        const count = try shape.wordCount();
        const log_size = try traceLogSize(count);
        const rows = try allocator.alloc(PreprocessedRow, count);
        errdefer allocator.free(rows);
        for (rows, 0..) |*row, index| row.* = expectedRow(shape, index);
        return .{
            .allocator = allocator,
            .shape = shape,
            .log_size = log_size,
            .rows = rows,
            .authority_digest = rowsDigest(shape, rows),
        };
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validate(self: *const Preprocessed) Error!void {
        const count = try self.shape.wordCount();
        if (self.rows.len != count or self.log_size != try traceLogSize(count) or
            !std.mem.eql(
                u8,
                &self.authority_digest,
                &rowsDigest(self.shape, self.rows),
            ))
        {
            return error.AuthorityMismatch;
        }
        for (self.rows, 0..) |row, index| {
            if (!std.meta.eql(row, expectedRow(self.shape, index)))
                return error.AuthorityMismatch;
        }
    }

    pub fn generateInto(
        self: *const Preprocessed,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
        executor: *const Executor,
    ) Error!void {
        try self.validate();
        return direct.generateMainInto(
            M31,
            PreprocessedRow,
            PREPROCESSED_COLUMN_COUNT,
            columns,
            self.rows,
            self.log_size,
            M31.zero(),
            executor,
            validatePreprocessedRow,
            writePreprocessedRow,
        );
    }
};

pub const MainRow = struct {
    value: M31,
    low_byte: M31,
    high_byte: M31,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{ M31.one(), self.value, self.low_byte, self.high_byte };
    }
};

pub const ClaimWitness = union(ProofKind) {
    segment_leaf: []const M31,
    binary_node: void,
    empty_leaf: void,

    pub fn proofKind(self: ClaimWitness) ProofKind {
        return std.meta.activeTag(self);
    }
};

pub const MainWitness = struct {
    allocator: std.mem.Allocator,
    rows: []MainRow,
    proof_kind: ProofKind,
    authority_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        preprocessing: *const Preprocessed,
        claim: ClaimWitness,
    ) Error!MainWitness {
        try preprocessing.validate();
        switch (claim) {
            .segment_leaf => |words| if (words.len != preprocessing.rows.len)
                return error.WordCountMismatch,
            .binary_node, .empty_leaf => {},
        }
        const rows = try allocator.alloc(MainRow, preprocessing.rows.len);
        errdefer allocator.free(rows);
        for (rows, preprocessing.rows, 0..) |*row, metadata, index| {
            const value = switch (claim) {
                .segment_leaf => |words| words[index],
                .binary_node, .empty_leaf => M31.zero(),
            };
            row.* = try canonicalMainRow(metadata.kind, value, claim.proofKind());
        }
        return .{
            .allocator = allocator,
            .rows = rows,
            .proof_kind = claim.proofKind(),
            .authority_digest = preprocessing.authority_digest,
        };
    }

    pub fn deinit(self: *MainWitness) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const MainWitness,
        preprocessing: *const Preprocessed,
    ) Error!void {
        try preprocessing.validate();
        if (self.rows.len != preprocessing.rows.len or
            !std.mem.eql(
                u8,
                &self.authority_digest,
                &preprocessing.authority_digest,
            )) return error.AuthorityMismatch;
        for (self.rows, preprocessing.rows) |row, metadata|
            try validateMainRowAgainst(metadata.kind, row, self.proof_kind);
    }

    pub fn generateInto(
        self: *const MainWitness,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        preprocessing: *const Preprocessed,
        executor: *const Executor,
    ) Error!void {
        try self.validateAgainst(preprocessing);
        return direct.generateMainInto(
            M31,
            MainRow,
            MAIN_COLUMN_COUNT,
            columns,
            self.rows,
            preprocessing.log_size,
            M31.zero(),
            executor,
            validateMainRow,
            writeMainRow,
        );
    }
};

pub fn logicalInputs(
    main: MainRow,
    preprocessing: PreprocessedRow,
    proof_kind: ProofKind,
) [air.LOGICAL_INPUT_COUNT]M31 {
    return main.values() ++ preprocessing.values() ++ .{
        proof_kind.selectors()[0],
        M31.fromCanonical(air.VM_CLAIM_SEMANTICS_SCOPE),
        M31.fromCanonical(air.VM_CLAIM_HASH_SCOPE),
        M31.fromCanonical(air.VM_PUBLIC_LOGUP_SCOPE),
        M31.fromCanonical(air.VM_PUBLIC_INPUT_KIND),
        M31.fromCanonical(air.VM_PUBLIC_OUTPUT_KIND),
        M31.fromCanonical(air.LOW_BYTE_INDEX),
        M31.fromCanonical(air.HIGH_BYTE_INDEX),
    };
}

fn canonicalMainRow(kind: WordKind, value: M31, proof_kind: ProofKind) Error!MainRow {
    if (proof_kind != .segment_leaf) return .{
        .value = M31.zero(),
        .low_byte = M31.zero(),
        .high_byte = M31.zero(),
    };
    const raw = value.toU32();
    return switch (kind) {
        .constant => |expected| if (raw == expected)
            .{ .value = value, .low_byte = M31.zero(), .high_byte = M31.zero() }
        else
            error.ConstantMismatch,
        .boolean => if (raw <= 1)
            .{ .value = value, .low_byte = M31.zero(), .high_byte = M31.zero() }
        else
            error.InvalidBooleanWord,
        .u16 => if (raw <= std.math.maxInt(u16))
            .{
                .value = value,
                .low_byte = M31.fromCanonical(raw & 0xff),
                .high_byte = M31.fromCanonical(raw >> 8),
            }
        else
            error.IntegerWordOutOfRange,
        .field => .{ .value = value, .low_byte = M31.zero(), .high_byte = M31.zero() },
    };
}

fn validateMainRowAgainst(
    kind: WordKind,
    row: MainRow,
    proof_kind: ProofKind,
) Error!void {
    const expected = try canonicalMainRow(kind, row.value, proof_kind);
    if (!std.meta.eql(row, expected)) {
        return switch (kind) {
            .constant => error.ConstantMismatch,
            .boolean => error.InvalidBooleanWord,
            .u16 => error.IntegerWordOutOfRange,
            .field => error.AuthorityMismatch,
        };
    }
}

fn expectedRow(shape: Shape, index: usize) PreprocessedRow {
    return .{
        .word_index = @intCast(index),
        .kind = expectedKind(shape, index),
        .input_io_index = inputIoIndex(shape, index),
        .output_io_index = outputIoIndex(shape, index),
    };
}

fn expectedKind(shape: Shape, index: usize) WordKind {
    const constants = [_]struct { index: usize, value: u32 }{
        .{ .index = 0, .value = 1 },
        .{ .index = 1, .value = 14 },
        .{ .index = 2, .value = shape.max_input_words & 0xffff },
        .{ .index = 3, .value = shape.max_input_words >> 16 },
        .{ .index = 4, .value = shape.max_output_words & 0xffff },
        .{ .index = 5, .value = shape.max_output_words >> 16 },
        .{ .index = 6, .value = 2 },
        .{ .index = 9, .value = 3 },
        .{ .index = 12, .value = 4 },
        .{ .index = 15, .value = 5 },
        .{ .index = 80, .value = 6 },
        .{ .index = 145, .value = 7 },
        .{ .index = 210, .value = 8 },
        .{ .index = 220, .value = 9 },
        .{ .index = 230, .value = 10 },
        .{ .index = 240, .value = 11 },
        .{ .index = 253, .value = 12 },
    };
    for (constants) |item| if (index == item.index)
        return .{ .constant = item.value };
    if (index == 211 or index == 221 or index == 231) return .boolean;
    if ((212 <= index and index < 220) or
        (222 <= index and index < 230) or
        (232 <= index and index < 240)) return .field;
    if (index < 256) return .u16;

    const output_tag = outputWordsTag(shape);
    if (index < output_tag) {
        const within = (index - 256) % INPUT_SLOT_WORDS;
        return if (within == 0) .boolean else .u16;
    }
    if (index == output_tag) return .{ .constant = 13 };
    if (index < output_tag + 3) return .u16;
    const within = (index - (output_tag + 3)) % OUTPUT_SLOT_WORDS;
    return if (within == 0) .boolean else .u16;
}

fn inputIoIndex(shape: Shape, index: usize) ?u32 {
    const mapped = if (index >= 241 and index < 245)
        3 + index - 241
    else if (index >= 254 and index < 256)
        7 + index - 254
    else if (index >= 256 and index < outputWordsTag(shape))
        9 + index - 256
    else
        return null;
    return @intCast(mapped);
}

fn outputIoIndex(shape: Shape, index: usize) ?u32 {
    if (index >= 245 and index < 251) return @intCast(3 + index - 245);
    const count_start = outputWordsTag(shape) + 1;
    if (index >= count_start and index < count_start + 2)
        return @intCast(9 + index - count_start);
    const slots_start = count_start + 2;
    if (index < slots_start) return null;
    const offset = index - slots_start;
    const slot = offset / OUTPUT_SLOT_WORDS;
    const within = offset % OUTPUT_SLOT_WORDS;
    if (slot >= @as(usize, shape.max_output_words) or within >= 5) return null;
    return @intCast(11 + slot * 5 + within);
}

fn outputWordsTag(shape: Shape) usize {
    return 256 + @as(usize, shape.max_input_words) * INPUT_SLOT_WORDS;
}

fn traceLogSize(row_count: usize) Error!u32 {
    const result: u32 = @max(
        MIN_LOG_SIZE,
        @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(row_count, 1)))),
    );
    if (result > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
    return result;
}

fn validatePreprocessedRow(row: PreprocessedRow) direct.Error!void {
    if (row.word_index >= m31.Modulus or
        (row.input_io_index != null and row.input_io_index.? >= m31.Modulus) or
        (row.output_io_index != null and row.output_io_index.? >= m31.Modulus))
    {
        return error.InvalidTraceRow;
    }
}

fn validateMainRow(row: MainRow) direct.Error!void {
    if (row.low_byte.toU32() > 255 or row.high_byte.toU32() > 255)
        return error.InvalidTraceRow;
}

fn writePreprocessedRow(
    columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    logical_row: usize,
    row: PreprocessedRow,
) void {
    const values = row.values();
    for (columns, values) |column, value| column[logical_row] = value;
}

fn writeMainRow(
    columns: *[MAIN_COLUMN_COUNT][]M31,
    logical_row: usize,
    row: MainRow,
) void {
    const values = row.values();
    for (columns, values) |column, value| column[logical_row] = value;
}

fn rowsDigest(shape: Shape, rows: []const PreprocessedRow) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PREPROCESSING_DOMAIN);
    hashInt(&hash, u32, shape.max_input_words);
    hashInt(&hash, u32, shape.max_output_words);
    hashInt(&hash, u32, rows.len);
    for (rows) |row| {
        hashInt(&hash, u32, row.word_index);
        hashInt(&hash, u8, @intFromEnum(std.meta.activeTag(row.kind)));
        hashInt(&hash, u32, switch (row.kind) {
            .constant => |value| value,
            else => 0,
        });
        hashOptional(&hash, row.input_io_index);
        hashOptional(&hash, row.output_io_index);
    }
    return hash.finalResult();
}

fn hashOptional(hash: anytype, value: ?u32) void {
    hashInt(hash, u8, @intFromBool(value != null));
    hashInt(hash, u32, value orelse 0);
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
