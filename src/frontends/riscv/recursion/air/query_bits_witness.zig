//! Verifier-owned query profile and allocation-free direct SoA writer for row 20.
//!
//! Admission hashes the VM and recursive query counts together with the exact
//! downstream bit-use multiplicities. The hot writer performs no allocation,
//! hashing, or dynamic dispatch and writes canonical M31 bits directly into
//! final column-major storage.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const digest = @import("../../air/lang/digest.zig");
const direct = @import("../../air/lang/direct_witness_executor.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("query_bits.zig");
const proof_kind_mod = @import("proof_kind.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const SEGMENT_VERIFIER_ID: u32 = 0;
pub const LEFT_RECURSION_VERIFIER_ID: u32 = 1;
pub const RIGHT_RECURSION_VERIFIER_ID: u32 = 2;
pub const RAW_QUERY_KIND: u32 = 5;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = proof_kind_mod.ProofKind;

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN = "stwo-zig/typed-air/recursion-query-bits-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "61408226ec18c881e35353a25ffdb68173249b5d43b134e75c79990e2499ea82";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion query-bits witness-binding digest",
);
pub const REFERENCE_FORMAT_VERSION: u16 = 1;
pub const REFERENCE_DOMAIN = "stwo-zig/typed-air/recursion-query-bits-reference/v1\x00";

pub const Error = direct.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    InvalidProfile,
    InvalidWitnessBinding,
    InvalidWitnessValue,
    LogSizeOutOfRange,
    QueryCountMismatch,
    QueryMissing,
};

pub const MainSource = enum(u8) {
    enabler = 0,
    word = 1,
    canonical_inverse = 2,
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
    query = 4,
    use_count = 5,
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
        witness: QueryWitness,
    ) Error!void {
        return preprocessing.generateMainInto(reference, columns, witness, self);
    }
};

pub const LaneProfile = struct {
    query_count: u32,
    /// Number of low bits retained by the authenticated raw-query to domain-
    /// position projection.  This is verifier-owned protocol shape, not proof
    /// material.
    lifting_log_size: u32,
    trace_tree_count: u32,
    fri_layer_count: u32,

    /// Exact number of query-bit-vector consumers in Stark-V:
    /// every trace tree, DEEP, two uses per FRI layer, and last-layer.
    pub fn useCount(self: LaneProfile) Error!u32 {
        const fri_uses = std.math.mul(u32, self.fri_layer_count, 2) catch
            return error.ArithmeticOverflow;
        const with_trees = std.math.add(u32, self.trace_tree_count, fri_uses) catch
            return error.ArithmeticOverflow;
        return std.math.add(u32, with_trees, 2) catch
            return error.ArithmeticOverflow;
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
};

pub const Row = struct {
    row_mask: u32,
    segment_mask: u32,
    binary_mask: u32,
    verifier_id: u32,
    query: u32,
    use_count: u32,

    pub fn values(self: Row) [PREPROCESSED_COLUMN_COUNT]M31 {
        return .{
            M31.fromCanonical(self.row_mask),
            M31.fromCanonical(self.segment_mask),
            M31.fromCanonical(self.binary_mask),
            M31.fromCanonical(self.verifier_id),
            M31.fromCanonical(self.query),
            M31.fromCanonical(self.use_count),
        };
    }
};

pub const QueryWitness = union(ProofKind) {
    segment_leaf: []const M31,
    binary_node: struct { left: []const M31, right: []const M31 },
    empty_leaf: void,

    pub fn proofKind(self: QueryWitness) ProofKind {
        return std.meta.activeTag(self);
    }
};

pub const MainRow = struct {
    enabler: M31,
    word: M31,
    canonical_inverse: M31,
    bits: [component.M31_BIT_COUNT]M31,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{ self.enabler, self.word, self.canonical_inverse } ++ self.bits;
    }
};

pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []Row,
    reference_digest: digest.Digest,
    authority_digest: digest.Digest,

    pub fn init(allocator: std.mem.Allocator, reference: Reference) Error!Preprocessed {
        try reference.validate();
        const row_count = try totalRows(reference.vm, reference.recursion);
        const log_size = try traceLogSize(row_count);
        const rows = try allocator.alloc(Row, row_count);
        errdefer allocator.free(rows);
        for (rows, 0..) |*row, index| row.* = expectedRow(reference, index);
        return .{
            .allocator = allocator,
            .log_size = log_size,
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
        const row_count = try totalRows(reference.vm, reference.recursion);
        if (self.rows.len != row_count or self.log_size != try traceLogSize(row_count) or
            !std.mem.eql(u8, &self.reference_digest, &reference.authority_digest) or
            !std.mem.eql(u8, &self.authority_digest, &rowsDigest(self.rows)))
        {
            return error.AuthorityMismatch;
        }
        for (self.rows, 0..) |row, index| {
            if (!std.meta.eql(row, expectedRow(reference, index)))
                return error.AuthorityMismatch;
        }
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
        witness: QueryWitness,
        executor: *const Executor,
    ) Error!void {
        try self.validateAgainst(reference);
        try validateWitness(reference, witness);
        _ = try preflightMain(columns, self, witness, executor);
        for (columns) |column| @memset(column, M31.zero());
        for (self.rows, 0..) |row, logical_row| {
            const word = queryWordAssumeValid(row, witness) orelse continue;
            writeActiveMainRow(columns, logical_row, word);
        }
    }
};

pub fn mainRow(row: Row, witness: QueryWitness) Error!MainRow {
    try validateRow(row);
    const maybe_word = try queryWord(row, witness);
    if (maybe_word) |word| {
        const raw = word.toU32();
        var bits: [component.M31_BIT_COUNT]M31 = undefined;
        for (&bits, 0..) |*bit, index|
            bit.* = M31.fromCanonical((raw >> @intCast(index)) & 1);
        const zero_count = component.M31_BIT_COUNT - @popCount(raw);
        if (zero_count == 0) return error.InvalidWitnessValue;
        return .{
            .enabler = M31.one(),
            .word = word,
            .canonical_inverse = ZERO_COUNT_INVERSES[zero_count],
            .bits = bits,
        };
    }
    return .{
        .enabler = M31.zero(),
        .word = M31.zero(),
        .canonical_inverse = M31.zero(),
        .bits = [_]M31{M31.zero()} ** component.M31_BIT_COUNT,
    };
}

/// Materializes one admitted logical row with already-derived verifier-owned
/// projection parameters.  Keeping cold reference validation in
/// `parameterValues` lets bulk interaction generation hash the profile once,
/// not once per row.
pub fn logicalRow(
    row: Row,
    witness: QueryWitness,
    parameters: [component.PARAMETER_COUNT]M31,
) Error![component.LOGICAL_INPUT_COUNT]M31 {
    const main = (try mainRow(row, witness)).values();
    return main ++ row.values() ++ parameters;
}

/// Exact constants supplied to the typed AIR adapter.  A proof never selects
/// these masks: they are derived from the sealed VM/recursion profile, and an
/// empty leaf exposes no projected position bits.
pub fn parameterValues(
    reference: Reference,
    kind: ProofKind,
) Error![component.PARAMETER_COUNT]M31 {
    try reference.validate();
    const selectors = kind.selectors();
    const lifting_log_size: u32 = switch (kind) {
        .segment_leaf => reference.vm.lifting_log_size,
        .binary_node => reference.recursion.lifting_log_size,
        .empty_leaf => 0,
    };
    var result: [component.PARAMETER_COUNT]M31 = undefined;
    result[0] = selectors[0];
    result[1] = selectors[1];
    result[2] = M31.fromCanonical(RAW_QUERY_KIND);
    for (result[3..], 0..) |*mask, bit| {
        mask.* = M31.fromCanonical(@intFromBool(bit < lifting_log_size));
    }
    return result;
}

fn validateProfiles(vm: LaneProfile, recursion: LaneProfile) Error!void {
    for ([_]LaneProfile{ vm, recursion }) |profile| {
        const use_count = try profile.useCount();
        if (profile.query_count == 0 or profile.query_count >= m31.Modulus or
            profile.lifting_log_size < MIN_LOG_SIZE or
            profile.lifting_log_size > MAX_LOG_SIZE or
            profile.trace_tree_count == 0 or profile.trace_tree_count >= m31.Modulus or
            profile.fri_layer_count == 0 or profile.fri_layer_count >= m31.Modulus or
            use_count == 0 or use_count >= m31.Modulus)
        {
            return error.InvalidProfile;
        }
    }
    _ = try totalRows(vm, recursion);
}

fn totalRows(vm: LaneProfile, recursion: LaneProfile) Error!usize {
    const recursion_rows = std.math.mul(usize, recursion.query_count, 2) catch
        return error.ArithmeticOverflow;
    return std.math.add(usize, vm.query_count, recursion_rows) catch
        return error.ArithmeticOverflow;
}

fn expectedRow(reference: Reference, index: usize) Row {
    const vm_count: usize = @intCast(reference.vm.query_count);
    const recursion_count: usize = @intCast(reference.recursion.query_count);
    if (index < vm_count) return .{
        .row_mask = 1,
        .segment_mask = 1,
        .binary_mask = 0,
        .verifier_id = SEGMENT_VERIFIER_ID,
        .query = @intCast(index),
        .use_count = reference.vm.useCount() catch unreachable,
    };
    const recursion_index = index - vm_count;
    const right = recursion_index >= recursion_count;
    return .{
        .row_mask = 1,
        .segment_mask = 0,
        .binary_mask = 1,
        .verifier_id = if (right) RIGHT_RECURSION_VERIFIER_ID else LEFT_RECURSION_VERIFIER_ID,
        .query = @intCast(if (right) recursion_index - recursion_count else recursion_index),
        .use_count = reference.recursion.useCount() catch unreachable,
    };
}

fn validateWitness(reference: Reference, witness: QueryWitness) Error!void {
    const vm_count: usize = @intCast(reference.vm.query_count);
    const recursion_count: usize = @intCast(reference.recursion.query_count);
    switch (witness) {
        .segment_leaf => |queries| if (queries.len != vm_count)
            return error.QueryCountMismatch,
        .binary_node => |queries| if (queries.left.len != recursion_count or
            queries.right.len != recursion_count)
        {
            return error.QueryCountMismatch;
        },
        .empty_leaf => {},
    }
}

fn queryWord(row: Row, witness: QueryWitness) Error!?M31 {
    const query: usize = @intCast(row.query);
    const values: ?[]const M31 = switch (witness) {
        .segment_leaf => |queries| if (row.verifier_id == SEGMENT_VERIFIER_ID)
            queries
        else
            null,
        .binary_node => |queries| switch (row.verifier_id) {
            LEFT_RECURSION_VERIFIER_ID => queries.left,
            RIGHT_RECURSION_VERIFIER_ID => queries.right,
            else => null,
        },
        .empty_leaf => null,
    };
    const selected = values orelse return null;
    if (query >= selected.len) return error.QueryMissing;
    return selected[query];
}

fn queryWordAssumeValid(row: Row, witness: QueryWitness) ?M31 {
    const query: usize = @intCast(row.query);
    return switch (witness) {
        .segment_leaf => |queries| if (row.verifier_id == SEGMENT_VERIFIER_ID)
            queries[query]
        else
            null,
        .binary_node => |queries| switch (row.verifier_id) {
            LEFT_RECURSION_VERIFIER_ID => queries.left[query],
            RIGHT_RECURSION_VERIFIER_ID => queries.right[query],
            else => null,
        },
        .empty_leaf => null,
    };
}

fn writeActiveMainRow(
    columns: *[MAIN_COLUMN_COUNT][]M31,
    logical_row: usize,
    word: M31,
) void {
    const raw = word.toU32();
    const zero_count = component.M31_BIT_COUNT - @popCount(raw);
    std.debug.assert(zero_count > 0);
    columns[0][logical_row] = M31.one();
    columns[1][logical_row] = word;
    columns[2][logical_row] = ZERO_COUNT_INVERSES[zero_count];
    inline for (0..component.M31_BIT_COUNT) |bit| {
        columns[3 + bit][logical_row] = M31.fromCanonical((raw >> bit) & 1);
    }
}

fn validateRow(row: Row) Error!void {
    if (row.row_mask != 1 or row.segment_mask > 1 or row.binary_mask > 1 or
        row.segment_mask + row.binary_mask != 1 or
        row.verifier_id > RIGHT_RECURSION_VERIFIER_ID or
        row.query >= m31.Modulus or row.use_count == 0 or row.use_count >= m31.Modulus or
        row.segment_mask != @intFromBool(row.verifier_id == SEGMENT_VERIFIER_ID) or
        row.binary_mask != @intFromBool(row.verifier_id != SEGMENT_VERIFIER_ID))
    {
        return error.InvalidProfile;
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
    witness: QueryWitness,
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
    const descriptors = try objectRange(columns);
    const protected = try objectRange(preprocessing);
    const binding = try objectRange(executor);
    const rows = try sliceRange(Row, preprocessing.rows);
    for (destinations) |destination| {
        if (destination.overlaps(descriptors) or destination.overlaps(protected) or
            destination.overlaps(binding)) return error.AliasedDestination;
        if (destination.overlaps(rows)) return error.AliasedInput;
    }
    switch (witness) {
        .segment_leaf => |queries| try rejectSourceAlias(destinations, queries),
        .binary_node => |queries| {
            try rejectSourceAlias(destinations, queries.left);
            try rejectSourceAlias(destinations, queries.right);
        },
        .empty_leaf => {},
    }
    return size;
}

fn rejectSourceAlias(
    destinations: [MAIN_COLUMN_COUNT]AddressRange,
    values: []const M31,
) direct.Error!void {
    const source_range = try sliceRange(M31, values);
    for (destinations) |destination| if (destination.overlaps(source_range))
        return error.AliasedInput;
}

fn sliceRange(comptime T: type, values: []const T) direct.Error!AddressRange {
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    const end = std.math.add(usize, start, byte_len) catch return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

fn objectRange(value: anytype) direct.Error!AddressRange {
    const Pointer = @TypeOf(value);
    const Child = @typeInfo(Pointer).pointer.child;
    const start = @intFromPtr(value);
    const end = std.math.add(usize, start, @sizeOf(Child)) catch return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

fn traceLogSize(row_count: usize) Error!u32 {
    const result: u32 = @max(
        MIN_LOG_SIZE,
        @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(row_count, 1)))),
    );
    if (result > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
    return result;
}

fn referenceDigest(vm: LaneProfile, recursion: LaneProfile) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(REFERENCE_DOMAIN);
    hashInt(&hash, u16, REFERENCE_FORMAT_VERSION);
    hashProfile(&hash, vm);
    hashProfile(&hash, recursion);
    return hash.finalResult();
}

fn rowsDigest(rows: []const Row) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursion-query-bits-rows/v1\x00");
    hashInt(&hash, u32, rows.len);
    for (rows) |row| {
        hashInt(&hash, u32, row.row_mask);
        hashInt(&hash, u32, row.segment_mask);
        hashInt(&hash, u32, row.binary_mask);
        hashInt(&hash, u32, row.verifier_id);
        hashInt(&hash, u32, row.query);
        hashInt(&hash, u32, row.use_count);
    }
    return hash.finalResult();
}

fn hashProfile(hash: anytype, profile: LaneProfile) void {
    hashInt(hash, u32, profile.query_count);
    hashInt(hash, u32, profile.lifting_log_size);
    hashInt(hash, u32, profile.trace_tree_count);
    hashInt(hash, u32, profile.fri_layer_count);
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

const ZERO_COUNT_INVERSES: [component.M31_BIT_COUNT + 1]M31 = blk: {
    @setEvalBranchQuota(10_000);
    var result = [_]M31{M31.zero()} ** (component.M31_BIT_COUNT + 1);
    for (1..result.len) |index| {
        result[index] = M31.fromCanonical(@intCast(index)).invUncheckedNonZero();
    }
    break :blk result;
};
