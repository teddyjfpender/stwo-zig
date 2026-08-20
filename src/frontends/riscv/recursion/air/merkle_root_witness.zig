//! Authenticated root ownership and allocation-free direct row-22 writer.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const digest = @import("../../air/lang/digest.zig");
const direct = @import("../../air/lang/direct_witness_executor.zig");
const types = @import("../../air/lang/types.zig");
const protocol = @import("../protocol.zig");
const component = @import("merkle_root.zig");
const proof_kind_mod = @import("proof_kind.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const SEGMENT_VERIFIER_ID: u32 = 0;
pub const LEFT_RECURSION_VERIFIER_ID: u32 = 1;
pub const RIGHT_RECURSION_VERIFIER_ID: u32 = 2;
pub const VERIFIER_TREE_STRIDE: u32 = 1 << 16;
pub const FRI_TREE_OFFSET: u32 = 1 << 15;
pub const TREE_INDEX_LIMIT: usize = FRI_TREE_OFFSET;
pub const COMMITMENT_INPUT_KIND: u32 = 4;
pub const FRI_COMMITMENT_INPUT_KIND: u32 = 7;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = proof_kind_mod.ProofKind;
pub const Digest = protocol.Digest;

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN = "stwo-zig/typed-air/recursion-merkle-root-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "8c76032d5e206873035e12651f863f6eebe394bbbcd3db11dd45187dc70741d9";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion Merkle-root witness-binding digest",
);
pub const REFERENCE_FORMAT_VERSION: u16 = 1;
pub const REFERENCE_DOMAIN = "stwo-zig/typed-air/recursion-merkle-root-reference/v1\x00";

pub const Error = direct.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    InvalidProfile,
    InvalidWitness,
    InvalidWitnessBinding,
    LogSizeOutOfRange,
};

pub const MainSource = enum(u8) {
    enabler = 0,
    digest_0 = 1,
    digest_1 = 2,
    digest_2 = 3,
    digest_3 = 4,
    digest_4 = 5,
    digest_5 = 6,
    digest_6 = 7,
    digest_7 = 8,
};

pub const PreprocessedSource = enum(u8) {
    row_mask = 0,
    segment_mask = 1,
    binary_mask = 2,
    verifier_id = 3,
    input_kind = 4,
    item = 5,
    tree_id = 6,
    path_count = 7,
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
        root_witness: RootWitness,
    ) Error!void {
        return preprocessing.generateMainInto(reference, columns, root_witness, self);
    }
};

pub const LaneProfile = struct {
    query_count: u32,
    trace_tree_count: u32,
    fri_layer_count: u32,
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

pub const RootSource = enum(u8) { trace = 0, fri = 1 };

pub const Row = struct {
    row_mask: u32,
    segment_mask: u32,
    binary_mask: u32,
    verifier_id: u32,
    source: RootSource,
    item: u32,
    tree_id: u32,
    path_count: u32,

    pub fn inputKind(self: Row) u32 {
        return switch (self.source) {
            .trace => COMMITMENT_INPUT_KIND,
            .fri => FRI_COMMITMENT_INPUT_KIND,
        };
    }

    pub fn values(self: Row) [PREPROCESSED_COLUMN_COUNT]M31 {
        return .{
            M31.fromCanonical(self.row_mask),
            M31.fromCanonical(self.segment_mask),
            M31.fromCanonical(self.binary_mask),
            M31.fromCanonical(self.verifier_id),
            M31.fromCanonical(self.inputKind()),
            M31.fromCanonical(self.item),
            M31.fromCanonical(self.tree_id),
            M31.fromCanonical(self.path_count),
        };
    }
};

pub const RootSet = struct {
    trace: []const Digest,
    fri: []const Digest,
};

pub const RootWitness = union(ProofKind) {
    segment_leaf: RootSet,
    binary_node: struct { left: RootSet, right: RootSet },
    empty_leaf: void,

    pub fn proofKind(self: RootWitness) ProofKind {
        return std.meta.activeTag(self);
    }
};

pub const MainRow = struct {
    enabler: M31,
    digest_words: [component.DIGEST_WORD_COUNT]M31,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{self.enabler} ++ self.digest_words;
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
        var cursor: usize = 0;
        fillLaneRows(rows, &cursor, reference.vm, SEGMENT_VERIFIER_ID, 1, 0);
        fillLaneRows(rows, &cursor, reference.recursion, LEFT_RECURSION_VERIFIER_ID, 0, 1);
        fillLaneRows(rows, &cursor, reference.recursion, RIGHT_RECURSION_VERIFIER_ID, 0, 1);
        std.debug.assert(cursor == rows.len);
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
        root_witness: RootWitness,
        executor: *const Executor,
    ) Error!void {
        try self.validateAgainst(reference);
        try validateWitness(reference, root_witness);
        _ = try preflightMain(columns, self, root_witness, executor);
        for (columns) |column| @memset(column, M31.zero());
        for (self.rows, 0..) |row, logical_row| {
            const selected = selectDigestAssumeValid(row, root_witness) orelse continue;
            columns[0][logical_row] = M31.one();
            inline for (0..component.DIGEST_WORD_COUNT) |word|
                columns[1 + word][logical_row] = M31.fromCanonical(selected[word]);
        }
    }
};

pub fn mainRow(row: Row, root_witness: RootWitness) Error!MainRow {
    try validateRow(row);
    if (try selectDigest(row, root_witness)) |selected| {
        var words: [component.DIGEST_WORD_COUNT]M31 = undefined;
        for (&words, selected) |*word, value| {
            if (value >= m31.Modulus) return error.InvalidWitness;
            word.* = M31.fromCanonical(value);
        }
        return .{ .enabler = M31.one(), .digest_words = words };
    }
    return .{
        .enabler = M31.zero(),
        .digest_words = [_]M31{M31.zero()} ** component.DIGEST_WORD_COUNT,
    };
}

pub fn logicalRow(row: Row, root_witness: RootWitness) Error![component.LOGICAL_INPUT_COUNT]M31 {
    const main = (try mainRow(row, root_witness)).values();
    const selectors = root_witness.proofKind().selectors();
    return main ++ row.values() ++ .{ selectors[0], selectors[1] };
}

pub fn traceTreeId(verifier_id: u32, tree: usize) Error!u32 {
    return namespacedTreeId(verifier_id, tree, 0);
}

pub fn friTreeId(verifier_id: u32, layer: usize) Error!u32 {
    return namespacedTreeId(verifier_id, layer, FRI_TREE_OFFSET);
}

fn namespacedTreeId(verifier_id: u32, item: usize, offset: u32) Error!u32 {
    if (verifier_id > RIGHT_RECURSION_VERIFIER_ID or item >= TREE_INDEX_LIMIT)
        return error.InvalidProfile;
    const base = std.math.mul(u32, verifier_id, VERIFIER_TREE_STRIDE) catch
        return error.ArithmeticOverflow;
    const with_offset = std.math.add(u32, base, offset) catch
        return error.ArithmeticOverflow;
    const result = std.math.add(u32, with_offset, @intCast(item)) catch
        return error.ArithmeticOverflow;
    if (result >= m31.Modulus) return error.InvalidProfile;
    return result;
}

fn validateProfiles(vm: LaneProfile, recursion: LaneProfile) Error!void {
    for ([_]LaneProfile{ vm, recursion }) |profile| {
        if (profile.query_count == 0 or profile.query_count >= m31.Modulus or
            profile.trace_tree_count == 0 or profile.trace_tree_count > TREE_INDEX_LIMIT or
            profile.fri_layer_count == 0 or profile.fri_layer_count > TREE_INDEX_LIMIT)
        {
            return error.InvalidProfile;
        }
    }
    _ = try totalRows(vm, recursion);
}

fn laneRows(profile: LaneProfile) Error!usize {
    return std.math.add(usize, profile.trace_tree_count, profile.fri_layer_count) catch
        return error.ArithmeticOverflow;
}

fn totalRows(vm: LaneProfile, recursion: LaneProfile) Error!usize {
    const recursive = std.math.mul(usize, try laneRows(recursion), 2) catch
        return error.ArithmeticOverflow;
    return std.math.add(usize, try laneRows(vm), recursive) catch
        return error.ArithmeticOverflow;
}

fn fillLaneRows(
    rows: []Row,
    cursor: *usize,
    profile: LaneProfile,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) void {
    for (0..profile.trace_tree_count) |item| {
        rows[cursor.*] = laneRow(
            verifier_id,
            segment_mask,
            binary_mask,
            .trace,
            @intCast(item),
            profile.query_count,
        );
        cursor.* += 1;
    }
    for (0..profile.fri_layer_count) |item| {
        rows[cursor.*] = laneRow(
            verifier_id,
            segment_mask,
            binary_mask,
            .fri,
            @intCast(item),
            profile.query_count,
        );
        cursor.* += 1;
    }
}

fn laneRow(
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
    source: RootSource,
    item: u32,
    path_count: u32,
) Row {
    return .{
        .row_mask = 1,
        .segment_mask = segment_mask,
        .binary_mask = binary_mask,
        .verifier_id = verifier_id,
        .source = source,
        .item = item,
        .tree_id = switch (source) {
            .trace => traceTreeId(verifier_id, item) catch unreachable,
            .fri => friTreeId(verifier_id, item) catch unreachable,
        },
        .path_count = path_count,
    };
}

fn expectedRow(reference: Reference, index: usize) Row {
    const vm_count = reference.vm.trace_tree_count + reference.vm.fri_layer_count;
    const recursion_count = reference.recursion.trace_tree_count + reference.recursion.fri_layer_count;
    if (index < vm_count) return indexedLaneRow(reference.vm, SEGMENT_VERIFIER_ID, 1, 0, index);
    const recursion_index = index - vm_count;
    const right = recursion_index >= recursion_count;
    return indexedLaneRow(
        reference.recursion,
        if (right) RIGHT_RECURSION_VERIFIER_ID else LEFT_RECURSION_VERIFIER_ID,
        0,
        1,
        if (right) recursion_index - recursion_count else recursion_index,
    );
}

fn indexedLaneRow(
    profile: LaneProfile,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
    index: usize,
) Row {
    const is_fri = index >= profile.trace_tree_count;
    return laneRow(
        verifier_id,
        segment_mask,
        binary_mask,
        if (is_fri) .fri else .trace,
        @intCast(if (is_fri) index - profile.trace_tree_count else index),
        profile.query_count,
    );
}

fn validateWitness(reference: Reference, root_witness: RootWitness) Error!void {
    switch (root_witness) {
        .segment_leaf => |roots| try validateRootSet(reference.vm, roots),
        .binary_node => |roots| {
            try validateRootSet(reference.recursion, roots.left);
            try validateRootSet(reference.recursion, roots.right);
        },
        .empty_leaf => {},
    }
}

fn validateRootSet(profile: LaneProfile, roots: RootSet) Error!void {
    if (roots.trace.len != profile.trace_tree_count or
        roots.fri.len != profile.fri_layer_count)
    {
        return error.InvalidWitness;
    }
    for (roots.trace) |value| try validateDigest(value);
    for (roots.fri) |value| try validateDigest(value);
}

fn validateDigest(value: Digest) Error!void {
    for (value) |word| if (word >= m31.Modulus) return error.InvalidWitness;
}

fn selectDigest(row: Row, root_witness: RootWitness) Error!?Digest {
    const roots: ?RootSet = switch (root_witness) {
        .segment_leaf => |value| if (row.verifier_id == SEGMENT_VERIFIER_ID) value else null,
        .binary_node => |value| switch (row.verifier_id) {
            LEFT_RECURSION_VERIFIER_ID => value.left,
            RIGHT_RECURSION_VERIFIER_ID => value.right,
            else => null,
        },
        .empty_leaf => null,
    };
    const selected = roots orelse return null;
    const index: usize = @intCast(row.item);
    const values = switch (row.source) {
        .trace => selected.trace,
        .fri => selected.fri,
    };
    if (index >= values.len) return error.InvalidWitness;
    try validateDigest(values[index]);
    return values[index];
}

fn selectDigestAssumeValid(row: Row, root_witness: RootWitness) ?Digest {
    return selectDigest(row, root_witness) catch unreachable;
}

fn validateRow(row: Row) Error!void {
    if (row.row_mask != 1 or row.segment_mask > 1 or row.binary_mask > 1 or
        row.segment_mask + row.binary_mask != 1 or
        row.verifier_id > RIGHT_RECURSION_VERIFIER_ID or row.item >= TREE_INDEX_LIMIT or
        row.tree_id >= m31.Modulus or row.path_count == 0 or row.path_count >= m31.Modulus or
        row.segment_mask != @intFromBool(row.verifier_id == SEGMENT_VERIFIER_ID) or
        row.binary_mask != @intFromBool(row.verifier_id != SEGMENT_VERIFIER_ID))
    {
        return error.InvalidProfile;
    }
    const expected = switch (row.source) {
        .trace => try traceTreeId(row.verifier_id, row.item),
        .fri => try friTreeId(row.verifier_id, row.item),
    };
    if (row.tree_id != expected) return error.InvalidProfile;
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
    root_witness: RootWitness,
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
        for (objects) |object| if (destination.overlaps(object))
            return error.AliasedDestination;
        if (destination.overlaps(rows)) return error.AliasedInput;
    }
    switch (root_witness) {
        .segment_leaf => |roots| try rejectRootSetAlias(destinations, roots),
        .binary_node => |roots| {
            try rejectRootSetAlias(destinations, roots.left);
            try rejectRootSetAlias(destinations, roots.right);
        },
        .empty_leaf => {},
    }
    return size;
}

fn rejectRootSetAlias(destinations: [MAIN_COLUMN_COUNT]AddressRange, roots: RootSet) direct.Error!void {
    for ([_][]const Digest{ roots.trace, roots.fri }) |values| {
        const source = try sliceRange(Digest, values);
        for (destinations) |destination| if (destination.overlaps(source))
            return error.AliasedInput;
    }
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
    hash.update("stwo-zig/typed-air/recursion-merkle-root-rows/v1\x00");
    hashInt(&hash, u32, rows.len);
    for (rows) |row| {
        hashInt(&hash, u32, row.row_mask);
        hashInt(&hash, u32, row.segment_mask);
        hashInt(&hash, u32, row.binary_mask);
        hashInt(&hash, u32, row.verifier_id);
        hashInt(&hash, u8, @intFromEnum(row.source));
        hashInt(&hash, u32, row.item);
        hashInt(&hash, u32, row.tree_id);
        hashInt(&hash, u32, row.path_count);
    }
    return hash.finalResult();
}

fn hashProfile(hash: anytype, profile: LaneProfile) void {
    hashInt(hash, u32, profile.query_count);
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
