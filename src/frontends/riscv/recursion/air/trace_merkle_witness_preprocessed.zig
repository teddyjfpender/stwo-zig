//! Internal trace merkle witness authority shard; use trace_merkle_witness.zig publicly.

const dependency_0 = @import("trace_merkle_witness_contract.zig");

const BINDING_DIGEST = dependency_0.BINDING_DIGEST;
const Binding = dependency_0.Binding;
const Chunk = dependency_0.Chunk;
const Error = dependency_0.Error;
const LEAF_TAG = dependency_0.LEAF_TAG;
const LEFT_RECURSION_VERIFIER_ID = dependency_0.LEFT_RECURSION_VERIFIER_ID;
const LaneProfile = dependency_0.LaneProfile;
const M31 = dependency_0.M31;
const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const MAX_LOG_SIZE = dependency_0.MAX_LOG_SIZE;
const MIN_LOG_SIZE = dependency_0.MIN_LOG_SIZE;
const MainRow = dependency_0.MainRow;
const OpeningSet = dependency_0.OpeningSet;
const OpeningWitness = dependency_0.OpeningWitness;
const PREPROCESSED_COLUMN_COUNT = dependency_0.PREPROCESSED_COLUMN_COUNT;
const RIGHT_RECURSION_VERIFIER_ID = dependency_0.RIGHT_RECURSION_VERIFIER_ID;
const Reference = dependency_0.Reference;
const Row = dependency_0.Row;
const SEGMENT_VERIFIER_ID = dependency_0.SEGMENT_VERIFIER_ID;
const TRACE_POSITION_KIND = dependency_0.TRACE_POSITION_KIND;
const component = dependency_0.component;
const digest = dependency_0.digest;
const direct = dependency_0.direct;
const hashInt = dependency_0.hashInt;
const m31 = dependency_0.m31;
const materialize = dependency_0.materialize;
const maximumTreeColumns = dependency_0.maximumTreeColumns;
const merkle_root = dependency_0.merkle_root;
const query_mapping = dependency_0.query_mapping;
const schedule = dependency_0.schedule;
const std = dependency_0.std;
const totalRows = dependency_0.totalRows;
const validateLaneRows = dependency_0.validateLaneRows;
const writeMainRow = dependency_0.writeMainRow;

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
        opening_witness: OpeningWitness,
    ) Error!void {
        return preprocessing.generateMainInto(reference, columns, opening_witness, self);
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
        const maximum_columns = @max(maximumTreeColumns(reference.vm), maximumTreeColumns(reference.recursion));
        const order = try allocator.alloc(u32, maximum_columns);
        defer allocator.free(order);
        var cursor: usize = 0;
        try fillLaneRows(rows, &cursor, reference.vm, reference.vm_control_start, SEGMENT_VERIFIER_ID, 1, 0, order);
        try fillLaneRows(rows, &cursor, reference.recursion, reference.recursion_control_start, LEFT_RECURSION_VERIFIER_ID, 0, 1, order);
        try fillLaneRows(rows, &cursor, reference.recursion, reference.recursion_control_start, RIGHT_RECURSION_VERIFIER_ID, 0, 1, order);
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
        if (self.rows.len != try totalRows(reference.vm, reference.recursion) or
            self.log_size != try traceLogSize(self.rows.len) or
            !std.mem.eql(u8, &self.reference_digest, &reference.authority_digest) or
            !std.mem.eql(u8, &self.authority_digest, &rowsDigest(self.rows)))
        {
            return error.AuthorityMismatch;
        }
    }

    /// Cold admission audit that independently regenerates the exact stable
    /// ordering and control schedule. Hot writers use the sealed linear scan
    /// above and therefore remain allocation-free.
    pub fn validateAgainstAuthority(
        self: *const Preprocessed,
        reference: Reference,
    ) Error!void {
        try self.validateAgainst(reference);
        const maximum_columns = @max(
            maximumTreeColumns(reference.vm),
            maximumTreeColumns(reference.recursion),
        );
        const order = try self.allocator.alloc(u32, maximum_columns);
        defer self.allocator.free(order);
        var cursor: usize = 0;
        try validateLaneRows(
            self.rows,
            &cursor,
            reference.vm,
            reference.vm_control_start,
            SEGMENT_VERIFIER_ID,
            1,
            0,
            order,
        );
        try validateLaneRows(
            self.rows,
            &cursor,
            reference.recursion,
            reference.recursion_control_start,
            LEFT_RECURSION_VERIFIER_ID,
            0,
            1,
            order,
        );
        try validateLaneRows(
            self.rows,
            &cursor,
            reference.recursion,
            reference.recursion_control_start,
            RIGHT_RECURSION_VERIFIER_ID,
            0,
            1,
            order,
        );
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
        opening_witness: OpeningWitness,
        executor: *const Executor,
    ) Error!void {
        try self.validateAgainst(reference);
        try validateWitness(reference, opening_witness);
        _ = try preflightMain(columns, self, opening_witness, executor);
        for (columns) |column| @memset(column, M31.zero());
        var state = [_]M31{M31.zero()} ** component.STATE_WIDTH;
        for (self.rows, 0..) |row, logical_row| {
            const opening = selectOpening(row.verifier_id, opening_witness) orelse continue;
            if (row.first == 1) {
                state = [_]M31{M31.zero()} ** component.STATE_WIDTH;
                state[component.STATE_WIDTH - 1] = M31.fromCanonical(LEAF_TAG);
            }
            const result = materialize(row, opening, state);
            state = result.output;
            writeMainRow(columns, logical_row, result);
        }
    }
};

pub fn logicalRow(
    reference: Reference,
    preprocessing: *const Preprocessed,
    row_index: usize,
    opening_witness: OpeningWitness,
) Error![component.LOGICAL_INPUT_COUNT]M31 {
    try preprocessing.validateAgainst(reference);
    try validateWitness(reference, opening_witness);
    if (row_index >= preprocessing.rows.len) return error.InvalidWitness;
    var state = [_]M31{M31.zero()} ** component.STATE_WIDTH;
    var main = zeroMainRow();
    for (preprocessing.rows[0 .. row_index + 1], 0..) |row, index| {
        const opening = selectOpening(row.verifier_id, opening_witness);
        if (opening) |active_opening| {
            if (row.first == 1) {
                state = [_]M31{M31.zero()} ** component.STATE_WIDTH;
                state[component.STATE_WIDTH - 1] = M31.fromCanonical(LEAF_TAG);
            }
            const result = materialize(row, active_opening, state);
            state = result.output;
            if (index == row_index) main = result;
        } else if (index == row_index) main = zeroMainRow();
    }
    const selectors = opening_witness.proofKind().selectors();
    return main.values() ++ preprocessing.rows[row_index].values() ++ .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(LEAF_TAG),
        M31.fromCanonical(TRACE_POSITION_KIND),
    };
}

pub fn zeroMainRow() MainRow {
    return .{
        .enabler = M31.zero(),
        .position = M31.zero(),
        .previous = [_]M31{M31.zero()} ** component.STATE_WIDTH,
        .chunks = [_]M31{M31.zero()} ** component.RATE,
        .output = [_]M31{M31.zero()} ** component.STATE_WIDTH,
    };
}

pub fn fillLaneRows(
    rows: []Row,
    cursor: *usize,
    profile: LaneProfile,
    control_start: u32,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
    order_storage: []u32,
) Error!void {
    var tree_offset: usize = 0;
    for (profile.trees, 0..) |tree, tree_index| {
        const order = order_storage[0..tree.column_log_sizes.len];
        for (order, 0..) |*value, index| value.* = @intCast(index);
        std.mem.sortUnstable(u32, order, tree.column_log_sizes, struct {
            fn lessThan(log_sizes: []const u32, lhs: u32, rhs: u32) bool {
                return log_sizes[lhs] < log_sizes[rhs] or
                    (log_sizes[lhs] == log_sizes[rhs] and lhs < rhs);
            }
        }.lessThan);
        const step_count = std.math.divCeil(usize, tree.column_log_sizes.len + 1, component.RATE) catch
            return error.ArithmeticOverflow;
        for (0..profile.query_count) |query| for (0..step_count) |step| {
            var chunks = [_]Chunk{.{
                .source_mask = 0,
                .column = 0,
                .constant = 0,
                .flat_index = 0,
            }} ** component.RATE;
            for (&chunks, 0..) |*chunk, slot| {
                const stream_index = step * component.RATE + slot;
                if (stream_index < order.len) {
                    const column = order[stream_index];
                    chunk.* = .{
                        .source_mask = 1,
                        .column = column,
                        .constant = 0,
                        .flat_index = (tree_offset + column) * profile.query_count + query,
                    };
                } else if (stream_index == order.len) {
                    chunk.constant = 1;
                }
            }
            rows[cursor.*] = .{
                .row_mask = 1,
                .segment_mask = segment_mask,
                .binary_mask = binary_mask,
                .verifier_id = verifier_id,
                .tree = @intCast(tree_index),
                .query = @intCast(query),
                .tree_id = try merkle_root.traceTreeId(verifier_id, tree_index),
                .tree_height = tree.height,
                .step = @intCast(step),
                .first = @intFromBool(step == 0),
                .last = @intFromBool(step + 1 == step_count),
                .control_sequence = control_start + @as(u32, @intCast(tree_index * profile.query_count + query)),
                .control_tag = 22,
                .control_args = .{ @intCast(tree_index), @intCast(query), tree.height, 0 },
                .chunks = chunks,
                .position_weights = if (tree_index == 0)
                    try query_mapping.preprocessedTreeWeights(
                        profile.lifting_log_size,
                        tree.height,
                    )
                else
                    try query_mapping.shiftedWeights(0, tree.height),
            };
            cursor.* += 1;
        };
        tree_offset += tree.column_log_sizes.len;
    }
}

pub fn validateWitness(reference: Reference, opening_witness: OpeningWitness) Error!void {
    switch (opening_witness) {
        .segment_leaf => |opening| try validateOpening(reference.vm, opening),
        .binary_node => |opening| {
            try validateOpening(reference.recursion, opening.left);
            try validateOpening(reference.recursion, opening.right);
        },
        .empty_leaf => {},
    }
}

pub fn validateOpening(profile: LaneProfile, opening: OpeningSet) Error!void {
    if (opening.queried_values.len != try profile.queriedValueCount() or
        opening.raw_queries.len != profile.query_count)
    {
        return error.InvalidWitness;
    }
}

pub fn selectOpening(verifier_id: u32, opening_witness: OpeningWitness) ?OpeningSet {
    return switch (opening_witness) {
        .segment_leaf => |opening| if (verifier_id == SEGMENT_VERIFIER_ID) opening else null,
        .binary_node => |opening| switch (verifier_id) {
            LEFT_RECURSION_VERIFIER_ID => opening.left,
            RIGHT_RECURSION_VERIFIER_ID => opening.right,
            else => null,
        },
        .empty_leaf => null,
    };
}

pub fn validateRow(row: Row) Error!void {
    if (row.row_mask != 1 or row.segment_mask > 1 or row.binary_mask > 1 or
        row.segment_mask + row.binary_mask != 1 or
        row.verifier_id > RIGHT_RECURSION_VERIFIER_ID or row.tree >= merkle_root.TREE_INDEX_LIMIT or
        row.query >= m31.Modulus or row.tree_height == 0 or row.tree_height > MAX_LOG_SIZE or
        row.step >= m31.Modulus or row.first > 1 or row.last > 1 or
        row.control_tag != 22 or row.control_args[0] != row.tree or
        row.control_args[1] != row.query or row.control_args[2] != row.tree_height or
        row.control_args[3] != 0 or
        row.tree_id != try merkle_root.traceTreeId(row.verifier_id, row.tree))
    {
        return error.InvalidProfile;
    }
    for (row.chunks) |chunk| if (chunk.source_mask > 1 or
        chunk.column >= m31.Modulus or chunk.constant >= m31.Modulus)
    {
        return error.InvalidProfile;
    };
    for (row.position_weights) |weight| if (weight >= m31.Modulus)
        return error.InvalidProfile;
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
    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

pub fn preflightMain(
    columns: *const [MAIN_COLUMN_COUNT][]M31,
    preprocessing: *const Preprocessed,
    opening_witness: OpeningWitness,
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
    }
    switch (opening_witness) {
        .segment_leaf => |opening| try rejectOpeningAlias(destinations, opening),
        .binary_node => |opening| {
            try rejectOpeningAlias(destinations, opening.left);
            try rejectOpeningAlias(destinations, opening.right);
        },
        .empty_leaf => {},
    }
    return size;
}

pub fn rejectOpeningAlias(destinations: [MAIN_COLUMN_COUNT]AddressRange, opening: OpeningSet) direct.Error!void {
    for ([_][]const M31{ opening.queried_values, opening.raw_queries }) |values| {
        const source = try sliceRange(M31, values);
        for (destinations) |destination| if (destination.overlaps(source))
            return error.AliasedInput;
    }
}

pub fn sliceRange(comptime T: type, values: []const T) direct.Error!AddressRange {
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    const end = std.math.add(usize, start, byte_len) catch return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

pub fn objectRange(value: anytype) direct.Error!AddressRange {
    const Pointer = @TypeOf(value);
    const Child = @typeInfo(Pointer).pointer.child;
    const start = @intFromPtr(value);
    const end = std.math.add(usize, start, @sizeOf(Child)) catch return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

pub fn traceLogSize(row_count: usize) Error!u32 {
    const result: u32 = @max(
        MIN_LOG_SIZE,
        @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(row_count, 1)))),
    );
    if (result > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
    return result;
}

pub fn rowsDigest(rows: []const Row) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursion-trace-merkle-rows/v1\x00");
    hashInt(&hash, u32, rows.len);
    for (rows) |row| {
        for (row.values()) |value| hashInt(&hash, u32, value.toU32());
        for (row.chunks) |chunk| hashInt(&hash, u64, chunk.flat_index);
        for (row.position_weights) |weight| hashInt(&hash, u32, weight);
    }
    return hash.finalResult();
}
