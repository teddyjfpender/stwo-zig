//! Internal query mapping witness authority shard; use query_mapping_witness.zig publicly.

const dependency_0 = @import("query_mapping_witness_preprocessed_source.zig");

const BINDING_DIGEST = dependency_0.BINDING_DIGEST;
const Binding = dependency_0.Binding;
const Error = dependency_0.Error;
const LEFT_RECURSION_VERIFIER_ID = dependency_0.LEFT_RECURSION_VERIFIER_ID;
const LaneProfile = dependency_0.LaneProfile;
const M31 = dependency_0.M31;
const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const MAX_LOG_SIZE = dependency_0.MAX_LOG_SIZE;
const MIN_LOG_SIZE = dependency_0.MIN_LOG_SIZE;
const PREPROCESSED_COLUMN_COUNT = dependency_0.PREPROCESSED_COLUMN_COUNT;
const QueryWitness = dependency_0.QueryWitness;
const RIGHT_RECURSION_VERIFIER_ID = dependency_0.RIGHT_RECURSION_VERIFIER_ID;
const Reference = dependency_0.Reference;
const Row = dependency_0.Row;
const SEGMENT_VERIFIER_ID = dependency_0.SEGMENT_VERIFIER_ID;
const component = dependency_0.component;
const digest = dependency_0.digest;
const direct = dependency_0.direct;
const expectRow = dependency_0.expectRow;
const fillProfileRows = dependency_0.fillProfileRows;
const hashInt = dependency_0.hashInt;
const laneRows = dependency_0.laneRows;
const m31 = dependency_0.m31;
const preprocessedTreeWeights = dependency_0.preprocessedTreeWeights;
const routeRow = dependency_0.routeRow;
const shiftedWeights = dependency_0.shiftedWeights;
const std = dependency_0.std;
const totalRows = dependency_0.totalRows;

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

pub const MainRow = struct {
    enabler: M31,
    position: M31,
    offset: M31,
    bits: [component.M31_BIT_COUNT]M31,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{ self.enabler, self.position, self.offset } ++ self.bits;
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
        try fillProfileRows(rows, &cursor, reference.vm, SEGMENT_VERIFIER_ID, 1, 0);
        try fillProfileRows(rows, &cursor, reference.recursion, LEFT_RECURSION_VERIFIER_ID, 0, 1);
        try fillProfileRows(rows, &cursor, reference.recursion, RIGHT_RECURSION_VERIFIER_ID, 0, 1);
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
        var cursor: usize = 0;
        try validateProfileRows(self.rows, &cursor, reference.vm, SEGMENT_VERIFIER_ID, 1, 0);
        try validateProfileRows(self.rows, &cursor, reference.recursion, LEFT_RECURSION_VERIFIER_ID, 0, 1);
        try validateProfileRows(self.rows, &cursor, reference.recursion, RIGHT_RECURSION_VERIFIER_ID, 0, 1);
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
        witness: QueryWitness,
        executor: *const Executor,
    ) Error!void {
        try self.validateAgainst(reference);
        try validateWitness(reference, witness);
        _ = try preflightMain(columns, self, witness, executor);
        for (columns) |column| @memset(column, M31.zero());
        for (self.rows, 0..) |row, logical_row| {
            const word = queryWordAssumeValid(row, witness) orelse continue;
            writeActiveMainRow(columns, logical_row, row, word);
        }
    }
};

pub fn mainRow(row: Row, witness: QueryWitness) Error!MainRow {
    try validateRow(row);
    const maybe_word = try queryWord(row, witness);
    if (maybe_word) |word| {
        var bits: [component.M31_BIT_COUNT]M31 = undefined;
        const raw = word.toU32();
        for (&bits, 0..) |*bit, index|
            bit.* = M31.fromCanonical((raw >> @intCast(index)) & 1);
        return .{
            .enabler = M31.one(),
            .position = try applyWeights(word, row.position_weights),
            .offset = try applyWeights(word, row.offset_weights),
            .bits = bits,
        };
    }
    return .{
        .enabler = M31.zero(),
        .position = M31.zero(),
        .offset = M31.zero(),
        .bits = [_]M31{M31.zero()} ** component.M31_BIT_COUNT,
    };
}

pub fn logicalRow(row: Row, witness: QueryWitness) Error![component.LOGICAL_INPUT_COUNT]M31 {
    const main = (try mainRow(row, witness)).values();
    const selectors = witness.proofKind().selectors();
    return main ++ row.values() ++ .{ selectors[0], selectors[1] };
}

pub fn applyWeights(
    word: M31,
    weights: [component.M31_BIT_COUNT]u32,
) Error!M31 {
    var value: u32 = 0;
    for (weights, 0..) |weight, bit| {
        value = std.math.add(
            u32,
            value,
            ((word.toU32() >> @intCast(bit)) & 1) * weight,
        ) catch return error.PositionNotCanonical;
    }
    if (value >= m31.Modulus) return error.PositionNotCanonical;
    return M31.fromCanonical(value);
}

pub fn validateProfileRows(
    rows: []const Row,
    cursor: *usize,
    profile: LaneProfile,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    const count = try laneRows(profile);
    if (cursor.* > rows.len or count > rows.len - cursor.*) return error.AuthorityMismatch;
    const actual = rows[cursor.*..][0..count];
    // Validation is cold and allocation-free. Reuse a bounded page of the
    // verifier-owned row storage as an exact generator target is unsafe, so
    // derive each route in the same canonical order and compare immediately.
    var index: usize = 0;
    for (0..profile.query_count) |query| {
        for (profile.tree_heights, 0..) |height, tree| {
            const weights = if (tree == 0)
                try preprocessedTreeWeights(profile.lifting_log_size, height)
            else
                try shiftedWeights(0, height);
            try expectRow(actual[index], routeRow(
                verifier_id,
                segment_mask,
                binary_mask,
                .trace_tree,
                @intCast(tree),
                @intCast(query),
                weights,
                [_]u32{0} ** component.M31_BIT_COUNT,
            ));
            index += 1;
        }
        try expectRow(actual[index], routeRow(
            verifier_id,
            segment_mask,
            binary_mask,
            .deep,
            0,
            @intCast(query),
            try shiftedWeights(0, profile.lifting_log_size),
            [_]u32{0} ** component.M31_BIT_COUNT,
        ));
        index += 1;
        var folded_bits: u32 = 0;
        for (profile.fri_fold_widths, 0..) |width, layer| {
            const fold_step = std.math.log2_int(u32, width);
            const remaining = profile.lifting_log_size - folded_bits;
            try expectRow(actual[index], routeRow(
                verifier_id,
                segment_mask,
                binary_mask,
                .fri_fold,
                @intCast(layer),
                @intCast(query),
                try shiftedWeights(folded_bits, remaining),
                try shiftedWeights(folded_bits, fold_step),
            ));
            index += 1;
            folded_bits += fold_step;
            try expectRow(actual[index], routeRow(
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
            ));
            index += 1;
        }
        try expectRow(actual[index], routeRow(
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
        ));
        index += 1;
    }
    std.debug.assert(index == count);
    cursor.* += count;
}

pub fn validateWitness(reference: Reference, witness: QueryWitness) Error!void {
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

pub fn queryWord(row: Row, witness: QueryWitness) Error!?M31 {
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
    if (query >= selected.len) return error.QueryCountMismatch;
    return selected[query];
}

pub fn queryWordAssumeValid(row: Row, witness: QueryWitness) ?M31 {
    return queryWord(row, witness) catch unreachable;
}

pub fn writeActiveMainRow(
    columns: *[MAIN_COLUMN_COUNT][]M31,
    logical_row: usize,
    row: Row,
    word: M31,
) void {
    columns[0][logical_row] = M31.one();
    columns[1][logical_row] = applyWeights(word, row.position_weights) catch unreachable;
    columns[2][logical_row] = applyWeights(word, row.offset_weights) catch unreachable;
    const raw = word.toU32();
    inline for (0..component.M31_BIT_COUNT) |bit| {
        columns[3 + bit][logical_row] = M31.fromCanonical((raw >> bit) & 1);
    }
}

pub fn validateRow(row: Row) Error!void {
    if (row.row_mask != 1 or row.segment_mask > 1 or row.binary_mask > 1 or
        row.segment_mask + row.binary_mask != 1 or
        row.verifier_id > RIGHT_RECURSION_VERIFIER_ID or
        row.item >= m31.Modulus or row.query >= m31.Modulus or
        row.segment_mask != @intFromBool(row.verifier_id == SEGMENT_VERIFIER_ID) or
        row.binary_mask != @intFromBool(row.verifier_id != SEGMENT_VERIFIER_ID))
    {
        return error.InvalidProfile;
    }
    for (row.position_weights ++ row.offset_weights) |weight| if (weight >= m31.Modulus)
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

pub fn rejectSourceAlias(
    destinations: [MAIN_COLUMN_COUNT]AddressRange,
    values: []const M31,
) direct.Error!void {
    const source_range = try sliceRange(M31, values);
    for (destinations) |destination| if (destination.overlaps(source_range))
        return error.AliasedInput;
}

pub fn sliceRange(comptime T: type, values: []const T) direct.Error!AddressRange {
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
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
    hash.update("stwo-zig/typed-air/recursion-query-mapping-rows/v1\x00");
    hashInt(&hash, u32, rows.len);
    for (rows) |row| {
        hashInt(&hash, u32, row.row_mask);
        hashInt(&hash, u32, row.segment_mask);
        hashInt(&hash, u32, row.binary_mask);
        hashInt(&hash, u32, row.verifier_id);
        hashInt(&hash, u32, @intFromEnum(row.kind));
        hashInt(&hash, u32, row.item);
        hashInt(&hash, u32, row.query);
        for (row.position_weights ++ row.offset_weights) |weight|
            hashInt(&hash, u32, weight);
    }
    return hash.finalResult();
}
