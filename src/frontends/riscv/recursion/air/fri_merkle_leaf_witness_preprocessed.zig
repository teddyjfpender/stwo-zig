//! Internal fri merkle leaf witness authority shard; use fri_merkle_leaf_witness.zig publicly.

const dependency_0 = @import("fri_merkle_leaf_witness_contract.zig");

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
const ROWS_DOMAIN = dependency_0.ROWS_DOMAIN;
const Reference = dependency_0.Reference;
const Row = dependency_0.Row;
const SECURE_WORD_COUNT = dependency_0.SECURE_WORD_COUNT;
const SEGMENT_VERIFIER_ID = dependency_0.SEGMENT_VERIFIER_ID;
const component = dependency_0.component;
const digest = dependency_0.digest;
const direct = dependency_0.direct;
const fillLaneRows = dependency_0.fillLaneRows;
const hashInt = dependency_0.hashInt;
const layerGeometry = dependency_0.layerGeometry;
const m31 = dependency_0.m31;
const materialize = dependency_0.materialize;
const merkle_root = dependency_0.merkle_root;
const rowsForLane = dependency_0.rowsForLane;
const std = dependency_0.std;

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
        var cursor: usize = 0;
        try fillLaneRows(rows, &cursor, reference.vm, SEGMENT_VERIFIER_ID, 1, 0);
        try fillLaneRows(rows, &cursor, reference.recursion, LEFT_RECURSION_VERIFIER_ID, 0, 1);
        try fillLaneRows(rows, &cursor, reference.recursion, RIGHT_RECURSION_VERIFIER_ID, 0, 1);
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

    pub fn validateAgainstAuthority(
        self: *const Preprocessed,
        reference: Reference,
    ) Error!void {
        try self.validateAgainst(reference);
        var cursor: usize = 0;
        try validateLaneRows(self.rows, &cursor, reference.vm, SEGMENT_VERIFIER_ID, 1, 0);
        try validateLaneRows(self.rows, &cursor, reference.recursion, LEFT_RECURSION_VERIFIER_ID, 0, 1);
        try validateLaneRows(self.rows, &cursor, reference.recursion, RIGHT_RECURSION_VERIFIER_ID, 0, 1);
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
        for (self.rows, 0..) |row, row_index| {
            const opening = selectOpening(row.verifier_id, opening_witness) orelse {
                writeMainRow(columns, row_index, zeroMainRow(row));
                continue;
            };
            if (row.first == 1) {
                state = [_]M31{M31.zero()} ** component.STATE_WIDTH;
                state[component.STATE_WIDTH - 1] = M31.fromCanonical(LEAF_TAG);
            }
            const result = materialize(row, opening, state);
            state = result.output;
            writeMainRow(columns, row_index, result);
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
    var main = zeroMainRow(preprocessing.rows[row_index]);
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
        } else if (index == row_index) main = zeroMainRow(row);
    }
    const selectors = opening_witness.proofKind().selectors();
    return main.values() ++ preprocessing.rows[row_index].values() ++ .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(LEAF_TAG),
    };
}

pub fn validateLaneRows(
    rows: []const Row,
    cursor: *usize,
    profile: LaneProfile,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    const count = try rowsForLane(profile);
    if (cursor.* > rows.len or count > rows.len - cursor.*)
        return error.AuthorityMismatch;
    var target: usize = cursor.*;
    var folded_bits: u32 = 0;
    for (profile.layers, 0..) |layer, layer_index| {
        const geometry = try layerGeometry(profile.lifting_log_size, folded_bits, layer);
        folded_bits += geometry.fold_step;
        const tree_id = try merkle_root.friTreeId(verifier_id, layer_index);
        const semantic_words = geometry.leaf_size * SECURE_WORD_COUNT;
        const hash_steps = std.math.divCeil(u32, semantic_words + 1, component.RATE) catch
            return error.ArithmeticOverflow;
        for (0..profile.query_count) |query| for (0..geometry.leaf_count) |packed_index| {
            for (0..hash_steps) |step| {
                var chunks = [_]Chunk{.{
                    .source_mask = 0,
                    .offset = 0,
                    .word = 0,
                    .constant = 0,
                }} ** component.RATE;
                for (&chunks, 0..) |*chunk, slot| {
                    const stream_index = step * component.RATE + slot;
                    if (stream_index < semantic_words) chunk.* = .{
                        .source_mask = 1,
                        .offset = @intCast(packed_index * geometry.leaf_size +
                            stream_index / SECURE_WORD_COUNT),
                        .word = @intCast(stream_index % SECURE_WORD_COUNT),
                        .constant = 0,
                    } else if (stream_index == semantic_words) chunk.constant = 1;
                }
                const last = step + 1 == hash_steps;
                const expected = Row{
                    .row_mask = 1,
                    .segment_mask = segment_mask,
                    .binary_mask = binary_mask,
                    .verifier_id = verifier_id,
                    .layer = @intCast(layer_index),
                    .query = @intCast(query),
                    .packed_index = @intCast(packed_index),
                    .leaf_count = geometry.leaf_count,
                    .local_root_mask = @intFromBool(geometry.leaf_count == 1),
                    .tree_id = tree_id,
                    .tree_height = layer.tree_height,
                    .step = @intCast(step),
                    .first = @intFromBool(step == 0),
                    .last = @intFromBool(last),
                    .chunks = chunks,
                    .merkle_endpoint_mask = @intFromBool(last and geometry.leaf_count != 1),
                    .local_root_endpoint_mask = @intFromBool(last and geometry.leaf_count == 1),
                    .position_shift = folded_bits,
                    .position_bits = profile.lifting_log_size - folded_bits,
                };
                if (!std.meta.eql(expected, rows[target])) return error.AuthorityMismatch;
                target += 1;
            }
        };
    }
    if (target - cursor.* != count) return error.AuthorityMismatch;
    cursor.* = target;
}

pub fn totalRows(vm: LaneProfile, recursion: LaneProfile) Error!usize {
    const vm_rows = try rowsForLane(vm);
    const recursion_rows = try rowsForLane(recursion);
    return std.math.add(usize, vm_rows, 2 * recursion_rows) catch
        return error.ArithmeticOverflow;
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
    if (opening.raw_queries.len != profile.query_count or
        opening.layers.len != profile.layers.len)
    {
        return error.InvalidWitness;
    }
    for (opening.raw_queries) |raw| if (raw.toU32() >= m31.Modulus)
        return error.InvalidWitness;
    for (profile.layers, opening.layers) |profile_layer, layer| {
        const expected = std.math.mul(
            usize,
            profile.query_count,
            @as(usize, profile_layer.width) * SECURE_WORD_COUNT,
        ) catch return error.ArithmeticOverflow;
        if (layer.width != profile_layer.width or layer.values.len != expected)
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
        row.segment_mask + row.binary_mask != 1 or row.verifier_id > RIGHT_RECURSION_VERIFIER_ID or
        row.layer >= merkle_root.TREE_INDEX_LIMIT or row.query >= m31.Modulus or
        row.packed_index >= row.leaf_count or row.leaf_count == 0 or
        !std.math.isPowerOfTwo(row.leaf_count) or row.local_root_mask > 1 or
        row.local_root_mask != @intFromBool(row.leaf_count == 1) or
        row.tree_height == 0 or row.tree_height > MAX_LOG_SIZE or row.step >= m31.Modulus or
        row.first > 1 or row.last > 1 or row.merkle_endpoint_mask > 1 or
        row.local_root_endpoint_mask > 1 or row.position_shift >= component.STATE_WIDTH * 2 or
        row.position_bits == 0 or row.position_bits > 31 or
        row.tree_id != try merkle_root.friTreeId(row.verifier_id, row.layer))
    {
        return error.InvalidProfile;
    }
    for (row.chunks) |chunk| if (chunk.source_mask > 1 or chunk.offset >= 16 or
        chunk.word >= SECURE_WORD_COUNT or chunk.constant >= m31.Modulus)
    {
        return error.InvalidProfile;
    };
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

pub fn writeMainRow(
    columns: *[MAIN_COLUMN_COUNT][]M31,
    logical_row: usize,
    row: MainRow,
) void {
    const values = row.values();
    for (columns, values) |column, value| column[logical_row] = value;
}

pub fn zeroMainRow(row: Row) MainRow {
    return .{
        .enabler = M31.zero(),
        .position = M31.zero(),
        .leaf_index = M31.fromCanonical(row.packed_index),
        .previous = [_]M31{M31.zero()} ** component.STATE_WIDTH,
        .chunks = [_]M31{M31.zero()} ** component.RATE,
        .output = [_]M31{M31.zero()} ** component.STATE_WIDTH,
    };
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
        switch (opening_witness) {
            .segment_leaf => |opening| try rejectOpeningAlias(destination, opening),
            .binary_node => |opening| {
                try rejectOpeningAlias(destination, opening.left);
                try rejectOpeningAlias(destination, opening.right);
            },
            .empty_leaf => {},
        }
    }
    return size;
}

pub fn rejectOpeningAlias(destination: AddressRange, opening: OpeningSet) direct.Error!void {
    const raw = try sliceRange(M31, opening.raw_queries);
    if (destination.overlaps(raw)) return error.AliasedInput;
    for (opening.layers) |layer| {
        const values = try sliceRange(M31, layer.values);
        if (destination.overlaps(values)) return error.AliasedInput;
    }
}

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
    hash.update(ROWS_DOMAIN);
    hashInt(&hash, u32, rows.len);
    for (rows) |row| {
        for (row.values()) |value| hashInt(&hash, u32, value.toU32());
        hashInt(&hash, u32, row.position_shift);
        hashInt(&hash, u32, row.position_bits);
    }
    return hash.finalResult();
}
