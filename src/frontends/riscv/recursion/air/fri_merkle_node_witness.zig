//! Authenticated FRI local-subtree schedule and allocation-free row-26 writer.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const digest = @import("../../air/lang/digest.zig");
const direct = @import("../../air/lang/direct_witness_executor.zig");
const types = @import("../../air/lang/types.zig");
const poseidon2 = @import("../../air/memory_commitment/poseidon2.zig");
const component = @import("fri_merkle_node.zig");
pub const leaf = @import("fri_merkle_leaf_witness.zig");
const merkle_root = @import("merkle_root_witness.zig");

pub const MIN_LOG_SIZE = leaf.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = leaf.MAX_LOG_SIZE;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const DIGEST_WORD_COUNT = component.DIGEST_WORD_COUNT;
pub const STATE_WIDTH = component.STATE_WIDTH;
pub const MAX_LEAF_COUNT: usize = 4;
pub const Reference = leaf.Reference;
pub const OpeningWitness = leaf.OpeningWitness;
pub const OpeningSet = leaf.OpeningSet;
pub const ProofKind = leaf.ProofKind;
pub const SEGMENT_VERIFIER_ID = leaf.SEGMENT_VERIFIER_ID;
pub const LEFT_RECURSION_VERIFIER_ID = leaf.LEFT_RECURSION_VERIFIER_ID;
pub const RIGHT_RECURSION_VERIFIER_ID = leaf.RIGHT_RECURSION_VERIFIER_ID;

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN = "stwo-zig/typed-air/recursion-fri-merkle-node-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "92572aeb4d83b2cefcb9864789bd5ac7246d12f6480c0872aa74a28cddab52c9";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion FRI-Merkle-node witness-binding digest",
);
pub const ROWS_DOMAIN = "stwo-zig/typed-air/recursion-fri-merkle-node-rows/v1\x00";

pub const Error = direct.Error || std.mem.Allocator.Error || leaf.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    InvalidProfile,
    InvalidWitness,
    InvalidWitnessBinding,
    LogSizeOutOfRange,
};

pub const MainSource = enum(u8) {
    enabler = 0,
    index = 1,
    left_0 = 2,
    left_1 = 3,
    left_2 = 4,
    left_3 = 5,
    left_4 = 6,
    left_5 = 7,
    left_6 = 8,
    left_7 = 9,
    right_0 = 10,
    right_1 = 11,
    right_2 = 12,
    right_3 = 13,
    right_4 = 14,
    right_5 = 15,
    right_6 = 16,
    right_7 = 17,
    parent_0 = 18,
    parent_1 = 19,
    parent_2 = 20,
    parent_3 = 21,
    parent_4 = 22,
    parent_5 = 23,
    parent_6 = 24,
    parent_7 = 25,
    output_8 = 26,
    output_9 = 27,
    output_10 = 28,
    output_11 = 29,
    output_12 = 30,
    output_13 = 31,
    output_14 = 32,
    output_15 = 33,
};

pub const PreprocessedSource = enum(u8) {
    row_mask = 0,
    segment_mask = 1,
    binary_mask = 2,
    tree_id = 3,
    depth = 4,
    local_root_mask = 5,
};

pub fn Slot(comptime SourceType: type) type {
    return struct { column: u8, value: types.ValueId, source: SourceType };
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
        opening_witness: OpeningWitness,
    ) Error!void {
        return preprocessing.generateMainInto(reference, columns, opening_witness, self);
    }
};

pub const Row = struct {
    row_mask: u32,
    segment_mask: u32,
    binary_mask: u32,
    tree_id: u32,
    depth: u32,
    local_root_mask: u32,
    verifier_id: u32,
    layer: u32,
    query: u32,
    relative_index: u32,
    local_depth: u32,
    position_shift: u32,
    position_bits: u32,

    pub fn values(self: Row) [PREPROCESSED_COLUMN_COUNT]M31 {
        return .{
            M31.fromCanonical(self.row_mask),
            M31.fromCanonical(self.segment_mask),
            M31.fromCanonical(self.binary_mask),
            M31.fromCanonical(self.tree_id),
            M31.fromCanonical(self.depth),
            M31.fromCanonical(self.local_root_mask),
        };
    }
};

pub const MainRow = struct {
    enabler: M31,
    index: M31,
    left: [DIGEST_WORD_COUNT]M31,
    right: [DIGEST_WORD_COUNT]M31,
    parent: [DIGEST_WORD_COUNT]M31,
    output_tail: [DIGEST_WORD_COUNT]M31,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{ self.enabler, self.index } ++ self.left ++ self.right ++
            self.parent ++ self.output_tail;
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
        const row_count = try totalRows(reference);
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
        reference: Reference,
    ) Error!void {
        try self.validateAgainst(reference);
        var cursor: usize = 0;
        try validateLaneRows(self.rows, &cursor, reference.vm, SEGMENT_VERIFIER_ID, 1, 0);
        try validateLaneRows(
            self.rows,
            &cursor,
            reference.recursion,
            LEFT_RECURSION_VERIFIER_ID,
            0,
            1,
        );
        try validateLaneRows(
            self.rows,
            &cursor,
            reference.recursion,
            RIGHT_RECURSION_VERIFIER_ID,
            0,
            1,
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
        _ = try materializeAll(reference, self, opening_witness, columns, null);
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
    const main = try materializeAll(reference, preprocessing, opening_witness, null, row_index);
    const selectors = opening_witness.proofKind().selectors();
    return main.values() ++ preprocessing.rows[row_index].values() ++ .{
        selectors[0],
        selectors[1],
    };
}

fn materializeAll(
    reference: Reference,
    preprocessing: *const Preprocessed,
    opening_witness: OpeningWitness,
    columns: ?*[MAIN_COLUMN_COUNT][]M31,
    target: ?usize,
) Error!MainRow {
    var result = zeroMainRow();
    var cursor: usize = 0;
    try materializeLane(
        reference.vm,
        selectOpening(SEGMENT_VERIFIER_ID, opening_witness),
        preprocessing.rows,
        &cursor,
        columns,
        target,
        &result,
    );
    try materializeLane(
        reference.recursion,
        selectOpening(LEFT_RECURSION_VERIFIER_ID, opening_witness),
        preprocessing.rows,
        &cursor,
        columns,
        target,
        &result,
    );
    try materializeLane(
        reference.recursion,
        selectOpening(RIGHT_RECURSION_VERIFIER_ID, opening_witness),
        preprocessing.rows,
        &cursor,
        columns,
        target,
        &result,
    );
    if (cursor != preprocessing.rows.len) return error.AuthorityMismatch;
    return result;
}

fn materializeLane(
    profile: leaf.LaneProfile,
    opening: ?OpeningSet,
    rows: []const Row,
    cursor: *usize,
    columns: ?*[MAIN_COLUMN_COUNT][]M31,
    target: ?usize,
    target_result: *MainRow,
) Error!void {
    var folded_bits: u32 = 0;
    for (profile.layers, 0..) |layer_profile, layer_index| {
        const geometry = try leaf.layerGeometry(profile.lifting_log_size, folded_bits, layer_profile);
        folded_bits += geometry.fold_step;
        const row_count = geometry.leaf_count - 1;
        for (0..profile.query_count) |query| {
            if (opening == null) {
                cursor.* += row_count;
                continue;
            }
            const active_opening = opening.?;
            var current = [_][DIGEST_WORD_COUNT]M31{
                [_]M31{M31.zero()} ** DIGEST_WORD_COUNT,
            } ** MAX_LEAF_COUNT;
            for (0..geometry.leaf_count) |packed_index| current[packed_index] = hashPackedLeaf(
                active_opening,
                @intCast(layer_index),
                @intCast(query),
                geometry,
                @intCast(packed_index),
            );

            var local_depth = geometry.subtree_height;
            while (local_depth > 0) {
                local_depth -= 1;
                const count = @as(u32, 1) << @intCast(local_depth);
                var next = [_][DIGEST_WORD_COUNT]M31{
                    [_]M31{M31.zero()} ** DIGEST_WORD_COUNT,
                } ** MAX_LEAF_COUNT;
                for (0..count) |relative_index| {
                    if (cursor.* >= rows.len) return error.AuthorityMismatch;
                    var state = current[2 * relative_index] ++ current[2 * relative_index + 1];
                    poseidon2.permute(&state);
                    const route = routePosition(
                        active_opening.raw_queries[query],
                        folded_bits,
                        profile.lifting_log_size - folded_bits,
                    );
                    const index = (@as(u64, route.toU32()) << @intCast(local_depth)) +
                        relative_index;
                    if (index >= m31.Modulus) return error.InvalidWitness;
                    const main = MainRow{
                        .enabler = M31.one(),
                        .index = M31.fromCanonical(@intCast(index)),
                        .left = current[2 * relative_index],
                        .right = current[2 * relative_index + 1],
                        .parent = state[0..DIGEST_WORD_COUNT].*,
                        .output_tail = state[DIGEST_WORD_COUNT..STATE_WIDTH].*,
                    };
                    if (columns) |destination| writeMainRow(destination, cursor.*, main);
                    if (target != null and target.? == cursor.*) target_result.* = main;
                    next[relative_index] = main.parent;
                    cursor.* += 1;
                }
                current = next;
            }
        }
    }
}

fn hashPackedLeaf(
    opening: OpeningSet,
    layer_index: u32,
    query: u32,
    geometry: leaf.Geometry,
    packed_index: u32,
) [DIGEST_WORD_COUNT]M31 {
    var state = [_]M31{M31.zero()} ** STATE_WIDTH;
    state[STATE_WIDTH - 1] = M31.fromCanonical(leaf.LEAF_TAG);
    const semantic_words = geometry.leaf_size * leaf.SECURE_WORD_COUNT;
    const hash_steps = std.math.divCeil(u32, semantic_words + 1, DIGEST_WORD_COUNT) catch unreachable;
    const layer = opening.layers[layer_index];
    for (0..hash_steps) |step| {
        for (0..DIGEST_WORD_COUNT) |slot| {
            const stream_index = step * DIGEST_WORD_COUNT + slot;
            const chunk = if (stream_index < semantic_words) layer.values[
                (@as(usize, query) * layer.width + packed_index * geometry.leaf_size +
                    stream_index / leaf.SECURE_WORD_COUNT) * leaf.SECURE_WORD_COUNT +
                    stream_index % leaf.SECURE_WORD_COUNT
            ] else if (stream_index == semantic_words) M31.one() else M31.zero();
            state[slot] = state[slot].add(chunk);
        }
        poseidon2.permute(&state);
    }
    return state[0..DIGEST_WORD_COUNT].*;
}

fn fillLaneRows(
    rows: []Row,
    cursor: *usize,
    profile: leaf.LaneProfile,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    var folded_bits: u32 = 0;
    for (profile.layers, 0..) |layer, layer_index| {
        const geometry = try leaf.layerGeometry(profile.lifting_log_size, folded_bits, layer);
        folded_bits += geometry.fold_step;
        const tree_id = try merkle_root.friTreeId(verifier_id, layer_index);
        const path_depth = layer.tree_height - geometry.subtree_height;
        for (0..profile.query_count) |query| {
            var local_depth = geometry.subtree_height;
            while (local_depth > 0) {
                local_depth -= 1;
                for (0..@as(u32, 1) << @intCast(local_depth)) |relative_index| {
                    rows[cursor.*] = .{
                        .row_mask = 1,
                        .segment_mask = segment_mask,
                        .binary_mask = binary_mask,
                        .tree_id = tree_id,
                        .depth = path_depth + local_depth,
                        .local_root_mask = @intFromBool(local_depth == 0),
                        .verifier_id = verifier_id,
                        .layer = @intCast(layer_index),
                        .query = @intCast(query),
                        .relative_index = @intCast(relative_index),
                        .local_depth = local_depth,
                        .position_shift = folded_bits,
                        .position_bits = profile.lifting_log_size - folded_bits,
                    };
                    cursor.* += 1;
                }
            }
        }
    }
}

fn validateLaneRows(
    rows: []const Row,
    cursor: *usize,
    profile: leaf.LaneProfile,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    const count = try rowsForLane(profile);
    if (cursor.* > rows.len or count > rows.len - cursor.*) return error.AuthorityMismatch;
    var target = cursor.*;
    var folded_bits: u32 = 0;
    for (profile.layers, 0..) |layer, layer_index| {
        const geometry = try leaf.layerGeometry(profile.lifting_log_size, folded_bits, layer);
        folded_bits += geometry.fold_step;
        const tree_id = try merkle_root.friTreeId(verifier_id, layer_index);
        const path_depth = layer.tree_height - geometry.subtree_height;
        for (0..profile.query_count) |query| {
            var local_depth = geometry.subtree_height;
            while (local_depth > 0) {
                local_depth -= 1;
                for (0..@as(u32, 1) << @intCast(local_depth)) |relative_index| {
                    const expected = Row{
                        .row_mask = 1,
                        .segment_mask = segment_mask,
                        .binary_mask = binary_mask,
                        .tree_id = tree_id,
                        .depth = path_depth + local_depth,
                        .local_root_mask = @intFromBool(local_depth == 0),
                        .verifier_id = verifier_id,
                        .layer = @intCast(layer_index),
                        .query = @intCast(query),
                        .relative_index = @intCast(relative_index),
                        .local_depth = local_depth,
                        .position_shift = folded_bits,
                        .position_bits = profile.lifting_log_size - folded_bits,
                    };
                    if (!std.meta.eql(expected, rows[target])) return error.AuthorityMismatch;
                    target += 1;
                }
            }
        }
    }
    if (target - cursor.* != count) return error.AuthorityMismatch;
    cursor.* = target;
}

fn rowsForLane(profile: leaf.LaneProfile) Error!usize {
    var count: usize = 0;
    var folded: u32 = 0;
    for (profile.layers) |layer| {
        const geometry = try leaf.layerGeometry(profile.lifting_log_size, folded, layer);
        folded += geometry.fold_step;
        const layer_rows = std.math.mul(
            usize,
            profile.query_count,
            geometry.leaf_count - 1,
        ) catch return error.ArithmeticOverflow;
        count = std.math.add(usize, count, layer_rows) catch return error.ArithmeticOverflow;
    }
    return count;
}

fn totalRows(reference: Reference) Error!usize {
    const vm = try rowsForLane(reference.vm);
    const recursion = try rowsForLane(reference.recursion);
    return std.math.add(usize, vm, 2 * recursion) catch return error.ArithmeticOverflow;
}

fn validateWitness(reference: Reference, witness: OpeningWitness) Error!void {
    // The leaf authority validates exact lane, query, layer, width, and value
    // geometry. Reuse it by asking for one logical row only when rows exist is
    // undesirable; preserve its exact checks locally without allocations.
    switch (witness) {
        .segment_leaf => |opening| try validateOpening(reference.vm, opening),
        .binary_node => |opening| {
            try validateOpening(reference.recursion, opening.left);
            try validateOpening(reference.recursion, opening.right);
        },
        .empty_leaf => {},
    }
}

fn validateOpening(profile: leaf.LaneProfile, opening: OpeningSet) Error!void {
    if (opening.raw_queries.len != profile.query_count or opening.layers.len != profile.layers.len)
        return error.InvalidWitness;
    for (profile.layers, opening.layers) |profile_layer, layer| {
        const expected = std.math.mul(
            usize,
            profile.query_count,
            @as(usize, profile_layer.width) * leaf.SECURE_WORD_COUNT,
        ) catch return error.ArithmeticOverflow;
        if (layer.width != profile_layer.width or layer.values.len != expected)
            return error.InvalidWitness;
    }
}

fn selectOpening(verifier_id: u32, witness: OpeningWitness) ?OpeningSet {
    return switch (witness) {
        .segment_leaf => |opening| if (verifier_id == SEGMENT_VERIFIER_ID) opening else null,
        .binary_node => |opening| switch (verifier_id) {
            LEFT_RECURSION_VERIFIER_ID => opening.left,
            RIGHT_RECURSION_VERIFIER_ID => opening.right,
            else => null,
        },
        .empty_leaf => null,
    };
}

fn routePosition(raw: M31, shift: u32, bits: u32) M31 {
    const mask: u32 = if (bits == 31) std.math.maxInt(u31) else (@as(u32, 1) << @intCast(bits)) - 1;
    return M31.fromCanonical((raw.toU32() >> @intCast(shift)) & mask);
}

fn validateRow(row: Row) Error!void {
    if (row.row_mask != 1 or row.segment_mask > 1 or row.binary_mask > 1 or
        row.segment_mask + row.binary_mask != 1 or
        row.verifier_id > RIGHT_RECURSION_VERIFIER_ID or
        row.layer >= merkle_root.TREE_INDEX_LIMIT or row.query >= m31.Modulus or
        row.depth == 0 or row.depth > MAX_LOG_SIZE or row.local_root_mask > 1 or
        row.local_root_mask != @intFromBool(row.local_depth == 0) or
        row.relative_index >= (@as(u32, 1) << @intCast(row.local_depth)) or
        row.position_bits == 0 or row.position_bits > 31 or
        row.tree_id != try merkle_root.friTreeId(row.verifier_id, row.layer))
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

fn writeMainRow(columns: *[MAIN_COLUMN_COUNT][]M31, logical_row: usize, row: MainRow) void {
    const values = row.values();
    for (columns, values) |column, value| column[logical_row] = value;
}

fn zeroMainRow() MainRow {
    return .{
        .enabler = M31.zero(),
        .index = M31.zero(),
        .left = [_]M31{M31.zero()} ** DIGEST_WORD_COUNT,
        .right = [_]M31{M31.zero()} ** DIGEST_WORD_COUNT,
        .parent = [_]M31{M31.zero()} ** DIGEST_WORD_COUNT,
        .output_tail = [_]M31{M31.zero()} ** DIGEST_WORD_COUNT,
    };
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
    witness: OpeningWitness,
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
        switch (witness) {
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

fn rejectOpeningAlias(destination: AddressRange, opening: OpeningSet) direct.Error!void {
    if (destination.overlaps(try sliceRange(M31, opening.raw_queries)))
        return error.AliasedInput;
    for (opening.layers) |layer| if (destination.overlaps(try sliceRange(M31, layer.values)))
        return error.AliasedInput;
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

fn traceLogSize(row_count: usize) Error!u32 {
    const result: u32 = @max(
        MIN_LOG_SIZE,
        @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(row_count, 1)))),
    );
    if (result > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
    return result;
}

fn rowsDigest(rows: []const Row) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ROWS_DOMAIN);
    hashInt(&hash, u32, rows.len);
    for (rows) |row| {
        for (row.values()) |value| hashInt(&hash, u32, value.toU32());
        hashInt(&hash, u32, row.verifier_id);
        hashInt(&hash, u32, row.layer);
        hashInt(&hash, u32, row.query);
        hashInt(&hash, u32, row.relative_index);
        hashInt(&hash, u32, row.local_depth);
        hashInt(&hash, u32, row.position_shift);
        hashInt(&hash, u32, row.position_bits);
    }
    return hash.finalResult();
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
