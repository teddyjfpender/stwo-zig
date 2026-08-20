//! Internal trace merkle witness authority shard; use trace_merkle_witness.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const digest = @import("../../air/lang/digest.zig");
pub const direct = @import("../../air/lang/direct_witness_executor.zig");
pub const types = @import("../../air/lang/types.zig");
pub const poseidon2 = @import("../../air/memory_commitment/poseidon2.zig");
pub const component = @import("trace_merkle.zig");
pub const merkle_root = @import("merkle_root_witness.zig");
pub const query_mapping = @import("query_mapping_witness.zig");
pub const query_mapping_air = @import("query_mapping.zig");
pub const schedule = @import("verifier_schedule.zig");
pub const proof_kind_mod = @import("proof_kind.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const LEAF_TAG: u32 = 1;
pub const TRACE_POSITION_KIND: u32 = 1;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = proof_kind_mod.ProofKind;
pub const SEGMENT_VERIFIER_ID = merkle_root.SEGMENT_VERIFIER_ID;
pub const LEFT_RECURSION_VERIFIER_ID = merkle_root.LEFT_RECURSION_VERIFIER_ID;
pub const RIGHT_RECURSION_VERIFIER_ID = merkle_root.RIGHT_RECURSION_VERIFIER_ID;

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN = "stwo-zig/typed-air/recursion-trace-merkle-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "94c596a482bbf3c5abc11dab234c448688f5cdbc66e18868c7b787fb154eb2e1";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion trace-Merkle witness-binding digest",
);
pub const REFERENCE_FORMAT_VERSION: u16 = 1;
pub const REFERENCE_DOMAIN = "stwo-zig/typed-air/recursion-trace-merkle-reference/v1\x00";

pub const Error = direct.Error || std.mem.Allocator.Error || schedule.Error ||
    query_mapping.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    ControlStepMismatch,
    InvalidProfile,
    InvalidWitness,
    InvalidWitnessBinding,
    LogSizeOutOfRange,
};

pub const MainSource = enum(u8) {
    enabler = 0,
    position = 1,
    previous_0 = 2,
    previous_1 = 3,
    previous_2 = 4,
    previous_3 = 5,
    previous_4 = 6,
    previous_5 = 7,
    previous_6 = 8,
    previous_7 = 9,
    previous_8 = 10,
    previous_9 = 11,
    previous_10 = 12,
    previous_11 = 13,
    previous_12 = 14,
    previous_13 = 15,
    previous_14 = 16,
    previous_15 = 17,
    chunk_0 = 18,
    chunk_1 = 19,
    chunk_2 = 20,
    chunk_3 = 21,
    chunk_4 = 22,
    chunk_5 = 23,
    chunk_6 = 24,
    chunk_7 = 25,
    output_0 = 26,
    output_1 = 27,
    output_2 = 28,
    output_3 = 29,
    output_4 = 30,
    output_5 = 31,
    output_6 = 32,
    output_7 = 33,
    output_8 = 34,
    output_9 = 35,
    output_10 = 36,
    output_11 = 37,
    output_12 = 38,
    output_13 = 39,
    output_14 = 40,
    output_15 = 41,
};

pub const PreprocessedSource = enum(u8) {
    row_mask = 0,
    segment_mask = 1,
    binary_mask = 2,
    verifier_id = 3,
    tree = 4,
    query = 5,
    tree_id = 6,
    tree_height = 7,
    step = 8,
    first = 9,
    last = 10,
    control_sequence = 11,
    control_tag = 12,
    control_arg_0 = 13,
    control_arg_1 = 14,
    control_arg_2 = 15,
    control_arg_3 = 16,
    chunk_0_source_mask = 17,
    chunk_0_column = 18,
    chunk_0_constant = 19,
    chunk_1_source_mask = 20,
    chunk_1_column = 21,
    chunk_1_constant = 22,
    chunk_2_source_mask = 23,
    chunk_2_column = 24,
    chunk_2_constant = 25,
    chunk_3_source_mask = 26,
    chunk_3_column = 27,
    chunk_3_constant = 28,
    chunk_4_source_mask = 29,
    chunk_4_column = 30,
    chunk_4_constant = 31,
    chunk_5_source_mask = 32,
    chunk_5_column = 33,
    chunk_5_constant = 34,
    chunk_6_source_mask = 35,
    chunk_6_column = 36,
    chunk_6_constant = 37,
    chunk_7_source_mask = 38,
    chunk_7_column = 39,
    chunk_7_constant = 40,
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

pub const TreeProfile = struct {
    height: u32,
    column_log_sizes: []const u32,
};

pub const LaneProfile = struct {
    query_count: u32,
    lifting_log_size: u32,
    trees: []const TreeProfile,
    fri_fold_widths: []const u32,

    pub fn queriedValueCount(self: LaneProfile) Error!usize {
        var columns: usize = 0;
        for (self.trees) |tree| columns = std.math.add(
            usize,
            columns,
            tree.column_log_sizes.len,
        ) catch return error.ArithmeticOverflow;
        return std.math.mul(usize, columns, self.query_count) catch
            return error.ArithmeticOverflow;
    }
};

pub const Reference = struct {
    vm: LaneProfile,
    recursion: LaneProfile,
    vm_control_start: u32,
    recursion_control_start: u32,
    vm_schedule_digest: [8]u32,
    recursion_schedule_digest: [8]u32,
    authority_digest: digest.Digest,

    pub fn seal(
        vm: LaneProfile,
        vm_plan: *const schedule.Plan,
        recursion: LaneProfile,
        recursion_plan: *const schedule.Plan,
    ) Error!Reference {
        try validateProfiles(vm, recursion);
        const vm_start = try validatePlan(vm, vm_plan, .vm);
        const recursion_start = try validatePlan(recursion, recursion_plan, .recursion);
        const result = Reference{
            .vm = vm,
            .recursion = recursion,
            .vm_control_start = vm_start,
            .recursion_control_start = recursion_start,
            .vm_schedule_digest = vm_plan.authority_digest,
            .recursion_schedule_digest = recursion_plan.authority_digest,
            .authority_digest = undefined,
        };
        var sealed = result;
        sealed.authority_digest = referenceDigest(sealed);
        return sealed;
    }

    pub fn validate(self: Reference) Error!void {
        try validateProfiles(self.vm, self.recursion);
        if (!std.mem.eql(u8, &self.authority_digest, &referenceDigest(self)))
            return error.AuthorityMismatch;
    }

    pub fn validateQueryMapping(self: Reference, mapping: query_mapping.Reference) Error!void {
        try self.validate();
        try mapping.validate();
        try laneMatchesMapping(self.vm, mapping.vm);
        try laneMatchesMapping(self.recursion, mapping.recursion);
    }
};

pub const Chunk = struct {
    source_mask: u32,
    column: u32,
    constant: u32,
    flat_index: usize,
};

pub const Row = struct {
    row_mask: u32,
    segment_mask: u32,
    binary_mask: u32,
    verifier_id: u32,
    tree: u32,
    query: u32,
    tree_id: u32,
    tree_height: u32,
    step: u32,
    first: u32,
    last: u32,
    control_sequence: u32,
    control_tag: u32,
    control_args: [4]u32,
    chunks: [component.RATE]Chunk,
    /// Verifier-owned route coefficients derived from row 21's exact profile.
    position_weights: [query_mapping_air.M31_BIT_COUNT]u32,

    pub fn values(self: Row) [PREPROCESSED_COLUMN_COUNT]M31 {
        var result: [PREPROCESSED_COLUMN_COUNT]M31 = undefined;
        const fixed = [_]u32{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
            self.verifier_id,
            self.tree,
            self.query,
            self.tree_id,
            self.tree_height,
            self.step,
            self.first,
            self.last,
            self.control_sequence,
            self.control_tag,
            self.control_args[0],
            self.control_args[1],
            self.control_args[2],
            self.control_args[3],
        };
        for (fixed, 0..) |value, index| result[index] = M31.fromCanonical(value);
        for (self.chunks, 0..) |chunk, index| {
            result[17 + 3 * index] = M31.fromCanonical(chunk.source_mask);
            result[18 + 3 * index] = M31.fromCanonical(chunk.column);
            result[19 + 3 * index] = M31.fromCanonical(chunk.constant);
        }
        return result;
    }
};

pub const OpeningSet = struct {
    queried_values: []const M31,
    raw_queries: []const M31,
};

pub const OpeningWitness = union(ProofKind) {
    segment_leaf: OpeningSet,
    binary_node: struct { left: OpeningSet, right: OpeningSet },
    empty_leaf: void,

    pub fn proofKind(self: OpeningWitness) ProofKind {
        return std.meta.activeTag(self);
    }
};

pub const MainRow = struct {
    enabler: M31,
    position: M31,
    previous: [component.STATE_WIDTH]M31,
    chunks: [component.RATE]M31,
    output: [component.STATE_WIDTH]M31,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{ self.enabler, self.position } ++ self.previous ++ self.chunks ++ self.output;
    }
};

pub fn validateLaneRows(
    rows: []const Row,
    cursor: *usize,
    profile: LaneProfile,
    control_start: u32,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
    order_storage: []u32,
) Error!void {
    const count = try rowsForLane(profile);
    if (cursor.* > rows.len or count > rows.len - cursor.*)
        return error.AuthorityMismatch;
    const expected = try selfContainedLaneRows(
        rows[cursor.*..][0..count],
        profile,
        control_start,
        verifier_id,
        segment_mask,
        binary_mask,
        order_storage,
    );
    if (expected != count) return error.AuthorityMismatch;
    cursor.* += count;
}

pub fn selfContainedLaneRows(
    actual: []const Row,
    profile: LaneProfile,
    control_start: u32,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
    order_storage: []u32,
) Error!usize {
    var index: usize = 0;
    var tree_offset: usize = 0;
    for (profile.trees, 0..) |tree, tree_index| {
        const order = order_storage[0..tree.column_log_sizes.len];
        for (order, 0..) |*value, column| value.* = @intCast(column);
        std.mem.sortUnstable(u32, order, tree.column_log_sizes, struct {
            fn lessThan(log_sizes: []const u32, lhs: u32, rhs: u32) bool {
                return log_sizes[lhs] < log_sizes[rhs] or
                    (log_sizes[lhs] == log_sizes[rhs] and lhs < rhs);
            }
        }.lessThan);
        const step_count = std.math.divCeil(
            usize,
            tree.column_log_sizes.len + 1,
            component.RATE,
        ) catch return error.ArithmeticOverflow;
        for (0..profile.query_count) |query| for (0..step_count) |step| {
            if (index >= actual.len) return error.AuthorityMismatch;
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
            const expected = Row{
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
                .control_sequence = control_start + @as(u32, @intCast(
                    tree_index * profile.query_count + query,
                )),
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
            if (!std.meta.eql(actual[index], expected)) return error.AuthorityMismatch;
            index += 1;
        };
        tree_offset += tree.column_log_sizes.len;
    }
    return index;
}

pub fn materialize(row: Row, opening: OpeningSet, previous: [component.STATE_WIDTH]M31) MainRow {
    var chunks: [component.RATE]M31 = undefined;
    for (&chunks, row.chunks) |*value, chunk| value.* = if (chunk.source_mask == 1)
        opening.queried_values[chunk.flat_index]
    else
        M31.fromCanonical(chunk.constant);
    var output = previous;
    for (chunks, 0..) |chunk, index| output[index] = output[index].add(chunk);
    poseidon2.permute(&output);
    const position = if (row.last == 1) blk: {
        const raw = opening.raw_queries[row.query];
        break :blk query_mapping.applyWeights(raw, row.position_weights) catch unreachable;
    } else M31.zero();
    return .{
        .enabler = M31.one(),
        .position = position,
        .previous = previous,
        .chunks = chunks,
        .output = output,
    };
}

pub fn writeMainRow(columns: *[MAIN_COLUMN_COUNT][]M31, row: usize, value: MainRow) void {
    columns[0][row] = value.enabler;
    columns[1][row] = value.position;
    inline for (0..component.STATE_WIDTH) |index| columns[2 + index][row] = value.previous[index];
    inline for (0..component.RATE) |index| columns[2 + component.STATE_WIDTH + index][row] = value.chunks[index];
    inline for (0..component.STATE_WIDTH) |index| columns[2 + component.STATE_WIDTH + component.RATE + index][row] = value.output[index];
}

pub fn validateProfiles(vm: LaneProfile, recursion: LaneProfile) Error!void {
    for ([_]LaneProfile{ vm, recursion }) |profile| {
        if (profile.query_count == 0 or profile.query_count >= m31.Modulus or
            profile.lifting_log_size < MIN_LOG_SIZE or profile.lifting_log_size > MAX_LOG_SIZE or
            profile.trees.len == 0 or profile.trees.len >= merkle_root.TREE_INDEX_LIMIT or
            profile.fri_fold_widths.len == 0)
        {
            return error.InvalidProfile;
        }
        for (profile.trees) |tree| {
            if (tree.height == 0 or tree.height > MAX_LOG_SIZE or
                tree.column_log_sizes.len == 0 or tree.column_log_sizes.len >= m31.Modulus)
            {
                return error.InvalidProfile;
            }
            for (tree.column_log_sizes) |log_size| if (log_size > tree.height)
                return error.InvalidProfile;
        }
        _ = try profile.queriedValueCount();
    }
    _ = try totalRows(vm, recursion);
}

pub fn validatePlan(profile: LaneProfile, plan: *const schedule.Plan, expected: schedule.Schema) Error!u32 {
    try plan.validate();
    if (plan.schema != expected) return error.ControlStepMismatch;
    var first: ?usize = null;
    for (profile.trees, 0..) |tree, tree_index| for (0..profile.query_count) |query| {
        const expected_step = schedule.VerifierStep{ .verify_trace_merkle_path = .{
            .tree = @intCast(tree_index),
            .query = @intCast(query),
            .depth = tree.height,
        } };
        var match: ?usize = null;
        for (plan.steps, 0..) |step, sequence| if (std.meta.eql(step, expected_step)) {
            if (match != null) return error.ControlStepMismatch;
            match = sequence;
        };
        const sequence = match orelse return error.ControlStepMismatch;
        if (first == null) first = sequence;
        const offset = tree_index * profile.query_count + query;
        if (sequence != first.? + offset) return error.ControlStepMismatch;
    };
    return @intCast(first orelse return error.ControlStepMismatch);
}

pub fn laneMatchesMapping(profile: LaneProfile, mapping: query_mapping.LaneProfile) Error!void {
    if (profile.query_count != mapping.query_count or
        profile.lifting_log_size != mapping.lifting_log_size or
        profile.trees.len != mapping.tree_heights.len or
        !std.mem.eql(u32, profile.fri_fold_widths, mapping.fri_fold_widths))
    {
        return error.AuthorityMismatch;
    }
    for (profile.trees, mapping.tree_heights) |tree, height| if (tree.height != height)
        return error.AuthorityMismatch;
}

pub fn rowsForLane(profile: LaneProfile) Error!usize {
    var result: usize = 0;
    for (profile.trees) |tree| {
        const steps = std.math.divCeil(usize, tree.column_log_sizes.len + 1, component.RATE) catch
            return error.ArithmeticOverflow;
        result = std.math.add(usize, result, std.math.mul(usize, steps, profile.query_count) catch
            return error.ArithmeticOverflow) catch return error.ArithmeticOverflow;
    }
    return result;
}

pub fn totalRows(vm: LaneProfile, recursion: LaneProfile) Error!usize {
    const recursive = std.math.mul(usize, try rowsForLane(recursion), 2) catch
        return error.ArithmeticOverflow;
    return std.math.add(usize, try rowsForLane(vm), recursive) catch
        return error.ArithmeticOverflow;
}

pub fn maximumTreeColumns(profile: LaneProfile) usize {
    var result: usize = 0;
    for (profile.trees) |tree| result = @max(result, tree.column_log_sizes.len);
    return result;
}

pub fn referenceDigest(reference: Reference) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(REFERENCE_DOMAIN);
    hashInt(&hash, u16, REFERENCE_FORMAT_VERSION);
    hashLane(&hash, reference.vm);
    hashLane(&hash, reference.recursion);
    hashInt(&hash, u32, reference.vm_control_start);
    hashInt(&hash, u32, reference.recursion_control_start);
    for (reference.vm_schedule_digest) |word| hashInt(&hash, u32, word);
    for (reference.recursion_schedule_digest) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

pub fn hashLane(hash: anytype, profile: LaneProfile) void {
    hashInt(hash, u32, profile.query_count);
    hashInt(hash, u32, profile.lifting_log_size);
    hashInt(hash, u32, profile.trees.len);
    for (profile.trees) |tree| {
        hashInt(hash, u32, tree.height);
        hashInt(hash, u32, tree.column_log_sizes.len);
        for (tree.column_log_sizes) |log_size| hashInt(hash, u32, log_size);
    }
    hashInt(hash, u32, profile.fri_fold_widths.len);
    for (profile.fri_fold_widths) |width| hashInt(hash, u32, width);
}

pub fn hashSlot(hash: anytype, slot: anytype) void {
    hashInt(hash, u8, slot.column);
    hashInt(hash, u32, @intFromEnum(slot.value));
    hashInt(hash, u8, @intFromEnum(slot.source));
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
