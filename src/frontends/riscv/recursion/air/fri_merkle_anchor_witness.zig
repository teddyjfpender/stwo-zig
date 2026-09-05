//! Verifier-owned FRI anchor schedule and allocation-free row-27 writer.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const digest = @import("../../air/lang/digest.zig");
const direct = @import("../../air/lang/direct_witness_executor.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("fri_merkle_anchor.zig");
pub const leaf = @import("fri_merkle_leaf_witness.zig");
const node = @import("fri_merkle_node_witness.zig");
const merkle_root = @import("merkle_root_witness.zig");
const query_mapping = @import("query_mapping_witness.zig");
const schedule = @import("verifier_schedule.zig");

pub const MIN_LOG_SIZE = leaf.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = leaf.MAX_LOG_SIZE;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const DIGEST_WORD_COUNT = component.DIGEST_WORD_COUNT;
pub const Reference = leaf.Reference;
pub const OpeningWitness = leaf.OpeningWitness;
pub const OpeningSet = leaf.OpeningSet;
pub const ProofKind = leaf.ProofKind;
pub const SEGMENT_VERIFIER_ID = leaf.SEGMENT_VERIFIER_ID;
pub const LEFT_RECURSION_VERIFIER_ID = leaf.LEFT_RECURSION_VERIFIER_ID;
pub const RIGHT_RECURSION_VERIFIER_ID = leaf.RIGHT_RECURSION_VERIFIER_ID;
pub const FRI_MERKLE_KIND: u32 = @intFromEnum(query_mapping.QueryPositionKind.fri_merkle);

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN = "stwo-zig/typed-air/recursion-fri-merkle-anchor-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "f6695fbee0b285643a87396d85ec7c9b5f67f185a4aa5dbe995663b406bb1f8d";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion FRI-Merkle-anchor witness-binding digest",
);
pub const ROWS_DOMAIN = "stwo-zig/typed-air/recursion-fri-merkle-anchor-rows/v1\x00";

pub const Error = direct.Error || std.mem.Allocator.Error || leaf.Error || schedule.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    InvalidProfile,
    InvalidWitness,
    InvalidWitnessBinding,
    LogSizeOutOfRange,
    ScheduleAuthorityMismatch,
};

pub const MainSource = enum(u8) {
    enabler = 0,
    position = 1,
    digest_0 = 2,
    digest_1 = 3,
    digest_2 = 4,
    digest_3 = 5,
    digest_4 = 6,
    digest_5 = 7,
    digest_6 = 8,
    digest_7 = 9,
};

pub const PreprocessedSource = enum(u8) {
    row_mask = 0,
    segment_mask = 1,
    binary_mask = 2,
    verifier_id = 3,
    layer = 4,
    query = 5,
    tree_id = 6,
    path_depth = 7,
    leaf_count = 8,
    control_sequence = 9,
    control_tag = 10,
    control_arg_0 = 11,
    control_arg_1 = 12,
    control_arg_2 = 13,
    control_arg_3 = 14,
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
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    ) Error!void {
        return preprocessing.generatePreprocessedInto(
            reference,
            vm_plan,
            recursion_plan,
            columns,
            self,
        );
    }

    pub fn generateMainInto(
        self: *const Executor,
        preprocessing: *const Preprocessed,
        reference: Reference,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        opening_witness: OpeningWitness,
    ) Error!void {
        return preprocessing.generateMainInto(
            reference,
            vm_plan,
            recursion_plan,
            columns,
            opening_witness,
            self,
        );
    }
};

pub const Row = struct {
    row_mask: u32,
    segment_mask: u32,
    binary_mask: u32,
    verifier_id: u32,
    layer: u32,
    query: u32,
    tree_id: u32,
    path_depth: u32,
    leaf_count: u32,
    control_sequence: u32,
    control_tag: u32,
    control_args: [4]u32,
    position_shift: u32,
    position_bits: u32,

    pub fn values(self: Row) [PREPROCESSED_COLUMN_COUNT]M31 {
        return .{
            M31.fromCanonical(self.row_mask),
            M31.fromCanonical(self.segment_mask),
            M31.fromCanonical(self.binary_mask),
            M31.fromCanonical(self.verifier_id),
            M31.fromCanonical(self.layer),
            M31.fromCanonical(self.query),
            M31.fromCanonical(self.tree_id),
            M31.fromCanonical(self.path_depth),
            M31.fromCanonical(self.leaf_count),
            M31.fromCanonical(self.control_sequence),
            M31.fromCanonical(self.control_tag),
            M31.fromCanonical(self.control_args[0]),
            M31.fromCanonical(self.control_args[1]),
            M31.fromCanonical(self.control_args[2]),
            M31.fromCanonical(self.control_args[3]),
        };
    }
};

pub const MainRow = struct {
    enabler: M31,
    position: M31,
    digest_words: [DIGEST_WORD_COUNT]M31,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{ self.enabler, self.position } ++ self.digest_words;
    }
};

pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []Row,
    reference_digest: digest.Digest,
    vm_schedule_digest: [8]u32,
    recursion_schedule_digest: [8]u32,
    authority_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        reference: Reference,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
    ) Error!Preprocessed {
        try validateAuthorities(reference, vm_plan, recursion_plan);
        const row_count = try totalRows(reference);
        const log_size = try traceLogSize(row_count);
        const rows = try allocator.alloc(Row, row_count);
        errdefer allocator.free(rows);
        var cursor: usize = 0;
        try fillLaneRows(
            rows,
            &cursor,
            reference.vm,
            vm_plan,
            SEGMENT_VERIFIER_ID,
            1,
            0,
        );
        try fillLaneRows(
            rows,
            &cursor,
            reference.recursion,
            recursion_plan,
            LEFT_RECURSION_VERIFIER_ID,
            0,
            1,
        );
        try fillLaneRows(
            rows,
            &cursor,
            reference.recursion,
            recursion_plan,
            RIGHT_RECURSION_VERIFIER_ID,
            0,
            1,
        );
        std.debug.assert(cursor == rows.len);
        return .{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .reference_digest = reference.authority_digest,
            .vm_schedule_digest = vm_plan.authority_digest,
            .recursion_schedule_digest = recursion_plan.authority_digest,
            .authority_digest = rowsDigest(rows),
        };
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const Preprocessed,
        reference: Reference,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
    ) Error!void {
        try validateAuthorities(reference, vm_plan, recursion_plan);
        if (self.rows.len != try totalRows(reference) or
            self.log_size != try traceLogSize(self.rows.len) or
            !std.mem.eql(u8, &self.reference_digest, &reference.authority_digest) or
            !std.meta.eql(self.vm_schedule_digest, vm_plan.authority_digest) or
            !std.meta.eql(self.recursion_schedule_digest, recursion_plan.authority_digest) or
            !std.mem.eql(u8, &self.authority_digest, &rowsDigest(self.rows)))
        {
            return error.AuthorityMismatch;
        }
    }

    pub fn validateAgainstAuthority(
        self: *const Preprocessed,
        reference: Reference,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
    ) Error!void {
        try self.validateAgainst(reference, vm_plan, recursion_plan);
        var cursor: usize = 0;
        try validateLaneRows(
            self.rows,
            &cursor,
            reference.vm,
            vm_plan,
            SEGMENT_VERIFIER_ID,
            1,
            0,
        );
        try validateLaneRows(
            self.rows,
            &cursor,
            reference.recursion,
            recursion_plan,
            LEFT_RECURSION_VERIFIER_ID,
            0,
            1,
        );
        try validateLaneRows(
            self.rows,
            &cursor,
            reference.recursion,
            recursion_plan,
            RIGHT_RECURSION_VERIFIER_ID,
            0,
            1,
        );
        if (cursor != self.rows.len) return error.AuthorityMismatch;
    }

    fn generatePreprocessedInto(
        self: *const Preprocessed,
        reference: Reference,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
        executor: *const Executor,
    ) Error!void {
        try self.validateAgainst(reference, vm_plan, recursion_plan);
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
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        opening_witness: OpeningWitness,
        executor: *const Executor,
    ) Error!void {
        try self.validateAgainst(reference, vm_plan, recursion_plan);
        try validateWitness(reference, opening_witness);
        _ = try preflightMain(columns, self, opening_witness, executor);
        for (columns) |column| @memset(column, M31.zero());
        for (self.rows, 0..) |row, row_index| {
            const opening = selectOpening(row.verifier_id, opening_witness) orelse continue;
            writeMainRow(columns, row_index, materialize(reference, row, opening));
        }
    }
};

pub fn logicalRow(
    reference: Reference,
    preprocessing: *const Preprocessed,
    vm_plan: *const schedule.Plan,
    recursion_plan: *const schedule.Plan,
    row_index: usize,
    opening_witness: OpeningWitness,
) Error![component.LOGICAL_INPUT_COUNT]M31 {
    try preprocessing.validateAgainst(reference, vm_plan, recursion_plan);
    try validateWitness(reference, opening_witness);
    if (row_index >= preprocessing.rows.len) return error.InvalidWitness;
    const row = preprocessing.rows[row_index];
    const main = if (selectOpening(row.verifier_id, opening_witness)) |opening|
        materialize(reference, row, opening)
    else
        zeroMainRow();
    const selectors = opening_witness.proofKind().selectors();
    return main.values() ++ row.values() ++ .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(FRI_MERKLE_KIND),
    };
}

fn materialize(reference: Reference, row: Row, opening: OpeningSet) MainRow {
    const profile = if (row.verifier_id == SEGMENT_VERIFIER_ID)
        reference.vm
    else
        reference.recursion;
    var folded: u32 = 0;
    for (profile.layers[0..row.layer]) |layer_profile| {
        const geometry = leaf.layerGeometry(profile.lifting_log_size, folded, layer_profile) catch
            unreachable;
        folded += geometry.fold_step;
    }
    const geometry = leaf.layerGeometry(
        profile.lifting_log_size,
        folded,
        profile.layers[row.layer],
    ) catch unreachable;
    var current = [_][DIGEST_WORD_COUNT]M31{
        [_]M31{M31.zero()} ** DIGEST_WORD_COUNT,
    } ** node.MAX_LEAF_COUNT;
    for (0..geometry.leaf_count) |packed_index| current[packed_index] = hashPackedLeaf(
        opening,
        row.layer,
        row.query,
        geometry,
        @intCast(packed_index),
    );
    var count = geometry.leaf_count;
    while (count > 1) {
        count /= 2;
        for (0..count) |index| {
            var state = current[2 * index] ++ current[2 * index + 1];
            @import("../../air/memory_commitment/poseidon2.zig").permute(&state);
            current[index] = state[0..DIGEST_WORD_COUNT].*;
        }
    }
    return .{
        .enabler = M31.one(),
        .position = routePosition(opening.raw_queries[row.query], row.position_shift, row.position_bits),
        .digest_words = current[0],
    };
}

fn hashPackedLeaf(
    opening: OpeningSet,
    layer_index: u32,
    query: u32,
    geometry: leaf.Geometry,
    packed_index: u32,
) [DIGEST_WORD_COUNT]M31 {
    const poseidon2 = @import("../../air/memory_commitment/poseidon2.zig");
    var state = [_]M31{M31.zero()} ** node.STATE_WIDTH;
    state[node.STATE_WIDTH - 1] = M31.fromCanonical(leaf.LEAF_TAG);
    const semantic_words = geometry.leaf_size * leaf.SECURE_WORD_COUNT;
    const steps = std.math.divCeil(u32, semantic_words + 1, DIGEST_WORD_COUNT) catch unreachable;
    const layer = opening.layers[layer_index];
    for (0..steps) |step| {
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

pub fn fillLaneRows(
    rows: []Row,
    cursor: *usize,
    profile: leaf.LaneProfile,
    plan: *const schedule.Plan,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    var folded_bits: u32 = 0;
    for (profile.layers, 0..) |layer, layer_index| {
        const geometry = try leaf.layerGeometry(profile.lifting_log_size, folded_bits, layer);
        folded_bits += geometry.fold_step;
        const path_depth = layer.tree_height - geometry.subtree_height;
        for (0..profile.query_count) |query| {
            const step = schedule.VerifierStep{ .verify_fri_merkle_path = .{
                .layer = @intCast(layer_index),
                .query = @intCast(query),
                .depth = path_depth,
                .width = layer.width,
            } };
            const sequence = try findUniqueStep(plan, step);
            const encoded = step.encode();
            rows[cursor.*] = .{
                .row_mask = 1,
                .segment_mask = segment_mask,
                .binary_mask = binary_mask,
                .verifier_id = verifier_id,
                .layer = @intCast(layer_index),
                .query = @intCast(query),
                .tree_id = try merkle_root.friTreeId(verifier_id, layer_index),
                .path_depth = path_depth,
                .leaf_count = geometry.leaf_count,
                .control_sequence = sequence,
                .control_tag = encoded.tag,
                .control_args = encoded.args,
                .position_shift = folded_bits,
                .position_bits = profile.lifting_log_size - folded_bits,
            };
            cursor.* += 1;
        }
    }
}

pub fn validateLaneRows(
    rows: []const Row,
    cursor: *usize,
    profile: leaf.LaneProfile,
    plan: *const schedule.Plan,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    const count = std.math.mul(usize, profile.query_count, profile.layers.len) catch
        return error.ArithmeticOverflow;
    if (cursor.* > rows.len or count > rows.len - cursor.*) return error.AuthorityMismatch;
    const start = cursor.*;
    var expected_storage: [1]Row = undefined;
    for (profile.layers, 0..) |layer, layer_index| for (0..profile.query_count) |query| {
        // Direct construction avoids allocating an expected schedule. Folded
        // offsets must include all previous layers, so mirror fill explicitly.
        var folded: u32 = 0;
        for (profile.layers[0..layer_index]) |previous| {
            const previous_geometry = try leaf.layerGeometry(profile.lifting_log_size, folded, previous);
            folded += previous_geometry.fold_step;
        }
        const geometry = try leaf.layerGeometry(profile.lifting_log_size, folded, layer);
        folded += geometry.fold_step;
        const path_depth = layer.tree_height - geometry.subtree_height;
        const step = schedule.VerifierStep{ .verify_fri_merkle_path = .{
            .layer = @intCast(layer_index),
            .query = @intCast(query),
            .depth = path_depth,
            .width = layer.width,
        } };
        const encoded = step.encode();
        expected_storage[0] = .{
            .row_mask = 1,
            .segment_mask = segment_mask,
            .binary_mask = binary_mask,
            .verifier_id = verifier_id,
            .layer = @intCast(layer_index),
            .query = @intCast(query),
            .tree_id = try merkle_root.friTreeId(verifier_id, layer_index),
            .path_depth = path_depth,
            .leaf_count = geometry.leaf_count,
            .control_sequence = try findUniqueStep(plan, step),
            .control_tag = encoded.tag,
            .control_args = encoded.args,
            .position_shift = folded,
            .position_bits = profile.lifting_log_size - folded,
        };
        if (!std.meta.eql(rows[cursor.*], expected_storage[0])) return error.AuthorityMismatch;
        cursor.* += 1;
    };
    if (cursor.* - start != count) return error.AuthorityMismatch;
}

pub fn findUniqueStep(plan: *const schedule.Plan, expected: schedule.VerifierStep) Error!u32 {
    var found: ?u32 = null;
    for (plan.steps, 0..) |step, sequence| if (std.meta.eql(step, expected)) {
        if (found != null) return error.ScheduleAuthorityMismatch;
        found = std.math.cast(u32, sequence) orelse return error.ArithmeticOverflow;
    };
    return found orelse error.ScheduleAuthorityMismatch;
}

fn validateAuthorities(
    reference: Reference,
    vm_plan: *const schedule.Plan,
    recursion_plan: *const schedule.Plan,
) Error!void {
    try reference.validate();
    try vm_plan.validate();
    try recursion_plan.validate();
    if (vm_plan.schema != .vm or recursion_plan.schema != .recursion)
        return error.ScheduleAuthorityMismatch;
    try validatePlanGeometry(reference.vm, vm_plan);
    try validatePlanGeometry(reference.recursion, recursion_plan);
}

pub fn validatePlanGeometry(profile: leaf.LaneProfile, plan: *const schedule.Plan) Error!void {
    var folded: u32 = 0;
    for (profile.layers, 0..) |layer, layer_index| {
        const geometry = try leaf.layerGeometry(profile.lifting_log_size, folded, layer);
        folded += geometry.fold_step;
        for (0..profile.query_count) |query| _ = try findUniqueStep(plan, .{
            .verify_fri_merkle_path = .{
                .layer = @intCast(layer_index),
                .query = @intCast(query),
                .depth = layer.tree_height - geometry.subtree_height,
                .width = layer.width,
            },
        });
    }
}

fn totalRows(reference: Reference) Error!usize {
    const vm = std.math.mul(usize, reference.vm.query_count, reference.vm.layers.len) catch
        return error.ArithmeticOverflow;
    const recursion = std.math.mul(
        usize,
        reference.recursion.query_count,
        reference.recursion.layers.len,
    ) catch return error.ArithmeticOverflow;
    return std.math.add(usize, vm, 2 * recursion) catch return error.ArithmeticOverflow;
}

fn validateWitness(reference: Reference, witness: OpeningWitness) Error!void {
    switch (witness) {
        .segment_leaf => |opening| try validateOpening(reference.vm, opening),
        .binary_node => |opening| {
            try validateOpening(reference.recursion, opening.left);
            try validateOpening(reference.recursion, opening.right);
        },
        .empty_leaf => {},
    }
}

pub fn validateOpening(profile: leaf.LaneProfile, opening: OpeningSet) Error!void {
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

pub fn selectOpening(verifier_id: u32, witness: OpeningWitness) ?OpeningSet {
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
        row.path_depth == 0 or row.path_depth > MAX_LOG_SIZE or
        row.leaf_count == 0 or !std.math.isPowerOfTwo(row.leaf_count) or
        row.control_tag != 24 or row.control_sequence >= m31.Modulus or
        row.position_bits == 0 or row.position_bits > 31 or
        row.tree_id != try merkle_root.friTreeId(row.verifier_id, row.layer))
    {
        return error.InvalidProfile;
    }
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

pub fn writeMainRow(columns: *[MAIN_COLUMN_COUNT][]M31, logical_row: usize, row: MainRow) void {
    const values = row.values();
    for (columns, values) |column, value| column[logical_row] = value;
}

pub fn zeroMainRow() MainRow {
    return .{
        .enabler = M31.zero(),
        .position = M31.zero(),
        .digest_words = [_]M31{M31.zero()} ** DIGEST_WORD_COUNT,
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
