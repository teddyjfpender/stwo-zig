//! Verifier-owned FRI arithmetic-control schedule and allocation-free row-28 writer.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const digest = @import("../../air/lang/digest.zig");
const direct = @import("../../air/lang/direct_witness_executor.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("fri_verifier_control.zig");
const proof_kind_mod = @import("proof_kind.zig");
const query_mapping = @import("query_mapping_witness.zig");
const schedule = @import("verifier_schedule.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = proof_kind_mod.ProofKind;
pub const QueryWitness = query_mapping.QueryWitness;
pub const SEGMENT_VERIFIER_ID: u32 = 0;
pub const LEFT_RECURSION_VERIFIER_ID: u32 = 1;
pub const RIGHT_RECURSION_VERIFIER_ID: u32 = 2;
pub const POSITION_FIELD: u32 = 1;
pub const OFFSET_FIELD: u32 = 2;

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN = "stwo-zig/typed-air/recursion-fri-verifier-control-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "5de7804bb11d59c4878c37cc45e5b39314b4d7d3849d7695c84a9dc413bc9779";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion FRI-verifier-control witness-binding digest",
);
pub const ROWS_DOMAIN = "stwo-zig/typed-air/recursion-fri-verifier-control-rows/v1\x00";

pub const Error = direct.Error || std.mem.Allocator.Error || query_mapping.Error || schedule.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    InvalidProfile,
    InvalidWitness,
    InvalidWitnessBinding,
    LogSizeOutOfRange,
    ScheduleAuthorityMismatch,
};

pub const MainSource = enum(u8) { enabler = 0, position = 1, offset = 2 };
pub const PreprocessedSource = enum(u8) {
    row_mask = 0,
    segment_mask = 1,
    binary_mask = 2,
    route_mask = 3,
    offset_output_mask = 4,
    verifier_id = 5,
    route_kind = 6,
    item = 7,
    query = 8,
    sequence = 9,
    tag = 10,
    arg_0 = 11,
    arg_1 = 12,
    arg_2 = 13,
    arg_3 = 14,
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
        witness: QueryWitness,
    ) Error!void {
        return preprocessing.generateMainInto(reference, columns, witness, self);
    }
};

pub const Lane = struct {
    plan: *const schedule.Plan,
    mapping: query_mapping.LaneProfile,
};

pub const Reference = struct {
    vm: Lane,
    recursion: Lane,
    vm_schedule_digest: [8]u32,
    recursion_schedule_digest: [8]u32,
    authority_digest: digest.Digest,

    pub fn seal(vm: Lane, recursion: Lane) Error!Reference {
        try validateLaneAuthority(vm, .vm);
        try validateLaneAuthority(recursion, .recursion);
        const vm_schedule_digest = vm.plan.authority_digest;
        const recursion_schedule_digest = recursion.plan.authority_digest;
        return .{
            .vm = vm,
            .recursion = recursion,
            .vm_schedule_digest = vm_schedule_digest,
            .recursion_schedule_digest = recursion_schedule_digest,
            .authority_digest = referenceDigest(
                vm,
                recursion,
                vm_schedule_digest,
                recursion_schedule_digest,
            ),
        };
    }

    /// Allocation-free integrity check for proof-time writers. The immutable
    /// preprocessed row seal remains the hot authority; recomputing a schedule
    /// digest is intentionally reserved for the cold admission boundary.
    pub fn validate(self: Reference) Error!void {
        try validateLaneMetadata(self.vm, .vm);
        try validateLaneMetadata(self.recursion, .recursion);
        if (!std.meta.eql(self.vm.plan.authority_digest, self.vm_schedule_digest) or
            !std.meta.eql(
                self.recursion.plan.authority_digest,
                self.recursion_schedule_digest,
            ) or
            !std.mem.eql(
                u8,
                &self.authority_digest,
                &referenceDigest(
                    self.vm,
                    self.recursion,
                    self.vm_schedule_digest,
                    self.recursion_schedule_digest,
                ),
            ))
        {
            return error.AuthorityMismatch;
        }
    }

    /// Cold authority check used when admitting preprocessing. This recomputes
    /// both plan digests and validates the exact canonical schedule metadata.
    pub fn validateAuthority(self: Reference) Error!void {
        try self.validate();
        try validateLaneAuthority(self.vm, .vm);
        try validateLaneAuthority(self.recursion, .recursion);
    }

    pub fn mappingReference(self: Reference) Error!query_mapping.Reference {
        try self.validate();
        return query_mapping.Reference.seal(self.vm.mapping, self.recursion.mapping);
    }
};

pub const Row = struct {
    row_mask: u32,
    segment_mask: u32,
    binary_mask: u32,
    route_mask: u32,
    offset_output_mask: u32,
    verifier_id: u32,
    route_kind: u32,
    item: u32,
    query: u32,
    sequence: u32,
    tag: u32,
    args: [4]u32,
    position_weights: [31]u32,
    offset_weights: [31]u32,

    pub fn values(self: Row) [PREPROCESSED_COLUMN_COUNT]M31 {
        return .{
            M31.fromCanonical(self.row_mask),
            M31.fromCanonical(self.segment_mask),
            M31.fromCanonical(self.binary_mask),
            M31.fromCanonical(self.route_mask),
            M31.fromCanonical(self.offset_output_mask),
            M31.fromCanonical(self.verifier_id),
            M31.fromCanonical(self.route_kind),
            M31.fromCanonical(self.item),
            M31.fromCanonical(self.query),
            M31.fromCanonical(self.sequence),
            M31.fromCanonical(self.tag),
            M31.fromCanonical(self.args[0]),
            M31.fromCanonical(self.args[1]),
            M31.fromCanonical(self.args[2]),
            M31.fromCanonical(self.args[3]),
        };
    }
};

pub const MainRow = struct {
    enabler: M31,
    position: M31,
    offset: M31,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{ self.enabler, self.position, self.offset };
    }
};

pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []Row,
    reference_digest: digest.Digest,
    authority_digest: digest.Digest,

    pub fn init(allocator: std.mem.Allocator, reference: Reference) Error!Preprocessed {
        try reference.validateAuthority();
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
        try reference.validateAuthority();
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
        witness: QueryWitness,
        executor: *const Executor,
    ) Error!void {
        try self.validateAgainst(reference);
        try validateWitness(reference, witness);
        _ = try preflightMain(columns, self, witness, executor);
        for (columns) |column| @memset(column, M31.zero());
        for (self.rows, 0..) |row, row_index|
            writeMainRow(columns, row_index, materialize(row, witness));
    }
};

pub fn logicalRow(
    reference: Reference,
    preprocessing: *const Preprocessed,
    row_index: usize,
    witness: QueryWitness,
) Error![component.LOGICAL_INPUT_COUNT]M31 {
    try preprocessing.validateAgainst(reference);
    try validateWitness(reference, witness);
    if (row_index >= preprocessing.rows.len) return error.InvalidWitness;
    const selectors = witness.proofKind().selectors();
    return materialize(preprocessing.rows[row_index], witness).values() ++
        preprocessing.rows[row_index].values() ++ .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(POSITION_FIELD),
        M31.fromCanonical(OFFSET_FIELD),
    };
}

fn materialize(row: Row, witness: QueryWitness) MainRow {
    const word = selectQuery(row.verifier_id, row.query, witness) orelse
        return zeroMainRow(row.row_mask);
    const position = query_mapping.applyWeights(word, row.position_weights) catch unreachable;
    const offset = query_mapping.applyWeights(word, row.offset_weights) catch unreachable;
    return .{
        .enabler = M31.one(),
        .position = if (row.route_mask == 1) position else M31.zero(),
        .offset = if (row.offset_output_mask == 1) offset else M31.zero(),
    };
}

pub fn fillLaneRows(
    rows: []Row,
    cursor: *usize,
    lane: Lane,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    var deep_query: usize = 0;
    var fold_index: usize = 0;
    var last_query: usize = 0;
    for (lane.plan.steps, 0..) |step, sequence| {
        const route = switch (step) {
            .evaluate_deep_quotient => |item| blk: {
                if (item.query != deep_query) return error.ScheduleAuthorityMismatch;
                deep_query += 1;
                break :blk Route{ .kind = null, .item = 0, .query = item.query, .offset_output = false };
            },
            .fold_fri => |item| blk: {
                const expected_layer = fold_index / lane.mapping.query_count;
                const expected_query = fold_index % lane.mapping.query_count;
                if (item.layer != expected_layer or item.query != expected_query or
                    expected_layer >= lane.mapping.fri_fold_widths.len or
                    item.width != lane.mapping.fri_fold_widths[expected_layer])
                {
                    return error.ScheduleAuthorityMismatch;
                }
                fold_index += 1;
                break :blk Route{
                    .kind = .fri_fold,
                    .item = item.layer,
                    .query = item.query,
                    .offset_output = true,
                };
            },
            .verify_last_layer => |item| blk: {
                if (item.query != last_query) return error.ScheduleAuthorityMismatch;
                last_query += 1;
                break :blk Route{
                    .kind = .last_layer,
                    .item = 0,
                    .query = item.query,
                    .offset_output = false,
                };
            },
            else => continue,
        };
        const encoded = step.encode();
        const weights = try routeWeights(lane.mapping, route);
        rows[cursor.*] = .{
            .row_mask = 1,
            .segment_mask = segment_mask,
            .binary_mask = binary_mask,
            .route_mask = @intFromBool(route.kind != null),
            .offset_output_mask = @intFromBool(route.offset_output),
            .verifier_id = verifier_id,
            .route_kind = if (route.kind) |kind| @intFromEnum(kind) else 0,
            .item = route.item,
            .query = route.query,
            .sequence = @intCast(sequence),
            .tag = encoded.tag,
            .args = encoded.args,
            .position_weights = weights[0],
            .offset_weights = weights[1],
        };
        cursor.* += 1;
    }
    const query_count: usize = @intCast(lane.mapping.query_count);
    if (deep_query != query_count or
        fold_index != query_count * lane.mapping.fri_fold_widths.len or
        last_query != query_count)
    {
        return error.ScheduleAuthorityMismatch;
    }
}

pub fn validateLaneRows(
    rows: []const Row,
    cursor: *usize,
    lane: Lane,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    const count = try rowsForLane(lane.mapping);
    if (cursor.* > rows.len or count > rows.len - cursor.*) return error.AuthorityMismatch;
    // Cold validation uses a temporary bounded slice only conceptually: derive
    // each expected row by replaying the sealed plan into the existing tail.
    var deep_query: usize = 0;
    var fold_index: usize = 0;
    var last_query: usize = 0;
    const start = cursor.*;
    for (lane.plan.steps, 0..) |step, sequence| {
        const route = switch (step) {
            .evaluate_deep_quotient => |item| blk: {
                if (item.query != deep_query) return error.ScheduleAuthorityMismatch;
                deep_query += 1;
                break :blk Route{ .kind = null, .item = 0, .query = item.query, .offset_output = false };
            },
            .fold_fri => |item| blk: {
                const expected_layer = fold_index / lane.mapping.query_count;
                const expected_query = fold_index % lane.mapping.query_count;
                if (item.layer != expected_layer or item.query != expected_query or
                    expected_layer >= lane.mapping.fri_fold_widths.len or
                    item.width != lane.mapping.fri_fold_widths[expected_layer])
                {
                    return error.ScheduleAuthorityMismatch;
                }
                fold_index += 1;
                break :blk Route{
                    .kind = .fri_fold,
                    .item = item.layer,
                    .query = item.query,
                    .offset_output = true,
                };
            },
            .verify_last_layer => |item| blk: {
                if (item.query != last_query) return error.ScheduleAuthorityMismatch;
                last_query += 1;
                break :blk Route{ .kind = .last_layer, .item = 0, .query = item.query, .offset_output = false };
            },
            else => continue,
        };
        const encoded = step.encode();
        const weights = try routeWeights(lane.mapping, route);
        const expected = Row{
            .row_mask = 1,
            .segment_mask = segment_mask,
            .binary_mask = binary_mask,
            .route_mask = @intFromBool(route.kind != null),
            .offset_output_mask = @intFromBool(route.offset_output),
            .verifier_id = verifier_id,
            .route_kind = if (route.kind) |kind| @intFromEnum(kind) else 0,
            .item = route.item,
            .query = route.query,
            .sequence = @intCast(sequence),
            .tag = encoded.tag,
            .args = encoded.args,
            .position_weights = weights[0],
            .offset_weights = weights[1],
        };
        if (!std.meta.eql(expected, rows[cursor.*])) return error.AuthorityMismatch;
        cursor.* += 1;
    }
    if (cursor.* - start != count) return error.AuthorityMismatch;
}

const Route = struct {
    kind: ?query_mapping.QueryPositionKind,
    item: u32,
    query: u32,
    offset_output: bool,
};

fn routeWeights(
    profile: query_mapping.LaneProfile,
    route: Route,
) Error![2][31]u32 {
    const zeros = [_]u32{0} ** 31;
    const kind = route.kind orelse return .{ zeros, zeros };
    return switch (kind) {
        .fri_fold => blk: {
            var folded: u32 = 0;
            for (profile.fri_fold_widths[0..route.item]) |width|
                folded += std.math.log2_int(u32, width);
            const width = profile.fri_fold_widths[route.item];
            const fold_step = std.math.log2_int(u32, width);
            break :blk .{
                try query_mapping.shiftedWeights(folded, profile.lifting_log_size - folded),
                try query_mapping.shiftedWeights(folded, fold_step),
            };
        },
        .last_layer => blk: {
            var folded: u32 = 0;
            for (profile.fri_fold_widths) |width| folded += std.math.log2_int(u32, width);
            break :blk .{
                try query_mapping.shiftedWeights(folded, profile.lifting_log_size - folded),
                zeros,
            };
        },
        else => return error.InvalidProfile,
    };
}

pub fn validateLaneMetadata(lane: Lane, expected_schema: schedule.Schema) Error!void {
    if (lane.plan.schema != expected_schema) return error.ScheduleAuthorityMismatch;
    const mapping_reference = try query_mapping.Reference.seal(lane.mapping, lane.mapping);
    _ = mapping_reference;
    _ = try rowsForLane(lane.mapping);
    var expected_deep: usize = 0;
    var expected_fold: usize = 0;
    var expected_last: usize = 0;
    for (lane.plan.steps) |step| switch (step) {
        .evaluate_deep_quotient => expected_deep += 1,
        .fold_fri => expected_fold += 1,
        .verify_last_layer => expected_last += 1,
        else => {},
    };
    const query_count: usize = @intCast(lane.mapping.query_count);
    if (expected_deep != query_count or
        expected_fold != query_count * lane.mapping.fri_fold_widths.len or
        expected_last != query_count)
    {
        return error.ScheduleAuthorityMismatch;
    }
}

pub fn validateLaneAuthority(lane: Lane, expected_schema: schedule.Schema) Error!void {
    try lane.plan.validate();
    try validateLaneMetadata(lane, expected_schema);
}

pub fn rowsForLane(profile: query_mapping.LaneProfile) Error!usize {
    const per_query = std.math.add(usize, profile.fri_fold_widths.len, 2) catch
        return error.ArithmeticOverflow;
    return std.math.mul(usize, profile.query_count, per_query) catch
        return error.ArithmeticOverflow;
}

fn totalRows(reference: Reference) Error!usize {
    const vm = try rowsForLane(reference.vm.mapping);
    const recursion = try rowsForLane(reference.recursion.mapping);
    return std.math.add(usize, vm, 2 * recursion) catch return error.ArithmeticOverflow;
}

fn validateWitness(reference: Reference, witness: QueryWitness) Error!void {
    try reference.validate();
    switch (witness) {
        .segment_leaf => |queries| if (queries.len != @as(usize, reference.vm.mapping.query_count))
            return error.InvalidWitness
        else for (queries) |word| {
            if (word.toU32() >= m31.Modulus) return error.InvalidWitness;
        },
        .binary_node => |queries| if (queries.left.len != @as(usize, reference.recursion.mapping.query_count) or
            queries.right.len != @as(usize, reference.recursion.mapping.query_count))
        {
            return error.InvalidWitness;
        } else {
            for (queries.left) |word| if (word.toU32() >= m31.Modulus)
                return error.InvalidWitness;
            for (queries.right) |word| if (word.toU32() >= m31.Modulus)
                return error.InvalidWitness;
        },
        .empty_leaf => {},
    }
}

fn selectQuery(verifier_id: u32, query: u32, witness: QueryWitness) ?M31 {
    return switch (witness) {
        .segment_leaf => |queries| if (verifier_id == SEGMENT_VERIFIER_ID)
            queries[query]
        else
            null,
        .binary_node => |queries| switch (verifier_id) {
            LEFT_RECURSION_VERIFIER_ID => queries.left[query],
            RIGHT_RECURSION_VERIFIER_ID => queries.right[query],
            else => null,
        },
        .empty_leaf => null,
    };
}

fn validateRow(row: Row) Error!void {
    if (row.row_mask != 1 or row.segment_mask > 1 or row.binary_mask > 1 or
        row.segment_mask + row.binary_mask != 1 or row.route_mask > 1 or
        row.offset_output_mask > row.route_mask or row.verifier_id > RIGHT_RECURSION_VERIFIER_ID or
        row.query >= m31.Modulus or row.sequence >= m31.Modulus or row.tag >= m31.Modulus)
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

fn zeroMainRow(row_mask: u32) MainRow {
    return .{
        .enabler = M31.fromCanonical(row_mask),
        .position = M31.zero(),
        .offset = M31.zero(),
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
            .segment_leaf => |queries| if (destination.overlaps(try sliceRange(M31, queries)))
                return error.AliasedInput,
            .binary_node => |queries| {
                if (destination.overlaps(try sliceRange(M31, queries.left)) or
                    destination.overlaps(try sliceRange(M31, queries.right)))
                {
                    return error.AliasedInput;
                }
            },
            .empty_leaf => {},
        }
    }
    return size;
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

fn referenceDigest(
    vm: Lane,
    recursion: Lane,
    vm_schedule_digest: [8]u32,
    recursion_schedule_digest: [8]u32,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursion-fri-verifier-control-reference/v1\x00");
    for (vm_schedule_digest) |word| hashInt(&hash, u32, word);
    for (recursion_schedule_digest) |word| hashInt(&hash, u32, word);
    hashProfile(&hash, vm.mapping);
    hashProfile(&hash, recursion.mapping);
    return hash.finalResult();
}

pub fn rowsDigest(rows: []const Row) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ROWS_DOMAIN);
    hashInt(&hash, u32, rows.len);
    for (rows) |row| {
        for (row.values()) |value| hashInt(&hash, u32, value.toU32());
        for (row.position_weights) |value| hashInt(&hash, u32, value);
        for (row.offset_weights) |value| hashInt(&hash, u32, value);
    }
    return hash.finalResult();
}

fn hashProfile(hash: anytype, profile: query_mapping.LaneProfile) void {
    hashInt(hash, u32, profile.query_count);
    hashInt(hash, u32, profile.lifting_log_size);
    hashInt(hash, u32, profile.tree_heights.len);
    for (profile.tree_heights) |value| hashInt(hash, u32, value);
    hashInt(hash, u32, profile.fri_fold_widths.len);
    for (profile.fri_fold_widths) |value| hashInt(hash, u32, value);
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
