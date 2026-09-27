//! Prepared `wire(6)` interaction plan derived from the typed QM31 AIR.
//!
//! Authentication lowers the arena's three ordered effects once and seals the
//! exact schema, role, liveness expression, tuple projections, and pairs-batch
//! layout to the semantic digest. Runtime entry and interaction generation use
//! that plan; no independent denominator or evaluator transcription exists.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const permutation = @import("../../infra_trace/permutation.zig");
const logup = @import("../../air/logup.zig");
const challenges = @import("../../air/relation_challenges.zig");
const digest = @import("../../air/lang/digest.zig");
const lower_effects = @import("../../air/lang/lower_effects.zig");
const relation = @import("../../air/lang/relation.zig");
const types = @import("../../air/lang/types.zig");
const full = @import("qm31_mul_full.zig");
const wire = @import("wire_relation.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const EVENT_COUNT: usize = wire.EVENT_COUNT;
pub const BATCH_COUNT: usize = full.INTERACTION_BATCH_COUNT;
pub const INTERACTION_COLUMN_COUNT: usize = full.INTERACTION_COLUMN_COUNT;
pub const Challenge = challenges.RelationElements(wire.ARITY);

pub const Error = error{
    BatchPlanMismatch,
    BindingSealMismatch,
    ClaimMismatch,
    EntryArityMismatch,
    EntryNumeratorMismatch,
    EntryOrderMismatch,
    EntryRoleMismatch,
    EntrySchemaMismatch,
    EntryTupleMismatch,
    EventPlanMismatch,
    FormatVersionMismatch,
    InteractionColumnMismatch,
    InteractionGeometryMismatch,
    InvalidTraceShape,
    RelationSumNonZero,
};
pub const AuthenticationError = Error || full.ValidationError;
pub const InteractionError = AuthenticationError || logup.LogupError;
pub const ClaimError = AuthenticationError || QM31.Error;

pub const EventId = enum(u8) {
    lhs_consume = 0,
    rhs_consume = 1,
    result_emit = 2,
};

pub const WeightPlan = union(enum) {
    input: u8,
    product: struct {
        lhs: u8,
        rhs: u8,
    },

    inline fn evaluate(self: WeightPlan, row: Row) M31 {
        return switch (self) {
            .input => |column| row[column],
            .product => |columns| row[columns.lhs].mul(row[columns.rhs]),
        };
    }
};

pub const EventPlan = struct {
    id: EventId,
    effect: types.EffectId,
    schema: types.RelationSchemaId,
    schema_version: u16,
    role: relation.Role,
    liveness: types.ValueId,
    values: [wire.ARITY]types.ValueId,
    value_columns: [wire.ARITY]u8,
    weight: WeightPlan,
};

pub const BatchPlan = struct {
    ordinal: u8,
    first: EventId,
    second: ?EventId,
    interaction_column_start: u8,
};

pub const Plan = struct {
    format_version: u16,
    semantic_format_version: u16,
    semantic_digest: digest.Digest,
    events: [EVENT_COUNT]EventPlan,
    batches: [BATCH_COUNT]BatchPlan,

    pub fn validateAgainst(
        self: *const Plan,
        definition: *const full.Definition,
    ) AuthenticationError!void {
        try definition.validate();
        if (self.format_version != FORMAT_VERSION)
            return error.FormatVersionMismatch;
        if (self.semantic_format_version != digest.typed_effect_format_version or
            !std.mem.eql(u8, &self.semantic_digest, &full.SEMANTIC_DIGEST))
        {
            return error.BindingSealMismatch;
        }
        const schema = relation.get(.recursion_wire);
        const event_ids = definition.events.ordered();
        const expected_values = canonicalValues(definition);
        const expected_liveness = [_]types.ValueId{
            definition.main.in_circuit,
            definition.main.in_circuit,
            definition.events.result_weight,
        };
        for (self.events, event_ids, expected_values, expected_liveness, 0..) |
            event,
            effect_id,
            values,
            liveness,
            ordinal,
        | {
            const canonical = canonicalEvent(@enumFromInt(ordinal));
            if (event.id != canonical.id or event.effect != effect_id or
                event.schema != schema.id or event.schema_version != schema.version or
                event.role != canonical.role or event.liveness != liveness or
                !std.meta.eql(event.values, values) or
                !std.meta.eql(event.value_columns, try compileColumns(values)) or
                !std.meta.eql(event.weight, try compileWeight(definition, liveness)))
            {
                return error.EventPlanMismatch;
            }
        }
        for (self.batches, 0..) |batch, ordinal| {
            if (!std.meta.eql(batch, canonicalBatch(ordinal)))
                return error.BatchPlanMismatch;
        }
    }

    pub fn entries(
        self: *const Plan,
        definition: *const full.Definition,
        row: Row,
    ) AuthenticationError![EVENT_COUNT]Entry {
        try self.validateAgainst(definition);
        return entriesUnchecked(self, row);
    }

    pub fn validateEntries(
        self: *const Plan,
        definition: *const full.Definition,
        row: Row,
        actual: [EVENT_COUNT]Entry,
    ) AuthenticationError!void {
        try self.validateAgainst(definition);
        const expected = entriesUnchecked(self, row);
        for (actual, expected, 0..) |got, wanted, ordinal| {
            if (got.id != wanted.id or
                @as(usize, @intFromEnum(got.id)) != ordinal)
                return error.EntryOrderMismatch;
            if (got.schema != wanted.schema or
                got.schema_version != wanted.schema_version)
            {
                return error.EntrySchemaMismatch;
            }
            if (got.role != wanted.role) return error.EntryRoleMismatch;
            if (got.arity != wanted.arity) return error.EntryArityMismatch;
            if (!got.numerator.eql(wanted.numerator))
                return error.EntryNumeratorMismatch;
            for (got.values, wanted.values) |got_value, wanted_value| {
                if (!got_value.eql(wanted_value)) return error.EntryTupleMismatch;
            }
        }
    }

    pub fn rowPairs(
        self: *const Plan,
        definition: *const full.Definition,
        row: Row,
        challenge: Challenge,
    ) AuthenticationError![BATCH_COUNT]logup.RowPair {
        try self.validateAgainst(definition);
        return rowPairsUnchecked(self, row, challenge);
    }

    pub fn rowClaims(
        self: *const Plan,
        definition: *const full.Definition,
        row: Row,
        challenge: Challenge,
    ) ClaimError!Claims {
        const pairs = try self.rowPairs(definition, row, challenge);
        var sums: [BATCH_COUNT]QM31 = undefined;
        for (&sums, pairs) |*sum, pair| sum.* = try pairSum(pair);
        return .{ .sums = sums };
    }

    pub fn generateInteraction(
        self: *const Plan,
        allocator: std.mem.Allocator,
        definition: *const full.Definition,
        rows: []const Row,
        log_size: u32,
        challenge: Challenge,
    ) InteractionError!Interaction {
        try self.validateAgainst(definition);
        return generateInteractionUnchecked(
            self,
            allocator,
            rows,
            log_size,
            challenge,
        );
    }

    pub fn validateInteraction(
        self: *const Plan,
        allocator: std.mem.Allocator,
        definition: *const full.Definition,
        rows: []const Row,
        log_size: u32,
        challenge: Challenge,
        actual: *const Interaction,
    ) InteractionError!void {
        try self.validateAgainst(definition);
        const size = traceSize(log_size) catch return error.InvalidTraceShape;
        for (actual.columns) |column| {
            if (column.len != size) return error.InteractionGeometryMismatch;
        }
        var expected = try generateInteractionUnchecked(
            self,
            allocator,
            rows,
            log_size,
            challenge,
        );
        defer expected.deinit(allocator);
        if (!actual.claims.eql(expected.claims)) return error.ClaimMismatch;
        for (actual.columns, expected.columns) |got, wanted| {
            for (got, wanted) |got_value, wanted_value| {
                if (!got_value.eql(wanted_value))
                    return error.InteractionColumnMismatch;
            }
        }
    }
};

pub fn authenticate(
    definition: *const full.Definition,
) AuthenticationError!Plan {
    try definition.validate();
    const lowered = try lower_effects.ValidatedProgram.init(&definition.arena);
    const event_ids = definition.events.ordered();
    var events: [EVENT_COUNT]EventPlan = undefined;
    for (&events, event_ids, 0..) |*event_plan, effect_id, ordinal| {
        const event = lowered.event(effect_id) orelse return error.EventPlanMismatch;
        if (event.values.len != wire.ARITY) return error.EventPlanMismatch;
        const canonical = canonicalEvent(@enumFromInt(ordinal));
        event_plan.* = .{
            .id = canonical.id,
            .effect = event.effect,
            .schema = event.schema,
            .schema_version = event.schema_version,
            .role = event.role,
            .liveness = event.liveness,
            .values = event.values[0..wire.ARITY].*,
            .value_columns = try compileColumns(event.values[0..wire.ARITY].*),
            .weight = try compileWeight(definition, event.liveness),
        };
    }
    var batches: [BATCH_COUNT]BatchPlan = undefined;
    for (&batches, 0..) |*batch, ordinal| batch.* = canonicalBatch(ordinal);
    const result = Plan{
        .format_version = FORMAT_VERSION,
        .semantic_format_version = digest.typed_effect_format_version,
        .semantic_digest = full.SEMANTIC_DIGEST,
        .events = events,
        .batches = batches,
    };
    try result.validateAgainst(definition);
    return result;
}

pub const Row = [full.PHYSICAL_MAIN_COLUMN_COUNT]M31;

pub const Entry = struct {
    id: EventId,
    schema: types.RelationSchemaId,
    schema_version: u16,
    role: relation.Role,
    numerator: QM31,
    values: [wire.ARITY]QM31,
    arity: u8,

    fn denominator(self: Entry, challenge: Challenge) QM31 {
        return challenge.combineSecure(self.values);
    }
};

pub const Claims = struct {
    sums: [BATCH_COUNT]QM31,

    pub fn total(self: Claims) QM31 {
        var result = QM31.zero();
        for (self.sums) |sum| result = result.add(sum);
        return result;
    }

    pub fn eql(self: Claims, other: Claims) bool {
        for (self.sums, other.sums) |lhs, rhs| if (!lhs.eql(rhs)) return false;
        return true;
    }

    pub fn verifyClosure(self: Claims, counterpart: QM31) Error!void {
        if (!self.total().add(counterpart).isZero())
            return error.RelationSumNonZero;
    }
};

pub const Interaction = struct {
    columns: [INTERACTION_COLUMN_COUNT][]M31,
    claims: Claims,
    storage: []M31,

    pub fn deinit(self: *Interaction, allocator: std.mem.Allocator) void {
        allocator.free(self.storage);
        self.* = undefined;
    }
};

pub fn paddingPairs() [BATCH_COUNT]logup.RowPair {
    const zero = QM31.zero();
    const one = QM31.one();
    return .{
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
    };
}

fn entriesUnchecked(plan: *const Plan, row: Row) [EVENT_COUNT]Entry {
    var result: [EVENT_COUNT]Entry = undefined;
    for (&result, plan.events) |*entry, event_plan| {
        var lifted: [wire.ARITY]QM31 = undefined;
        for (&lifted, event_plan.value_columns) |*target, column| {
            target.* = QM31.fromBase(row[column]);
        }
        const weight = QM31.fromBase(event_plan.weight.evaluate(row));
        entry.* = .{
            .id = event_plan.id,
            .schema = event_plan.schema,
            .schema_version = event_plan.schema_version,
            .role = event_plan.role,
            .numerator = switch (event_plan.role) {
                .consume => weight.neg(),
                .emit => weight,
                .request => unreachable,
            },
            .values = lifted,
            .arity = wire.ARITY,
        };
    }
    return result;
}

fn rowPairsUnchecked(
    plan: *const Plan,
    row: Row,
    challenge: Challenge,
) [BATCH_COUNT]logup.RowPair {
    const entries = entriesUnchecked(plan, row);
    var result: [BATCH_COUNT]logup.RowPair = undefined;
    for (&result, plan.batches) |*pair, batch| {
        const first = entries[@intFromEnum(batch.first)];
        pair.* = if (batch.second) |second_id| blk: {
            const second = entries[@intFromEnum(second_id)];
            break :blk .{
                .n1 = first.numerator,
                .d1 = first.denominator(challenge),
                .n2 = second.numerator,
                .d2 = second.denominator(challenge),
            };
        } else logup.RowPair.single(first.numerator, first.denominator(challenge));
    }
    return result;
}

fn generateInteractionUnchecked(
    plan: *const Plan,
    allocator: std.mem.Allocator,
    rows: []const Row,
    log_size: u32,
    challenge: Challenge,
) (Error || logup.LogupError)!Interaction {
    const size = traceSize(log_size) catch return error.InvalidTraceShape;
    if (rows.len > size) return error.InvalidTraceShape;
    const pair_count = std.math.mul(usize, BATCH_COUNT, size) catch
        return error.InvalidTraceShape;
    const pairs = try allocator.alloc(logup.RowPair, pair_count);
    defer allocator.free(pairs);
    for (0..size) |row| {
        const row_pairs = if (row < rows.len)
            rowPairsUnchecked(plan, rows[row], challenge)
        else
            paddingPairs();
        for (row_pairs, 0..) |pair, batch| pairs[batch * size + row] = pair;
    }

    var cumulative: [BATCH_COUNT]logup.CumulativeColumn = undefined;
    var initialized: usize = 0;
    defer for (cumulative[0..initialized]) |*column| column.deinit(allocator);
    for (&cumulative, 0..) |*column, batch| {
        column.* = try logup.cumulativeColumn(
            allocator,
            pairs[batch * size ..][0..size],
        );
        initialized += 1;
    }

    const storage_len = std.math.mul(
        usize,
        INTERACTION_COLUMN_COUNT,
        size,
    ) catch return error.InvalidTraceShape;
    const storage = try allocator.alloc(M31, storage_len);
    errdefer allocator.free(storage);
    var columns: [INTERACTION_COLUMN_COUNT][]M31 = undefined;
    for (&columns, 0..) |*column, index| {
        column.* = storage[index * size ..][0..size];
    }
    const placement = try permutation.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    for (0..size) |row| {
        const destination = placement.map(row);
        for (plan.batches, 0..) |batch_plan, batch| {
            const coordinates = cumulative[batch].sums[row].toM31Array();
            for (coordinates, 0..) |coordinate, coordinate_index| {
                columns[batch_plan.interaction_column_start + coordinate_index][destination] =
                    coordinate;
            }
        }
    }
    return .{
        .columns = columns,
        .claims = .{ .sums = .{ cumulative[0].claimed, cumulative[1].claimed } },
        .storage = storage,
    };
}

fn canonicalEvent(id: EventId) struct {
    id: EventId,
    role: relation.Role,
} {
    return switch (id) {
        .lhs_consume => .{
            .id = id,
            .role = .consume,
        },
        .rhs_consume => .{
            .id = id,
            .role = .consume,
        },
        .result_emit => .{
            .id = id,
            .role = .emit,
        },
    };
}

fn compileColumns(values: [wire.ARITY]types.ValueId) Error![wire.ARITY]u8 {
    var result: [wire.ARITY]u8 = undefined;
    for (&result, values) |*column, value| column.* = try compileColumn(value);
    return result;
}

fn compileWeight(
    definition: *const full.Definition,
    liveness: types.ValueId,
) Error!WeightPlan {
    const node = definition.arena.node(liveness) orelse
        return error.EventPlanMismatch;
    return switch (node.key.op) {
        .input => .{ .input = try compileColumn(liveness) },
        .mul => |operands| .{ .product = .{
            .lhs = try compileColumn(operands.lhs),
            .rhs = try compileColumn(operands.rhs),
        } },
        else => error.EventPlanMismatch,
    };
}

fn compileColumn(value: types.ValueId) Error!u8 {
    const index = types.idIndex(value);
    if (index >= full.PHYSICAL_MAIN_COLUMN_COUNT)
        return error.EventPlanMismatch;
    return @intCast(index);
}

fn canonicalBatch(ordinal: usize) BatchPlan {
    return switch (ordinal) {
        0 => .{
            .ordinal = 0,
            .first = .lhs_consume,
            .second = .rhs_consume,
            .interaction_column_start = 0,
        },
        1 => .{
            .ordinal = 1,
            .first = .result_emit,
            .second = null,
            .interaction_column_start = 4,
        },
        else => unreachable,
    };
}

fn canonicalValues(
    definition: *const full.Definition,
) [EVENT_COUNT][wire.ARITY]types.ValueId {
    return .{
        (wire.Tuple{
            .circuit_id = definition.main.circuit_id,
            .node_id = definition.main.lhs_id,
            .value = definition.main.a,
        }).values(),
        (wire.Tuple{
            .circuit_id = definition.main.circuit_id,
            .node_id = definition.main.rhs_id,
            .value = definition.main.b,
        }).values(),
        (wire.Tuple{
            .circuit_id = definition.main.circuit_id,
            .node_id = definition.main.node_id,
            .value = definition.main.c,
        }).values(),
    };
}

fn pairSum(pair: logup.RowPair) QM31.Error!QM31 {
    return pair.n1.mul(try pair.d1.inv()).add(pair.n2.mul(try pair.d2.inv()));
}

fn traceSize(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidTraceShape;
    return @as(usize, 1) << @intCast(log_size);
}

comptime {
    if (EVENT_COUNT != 3 or BATCH_COUNT != 2 or INTERACTION_COLUMN_COUNT != 8)
        @compileError("recursion QM31 wire interaction geometry drifted");
}
