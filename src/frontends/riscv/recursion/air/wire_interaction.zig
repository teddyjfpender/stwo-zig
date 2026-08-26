//! Generic authenticated interaction compiler for recursion `wire(6)` effects.
//!
//! Component AIRs author typed effects. This module lowers their tuple and
//! multiplicity expressions once into fixed physical-column projections, then
//! owns entry construction, pair batching, cumulative columns, and claims.
//! Component-specific interaction evaluators and denominator transcriptions
//! are intentionally unnecessary.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const permutation = @import("../../infra_trace/permutation.zig");
const logup = @import("../../air/logup.zig");
const challenges = @import("../../air/relation_challenges.zig");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const lower_effects = @import("../../air/lang/lower_effects.zig");
const relation = @import("../../air/lang/relation.zig");
const types = @import("../../air/lang/types.zig");
const validate = @import("../../air/lang/validate.zig");
const wire = @import("wire_relation.zig");

pub const FORMAT_VERSION: u16 = 1;
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
pub const AuthenticationError = Error || validate.Error;
pub const InteractionError = AuthenticationError || logup.LogupError;
pub const ClaimError = AuthenticationError || QM31.Error;

pub const WeightPlan = union(enum) {
    input: u8,
    add: BinaryColumns,
    sub: BinaryColumns,
    mul: BinaryColumns,

    pub const BinaryColumns = struct {
        lhs: u8,
        rhs: u8,
    };

    inline fn evaluate(self: WeightPlan, row: anytype) M31 {
        return switch (self) {
            .input => |column| row[column],
            .add => |columns| row[columns.lhs].add(row[columns.rhs]),
            .sub => |columns| row[columns.lhs].sub(row[columns.rhs]),
            .mul => |columns| row[columns.lhs].mul(row[columns.rhs]),
        };
    }
};

pub const EventPlan = struct {
    ordinal: u8,
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
    first: u8,
    second: ?u8,
    interaction_column_start: u16,
};

pub const Entry = struct {
    ordinal: u8,
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

pub fn Runtime(comptime main_column_count: usize, comptime event_count: usize) type {
    comptime {
        if (main_column_count == 0 or main_column_count > std.math.maxInt(u8))
            @compileError("wire interaction main geometry must fit a u8 projection");
        if (event_count == 0 or event_count > std.math.maxInt(u8))
            @compileError("wire interaction event geometry must fit a u8 ordinal");
    }
    const batch_count = (event_count + 1) / 2;
    const interaction_column_count = 4 * batch_count;

    return struct {
        const Self = @This();

        pub const MAIN_COLUMN_COUNT = main_column_count;
        pub const EVENT_COUNT = event_count;
        pub const BATCH_COUNT = batch_count;
        pub const INTERACTION_COLUMN_COUNT = interaction_column_count;
        pub const Row = [MAIN_COLUMN_COUNT]M31;

        pub const Plan = struct {
            format_version: u16,
            semantic_format_version: u16,
            semantic_digest: digest.Digest,
            events: [EVENT_COUNT]EventPlan,
            batches: [BATCH_COUNT]BatchPlan,

            pub fn validateAgainst(
                self: *const Plan,
                arena: *const ir.Arena,
                expected_digest: digest.Digest,
                event_ids: [EVENT_COUNT]types.EffectId,
            ) AuthenticationError!void {
                if (self.format_version != FORMAT_VERSION)
                    return error.FormatVersionMismatch;
                if (self.semantic_format_version != digest.typed_effect_format_version or
                    !std.mem.eql(u8, &self.semantic_digest, &expected_digest))
                {
                    return error.BindingSealMismatch;
                }
                const expected = try compilePlan(arena, expected_digest, event_ids);
                if (!std.meta.eql(self.events, expected.events))
                    return error.EventPlanMismatch;
                if (!std.meta.eql(self.batches, expected.batches))
                    return error.BatchPlanMismatch;
            }

            pub fn entries(
                self: *const Plan,
                arena: *const ir.Arena,
                expected_digest: digest.Digest,
                event_ids: [EVENT_COUNT]types.EffectId,
                row: Row,
            ) AuthenticationError![EVENT_COUNT]Entry {
                try self.validateAgainst(arena, expected_digest, event_ids);
                return entriesUnchecked(self, &row);
            }

            pub fn validateEntries(
                self: *const Plan,
                arena: *const ir.Arena,
                expected_digest: digest.Digest,
                event_ids: [EVENT_COUNT]types.EffectId,
                row: Row,
                actual: [EVENT_COUNT]Entry,
            ) AuthenticationError!void {
                try self.validateAgainst(arena, expected_digest, event_ids);
                const expected = entriesUnchecked(self, &row);
                for (actual, expected, 0..) |got, wanted, ordinal| {
                    if (got.ordinal != wanted.ordinal or
                        @as(usize, got.ordinal) != ordinal)
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
                        if (!got_value.eql(wanted_value))
                            return error.EntryTupleMismatch;
                    }
                }
            }

            pub fn rowPairs(
                self: *const Plan,
                arena: *const ir.Arena,
                expected_digest: digest.Digest,
                event_ids: [EVENT_COUNT]types.EffectId,
                row: Row,
                challenge: Challenge,
            ) AuthenticationError![BATCH_COUNT]logup.RowPair {
                try self.validateAgainst(arena, expected_digest, event_ids);
                return rowPairsUnchecked(self, &row, challenge);
            }

            pub fn rowClaims(
                self: *const Plan,
                arena: *const ir.Arena,
                expected_digest: digest.Digest,
                event_ids: [EVENT_COUNT]types.EffectId,
                row: Row,
                challenge: Challenge,
            ) ClaimError!Claims {
                const pairs = try self.rowPairs(
                    arena,
                    expected_digest,
                    event_ids,
                    row,
                    challenge,
                );
                var sums: [BATCH_COUNT]QM31 = undefined;
                for (&sums, pairs) |*sum, pair| sum.* = try pairSum(pair);
                return .{ .sums = sums };
            }

            pub fn generateInteraction(
                self: *const Plan,
                allocator: std.mem.Allocator,
                arena: *const ir.Arena,
                expected_digest: digest.Digest,
                event_ids: [EVENT_COUNT]types.EffectId,
                rows: []const Row,
                log_size: u32,
                challenge: Challenge,
            ) InteractionError!Interaction {
                try self.validateAgainst(arena, expected_digest, event_ids);
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
                arena: *const ir.Arena,
                expected_digest: digest.Digest,
                event_ids: [EVENT_COUNT]types.EffectId,
                rows: []const Row,
                log_size: u32,
                challenge: Challenge,
                actual: *const Interaction,
            ) InteractionError!void {
                try self.validateAgainst(arena, expected_digest, event_ids);
                const size = traceSize(log_size) catch return error.InvalidTraceShape;
                const storage_len = std.math.mul(
                    usize,
                    INTERACTION_COLUMN_COUNT,
                    size,
                ) catch return error.InvalidTraceShape;
                if (actual.storage.len != storage_len)
                    return error.InteractionGeometryMismatch;
                for (actual.columns) |column| {
                    if (column.len != size)
                        return error.InteractionGeometryMismatch;
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

        pub const Claims = struct {
            sums: [BATCH_COUNT]QM31,

            pub fn total(self: Claims) QM31 {
                var result = QM31.zero();
                for (self.sums) |sum| result = result.add(sum);
                return result;
            }

            pub fn eql(self: Claims, other: Claims) bool {
                for (self.sums, other.sums) |lhs, rhs| {
                    if (!lhs.eql(rhs)) return false;
                }
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

        pub fn authenticate(
            arena: *const ir.Arena,
            expected_digest: digest.Digest,
            event_ids: [EVENT_COUNT]types.EffectId,
        ) AuthenticationError!Plan {
            return compilePlan(arena, expected_digest, event_ids);
        }

        fn compilePlan(
            arena: *const ir.Arena,
            expected_digest: digest.Digest,
            event_ids: [EVENT_COUNT]types.EffectId,
        ) AuthenticationError!Plan {
            const identity = try digest.computeIdentity(arena);
            if (identity.format_version != digest.typed_effect_format_version or
                !std.mem.eql(u8, &identity.bytes, &expected_digest))
            {
                return error.BindingSealMismatch;
            }
            if (arena.effectsView().len != EVENT_COUNT)
                return error.EventPlanMismatch;
            const lowered = try lower_effects.ValidatedProgram.init(arena);
            const schema = relation.get(.recursion_wire);
            var events: [EVENT_COUNT]EventPlan = undefined;
            for (&events, event_ids, 0..) |*plan, effect_id, ordinal| {
                if (types.idIndex(effect_id) != ordinal)
                    return error.EventPlanMismatch;
                const event = lowered.event(effect_id) orelse
                    return error.EventPlanMismatch;
                if (event.kind != .component_call or event.schema != schema.id or
                    event.schema_version != schema.version or
                    (event.role != .consume and event.role != .emit) or
                    event.access_ordinal != null or event.values.len != wire.ARITY)
                {
                    return error.EventPlanMismatch;
                }
                const values = event.values[0..wire.ARITY].*;
                plan.* = .{
                    .ordinal = @intCast(ordinal),
                    .effect = event.effect,
                    .schema = event.schema,
                    .schema_version = event.schema_version,
                    .role = event.role,
                    .liveness = event.liveness,
                    .values = values,
                    .value_columns = try compileColumns(arena, values),
                    .weight = try compileWeight(arena, event.liveness),
                };
            }
            var batches: [BATCH_COUNT]BatchPlan = undefined;
            for (&batches, 0..) |*batch, ordinal| {
                const first = 2 * ordinal;
                batch.* = .{
                    .ordinal = @intCast(ordinal),
                    .first = @intCast(first),
                    .second = if (first + 1 < EVENT_COUNT)
                        @intCast(first + 1)
                    else
                        null,
                    .interaction_column_start = @intCast(4 * ordinal),
                };
            }
            return .{
                .format_version = FORMAT_VERSION,
                .semantic_format_version = digest.typed_effect_format_version,
                .semantic_digest = expected_digest,
                .events = events,
                .batches = batches,
            };
        }

        fn entriesUnchecked(plan: *const Plan, row: *const Row) [EVENT_COUNT]Entry {
            var result: [EVENT_COUNT]Entry = undefined;
            for (&result, plan.events) |*entry, event_plan| {
                var values: [wire.ARITY]QM31 = undefined;
                for (&values, event_plan.value_columns) |*target, column| {
                    target.* = QM31.fromBase(row[column]);
                }
                const weight = QM31.fromBase(event_plan.weight.evaluate(row));
                entry.* = .{
                    .ordinal = event_plan.ordinal,
                    .schema = event_plan.schema,
                    .schema_version = event_plan.schema_version,
                    .role = event_plan.role,
                    .numerator = if (event_plan.role == .consume)
                        weight.neg()
                    else
                        weight,
                    .values = values,
                    .arity = wire.ARITY,
                };
            }
            return result;
        }

        fn rowPairsUnchecked(
            plan: *const Plan,
            row: *const Row,
            challenge: Challenge,
        ) [BATCH_COUNT]logup.RowPair {
            const entries = entriesUnchecked(plan, row);
            var result: [BATCH_COUNT]logup.RowPair = undefined;
            for (&result, plan.batches) |*pair, batch| {
                const first = entries[batch.first];
                pair.* = if (batch.second) |second| blk: {
                    const next = entries[second];
                    break :blk .{
                        .n1 = first.numerator,
                        .d1 = first.denominator(challenge),
                        .n2 = next.numerator,
                        .d2 = next.denominator(challenge),
                    };
                } else logup.RowPair.single(
                    first.numerator,
                    first.denominator(challenge),
                );
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
                    rowPairsUnchecked(plan, &rows[row], challenge)
                else
                    paddingPairs();
                for (row_pairs, 0..) |pair, batch| {
                    pairs[batch * size + row] = pair;
                }
            }

            var cumulative: [BATCH_COUNT]logup.CumulativeColumn = undefined;
            var initialized: usize = 0;
            defer for (cumulative[0..initialized]) |*column| {
                column.deinit(allocator);
            };
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
            var claims: [BATCH_COUNT]QM31 = undefined;
            for (&claims, cumulative) |*claim, column| claim.* = column.claimed;
            return .{
                .columns = columns,
                .claims = .{ .sums = claims },
                .storage = storage,
            };
        }

        fn paddingPairs() [BATCH_COUNT]logup.RowPair {
            const zero = QM31.zero();
            const one = QM31.one();
            return [_]logup.RowPair{.{
                .n1 = zero,
                .d1 = one,
                .n2 = zero,
                .d2 = one,
            }} ** BATCH_COUNT;
        }

        fn compileColumns(
            arena: *const ir.Arena,
            values: [wire.ARITY]types.ValueId,
        ) Error![wire.ARITY]u8 {
            var result: [wire.ARITY]u8 = undefined;
            for (&result, values) |*column, value| {
                column.* = try compileColumn(arena, value);
            }
            return result;
        }

        fn compileWeight(
            arena: *const ir.Arena,
            liveness: types.ValueId,
        ) Error!WeightPlan {
            const node = arena.node(liveness) orelse return error.EventPlanMismatch;
            return switch (node.key.op) {
                .input => .{ .input = try compileColumn(arena, liveness) },
                .add => |operands| .{ .add = try compileBinary(arena, operands) },
                .sub => |operands| .{ .sub = try compileBinary(arena, operands) },
                .mul => |operands| .{ .mul = try compileBinary(arena, operands) },
                else => error.EventPlanMismatch,
            };
        }

        fn compileBinary(
            arena: *const ir.Arena,
            operands: @import("../../air/lang/expr.zig").Binary,
        ) Error!WeightPlan.BinaryColumns {
            return .{
                .lhs = try compileColumn(arena, operands.lhs),
                .rhs = try compileColumn(arena, operands.rhs),
            };
        }

        fn compileColumn(
            arena: *const ir.Arena,
            value: types.ValueId,
        ) Error!u8 {
            const index = types.idIndex(value);
            if (index >= MAIN_COLUMN_COUNT) return error.EventPlanMismatch;
            const node = arena.node(value) orelse return error.EventPlanMismatch;
            switch (node.key.op) {
                .input => {},
                else => return error.EventPlanMismatch,
            }
            return @intCast(index);
        }
    };
}

fn pairSum(pair: logup.RowPair) QM31.Error!QM31 {
    return pair.n1.mul(try pair.d1.inv()).add(pair.n2.mul(try pair.d2.inv()));
}

fn traceSize(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidTraceShape;
    return @as(usize, 1) << @intCast(log_size);
}
