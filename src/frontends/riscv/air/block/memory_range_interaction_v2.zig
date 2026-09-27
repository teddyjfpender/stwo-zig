//! Block-v2 byte-range LogUp over the unchanged universal 8x8 relation.
//! The 35 request sources come from the typed row DAG, never a parallel
//! hand-authored byte list. Eighteen pair batches keep quotient degree small.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const lang = @import("../lang/definition.zig");
const relation = @import("../lang/relation.zig");
const component = @import("memory_component.zig");
const trace_mod = @import("memory_component_trace.zig");
const evaluator = @import("memory_component_eval.zig");
const bus = @import("../../prover/block_memory_relation_v2.zig");
const table_counter = @import("../lookups/tables/counter.zig");
const logup = @import("../logup_equations.zig");

pub const EVENT_COUNT: usize = 35;
pub const BATCH_COUNT: usize = (EVENT_COUNT + 1) / 2;
pub const COLUMN_COUNT: usize = 4 * BATCH_COUNT;
pub const CHUNK_ROWS: usize = 1024;
pub const FORMAT_VERSION: u32 = 2;
pub const CLAIM_TAG: u32 = 0x42325247; // B2RG
pub const Claims = [BATCH_COUNT]Q;
pub const CounterSnapshot = [32]u8;
pub const InteractionRow = [COLUMN_COUNT]M;
const Element = @import("../../recursion/air/universal_challenges.zig").Elements;

const Source = struct {
    low: lang.types.ValueId,
    high: lang.types.ValueId,
    gate: lang.types.ValueId,
};

/// Cold path. Exact count, binding, role and ordered IDs are pinned before
/// either the native interaction writer or verifier quotient can run.
pub const RangePlan = struct {
    sources: [EVENT_COUNT]Source,

    pub fn init(definition: *const component.Definition) !RangePlan {
        const arena = &definition.arena;
        if (arena.effectsView().len != EVENT_COUNT) return error.InvalidBlockRangeEventCount;
        const schema = relation.get(.range_check_8_8);
        var result: RangePlan = undefined;
        for (arena.effectsView(), &result.sources, 0..) |effect, *source, index| {
            _ = index;
            const binding = effect.binding orelse return error.InvalidBlockRangeBinding;
            if (effect.kind != .component_call or binding.schema != schema.id or
                binding.schema_version != schema.version or binding.role != .request)
                return error.InvalidBlockRangeBinding;
            const values = effect.values.slice(arena.effectValuesView()) orelse
                return error.InvalidBlockRangeBinding;
            if (values.len != 2 or effect.liveness == null)
                return error.InvalidBlockRangeBinding;
            source.* = .{ .low = values[0], .high = values[1], .gate = effect.liveness.? };
        }
        return result;
    }

    pub fn evaluateAt(
        self: *const RangePlan,
        scratch: []const Q,
        current: [BATCH_COUNT]Q,
        previous: [BATCH_COUNT]Q,
        is_first: Q,
        claims: Claims,
        challenge: *const Element,
    ) ![BATCH_COUNT]Q {
        if (challenge.arity != 2) return error.InvalidBlockRangeChallenge;
        var result: [BATCH_COUNT]Q = undefined;
        for (&result, 0..) |*constraint, batch| {
            const first = try self.secureTerm(scratch, 2 * batch, challenge);
            const second = if (2 * batch + 1 < EVENT_COUNT)
                try self.secureTerm(scratch, 2 * batch + 1, challenge)
            else
                logup.RowPairFor(Q).single(Q.zero(), Q.one());
            const pair = logup.RowPairFor(Q){
                .n1 = first.n1,
                .d1 = first.d1,
                .n2 = second.n1,
                .d2 = second.d1,
            };
            constraint.* = logup.pairConstraintGeneric(Q, current[batch], previous[batch], is_first, claims[batch], pair);
        }
        return result;
    }

    fn secureTerm(self: *const RangePlan, scratch: []const Q, index: usize, challenge: *const Element) !logup.RowPairFor(Q) {
        const source = self.sources[index];
        const low = try valueAt(Q, scratch, source.low);
        const high = try valueAt(Q, scratch, source.high);
        const gate = try valueAt(Q, scratch, source.gate);
        return .single(gate, try challenge.combineSecure(&.{ low, high }));
    }

    fn baseTerm(self: *const RangePlan, scratch: []const M, index: usize, challenge: *const Element, counter: *table_counter.Counter) !struct { numerator: M, denominator: Q } {
        const source = self.sources[index];
        const tuple = [2]M{ try valueAt(M, scratch, source.low), try valueAt(M, scratch, source.high) };
        const gate = try valueAt(M, scratch, source.gate);
        try counter.registerBase(gate, &tuple);
        return .{ .numerator = gate, .denominator = try challenge.combineBase(&tuple) };
    }
};

fn valueAt(comptime S: type, scratch: []const S, id: lang.types.ValueId) !S {
    const index = lang.types.idIndex(id);
    if (index >= scratch.len) return error.InvalidBlockRangeScratch;
    return scratch[index];
}

pub const Result = struct {
    columns: [COLUMN_COUNT][]M,
    claims: Claims,
    pub fn total(self: *const Result) Q {
        return claimTotal(self.claims);
    }
    pub fn takeColumns(self: *Result) [COLUMN_COUNT][]M {
        const moved = self.columns;
        self.columns = .{&.{}} ** COLUMN_COUNT;
        return moved;
    }
    pub fn deinit(self: *Result, a: std.mem.Allocator) void {
        for (self.columns) |column| if (column.len != 0) a.free(column);
        self.* = undefined;
    }
};

pub fn claimTotal(claims: Claims) Q {
    var total = Q.zero();
    for (claims) |claim| total = total.add(claim);
    return total;
}

/// Mix the authenticated per-batch claims before the interaction PCS root.
/// Both producer and receiver use this exact declaration-order schedule.
pub fn mixClaimsInto(claims: Claims, instance_index: u32, channel: anytype) !void {
    const canonical = @import("../../recursion/air/universal_provider_relations.zig");
    channel.mixU32s(&.{ CLAIM_TAG, FORMAT_VERSION, instance_index, BATCH_COUNT });
    for (claims) |claim| {
        if (!canonical.secureIsCanonical(&claim)) return error.InvalidBlockRangeClaim;
        for (claim.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
    }
}

/// The table component separately proves `table_claim` over its committed
/// multiplicity and fixed tuple columns. Only after that proof and all request
/// quotients verify may this zero check be used as global byte-range closure.
pub fn closed(requests: []const Claims, table_claim: Q) bool {
    var total = table_claim;
    for (requests) |claims| total = total.add(claimTotal(claims));
    return total.isZero();
}

/// First pass: collect provider multiplicities before the fixed/main PCS
/// commitment and manifest seal. The small snapshot binds each instance to
/// the exact replay of these counts after the challenge is drawn.
pub fn collectCounter(
    a: std.mem.Allocator,
    plan: *const RangePlan,
    definition: *const component.Definition,
    trace: anytype,
    global: *table_counter.Counter,
) !CounterSnapshot {
    if (!trace.sealed or global.kind != .range_check_8_8 or global.values.len != 1 << 16)
        return error.InvalidBlockRangeGeneration;
    var local = try table_counter.Counter.init(a, .range_check_8_8);
    defer local.deinit(a);
    const scratch = try a.alloc(M, definition.arena.nodeCount());
    defer a.free(scratch);
    const direct = try a.alloc(M, definition.arena.constraintsView().len);
    defer a.free(direct);
    for (0..trace.domainSize()) |logical| {
        const row = trace.inputRow(logical);
        try evaluator.evaluate(M, &definition.arena, &row, scratch, direct);
        for (plan.sources) |source| {
            const tuple = [2]M{
                try valueAt(M, scratch, source.low),
                try valueAt(M, scratch, source.high),
            };
            try local.registerBase(try valueAt(M, scratch, source.gate), &tuple);
        }
    }
    const snapshot = counterSnapshot(&local);
    mergeCounter(global, &local);
    return snapshot;
}

pub fn counterSnapshot(counter: *const table_counter.Counter) CounterSnapshot {
    var hash = std.crypto.hash.Blake3.init(.{});
    hash.update("stwo.riscv.block.range-counter.v2\x00");
    for (counter.values) |value| {
        var word: [4]u8 = undefined;
        std.mem.writeInt(u32, &word, value.toU32(), .little);
        hash.update(&word);
    }
    var digest: CounterSnapshot = undefined;
    hash.final(&digest);
    return digest;
}

fn mergeCounter(destination: *table_counter.Counter, source: *const table_counter.Counter) void {
    std.debug.assert(destination.kind == .range_check_8_8 and source.kind == .range_check_8_8);
    for (destination.values, source.values) |*dst, value| dst.* = dst.add(value);
}

pub fn generate(
    a: std.mem.Allocator,
    plan: *const RangePlan,
    definition: *const component.Definition,
    trace: anytype,
    challenge: *const Element,
    expected_snapshot: CounterSnapshot,
) !Result {
    if (!trace.sealed or challenge.arity != 2)
        return error.InvalidBlockRangeGeneration;
    // The provider's main commitment was sealed before this challenge. This
    // private replay counter must match its first-pass snapshot exactly.
    var local_counter = try table_counter.Counter.init(a, .range_check_8_8);
    defer local_counter.deinit(a);
    const size = trace.domainSize();
    var columns: [COLUMN_COUNT][]M = undefined;
    var allocated: usize = 0;
    errdefer for (columns[0..allocated]) |column| a.free(column);
    for (&columns) |*column| {
        column.* = try a.alloc(M, size);
        allocated += 1;
    }
    var accumulators: Claims = @splat(Q.zero());
    const scratch = try a.alloc(M, definition.arena.nodeCount());
    defer a.free(scratch);
    const direct = try a.alloc(M, definition.arena.constraintsView().len);
    defer a.free(direct);
    const max_terms = CHUNK_ROWS * EVENT_COUNT;
    const denominators = try a.alloc(Q, max_terms);
    defer a.free(denominators);
    const inverses = try a.alloc(Q, max_terms);
    defer a.free(inverses);
    const numerators = try a.alloc(M, max_terms);
    defer a.free(numerators);
    var start: usize = 0;
    while (start < size) {
        const count = @min(CHUNK_ROWS, size - start);
        for (0..count) |offset| {
            const logical = start + offset;
            const row = trace.inputRow(logical);
            try evaluator.evaluate(M, &definition.arena, &row, scratch, direct);
            for (0..EVENT_COUNT) |event| {
                const term = try plan.baseTerm(scratch, event, challenge, &local_counter);
                numerators[offset * EVENT_COUNT + event] = term.numerator;
                denominators[offset * EVENT_COUNT + event] = term.denominator;
            }
        }
        try core.fields.batchInverseInPlace(Q, denominators[0 .. count * EVENT_COUNT], inverses[0 .. count * EVENT_COUNT]);
        for (0..count) |offset| {
            const logical = start + offset;
            const physical = trace_mod.committedRow(logical, trace.claim.log_size);
            for (0..BATCH_COUNT) |batch| {
                const first = offset * EVENT_COUNT + 2 * batch;
                accumulators[batch] = accumulators[batch].add(inverses[first].mulM31(numerators[first]));
                if (2 * batch + 1 < EVENT_COUNT)
                    accumulators[batch] = accumulators[batch].add(inverses[first + 1].mulM31(numerators[first + 1]));
                const limbs = accumulators[batch].toM31Array();
                for (0..4) |limb| columns[4 * batch + limb][physical] = limbs[limb];
            }
        }
        start += count;
    }
    if (!std.mem.eql(u8, &counterSnapshot(&local_counter), &expected_snapshot))
        return error.BlockRangeCounterChangedAfterSeal;
    return .{ .columns = columns, .claims = accumulators };
}
