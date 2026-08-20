//! Exact interaction columns for the pinned Stark-V opcode lookup matrices.
//!
//! Inputs are the padded, bit-reversed M31 columns committed in the main tree.
//! Every logical row is parsed once through `opcode_entries.fromMain`; relation
//! denominators are then batch-inverted in bounded chunks for all of the
//! family's declaration-order batches.

const std = @import("std");
const builtin = @import("builtin");
const fields = @import("stwo_core").fields;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const work_pool = @import("stwo_prover_engine").work_pool;
const m31 = fields.m31;
const qm31 = fields.qm31;
const packed_qm31 = fields.packed_qm31;
const M31 = m31.M31;
const QM31 = qm31.QM31;
const PackedM31 = m31.PackedM31;
const PackedQM31 = packed_qm31.PackedQM31;
const infra = @import("../../infra_trace.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const trace = @import("../../runner/trace.zig");
const BaseScalar = @import("base_scalar.zig").Scalar;
const entry = @import("entry.zig");
const opcode_entries = @import("opcode_entries.zig");
const runtime_program = @import("../extract/runtime_program.zig");
const selected_batching = @import("../lang/lookup_batch_execution.zig");
const validation = @import("opcode_interaction_validation.zig");

pub const MAX_BATCHES: usize = entry.MAX_BATCHES;
pub const MAX_COLUMNS: usize = 4 * MAX_BATCHES;
pub const CHUNK_ROWS: usize = 4096;

const base_opcode_entries = opcode_entries.Entries(BaseScalar);
const BaseList = entry.Builder(BaseScalar).List;
const BaseEntry = entry.Builder(BaseScalar).Entry;

/// Data-oriented lookup replay derived from the exact production builder.
///
/// The symbolic DAG is the same backend-neutral program consumed by CPU and
/// Metal composition. Domain tags are sampled once from the typed builder so
/// relation selection remains production-owned too. Shards of one family can
/// share a plan; no row-sized state or challenge material is retained here.
pub const Plan = struct {
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    program: prover_component.OwnedLookupPolynomialProgram,
    reachable: []bool,
    domains: [entry.MAX_ENTRIES]entry.Domain = undefined,

    pub fn init(allocator: std.mem.Allocator, family: trace.OpcodeFamily) !Plan {
        var program = try runtime_program.buildLookups(allocator, family);
        errdefer program.deinit();
        const reachable = try lookupReachable(allocator, program);
        errdefer allocator.free(reachable);

        const zero_columns = [_]BaseScalar{BaseScalar.zero()} ** trace.MAX_FAMILY_COLUMNS;
        const typed = try base_opcode_entries.fromMain(
            family,
            zero_columns[0..trace.nColumnsForFamily(family)],
        );
        if (typed.len != program.entries.len or typed.batch_size != program.batch_size)
            return error.InvalidLookupPolynomialProgram;
        var result = Plan{
            .allocator = allocator,
            .family = family,
            .program = program,
            .reachable = reachable,
        };
        for (typed.entries[0..typed.len], result.domains[0..typed.len]) |source, *domain| {
            try source.validate();
            domain.* = source.domain;
        }
        return result;
    }

    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.reachable);
        self.program.deinit();
        self.* = undefined;
    }
};

pub const Result = struct {
    columns: [MAX_COLUMNS][]M31 = .{&.{}} ** MAX_COLUMNS,
    claims: [MAX_BATCHES]QM31 = .{QM31.zero()} ** MAX_BATCHES,
    n_batches: usize,

    pub fn nColumns(self: *const Result) usize {
        return 4 * self.n_batches;
    }

    pub fn total(self: *const Result) QM31 {
        var result = QM31.zero();
        for (self.claims[0..self.n_batches]) |claim| result = result.add(claim);
        return result;
    }

    /// Moves the current cumulative columns out for commitment. The returned
    /// active prefix is caller-owned and claims remain available afterwards.
    pub fn takeColumns(self: *Result) [MAX_COLUMNS][]M31 {
        const result = self.columns;
        for (self.columns[0..self.nColumns()]) |*column| column.* = &.{};
        return result;
    }

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        for (self.columns[0..self.nColumns()]) |column| {
            if (column.len != 0) allocator.free(column);
        }
        self.* = undefined;
    }
};

pub fn nColumns(family: trace.OpcodeFamily) usize {
    return opcode_entries.interactionColumnCount(family);
}

/// Generate all declaration-order cumulative columns for one opcode shard.
/// `main_columns` contains only the canonical family witness columns; derived
/// host-side bus columns are neither accepted nor needed.
pub fn generate(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    main_columns: []const []const M31,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !Result {
    return generateSequential(
        allocator,
        family,
        main_columns,
        log_size,
        relations,
        CompatibilityBatching{},
        opcode_entries.batchCount(family),
    );
}

/// Shadow candidate using the authenticated compiler-selected batch plan.
/// This deliberately returns the existing `Result` shape so trace/claim and
/// allocation differentials can run before any statement or proof protocol is
/// versioned. It is not selected by production orchestration.
pub fn generateSelected(
    allocator: std.mem.Allocator,
    family_plan: *const selected_batching.FamilyPlan,
    main_columns: []const []const M31,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !Result {
    try family_plan.validate();
    return generateSequential(
        allocator,
        family_plan.family,
        main_columns,
        log_size,
        relations,
        SelectedBatching{ .plan = family_plan },
        family_plan.batchCount(),
    );
}

/// Production-shaped selected generator over the static physical record. The
/// hot row loop reads only pinned contiguous ranges; setup performs no planner
/// or typed-arena work.
pub fn generateSelectedRangesV2(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    entry_count: u32,
    batches: []const prover_component.LookupPolynomialBatchV2,
    main_columns: []const []const M31,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !Result {
    var cursor: u32 = 0;
    for (batches) |batch| {
        if (batch.first_entry != cursor or
            batch.entry_count == 0 or
            batch.entry_count > 2)
        {
            return error.InvalidBatchCount;
        }
        cursor = std.math.add(u32, cursor, batch.entry_count) catch
            return error.InvalidBatchCount;
    }
    if (cursor != entry_count) return error.InvalidBatchCount;
    return generateSequential(
        allocator,
        family,
        main_columns,
        log_size,
        relations,
        PhysicalBatching{
            .entry_count = entry_count,
            .batches = batches,
        },
        batches.len,
    );
}

const CompatibilityBatching = struct {
    fn validateList(
        _: @This(),
        list: *const BaseList,
        expected_batches: usize,
    ) !void {
        if (list.batchCount() != expected_batches)
            return error.InvalidBatchCount;
    }

    fn rowPair(
        _: @This(),
        list: *const BaseList,
        batch: usize,
        relations: *const relations_mod.Relations,
    ) !logup.RowPair {
        return pairBase(list, batch, relations);
    }

    fn isSingleton(
        _: @This(),
        list: *const BaseList,
        batch: usize,
    ) bool {
        return list.batch_size == 1 or
            batch * list.batch_size + 1 == list.len;
    }
};

const SelectedBatching = struct {
    plan: *const selected_batching.FamilyPlan,

    fn validateList(
        self: @This(),
        list: *const BaseList,
        expected_batches: usize,
    ) !void {
        if (list.len != self.plan.selection.event_count or
            self.plan.batchCount() != expected_batches)
        {
            return error.InvalidBatchCount;
        }
    }

    fn rowPair(
        self: @This(),
        list: *const BaseList,
        batch: usize,
        relations: *const relations_mod.Relations,
    ) !logup.RowPair {
        return pairBaseSelected(
            list,
            self.plan.selection.batches[batch],
            relations,
        );
    }

    fn isSingleton(
        self: @This(),
        _: *const BaseList,
        batch: usize,
    ) bool {
        return self.plan.selection.batches[batch].event_count == 1;
    }
};

const PhysicalBatching = struct {
    entry_count: u32,
    batches: []const prover_component.LookupPolynomialBatchV2,

    fn validateList(
        self: @This(),
        list: *const BaseList,
        expected_batches: usize,
    ) !void {
        if (list.len != self.entry_count or
            self.batches.len != expected_batches)
        {
            return error.InvalidBatchCount;
        }
    }

    fn rowPair(
        self: @This(),
        list: *const BaseList,
        batch: usize,
        relations: *const relations_mod.Relations,
    ) !logup.RowPair {
        const range = self.batches[batch];
        return pairBaseRange(
            list,
            range.first_entry,
            range.entry_count,
            relations,
        );
    }

    fn isSingleton(
        self: @This(),
        _: *const BaseList,
        batch: usize,
    ) bool {
        return self.batches[batch].entry_count == 1;
    }
};

fn generateSequential(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    main_columns: []const []const M31,
    log_size: u32,
    relations: *const relations_mod.Relations,
    batching: anytype,
    n_batches: usize,
) !Result {
    const size = @as(usize, 1) << @intCast(log_size);
    try validateColumns(family, main_columns, size);
    if (n_batches == 0 or n_batches > MAX_BATCHES)
        return error.InvalidBatchCount;
    var result = Result{ .n_batches = n_batches };
    var allocated_columns: usize = 0;
    errdefer {
        for (result.columns[0..allocated_columns]) |column| allocator.free(column);
    }
    for (result.columns[0 .. 4 * n_batches]) |*column| {
        column.* = try allocator.alloc(M31, size);
        allocated_columns += 1;
    }
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    const chunk_capacity = @min(size, CHUNK_ROWS);
    const term_capacity = n_batches * chunk_capacity;
    const numerators = try allocator.alloc(QM31, term_capacity);
    defer allocator.free(numerators);
    const denominators = try allocator.alloc(QM31, term_capacity);
    defer allocator.free(denominators);
    const inverses = try allocator.alloc(QM31, term_capacity);
    defer allocator.free(inverses);

    var base: [trace.MAX_FAMILY_COLUMNS]BaseScalar = undefined;
    var row_start: usize = 0;
    while (row_start < size) {
        const chunk_len = @min(CHUNK_ROWS, size - row_start);
        const term_len = n_batches * chunk_len;
        for (0..chunk_len) |local_row| {
            const row = row_start + local_row;
            const committed_row = placement.map(row);
            for (main_columns, base[0..main_columns.len]) |column, *value| {
                value.* = BaseScalar.fromBase(column[committed_row]);
            }
            const list = try base_opcode_entries.fromMain(
                family,
                base[0..main_columns.len],
            );
            try batching.validateList(&list, n_batches);
            for (0..n_batches) |batch| {
                const pair = try batching.rowPair(&list, batch, relations);
                const index = batch * chunk_len + local_row;
                if (batching.isSingleton(&list, batch)) {
                    denominators[index] = pair.d1;
                    numerators[index] = pair.n1;
                } else {
                    denominators[index] = pair.d1.mul(pair.d2);
                    numerators[index] = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
                }
            }
        }
        try fields.batchInverseInPlace(
            QM31,
            denominators[0..term_len],
            inverses[0..term_len],
        );
        for (0..n_batches) |batch| {
            for (0..chunk_len) |local_row| {
                const row = row_start + local_row;
                const term_index = batch * chunk_len + local_row;
                result.claims[batch] = result.claims[batch].add(
                    numerators[term_index].mul(inverses[term_index]),
                );
                const coordinates = result.claims[batch].toM31Array();
                const dst = placement.map(row);
                for (coordinates, 0..) |coordinate, index| {
                    result.columns[4 * batch + index][dst] = coordinate;
                }
            }
        }
        row_start += chunk_len;
    }

    return result;
}

/// Parallel two-level prefix scan over one opcode family. Tuple reconstruction
/// first walks committed rows so every witness-column read is contiguous. A
/// second, much narrower pass scans the resulting fraction terms in logical
/// trace order; an ordered scan of chunk totals then drives a disjoint offset
/// pass. This trades random reads of every main column for random reads of one
/// secure term per batch while preserving the exact logical addition order.
pub fn generateParallel(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    main_columns: []const []const M31,
    log_size: u32,
    relations: *const relations_mod.Relations,
    pool: *work_pool.WorkPool,
) !Result {
    var plan = try Plan.init(allocator, family);
    defer plan.deinit();
    return generateParallelPlanned(
        allocator,
        &plan,
        main_columns,
        log_size,
        relations,
        pool,
    );
}

/// Parallel generation with a family plan retained across statement shards.
pub fn generateParallelPlanned(
    allocator: std.mem.Allocator,
    plan: *const Plan,
    main_columns: []const []const M31,
    log_size: u32,
    relations: *const relations_mod.Relations,
    pool: *work_pool.WorkPool,
) !Result {
    const family = plan.family;
    const size = @as(usize, 1) << @intCast(log_size);
    try validateColumns(family, main_columns, size);
    const n_batches = opcode_entries.batchCount(family);
    var result = Result{ .n_batches = n_batches };
    var allocated_columns: usize = 0;
    errdefer for (result.columns[0..allocated_columns]) |column| allocator.free(column);
    for (result.columns[0 .. 4 * n_batches]) |*column| {
        column.* = try allocator.alloc(M31, size);
        allocated_columns += 1;
    }
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    const trace_sums = try allocator.alloc(QM31, n_batches * size);
    defer allocator.free(trace_sums);

    const chunk_count = std.math.divCeil(usize, size, CHUNK_ROWS) catch unreachable;
    const chunks = try allocator.alloc(OpcodeChunk, chunk_count);
    defer allocator.free(chunks);
    for (chunks, 0..) |*chunk, index| {
        const row_start = index * CHUNK_ROWS;
        chunk.* = .{
            .allocator = allocator,
            .family = family,
            .plan = plan,
            .main_columns = main_columns,
            .relations = relations,
            .placement = placement,
            .trace_sums = trace_sums,
            .trace_size = size,
            .n_batches = n_batches,
            .row_start = row_start,
            .row_end = @min(size, row_start + CHUNK_ROWS),
        };
    }

    var wait_group = std.Thread.WaitGroup{};
    for (chunks[1..]) |*chunk| pool.spawnWg(&wait_group, OpcodeChunk.generate, .{chunk});
    OpcodeChunk.generate(&chunks[0]);
    wait_group.wait();
    for (chunks) |chunk| if (chunk.err) |err| return err;

    wait_group = .{};
    for (chunks[1..]) |*chunk| pool.spawnWg(&wait_group, OpcodeChunk.scan, .{chunk});
    OpcodeChunk.scan(&chunks[0]);
    wait_group.wait();
    for (chunks) |chunk| if (chunk.err) |err| return err;

    for (0..n_batches) |batch| {
        var claim = QM31.zero();
        for (chunks) |*chunk| {
            chunk.offsets[batch] = claim;
            claim = claim.add(chunk.totals[batch]);
        }
        result.claims[batch] = claim;
    }

    // Local scans are trace-order contiguous. Transpose them into committed
    // order once, after chunk offsets are known, so workers write disjoint
    // contiguous output ranges instead of repeatedly scattering bit-reversed
    // rows and then reading those same cache lines back for the offset pass.
    const logical_rows = try allocator.alloc(usize, size);
    defer allocator.free(logical_rows);
    for (placement.mapping, 0..) |committed_row, logical_row| {
        logical_rows[committed_row] = logical_row;
    }
    const placement_workers = try allocator.alloc(PlacementWorker, chunk_count);
    defer allocator.free(placement_workers);
    for (placement_workers, 0..) |*worker, index| {
        worker.* = .{
            .columns = &result.columns,
            .trace_sums = trace_sums,
            .logical_rows = logical_rows,
            .chunks = chunks,
            .n_batches = n_batches,
            .trace_size = size,
            .committed_start = size * index / chunk_count,
            .committed_end = size * (index + 1) / chunk_count,
        };
    }
    wait_group = .{};
    for (placement_workers[1..]) |*worker|
        pool.spawnWg(&wait_group, PlacementWorker.run, .{worker});
    PlacementWorker.run(&placement_workers[0]);
    wait_group.wait();
    return result;
}

const OpcodeChunk = struct {
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    plan: *const Plan,
    main_columns: []const []const M31,
    relations: *const relations_mod.Relations,
    placement: infra.BitReversalTable,
    trace_sums: []QM31,
    trace_size: usize,
    n_batches: usize,
    row_start: usize,
    row_end: usize,
    totals: [MAX_BATCHES]QM31 = .{QM31.zero()} ** MAX_BATCHES,
    offsets: [MAX_BATCHES]QM31 = .{QM31.zero()} ** MAX_BATCHES,
    err: ?anyerror = null,

    fn generate(self: *@This()) void {
        self.generateFallible() catch |err| {
            self.err = err;
        };
    }

    fn generateFallible(self: *@This()) !void {
        const chunk_len = self.row_end - self.row_start;
        const term_len = self.n_batches * chunk_len;
        const numerators = try self.allocator.alloc(QM31, term_len);
        defer self.allocator.free(numerators);
        const denominators = try self.allocator.alloc(QM31, term_len);
        defer self.allocator.free(denominators);
        const inverses = try self.allocator.alloc(QM31, term_len);
        defer self.allocator.free(inverses);
        const node_values = try self.allocator.alloc(PackedM31, self.plan.program.nodes.len);
        defer self.allocator.free(node_values);

        std.debug.assert(chunk_len % m31.PACK_WIDTH == 0);
        var base: [trace.MAX_FAMILY_COLUMNS]PackedM31 = undefined;
        var local_row: usize = 0;
        while (local_row < chunk_len) : (local_row += m31.PACK_WIDTH) {
            for (self.main_columns, base[0..self.main_columns.len]) |column, *value| {
                value.* = m31.loadPacked(column.ptr + self.row_start + local_row);
            }
            evaluateNodes(
                self.plan.program.nodes,
                self.plan.reachable,
                node_values,
                base[0..self.main_columns.len],
            );
            for (0..self.n_batches) |batch| {
                const pair = try pairPlanned(self.plan, node_values, batch, self.relations);
                const denominator = if (self.plan.program.batch_size == 1)
                    pair.d1
                else
                    pair.d1.mul(pair.d2);
                const numerator = if (self.plan.program.batch_size == 1)
                    PackedQM31.fromBase(pair.n1)
                else
                    pair.d2.mulBase(pair.n1).add(pair.d1.mulBase(pair.n2));
                inline for (0..m31.PACK_WIDTH) |lane| {
                    const index = batch * chunk_len + local_row + lane;
                    denominators[index] = denominator.lane(lane);
                    numerators[index] = numerator.lane(lane);
                }
            }
        }
        try fields.batchInverseInPlace(QM31, denominators, inverses);

        for (0..self.n_batches) |batch| {
            for (0..chunk_len) |row_offset| {
                const term_index = batch * chunk_len + row_offset;
                self.trace_sums[batch * self.trace_size + self.row_start + row_offset] =
                    numerators[term_index].mul(inverses[term_index]);
            }
        }
    }

    fn scan(self: *@This()) void {
        self.scanFallible() catch |err| {
            self.err = err;
        };
    }

    fn scanFallible(self: *@This()) !void {
        for (0..self.n_batches) |batch| {
            var accumulator = QM31.zero();
            for (self.row_start..self.row_end) |logical_row| {
                const committed_row = self.placement.map(logical_row);
                const index = batch * self.trace_size + committed_row;
                accumulator = accumulator.add(self.trace_sums[index]);
                self.trace_sums[index] = accumulator;
            }
            self.totals[batch] = accumulator;
        }
    }
};

const PlacementWorker = struct {
    columns: *[MAX_COLUMNS][]M31,
    trace_sums: []const QM31,
    logical_rows: []const usize,
    chunks: []const OpcodeChunk,
    n_batches: usize,
    trace_size: usize,
    committed_start: usize,
    committed_end: usize,

    fn run(self: *@This()) void {
        for (0..self.n_batches) |batch| {
            for (self.committed_start..self.committed_end) |committed_row| {
                const logical_row = self.logical_rows[committed_row];
                const offset = self.chunks[logical_row / CHUNK_ROWS].offsets[batch];
                const current = self.trace_sums[batch * self.trace_size + committed_row]
                    .add(offset).toM31Array();
                for (current, 0..) |coordinate, index| {
                    self.columns[4 * batch + index][committed_row] = coordinate;
                }
            }
        }
    }
};

fn unwrapValues(comptime arity: usize, values: [arity]BaseScalar) [arity]M31 {
    var result: [arity]M31 = undefined;
    for (values, &result) |value, *dst| dst.* = value.value;
    return result;
}

fn denominatorBase(
    relation_entry: *const BaseEntry,
    relations: *const relations_mod.Relations,
) !QM31 {
    try relation_entry.validate();
    return switch (relation_entry.domain) {
        .registers_state => relations.registers_state.combineBase(
            unwrapValues(2, relation_entry.values[0..2].*),
        ),
        .memory_access => relations.memory_access.combineBase(
            unwrapValues(7, relation_entry.values[0..7].*),
        ),
        .program_access => relations.program_access.combineBase(
            unwrapValues(5, relation_entry.values[0..5].*),
        ),
        .merkle => relations.merkle.combineBase(
            unwrapValues(4, relation_entry.values[0..4].*),
        ),
        .poseidon2 => relations.poseidon2.combineBase(
            unwrapValues(16, relation_entry.values[0..16].*),
        ),
        .poseidon2_io => relations.poseidon2_io.combineBase(
            unwrapValues(32, relation_entry.values[0..32].*),
        ),
        .bitwise => relations.bitwise.combineBase(
            unwrapValues(4, relation_entry.values[0..4].*),
        ),
        .range_check_20 => relations.range_check_20.combineBase(
            unwrapValues(1, relation_entry.values[0..1].*),
        ),
        .range_check_8_11 => relations.range_check_8_11.combineBase(
            unwrapValues(2, relation_entry.values[0..2].*),
        ),
        .range_check_8_8_4 => relations.range_check_8_8_4.combineBase(
            unwrapValues(3, relation_entry.values[0..3].*),
        ),
        .range_check_8_8 => relations.range_check_8_8.combineBase(
            unwrapValues(2, relation_entry.values[0..2].*),
        ),
        .range_check_m31 => relations.range_check_m31.combineBase(
            unwrapValues(2, relation_entry.values[0..2].*),
        ),
    };
}

fn pairBase(
    list: *const BaseList,
    batch: usize,
    relations: *const relations_mod.Relations,
) !logup.RowPair {
    const first = &list.entries[batch * list.batch_size];
    const first_numerator = QM31.fromBase(first.numerator.value);
    if (list.batch_size == 1 or batch * list.batch_size + 1 == list.len) {
        return logup.RowPair.single(
            first_numerator,
            try denominatorBase(first, relations),
        );
    }
    const second = &list.entries[batch * list.batch_size + 1];
    return .{
        .n1 = first_numerator,
        .d1 = try denominatorBase(first, relations),
        .n2 = QM31.fromBase(second.numerator.value),
        .d2 = try denominatorBase(second, relations),
    };
}

fn pairBaseSelected(
    list: *const BaseList,
    batch: @import("../lang/lookup_batch_planner.zig").Batch,
    relations: *const relations_mod.Relations,
) !logup.RowPair {
    return pairBaseRange(
        list,
        batch.first_event,
        batch.event_count,
        relations,
    );
}

fn pairBaseRange(
    list: *const BaseList,
    first_event: u32,
    event_count: u8,
    relations: *const relations_mod.Relations,
) !logup.RowPair {
    const first_index: usize = first_event;
    if (event_count == 0 or event_count > 2 or
        first_index >= list.len or first_index + event_count > list.len)
    {
        return error.InvalidBatchCount;
    }
    const first = &list.entries[first_index];
    const first_numerator = QM31.fromBase(first.numerator.value);
    if (event_count == 1) {
        return logup.RowPair.single(
            first_numerator,
            try denominatorBase(first, relations),
        );
    }
    const second = &list.entries[first_index + 1];
    return .{
        .n1 = first_numerator,
        .d1 = try denominatorBase(first, relations),
        .n2 = QM31.fromBase(second.numerator.value),
        .d2 = try denominatorBase(second, relations),
    };
}

const PackedRowPair = struct {
    n1: PackedM31,
    d1: PackedQM31,
    n2: PackedM31,
    d2: PackedQM31,
};

fn combinePlanned(
    comptime arity: usize,
    lookup: prover_component.LookupPolynomialEntry,
    nodes: []const PackedM31,
    relation: anytype,
) PackedQM31 {
    var result = PackedQM31.zero();
    inline for (0..arity) |value_index| {
        result = result.add(
            PackedQM31.splat(relation.alpha_powers[value_index])
                .mulBase(nodes[lookup.values[value_index]]),
        );
    }
    return result.sub(PackedQM31.splat(relation.z));
}

fn denominatorPlanned(
    lookup: prover_component.LookupPolynomialEntry,
    domain: entry.Domain,
    nodes: []const PackedM31,
    relations: *const relations_mod.Relations,
) !PackedQM31 {
    if (lookup.arity != entry.expectedArity(domain))
        return error.InvalidLookupPolynomialProgram;
    return switch (domain) {
        .registers_state => combinePlanned(2, lookup, nodes, relations.registers_state),
        .memory_access => combinePlanned(7, lookup, nodes, relations.memory_access),
        .program_access => combinePlanned(5, lookup, nodes, relations.program_access),
        .merkle => combinePlanned(4, lookup, nodes, relations.merkle),
        .poseidon2 => combinePlanned(16, lookup, nodes, relations.poseidon2),
        .poseidon2_io => combinePlanned(32, lookup, nodes, relations.poseidon2_io),
        .bitwise => combinePlanned(4, lookup, nodes, relations.bitwise),
        .range_check_20 => combinePlanned(1, lookup, nodes, relations.range_check_20),
        .range_check_8_11 => combinePlanned(2, lookup, nodes, relations.range_check_8_11),
        .range_check_8_8_4 => combinePlanned(3, lookup, nodes, relations.range_check_8_8_4),
        .range_check_8_8 => combinePlanned(2, lookup, nodes, relations.range_check_8_8),
        .range_check_m31 => combinePlanned(2, lookup, nodes, relations.range_check_m31),
    };
}

fn pairPlanned(
    plan: *const Plan,
    nodes: []const PackedM31,
    batch: usize,
    relations: *const relations_mod.Relations,
) !PackedRowPair {
    const program = plan.program;
    const first_index = batch * program.batch_size;
    if (first_index >= program.entries.len) return error.InvalidBatchCount;
    const first = program.entries[first_index];
    if (program.batch_size == 1 or first_index + 1 == program.entries.len) {
        return .{
            .n1 = nodes[first.numerator],
            .d1 = try denominatorPlanned(first, plan.domains[first_index], nodes, relations),
            .n2 = @splat(0),
            .d2 = PackedQM31.one(),
        };
    }
    const second_index = first_index + 1;
    const second = program.entries[second_index];
    return .{
        .n1 = nodes[first.numerator],
        .d1 = try denominatorPlanned(first, plan.domains[first_index], nodes, relations),
        .n2 = nodes[second.numerator],
        .d2 = try denominatorPlanned(second, plan.domains[second_index], nodes, relations),
    };
}

const evaluateNodes = validation.evaluateNodes;
const lookupReachable = validation.lookupReachable;
const validateColumns = validation.validateColumns;

/// Narrow test-only access to production-private reconstruction primitives.
///
/// The release module exposes an empty struct; the package test binary uses
/// these hooks to compare the packed DAG against the typed scalar authority.
pub const TestHooks = if (builtin.is_test) struct {
    pub const baseOpcodeEntries = base_opcode_entries;
    pub const pairBaseForTest = pairBase;
    pub const pairPlannedForTest = pairPlanned;
    pub const evaluateNodesForTest = evaluateNodes;
} else struct {};
