//! Exact interaction columns for the pinned Stark-V opcode lookup matrices.
//!
//! Inputs are the padded, bit-reversed M31 columns committed in the main tree.
//! Every logical row is parsed once through `opcode_entries.fromMain`; relation
//! denominators are then batch-inverted in bounded chunks for all of the
//! family's declaration-order batches.

const std = @import("std");
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
    const size = @as(usize, 1) << @intCast(log_size);
    try validateColumns(family, main_columns, size);
    const n_batches = opcode_entries.batchCount(family);
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
            if (list.batchCount() != n_batches) return error.InvalidBatchCount;
            for (0..n_batches) |batch| {
                const pair = try pairBase(&list, batch, relations);
                const index = batch * chunk_len + local_row;
                if (list.batch_size == 1) {
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

/// Parallel two-level prefix scan over one opcode family. Each bounded chunk
/// performs tuple reconstruction, batch inversion and a local inclusive scan;
/// an ordered scan of the chunk totals then drives a disjoint offset pass.
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
            var committed_rows: [m31.PACK_WIDTH]usize = undefined;
            inline for (0..m31.PACK_WIDTH) |lane| {
                committed_rows[lane] = self.placement.map(self.row_start + local_row + lane);
            }
            for (self.main_columns, base[0..self.main_columns.len]) |column, *value| {
                var lane_values: PackedM31 = undefined;
                inline for (0..m31.PACK_WIDTH) |lane| {
                    lane_values[lane] = column[committed_rows[lane]].v;
                }
                value.* = lane_values;
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
            var accumulator = QM31.zero();
            for (0..chunk_len) |row_offset| {
                const term_index = batch * chunk_len + row_offset;
                accumulator = accumulator.add(numerators[term_index].mul(inverses[term_index]));
                self.trace_sums[batch * self.trace_size + self.row_start + row_offset] = accumulator;
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
                const current = self.trace_sums[batch * self.trace_size + logical_row]
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

fn evaluateNodes(
    nodes: []const prover_component.BasePolynomialNode,
    reachable: []const bool,
    values: []PackedM31,
    columns: []const PackedM31,
) void {
    for (nodes, reachable, 0..) |node, is_reachable, index| {
        if (!is_reachable) continue;
        values[index] = switch (node.op) {
            .constant => @splat(node.value),
            .column => columns[node.value],
            .add => m31.addPacked(values[node.lhs], values[node.rhs]),
            .sub => m31.subPacked(values[node.lhs], values[node.rhs]),
            .mul => m31.mulPacked(values[node.lhs], values[node.rhs]),
            .neg => m31.negPacked(values[node.lhs]),
        };
    }
}

fn lookupReachable(
    allocator: std.mem.Allocator,
    program: prover_component.OwnedLookupPolynomialProgram,
) ![]bool {
    const reachable = try allocator.alloc(bool, program.nodes.len);
    @memset(reachable, false);
    for (program.entries) |lookup| {
        reachable[lookup.numerator] = true;
        for (lookup.values[0..lookup.arity]) |value| reachable[value] = true;
    }
    var cursor = program.nodes.len;
    while (cursor != 0) {
        cursor -= 1;
        if (!reachable[cursor]) continue;
        const node = program.nodes[cursor];
        switch (node.op) {
            .constant, .column => {},
            .add, .sub, .mul => {
                reachable[node.lhs] = true;
                reachable[node.rhs] = true;
            },
            .neg => reachable[node.lhs] = true,
        }
    }
    return reachable;
}

fn validateColumns(
    family: trace.OpcodeFamily,
    columns: []const []const M31,
    size: usize,
) !void {
    if (columns.len != trace.nColumnsForFamily(family))
        return error.InvalidColumnCount;
    for (columns) |column| {
        if (column.len != size) return error.InvalidColumnLength;
    }
}

fn testRow() trace.TraceRow {
    return .{
        .clk = 1,
        .pc = 0x1000,
        .opcode = .ADDI,
        .rd = 1,
        .rs1 = 0,
        .rs2 = 0,
        .imm = 1,
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_val = 1,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x1004,
        .inst_word = 0x00100093,
    };
}

const TestColumns = struct {
    storage: [trace.MAX_FAMILY_COLUMNS][]M31,
    len: usize,
};

fn testColumns(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    log_size: u32,
    rows: []const trace.TraceRow,
) !TestColumns {
    const len = trace.nColumnsForFamily(family);
    const size = @as(usize, 1) << @intCast(log_size);
    var result = TestColumns{ .storage = undefined, .len = len };
    var initialized: usize = 0;
    errdefer for (result.storage[0..initialized]) |column| allocator.free(column);
    for (result.storage[0..len]) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    if (rows.len > size) return error.InvalidTraceShape;
    for (rows, 0..) |row, index| {
        trace.fillFamilyColumns(&result.storage, placement.map(index), row, family);
    }
    return result;
}

fn freeTestColumns(
    allocator: std.mem.Allocator,
    columns: anytype,
) void {
    for (columns.storage[0..columns.len]) |column| allocator.free(column);
}

fn pairTerm(pair: logup.RowPair) !QM31 {
    const denominator = pair.d1.mul(pair.d2);
    const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    return numerator.mul(try denominator.inv());
}

fn expectBaseEntryParity(
    family: trace.OpcodeFamily,
    main: []const []const M31,
    committed_row: usize,
    relations: *const relations_mod.Relations,
) !void {
    var base: [trace.MAX_FAMILY_COLUMNS]BaseScalar = undefined;
    var secure: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
    for (main, base[0..main.len], secure[0..main.len]) |column, *base_value, *secure_value| {
        const value = column[committed_row];
        base_value.* = BaseScalar.fromBase(value);
        secure_value.* = QM31.fromBase(value);
    }
    const actual = try base_opcode_entries.fromMain(family, base[0..main.len]);
    const oracle = try opcode_entries.fromMain(family, secure[0..main.len]);
    try std.testing.expectEqual(oracle.len, actual.len);
    try std.testing.expectEqual(oracle.batch_size, actual.batch_size);
    for (actual.entries[0..actual.len], oracle.entries[0..oracle.len]) |got, want| {
        try std.testing.expectEqual(want.domain, got.domain);
        try std.testing.expectEqual(want.arity, got.arity);
        try std.testing.expectEqual(want.role, got.role);
        try std.testing.expectEqual(want.access_ordinal, got.access_ordinal);
        try std.testing.expect(QM31.fromBase(got.numerator.value).eql(want.numerator));
        for (got.values[0..got.arity], want.values[0..want.arity]) |got_value, want_value| {
            try std.testing.expect(QM31.fromBase(got_value.value).eql(want_value));
        }
    }
    try std.testing.expectEqual(oracle.batchCount(), actual.batchCount());
    for (0..actual.batchCount()) |batch| {
        const got = try pairBase(&actual, batch, relations);
        const want = try oracle.pair(batch, relations);
        try std.testing.expect(got.n1.eql(want.n1));
        try std.testing.expect(got.d1.eql(want.d1));
        try std.testing.expect(got.n2.eql(want.n2));
        try std.testing.expect(got.d2.eql(want.d2));
    }
}

fn expectPlanPairParity(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    main: []const []const M31,
    committed_active_row: usize,
    committed_padding_row: usize,
    relations: *const relations_mod.Relations,
) !void {
    var plan = try Plan.init(allocator, family);
    defer plan.deinit();
    const node_values = try allocator.alloc(PackedM31, plan.program.nodes.len);
    defer allocator.free(node_values);
    var packed_columns: [trace.MAX_FAMILY_COLUMNS]PackedM31 = undefined;
    for (main, packed_columns[0..main.len]) |column, *packed_column| {
        inline for (0..m31.PACK_WIDTH) |lane| {
            const row = if (lane % 2 == 0) committed_active_row else committed_padding_row;
            packed_column[lane] = column[row].v;
        }
    }
    evaluateNodes(
        plan.program.nodes,
        plan.reachable,
        node_values,
        packed_columns[0..main.len],
    );

    inline for (0..m31.PACK_WIDTH) |lane| {
        const row = if (lane % 2 == 0) committed_active_row else committed_padding_row;
        var scalar_columns: [trace.MAX_FAMILY_COLUMNS]BaseScalar = undefined;
        for (main, scalar_columns[0..main.len]) |column, *value| {
            value.* = BaseScalar.fromBase(column[row]);
        }
        const typed = try base_opcode_entries.fromMain(family, scalar_columns[0..main.len]);
        for (0..typed.batchCount()) |batch| {
            const expected = try pairBase(&typed, batch, relations);
            const actual = try pairPlanned(&plan, node_values, batch, relations);
            try std.testing.expect(QM31.fromBase(M31.fromCanonical(actual.n1[lane])).eql(expected.n1));
            try std.testing.expect(actual.d1.lane(lane).eql(expected.d1));
            try std.testing.expect(QM31.fromBase(M31.fromCanonical(actual.n2[lane])).eql(expected.n2));
            try std.testing.expect(actual.d2.lane(lane).eql(expected.d2));
        }
    }
}

fn testRowForFamily(family: trace.OpcodeFamily, row_index: usize) trace.TraceRow {
    var row = testRow();
    row.clk = @intCast(row_index + 1);
    row.pc = @intCast(0x1000 + 4 * row_index);
    row.next_pc = row.pc + 4;
    row.rs1_prev_clk = row.clk - 1;
    row.rs2_prev_clk = row.clk - 1;
    row.rd_prev_clk = row.clk - 1;
    row.rd_prev_val = 0;
    row.rd = 1;
    row.rs1 = 2;
    row.rs2 = 3;
    switch (family) {
        .base_alu_reg => {
            row.opcode = .ADD;
            row.rs1_val = 1;
            row.rs2_val = 2;
            row.rd_val = 3;
        },
        .base_alu_imm => {
            row.opcode = .ADDI;
            row.rs1_val = 2;
            row.imm = 1;
            row.rd_val = 3;
        },
        .shifts_reg => {
            row.opcode = .SLL;
            row.rs1_val = 3;
            row.rs2_val = 1;
            row.rd_val = 6;
        },
        .shifts_imm => {
            row.opcode = .SLLI;
            row.rs1_val = 3;
            row.imm = 1;
            row.rd_val = 6;
        },
        .lt_reg => {
            row.opcode = .SLTU;
            row.rs1_val = 1;
            row.rs2_val = 2;
            row.rd_val = 1;
        },
        .lt_imm => {
            row.opcode = .SLTIU;
            row.rs1_val = 1;
            row.imm = 2;
            row.rd_val = 1;
        },
        .branch_eq => {
            row.opcode = .BNE;
            row.rs1_val = 1;
            row.rs2_val = 2;
            row.imm = 8;
            row.branch_taken = true;
            row.next_pc = row.pc + 8;
        },
        .branch_lt => {
            row.opcode = .BLTU;
            row.rs1_val = 1;
            row.rs2_val = 2;
            row.imm = 8;
            row.branch_taken = true;
            row.next_pc = row.pc + 8;
        },
        .lui => {
            row.opcode = .LUI;
            row.imm = 0x1234_5000;
            row.rd_val = 0x1234_5000;
        },
        .auipc => {
            row.opcode = .AUIPC;
            row.imm = 0x1000;
            row.rd_val = row.pc + 0x1000;
        },
        .jalr => {
            row.opcode = .JALR;
            row.rs1_val = 0x2000;
            row.imm = 4;
            row.rd_val = row.pc + 4;
            row.next_pc = 0x2004;
        },
        .jal => {
            row.opcode = .JAL;
            row.imm = 8;
            row.rd_val = row.pc + 4;
            row.next_pc = row.pc + 8;
        },
        .load_store => {
            row.opcode = .LW;
            row.rs1_val = 0x2000;
            row.imm = 0;
            row.mem_addr = 0x2000;
            row.mem_val = 0x1122_3344;
            row.mem_prev_word = 0x1122_3344;
            row.mem_next_word = 0x1122_3344;
            row.rd_val = 0x1122_3344;
            row.is_load = true;
        },
        .mul => {
            row.opcode = .MUL;
            row.rs1_val = 2;
            row.rs2_val = 3;
            row.rd_val = 6;
        },
        .mulh => {
            row.opcode = .MULHU;
            row.rs1_val = 0x1_0000;
            row.rs2_val = 0x1_0000;
            row.rd_val = 1;
        },
        .div => {
            row.opcode = .DIVU;
            row.rs1_val = 7;
            row.rs2_val = 3;
            row.rd_val = 2;
        },
        .fence => {
            row.opcode = .FENCE;
            row.rd = 0;
            row.rs1 = 0;
            row.imm = 0x0ff;
            row.inst_word = 0x0ff0000f;
        },
    }
    return row;
}

fn secureAt(columns: []const []const M31, offset: usize, row: usize) QM31 {
    return QM31.fromM31(
        columns[offset][row],
        columns[offset + 1][row],
        columns[offset + 2][row],
        columns[offset + 3][row],
    );
}

fn expectScalarParity(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    row: trace.TraceRow,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !void {
    var main = try testColumns(allocator, family, log_size, &.{row});
    defer freeTestColumns(allocator, main);
    var generated = try generate(
        allocator,
        family,
        main.storage[0..main.len],
        log_size,
        relations,
    );
    defer generated.deinit(allocator);
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    const size = @as(usize, 1) << @intCast(log_size);
    const oracle = try opcode_entries.fromTraceRow(row, family);
    var accumulators = [_]QM31{QM31.zero()} ** MAX_BATCHES;
    var secure_row: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;

    for (0..size) |logical_row| {
        const committed_row = placement.map(logical_row);
        for (main.storage[0..main.len], secure_row[0..main.len]) |column, *value| {
            value.* = QM31.fromBase(column[committed_row]);
        }
        const actual_entries = try opcode_entries.fromMain(family, secure_row[0..main.len]);
        try std.testing.expectEqual(generated.n_batches, actual_entries.batchCount());
        for (0..generated.n_batches) |batch| {
            const term = try pairTerm(try actual_entries.pair(batch, relations));
            if (logical_row == 0) {
                const oracle_term = try pairTerm(try oracle.pair(batch, relations));
                try std.testing.expect(term.eql(oracle_term));
            } else {
                try std.testing.expect(term.isZero());
            }
            const expected_previous = if (logical_row == 0)
                generated.claims[batch]
            else
                accumulators[batch];
            accumulators[batch] = accumulators[batch].add(term);
            try std.testing.expect(
                secureAt(&generated.columns, 4 * batch, committed_row)
                    .eql(accumulators[batch]),
            );
            const previous_row = placement.map((logical_row + size - 1) % size);
            try std.testing.expect(
                secureAt(&generated.columns, 4 * batch, previous_row)
                    .eql(expected_previous),
            );
        }
    }
    for (accumulators[0..generated.n_batches], generated.claims[0..generated.n_batches]) |expected, actual| {
        try std.testing.expect(actual.eql(expected));
    }
}

test "opcode interaction derives exact claims from committed main columns" {
    const allocator = std.testing.allocator;
    const family: trace.OpcodeFamily = .base_alu_imm;
    const relations = relations_mod.Relations.dummy();
    var main = try testColumns(allocator, family, 4, &.{testRow()});
    defer freeTestColumns(allocator, main);
    var generated = try generate(
        allocator,
        family,
        main.storage[0..main.len],
        4,
        &relations,
    );
    defer generated.deinit(allocator);

    try std.testing.expectEqual(opcode_entries.batchCount(family), generated.n_batches);
    try std.testing.expectEqual(nColumns(family), generated.nColumns());
    const list = try opcode_entries.fromTraceRow(testRow(), family);
    var expected = QM31.zero();
    for (0..list.batchCount()) |batch| expected = expected.add(try pairTerm(
        try list.pair(batch, &relations),
    ));
    try std.testing.expect(generated.total().eql(expected));

    const column_count = generated.nColumns();
    const owned_columns = generated.takeColumns();
    defer for (owned_columns[0..column_count]) |column| allocator.free(column);
    for (generated.columns[0..column_count]) |column| {
        try std.testing.expectEqual(@as(usize, 0), column.len);
    }
    for (owned_columns[0..column_count]) |column| {
        try std.testing.expectEqual(@as(usize, 16), column.len);
    }
    try std.testing.expect(generated.total().eql(expected));
}

test "opcode interaction is padding invariant and shard additive" {
    const allocator = std.testing.allocator;
    const family: trace.OpcodeFamily = .base_alu_imm;
    const relations = relations_mod.Relations.dummy();
    var compact_main = try testColumns(allocator, family, 4, &.{testRow()});
    defer freeTestColumns(allocator, compact_main);
    var padded_main = try testColumns(allocator, family, 5, &.{testRow()});
    defer freeTestColumns(allocator, padded_main);
    var compact = try generate(
        allocator,
        family,
        compact_main.storage[0..compact_main.len],
        4,
        &relations,
    );
    defer compact.deinit(allocator);
    var padded = try generate(
        allocator,
        family,
        padded_main.storage[0..padded_main.len],
        5,
        &relations,
    );
    defer padded.deinit(allocator);
    try std.testing.expect(compact.total().eql(padded.total()));
    try std.testing.expectEqual(compact.n_batches, padded.n_batches);
    for (compact.claims[0..compact.n_batches], padded.claims[0..padded.n_batches]) |compact_claim, padded_claim| {
        try std.testing.expect(compact_claim.eql(padded_claim));
    }

    var combined_main = try testColumns(
        allocator,
        family,
        4,
        &.{ testRow(), testRow() },
    );
    defer freeTestColumns(allocator, combined_main);
    var combined = try generate(
        allocator,
        family,
        combined_main.storage[0..combined_main.len],
        4,
        &relations,
    );
    defer combined.deinit(allocator);
    try std.testing.expect(combined.total().eql(
        compact.total().add(padded.total()),
    ));
    try std.testing.expectEqual(compact.n_batches, combined.n_batches);
    for (
        combined.claims[0..combined.n_batches],
        compact.claims[0..compact.n_batches],
        padded.claims[0..padded.n_batches],
    ) |combined_claim, compact_claim, padded_claim| {
        try std.testing.expect(combined_claim.eql(compact_claim.add(padded_claim)));
    }
}

test "opcode interaction rejects malformed committed geometry" {
    const allocator = std.testing.allocator;
    const family: trace.OpcodeFamily = .base_alu_imm;
    const relations = relations_mod.Relations.dummy();
    var main = try testColumns(allocator, family, 4, &.{testRow()});
    defer freeTestColumns(allocator, main);
    try std.testing.expectError(
        error.InvalidColumnCount,
        generate(allocator, family, main.storage[0 .. main.len - 1], 4, &relations),
    );
    const saved = main.storage[0];
    main.storage[0] = saved[0 .. saved.len - 1];
    defer main.storage[0] = saved;
    try std.testing.expectError(
        error.InvalidColumnLength,
        generate(allocator, family, main.storage[0..main.len], 4, &relations),
    );
}

test "opcode interaction matches scalar prefixes for every family" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    // The batch geometry itself is pinned once, by `opcode_entries.zig`. This
    // test owns scalar parity of the generated interaction columns.
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        try expectScalarParity(
            allocator,
            family,
            testRowForFamily(family, index),
            4,
            &relations,
        );
    }
}

test "base-field opcode entries match secure reconstruction for every family and padding" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        var main = try testColumns(
            allocator,
            family,
            4,
            &.{testRowForFamily(family, index)},
        );
        defer freeTestColumns(allocator, main);
        const placement = try infra.BitReversalTable.init(allocator, 4);
        defer placement.deinit(allocator);
        try expectBaseEntryParity(
            family,
            main.storage[0..main.len],
            placement.map(0),
            &relations,
        );
        try expectBaseEntryParity(
            family,
            main.storage[0..main.len],
            placement.map(15),
            &relations,
        );
        try expectPlanPairParity(
            allocator,
            family,
            main.storage[0..main.len],
            placement.map(0),
            placement.map(15),
            &relations,
        );
    }
}

test "opcode interaction carries cumulative state across inversion chunks" {
    const allocator = std.testing.allocator;
    const family: trace.OpcodeFamily = .base_alu_imm;
    const relations = relations_mod.Relations.dummy();
    const n_rows = CHUNK_ROWS + 2;
    const log_size: u32 = 13;
    const rows = try allocator.alloc(trace.TraceRow, n_rows);
    defer allocator.free(rows);
    for (rows, 0..) |*row, index| row.* = testRowForFamily(family, index);
    var main = try testColumns(allocator, family, log_size, rows);
    defer freeTestColumns(allocator, main);
    var generated = try generate(
        allocator,
        family,
        main.storage[0..main.len],
        log_size,
        &relations,
    );
    defer generated.deinit(allocator);
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    var accumulators = [_]QM31{QM31.zero()} ** MAX_BATCHES;
    var secure_row: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;

    for (0..n_rows) |logical_row| {
        const committed_row = placement.map(logical_row);
        for (main.storage[0..main.len], secure_row[0..main.len]) |column, *value| {
            value.* = QM31.fromBase(column[committed_row]);
        }
        const list = try opcode_entries.fromMain(family, secure_row[0..main.len]);
        for (0..generated.n_batches) |batch| {
            accumulators[batch] = accumulators[batch].add(
                try pairTerm(try list.pair(batch, &relations)),
            );
            if (logical_row + 1 >= CHUNK_ROWS) {
                try std.testing.expect(
                    secureAt(&generated.columns, 4 * batch, committed_row)
                        .eql(accumulators[batch]),
                );
            }
        }
    }
    for (accumulators[0..generated.n_batches], generated.claims[0..generated.n_batches]) |expected, actual| {
        try std.testing.expect(actual.eql(expected));
    }
    const final_padding_row = placement.map((@as(usize, 1) << @intCast(log_size)) - 1);
    for (0..generated.n_batches) |batch| {
        try std.testing.expect(
            secureAt(&generated.columns, 4 * batch, final_padding_row)
                .eql(generated.claims[batch]),
        );
    }
}

fn generateForAllocationTest(
    allocator: std.mem.Allocator,
    columns: []const []const M31,
    relations: *const relations_mod.Relations,
) !void {
    var generated = try generate(
        allocator,
        .base_alu_imm,
        columns,
        4,
        relations,
    );
    defer generated.deinit(allocator);
}

test "opcode interaction rolls back every allocation failure" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    var main = try testColumns(allocator, .base_alu_imm, 4, &.{testRow()});
    defer freeTestColumns(allocator, main);
    try std.testing.checkAllAllocationFailures(
        allocator,
        generateForAllocationTest,
        .{ main.storage[0..main.len], &relations },
    );
}
