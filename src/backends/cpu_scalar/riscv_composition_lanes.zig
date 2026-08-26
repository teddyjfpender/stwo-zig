//! Allocation-free packed row lanes for specialized RISC-V composition.
//!
//! The coordinator owns every bucket, tile descriptor, and scratch slice.
//! A lane visits its canonical round-robin tile subset and writes disjoint
//! output rows without consulting an allocator or a process-global pool.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const admission = @import("riscv_composition_admission.zig");

const constraints = core.constraints;
const m31 = core.fields.m31;
const qm31 = core.fields.qm31;
const packed_qm31 = core.fields.packed_qm31;
const canonic = core.poly.circle.canonic;

const M31 = m31.M31;
const PackedM31 = m31.PackedM31;
const PackedQM31 = packed_qm31.PackedQM31;
const Poly = prover.air.component_prover.Poly;
const SecureColumn = prover.secure_column.SecureColumnByCoords;
const BaseProgramEntry = admission.BaseProgramEntry;
const LookupProgramEntry = admission.LookupProgramEntry;
const LookupProgramV2Entry = admission.LookupProgramV2Entry;
const LookupVersion = admission.LookupVersion;
const PairJob = admission.PairJob;

pub const TILE_ROWS: usize = 4096;
pub const LOOKUP_V2_ROW_ALLOCATION_COUNT: usize = 0;
pub const LOOKUP_V2_ROW_HASH_COUNT: usize = 0;
pub const LOOKUP_V2_ROW_PARTITION_SEARCH_COUNT: usize = 0;

comptime {
    if (!std.math.isPowerOfTwo(m31.PACK_WIDTH) or TILE_ROWS % m31.PACK_WIDTH != 0) {
        @compileError("RISC-V composition tiles must contain whole SIMD packs");
    }
}

pub const Bucket = struct {
    eval_log_size: u32,
    lookup_version: LookupVersion,
    row_count: usize,
    pair_indices: []usize,
    output: ?SecureColumn,
    denominator_inverses: [2]PackedM31,

    pub fn deinit(self: *Bucket, allocator: std.mem.Allocator) void {
        allocator.free(self.pair_indices);
        if (self.output) |*output| output.deinit(allocator);
        self.* = undefined;
    }
};

pub const EvaluationContext = struct {
    pairs: []const PairJob,
    base_programs: []const BaseProgramEntry,
    lookup_programs: []const LookupProgramEntry,
    lookup_programs_v2: []const LookupProgramV2Entry,
    powers: []const PackedQM31,
    max_main_columns: usize,
    max_base_nodes: usize,
    max_lookup_nodes: usize,
    max_lookup_entries: usize,
    max_lookup_v2_nodes: usize,
    max_lookup_v2_entries: usize,
};

pub const Tile = struct {
    bucket: *Bucket,
    row_start: usize,
    row_end: usize,
};

pub const TileLane = struct {
    allocator: std.mem.Allocator,
    context: *const EvaluationContext,
    tiles: []const Tile,
    lane_index: usize,
    lane_count: usize,
    main_values: []PackedM31,
    base_nodes: []PackedM31,
    lookup_nodes: []PackedM31,
    denominators: []PackedQM31,
    lookup_v2: ?PreparedLookupV2,

    pub fn init(
        allocator: std.mem.Allocator,
        context: *const EvaluationContext,
        tiles: []const Tile,
        lane_index: usize,
        lane_count: usize,
    ) !TileLane {
        if (lane_count == 0 or lane_index >= lane_count) return error.InvalidTileLane;
        const main_values = try allocator.alloc(PackedM31, context.max_main_columns);
        errdefer allocator.free(main_values);
        const base_nodes = try allocator.alloc(PackedM31, context.max_base_nodes);
        errdefer allocator.free(base_nodes);
        const lookup_nodes = try allocator.alloc(PackedM31, context.max_lookup_nodes);
        errdefer allocator.free(lookup_nodes);
        const denominators = try allocator.alloc(PackedQM31, context.max_lookup_entries);
        errdefer allocator.free(denominators);
        var lookup_v2: ?PreparedLookupV2 = if (context.max_lookup_v2_nodes == 0 and
            context.max_lookup_v2_entries == 0)
            null
        else
            try PreparedLookupV2.init(
                allocator,
                context.max_lookup_v2_nodes,
                context.max_lookup_v2_entries,
            );
        errdefer if (lookup_v2) |*prepared| prepared.deinit();
        return .{
            .allocator = allocator,
            .context = context,
            .tiles = tiles,
            .lane_index = lane_index,
            .lane_count = lane_count,
            .main_values = main_values,
            .base_nodes = base_nodes,
            .lookup_nodes = lookup_nodes,
            .denominators = denominators,
            .lookup_v2 = lookup_v2,
        };
    }

    pub fn deinit(self: *TileLane) void {
        const allocator = self.allocator;
        if (self.lookup_v2) |*prepared| prepared.deinit();
        allocator.free(self.denominators);
        allocator.free(self.lookup_nodes);
        allocator.free(self.base_nodes);
        allocator.free(self.main_values);
        self.* = undefined;
    }

    pub fn run(task_context: *prover.task_graph.TaskContext) anyerror!void {
        const self: *TileLane = @ptrCast(@alignCast(task_context.user_context));
        var tile_index = self.lane_index;
        if (self.context.lookup_programs_v2.len == 0) {
            while (tile_index < self.tiles.len) : (tile_index += self.lane_count) {
                if (task_context.isCancelled()) return;
                self.evaluateTileVersion(.v1, self.tiles[tile_index]);
            }
            return;
        }
        while (tile_index < self.tiles.len) : (tile_index += self.lane_count) {
            if (task_context.isCancelled()) return;
            self.evaluateTile(self.tiles[tile_index]);
        }
    }

    pub fn workEstimate(self: *const TileLane) !u64 {
        var total: u64 = 0;
        var tile_index = self.lane_index;
        while (tile_index < self.tiles.len) : (tile_index += self.lane_count) {
            const tile = self.tiles[tile_index];
            const tile_work = try prover.task_graph.checkedWorkEstimate(&.{
                std.math.cast(u64, tile.row_end - tile.row_start) orelse
                    return error.WorkEstimateOverflow,
                std.math.cast(u64, tile.bucket.pair_indices.len) orelse
                    return error.WorkEstimateOverflow,
            });
            total = std.math.add(u64, total, tile_work) catch
                return error.WorkEstimateOverflow;
        }
        return total;
    }

    pub fn resources(
        self: *const TileLane,
        scratch_bytes: usize,
    ) !prover.task_graph.ResourceReservation {
        const secure_element_bytes = std.math.mul(
            usize,
            qm31.SECURE_EXTENSION_DEGREE,
            @sizeOf(M31),
        ) catch return error.ResourceReservationOverflow;
        var final_output_bytes: usize = 0;
        var tile_index = self.lane_index;
        while (tile_index < self.tiles.len) : (tile_index += self.lane_count) {
            const tile = self.tiles[tile_index];
            const tile_output_bytes = std.math.mul(
                usize,
                tile.row_end - tile.row_start,
                secure_element_bytes,
            ) catch return error.ResourceReservationOverflow;
            final_output_bytes = std.math.add(
                usize,
                final_output_bytes,
                tile_output_bytes,
            ) catch return error.ResourceReservationOverflow;
        }
        return .{
            .final_output_bytes = final_output_bytes,
            // Scratch is allocated once during coordinator preparation and
            // remains owned by this lane until the graph drains.
            .shared_resident_bytes = scratch_bytes,
            .worker_stack_bytes = prover.air.prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        };
    }

    fn evaluateTile(self: *TileLane, tile: Tile) void {
        switch (tile.bucket.lookup_version) {
            .v1 => self.evaluateTileVersion(.v1, tile),
            .v2 => self.evaluateTileVersion(.v2, tile),
        }
    }

    fn evaluateTileVersion(
        self: *TileLane,
        comptime lookup_version: LookupVersion,
        tile: Tile,
    ) void {
        const context = self.context;
        const output = &tile.bucket.output.?;
        const half = tile.bucket.row_count / 2;
        var row = tile.row_start;
        while (row < tile.row_end) : (row += m31.PACK_WIDTH) {
            var previous_rows: [m31.PACK_WIDTH]usize = undefined;
            for (&previous_rows, 0..) |*previous, lane| {
                previous.* = core.utils.previousBitReversedCircleDomainIndex(
                    row + lane,
                    tile.bucket.eval_log_size - 1,
                    tile.bucket.eval_log_size,
                );
            }

            var accumulated = PackedQM31.zero();
            for (tile.bucket.pair_indices) |pair_index| {
                const pair = &context.pairs[pair_index];
                for (
                    pair.main_columns,
                    self.main_values[0..pair.main_columns.len],
                ) |column, *packed_value| {
                    packed_value.* = m31.loadPacked(column.values.ptr + row);
                }
                std.debug.assert(pair.lookup_version == lookup_version);
                const value = if (comptime lookup_version == .v1)
                    evaluatePairV1(
                        context,
                        pair,
                        row,
                        &previous_rows,
                        self.main_values,
                        self.base_nodes,
                        self.lookup_nodes,
                        self.denominators,
                    )
                else
                    self.lookup_v2.?.evaluatePair(
                        context,
                        pair,
                        row,
                        &previous_rows,
                        self.main_values,
                        self.base_nodes,
                    );
                accumulated = accumulated.add(value);
            }

            const denominator = tile.bucket.denominator_inverses[@intFromBool(row >= half)];
            const coordinates = accumulated.mulBase(denominator).coordinates();
            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                m31.storePacked(output.columns[coordinate].ptr + row, coordinates[coordinate]);
            }
        }
    }
};

pub fn buildBuckets(
    allocator: std.mem.Allocator,
    pairs: []const PairJob,
    buckets: *std.ArrayList(Bucket),
) !void {
    var has_v2 = false;
    for (pairs) |pair| has_v2 = has_v2 or pair.lookup_version == .v2;
    if (!has_v2) return buildBucketsV1(allocator, pairs, buckets);

    return buildBucketsMixed(allocator, pairs, buckets);
}

/// Keep the inactive V2 path's allocation shape identical to the original V1
/// planner. Version-aware grouping is entered only after explicit activation
/// has admitted at least one V2 pair.
fn buildBucketsV1(
    allocator: std.mem.Allocator,
    pairs: []const PairJob,
    buckets: *std.ArrayList(Bucket),
) !void {
    var max_log_size: u32 = 0;
    for (pairs) |pair| {
        std.debug.assert(pair.lookup_version == .v1);
        max_log_size = @max(max_log_size, pair.eval_log_size);
    }
    const counts = try allocator.alloc(usize, @as(usize, max_log_size) + 1);
    defer allocator.free(counts);
    @memset(counts, 0);
    for (pairs) |pair| counts[pair.eval_log_size] += 1;

    for (counts, 0..) |count, log_size_usize| {
        if (count == 0) continue;
        try appendBucket(
            allocator,
            buckets,
            @intCast(log_size_usize),
            .v1,
            count,
        );
    }
    const cursors = try allocator.alloc(usize, buckets.items.len);
    defer allocator.free(cursors);
    @memset(cursors, 0);
    for (pairs, 0..) |pair, pair_index| {
        const bucket_index = bucketIndex(
            buckets.items,
            pair.eval_log_size,
            .v1,
        ).?;
        buckets.items[bucket_index].pair_indices[cursors[bucket_index]] =
            pair_index;
        cursors[bucket_index] += 1;
    }
}

fn buildBucketsMixed(
    allocator: std.mem.Allocator,
    pairs: []const PairJob,
    buckets: *std.ArrayList(Bucket),
) !void {
    var max_log_size: u32 = 0;
    for (pairs) |pair| max_log_size = @max(max_log_size, pair.eval_log_size);
    const log_count = std.math.add(usize, max_log_size, 1) catch
        return error.ResourceReservationOverflow;
    const counts = try allocator.alloc(
        usize,
        std.math.mul(usize, log_count, 2) catch
            return error.ResourceReservationOverflow,
    );
    defer allocator.free(counts);
    @memset(counts, 0);
    for (pairs) |pair| {
        const count_index = @as(usize, pair.eval_log_size) * 2 +
            @intFromEnum(pair.lookup_version);
        counts[count_index] += 1;
    }

    for (counts, 0..) |count, count_index| {
        if (count == 0) continue;
        try appendBucket(
            allocator,
            buckets,
            @intCast(count_index / 2),
            @enumFromInt(count_index % 2),
            count,
        );
    }
    const cursors = try allocator.alloc(usize, buckets.items.len);
    defer allocator.free(cursors);
    @memset(cursors, 0);
    for (pairs, 0..) |pair, pair_index| {
        const bucket_index = bucketIndex(
            buckets.items,
            pair.eval_log_size,
            pair.lookup_version,
        ).?;
        buckets.items[bucket_index].pair_indices[cursors[bucket_index]] = pair_index;
        cursors[bucket_index] += 1;
    }
}

pub fn scratchBytes(
    main_columns: usize,
    base_nodes: usize,
    lookup_nodes: usize,
    lookup_entries: usize,
) !usize {
    const packed_m31_count = try std.math.add(
        usize,
        try std.math.add(usize, main_columns, base_nodes),
        lookup_nodes,
    );
    return try std.math.add(
        usize,
        try std.math.mul(usize, packed_m31_count, @sizeOf(PackedM31)),
        try std.math.mul(usize, lookup_entries, @sizeOf(PackedQM31)),
    );
}

pub fn lookupV2ScratchBytes(node_count: usize, entry_count: usize) !usize {
    if (node_count == 0 and entry_count == 0) return 0;
    if (node_count == 0 or entry_count == 0 or
        node_count > prover.air.lookup_polynomial_v2.MAX_PROGRAM_NODES or
        entry_count > prover.air.lookup_polynomial_v2.MAX_LOOKUP_ENTRIES)
    {
        return error.InvalidPreparedCapacity;
    }
    const nodes = std.math.mul(usize, node_count, @sizeOf(PackedM31)) catch
        return error.ResourceReservationOverflow;
    const denominators = std.math.mul(
        usize,
        entry_count,
        @sizeOf(PackedQM31),
    ) catch return error.ResourceReservationOverflow;
    return std.math.add(usize, nodes, denominators) catch
        error.ResourceReservationOverflow;
}

fn appendBucket(
    allocator: std.mem.Allocator,
    buckets: *std.ArrayList(Bucket),
    eval_log_size: u32,
    lookup_version: LookupVersion,
    pair_count: usize,
) !void {
    const row_count = @as(usize, 1) << @intCast(eval_log_size);
    const pair_indices = try allocator.alloc(usize, pair_count);
    errdefer allocator.free(pair_indices);
    var output = try SecureColumn.zeros(allocator, row_count);
    errdefer output.deinit(allocator);
    try buckets.append(allocator, .{
        .eval_log_size = eval_log_size,
        .lookup_version = lookup_version,
        .row_count = row_count,
        .pair_indices = pair_indices,
        .output = output,
        .denominator_inverses = try denominatorInverses(eval_log_size),
    });
}

fn bucketIndex(
    buckets: []const Bucket,
    eval_log_size: u32,
    lookup_version: LookupVersion,
) ?usize {
    for (buckets, 0..) |bucket, index| {
        if (bucket.eval_log_size == eval_log_size and
            bucket.lookup_version == lookup_version)
        {
            return index;
        }
    }
    return null;
}

fn denominatorInverses(eval_log_size: u32) ![2]PackedM31 {
    const scalars = try denominatorScalars(eval_log_size);
    return .{ m31.splatPacked(scalars[0]), m31.splatPacked(scalars[1]) };
}

fn denominatorScalars(eval_log_size: u32) ![2]M31 {
    if (eval_log_size == 0) return error.InvalidCompositionLogSize;
    const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
    const trace_coset = canonic.CanonicCoset.new(eval_log_size - 1).coset();
    var result: [2]M31 = undefined;
    for (&result, 0..) |*inverse, index| {
        inverse.* = try constraints.cosetVanishing(
            M31,
            trace_coset,
            eval_domain.at(core.utils.bitReverseIndex(index, 1)),
        ).inv();
    }
    return result;
}

fn evaluatePairV1(
    context: *const EvaluationContext,
    pair: *const PairJob,
    row: usize,
    previous_rows: *const [m31.PACK_WIDTH]usize,
    main_values: []const PackedM31,
    base_nodes: []PackedM31,
    lookup_nodes: []PackedM31,
    denominators: []PackedQM31,
) PackedQM31 {
    const base_entry = &context.base_programs[pair.base_program_index];
    const lookup_entry = &context.lookup_programs[pair.lookup_program_index];
    const semantic_selector = m31.loadPacked(pair.semantic_selector.ptr + row);
    evaluateNodes(
        base_entry.program.nodes,
        base_entry.reachable,
        base_nodes,
        main_values[0..pair.main_columns.len],
        semantic_selector,
    );
    var semantic = PackedQM31.zero();
    for (base_entry.program.roots, 0..) |root, root_index| {
        const power = context.powers[
            pair.semantic_power_start + base_entry.program.roots.len - 1 - root_index
        ];
        semantic = semantic.add(power.mulBase(base_nodes[root]));
    }

    evaluateNodes(
        lookup_entry.program.nodes,
        lookup_entry.reachable,
        lookup_nodes,
        main_values[0..pair.main_columns.len],
        null,
    );
    const program = lookup_entry.program;
    var parameter_cursor: usize = 0;
    for (program.entries, denominators[0..program.entries.len]) |entry, *denominator| {
        denominator.* = PackedQM31.zero();
        for (entry.values[0..entry.arity], 0..) |root, value_index| {
            denominator.* = denominator.add(
                PackedQM31.splat(pair.parameters[parameter_cursor + 1 + value_index])
                    .mulBase(lookup_nodes[root]),
            );
        }
        denominator.* = denominator.sub(PackedQM31.splat(pair.parameters[parameter_cursor]));
        parameter_cursor += 1 + entry.arity;
    }

    const lookup_selector = m31.loadPacked(pair.lookup_selector.ptr + row);
    var lookup = PackedQM31.zero();
    for (0..program.batchCount()) |batch| {
        const first = batch * program.batch_size;
        const has_second = first + 1 < program.entries.len and program.batch_size == 2;
        const current = loadSecure(pair.interaction_columns, batch * 4, row);
        const previous = gatherSecure(pair.interaction_columns, batch * 4, previous_rows);
        const claim = PackedQM31.splat(pair.parameters[parameter_cursor + batch]);
        const delta = current.sub(previous).add(claim.mulBase(lookup_selector));
        const first_entry = program.entries[first];
        var constraint = if (has_second) blk: {
            const second_entry = program.entries[first + 1];
            break :blk delta.mul(denominators[first]).mul(denominators[first + 1])
                .sub(denominators[first + 1].mulBase(lookup_nodes[first_entry.numerator]))
                .sub(denominators[first].mulBase(lookup_nodes[second_entry.numerator]));
        } else delta.mul(denominators[first])
            .sub(PackedQM31.fromBase(lookup_nodes[first_entry.numerator]));
        const power = context.powers[
            pair.lookup_power_start + program.batchCount() - 1 - batch
        ];
        constraint = power.mul(constraint);
        lookup = lookup.add(constraint);
    }
    return semantic.add(lookup);
}

/// Per-worker packed scratch for an already-authenticated V2 program. The
/// coordinator allocates one instance for each tile lane before graph launch;
/// row evaluation performs only direct DAG and batch-array traversal.
pub const PreparedLookupV2 = struct {
    allocator: std.mem.Allocator,
    node_values: []PackedM31,
    denominators: []PackedQM31,
    scratch_bytes: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        max_node_count: usize,
        max_entry_count: usize,
    ) !PreparedLookupV2 {
        const scratch_bytes = try lookupV2ScratchBytes(
            max_node_count,
            max_entry_count,
        );
        if (scratch_bytes == 0) return error.InvalidPreparedCapacity;
        const node_values = try allocator.alloc(PackedM31, max_node_count);
        errdefer allocator.free(node_values);
        const denominators = try allocator.alloc(PackedQM31, max_entry_count);
        errdefer allocator.free(denominators);
        return .{
            .allocator = allocator,
            .node_values = node_values,
            .denominators = denominators,
            .scratch_bytes = scratch_bytes,
        };
    }

    pub fn deinit(self: *PreparedLookupV2) void {
        const allocator = self.allocator;
        allocator.free(self.denominators);
        allocator.free(self.node_values);
        self.* = undefined;
    }

    pub fn resources(self: *const PreparedLookupV2) prover.task_graph.ResourceReservation {
        return .{
            .shared_resident_bytes = self.scratch_bytes,
            .worker_stack_bytes = prover.air.prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        };
    }

    fn evaluatePair(
        self: *PreparedLookupV2,
        context: *const EvaluationContext,
        pair: *const PairJob,
        row: usize,
        previous_rows: *const [m31.PACK_WIDTH]usize,
        main_values: []const PackedM31,
        base_nodes: []PackedM31,
    ) PackedQM31 {
        const base_entry = &context.base_programs[pair.base_program_index];
        const lookup_entry =
            &context.lookup_programs_v2[pair.lookup_program_index];
        const semantic_selector = m31.loadPacked(
            pair.semantic_selector.ptr + row,
        );
        evaluateNodes(
            base_entry.program.nodes,
            base_entry.reachable,
            base_nodes,
            main_values[0..pair.main_columns.len],
            semantic_selector,
        );
        var semantic = PackedQM31.zero();
        for (base_entry.program.roots, 0..) |root, root_index| {
            const power = context.powers[
                pair.semantic_power_start +
                    base_entry.program.roots.len - 1 - root_index
            ];
            semantic = semantic.add(power.mulBase(base_nodes[root]));
        }

        const program = &lookup_entry.program;
        std.debug.assert(program.nodes.len <= self.node_values.len);
        std.debug.assert(program.entries.len <= self.denominators.len);
        evaluateNodes(
            program.nodes,
            lookup_entry.reachable,
            self.node_values,
            main_values[0..pair.main_columns.len],
            null,
        );
        var parameter_cursor: usize = 0;
        for (
            program.entries,
            self.denominators[0..program.entries.len],
        ) |entry, *denominator| {
            denominator.* = PackedQM31.zero();
            for (entry.values[0..entry.arity], 0..) |root, value_index| {
                denominator.* = denominator.add(
                    PackedQM31.splat(
                        pair.parameters[parameter_cursor + 1 + value_index],
                    ).mulBase(self.node_values[root]),
                );
            }
            denominator.* = denominator.sub(
                PackedQM31.splat(pair.parameters[parameter_cursor]),
            );
            parameter_cursor += 1 + entry.arity;
        }
        std.debug.assert(
            parameter_cursor + program.batches.len == pair.parameters.len,
        );

        const lookup_selector = m31.loadPacked(
            pair.lookup_selector.ptr + row,
        );
        var lookup = PackedQM31.zero();
        for (program.batches, 0..) |batch, batch_index| {
            const first: usize = @intCast(batch.first_entry);
            const current = loadSecure(
                pair.interaction_columns,
                batch_index * qm31.SECURE_EXTENSION_DEGREE,
                row,
            );
            const previous = gatherSecure(
                pair.interaction_columns,
                batch_index * qm31.SECURE_EXTENSION_DEGREE,
                previous_rows,
            );
            const claim = PackedQM31.splat(
                pair.parameters[parameter_cursor + batch_index],
            );
            const delta = current.sub(previous).add(
                claim.mulBase(lookup_selector),
            );
            const first_entry = program.entries[first];
            var constraint = if (batch.entry_count == 2) paired: {
                const second = first + 1;
                const second_entry = program.entries[second];
                break :paired delta.mul(self.denominators[first])
                    .mul(self.denominators[second])
                    .sub(self.denominators[second].mulBase(
                        self.node_values[first_entry.numerator],
                    ))
                    .sub(self.denominators[first].mulBase(
                    self.node_values[second_entry.numerator],
                ));
            } else delta.mul(self.denominators[first]).sub(
                PackedQM31.fromBase(
                    self.node_values[first_entry.numerator],
                ),
            );
            const power = context.powers[
                pair.lookup_power_start +
                    program.batches.len - 1 - batch_index
            ];
            constraint = power.mul(constraint);
            lookup = lookup.add(constraint);
        }
        return semantic.add(lookup);
    }
};

fn evaluateNodes(
    nodes: []const prover.air.component_prover.BasePolynomialNode,
    reachable: []const bool,
    values: []PackedM31,
    columns: []const PackedM31,
    selector: ?PackedM31,
) void {
    for (nodes, reachable, 0..) |node, is_reachable, index| {
        if (!is_reachable) continue;
        values[index] = switch (node.op) {
            .constant => @splat(node.value),
            .column => if (node.value < columns.len) columns[node.value] else selector.?,
            .add => m31.addPacked(values[node.lhs], values[node.rhs]),
            .sub => m31.subPacked(values[node.lhs], values[node.rhs]),
            .mul => m31.mulPacked(values[node.lhs], values[node.rhs]),
            .neg => m31.negPacked(values[node.lhs]),
        };
    }
}

fn loadSecure(columns: []const Poly, first_column: usize, row: usize) PackedQM31 {
    return .{
        .c0 = .{
            .a = m31.loadPacked(columns[first_column].values.ptr + row),
            .b = m31.loadPacked(columns[first_column + 1].values.ptr + row),
        },
        .c1 = .{
            .a = m31.loadPacked(columns[first_column + 2].values.ptr + row),
            .b = m31.loadPacked(columns[first_column + 3].values.ptr + row),
        },
    };
}

fn gatherSecure(
    columns: []const Poly,
    first_column: usize,
    rows: *const [m31.PACK_WIDTH]usize,
) PackedQM31 {
    var coordinates: [qm31.SECURE_EXTENSION_DEGREE]PackedM31 = .{
        @splat(0), @splat(0), @splat(0), @splat(0),
    };
    for (rows, 0..) |row, lane| {
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
            coordinates[coordinate][lane] = columns[first_column + coordinate].values[row].v;
        }
    }
    return .{
        .c0 = .{ .a = coordinates[0], .b = coordinates[1] },
        .c1 = .{ .a = coordinates[2], .b = coordinates[3] },
    };
}
