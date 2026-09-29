//! Live assembly of an official Cairo base commitment tree.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const adapter = @import("../adapter/mod.zig");
const claim_generator = @import("../claim_generator.zig");
const fixed_trace = @import("../conformance/fixed_trace.zig");
const multiplicity_tables = @import("../conformance/multiplicity_tables.zig");
const cpu_memory = @import("../witness/cpu_memory_multiplicity.zig");
const feed_topology = @import("../witness/feed_topology.zig");
const fixed_tables = @import("../witness/fixed_table_bundle.zig");
const implicit = @import("../witness/implicit_interaction_sources.zig");
const live_graph = @import("../witness/live_graph.zig");
const deductions = @import("../witness/deductions/mod.zig");
const witness_bundle = @import("../witness/bundle.zig");
const trace_arena = @import("trace_arena.zig");

const M31 = core.fields.m31.M31;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;

pub const Prepared = @import("base_columns.zig").Prepared;
const Collector = @import("base_columns.zig").Collector;
const base_columns = @import("base_columns.zig");
const incremental_multiplicities = @import("incremental_multiplicities.zig");

const FeedCollector = struct {
    columns: *Collector,
    multiplicities: *incremental_multiplicities.State,

    fn destination(raw: *anyopaque, a: std.mem.Allocator, layout: @import("../witness/component_layout.zig").ComponentLayout) !?[][]u32 {
        const self: *@This() = @ptrCast(@alignCast(raw));
        return base_columns.reserveGenerated(self.columns, a, layout);
    }

    fn visit(raw: *anyopaque, layout: @import("../witness/component_layout.zig").ComponentLayout, execution: *const @import("../witness/component_executor.zig").Execution) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        return base_columns.observeGenerated(self.columns, layout, execution);
    }

    fn consume(raw: *anyopaque, producer: *const live_graph.ProducerOutput) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        try self.multiplicities.consume(producer);
    }
};

pub const BaseTrace = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    geometry: claim_generator.OwnedClaimGeometry,
    execution: live_graph.Execution,
    fixed_multiplicities: multiplicity_tables.Tables,
    memory_counts: cpu_memory.Counts,
    /// Column values borrow a caller-owned arena and must not be freed here.
    arena_backed: bool = false,
    /// True when the caller supplied both the geometry and the arena.
    borrowed_geometry: bool = false,
    /// False once `releaseWitnessFeeds` has handed the execution back early.
    execution_owned: bool = true,

    pub fn deinit(self: *BaseTrace) void {
        if (self.execution_owned) {
            self.fixed_multiplicities.deinit();
            self.memory_counts.deinit();
        }
        if (self.arena_backed) {
            self.allocator.free(self.columns);
            if (self.execution_owned) self.execution.deinit();
            if (!self.borrowed_geometry) self.geometry.deinit();
            self.* = undefined;
            return;
        }
        deinitColumns(self.allocator, self.columns);
        if (self.execution_owned) self.execution.deinit();
        if (!self.borrowed_geometry) self.geometry.deinit();
        self.* = undefined;
    }

    pub fn takeColumns(self: *BaseTrace) []ColumnEvaluation {
        const columns = self.columns;
        self.columns = &.{};
        return columns;
    }

    pub fn releaseWitnessFeeds(self: *BaseTrace) void {
        if (!self.execution_owned) return;
        self.fixed_multiplicities.deinit();
        self.memory_counts.deinit();
        self.execution.deinit();
        self.execution_owned = false;
    }
};

pub fn build(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    programs: *const witness_bundle.Bundle,
    generated_executor: ?@import("../witness/generated_executor.zig").Executor,
    interaction_executor: ?@import("../witness/interaction_executor.zig").Executor,
    topology: feed_topology.Loaded,
    fixed: *const fixed_tables.Bundle,
    variant: claim_generator.PreprocessedVariant,
    pedersen_table: ?deductions.PedersenTable,
    recorder: ?*prover.stage_profile.Recorder,
) !BaseTrace {
    return buildInto(
        allocator,
        input,
        programs,
        generated_executor,
        interaction_executor,
        topology,
        fixed,
        variant,
        pedersen_table,
        recorder,
        null,
    );
}

/// `prepared` is the allocation-before-execution seam: when it is supplied the
/// claim geometry has already been derived and one contiguous arena has already
/// been planned and allocated from it, and every column is written at its final
/// offset rather than assembled and then moved.
pub fn buildInto(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    programs: *const witness_bundle.Bundle,
    generated_executor: ?@import("../witness/generated_executor.zig").Executor,
    interaction_executor: ?@import("../witness/interaction_executor.zig").Executor,
    topology: feed_topology.Loaded,
    fixed: *const fixed_tables.Bundle,
    variant: claim_generator.PreprocessedVariant,
    pedersen_table: ?deductions.PedersenTable,
    recorder: ?*prover.stage_profile.Recorder,
    prepared: ?Prepared,
) !BaseTrace {
    if (prepared) |ready| {
        var collector = try Collector.initPrepared(allocator, ready);
        defer collector.deinit();
        return buildWithCollector(
            allocator,
            input,
            programs,
            generated_executor,
            interaction_executor,
            topology,
            fixed,
            pedersen_table,
            recorder,
            ready.geometry,
            &collector,
            true,
        );
    }
    var geometry = blk: {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "base_geometry",
            "Base geometry derivation",
        );
        defer stage.end();
        break :blk try claim_generator.deriveFromProverInput(
            allocator,
            input,
            .{ .preprocessed_variant = variant },
        );
    };
    errdefer geometry.deinit();
    var collector = try Collector.init(allocator, &geometry);
    defer collector.deinit();
    return buildWithCollector(
        allocator,
        input,
        programs,
        generated_executor,
        interaction_executor,
        topology,
        fixed,
        pedersen_table,
        recorder,
        &geometry,
        &collector,
        false,
    );
}

fn buildWithCollector(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    programs: *const witness_bundle.Bundle,
    generated_executor: ?@import("../witness/generated_executor.zig").Executor,
    interaction_executor: ?@import("../witness/interaction_executor.zig").Executor,
    topology: feed_topology.Loaded,
    fixed: *const fixed_tables.Bundle,
    pedersen_table: ?deductions.PedersenTable,
    recorder: ?*prover.stage_profile.Recorder,
    geometry: *claim_generator.OwnedClaimGeometry,
    collector: *Collector,
    borrowed: bool,
) !BaseTrace {
    // Qualification control only. The new lifetime policy remains opt-in until
    // CPU and Metal measurements pass the memory and timing gates.
    const incremental = if (std.posix.getenv("STWO_CAIRO_INCREMENTAL_MULTIPLICITIES")) |value| std.mem.eql(u8, value, "1") else false;
    var counts_state: ?incremental_multiplicities.State = if (incremental)
        try incremental_multiplicities.State.init(allocator, input, topology, fixed)
    else
        null;
    defer if (counts_state) |*state| state.deinit();
    var observer_context: FeedCollector = undefined;
    if (counts_state) |*state| observer_context = .{ .columns = collector, .multiplicities = state };
    var execution = blk: {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "base_witness_graph",
            "Recorded witness graph",
        );
        defer stage.end();
        break :blk try live_graph.execute(
            allocator,
            input,
            programs,
            generated_executor,
            interaction_executor,
            topology,
            geometry,
            if (incremental) .{
                .context = &observer_context,
                .destination = FeedCollector.destination,
                .visit = FeedCollector.visit,
                .consume = FeedCollector.consume,
            } else .{
                .context = collector,
                .destination = base_columns.reserveGenerated,
                .visit = base_columns.observeGenerated,
            },
            pedersen_table,
            recorder,
        );
    };
    errdefer execution.deinit();

    var multiplicities = blk: {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "base_fixed_multiplicities",
            "Fixed-table multiplicities",
        );
        defer stage.end();
        if (counts_state) |*state| {
            var tables = try state.takeTables();
            errdefer tables.deinit();
            try fixed_trace.addMemoryRangeChecksLive(input, &tables);
            break :blk tables;
        }
        break :blk try fixed_trace.populateLiveTopology(
            allocator,
            input,
            topology,
            execution.producers,
            fixed,
        );
    };
    errdefer multiplicities.deinit();
    var max_fixed_rows: usize = 0;
    for (fixed.entries) |entry| {
        max_fixed_rows = @max(max_fixed_rows, entry.row_count);
    }
    const zeros = try allocator.alloc(u32, max_fixed_rows);
    defer allocator.free(zeros);
    @memset(zeros, 0);
    for (fixed.entries) |entry| {
        if (collector.findIndex(entry.component, 0) == null) continue;
        const source_columns = try allocator.alloc(
            []const u32,
            entry.trace_multiplicity_columns.len,
        );
        defer allocator.free(source_columns);
        for (entry.trace_multiplicity_columns, source_columns) |relation, *source| {
            source.* = try multiplicities.column(entry.component, relation, zeros);
        }
        try collector.captureNamed(entry.component, 0, source_columns);
    }

    var memory_counts = blk: {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "base_memory_tables",
            "Memory-table construction",
        );
        defer stage.end();
        var counts = if (counts_state) |*state| try state.takeCounts() else try cpu_memory.collectTopology(
            allocator,
            input,
            topology,
            execution.producers,
        );
        errdefer counts.deinit();
        // Graph consumers, fixed multiplicities, and memory counts have all
        // joined. Retire their subcomponent feeds before allocating memory
        // columns; interaction generation needs only the separate lookup slab.
        for (execution.producers) |*producer| producer.releaseSubcomponentWords(allocator);
        const tables = @import("../witness/memory_tables.zig");
        const address = try collector.reserveNamed(
            "memory_address_to_id",
            0,
            tables.address_column_count,
            try tables.addressRowCount(input),
        );
        defer allocator.free(address);
        try implicit.memoryAddressInto(input, &counts, address);
        const big_component_count = try tables.bigComponentCount(input);
        for (0..big_component_count) |component_index| {
            const big = try collector.reserveNamed(
                "memory_id_to_big",
                @intCast(component_index),
                tables.big_column_count,
                try tables.bigRowCount(input, component_index),
            );
            defer allocator.free(big);
            // Base AIR places multiplicity first; interaction sources place it
            // last. Reorder headers alone, never the underlying field columns.
            var source_order: [tables.big_column_count][]u32 = undefined;
            @memcpy(source_order[0..tables.big_limb_count], big[1..]);
            source_order[tables.big_limb_count] = big[0];
            try implicit.memoryBigInto(input, &counts, component_index, &source_order);
        }
        const small = try collector.reserveNamed(
            "memory_id_to_small",
            0,
            tables.small_column_count,
            try tables.smallRowCount(input),
        );
        defer allocator.free(small);
        var source_order: [tables.small_column_count][]u32 = undefined;
        @memcpy(source_order[0..tables.small_limb_count], small[1..]);
        source_order[tables.small_limb_count] = small[0];
        try implicit.memorySmallInto(input, &counts, &source_order);
        break :blk counts;
    };
    errdefer memory_counts.deinit();

    const columns = blk: {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "base_finalize",
            "Base-column finalization",
        );
        defer stage.end();
        break :blk try collector.finish();
    };
    return .{
        .allocator = allocator,
        .columns = columns,
        .geometry = geometry.*,
        .execution = execution,
        .fixed_multiplicities = multiplicities,
        .memory_counts = memory_counts,
        .arena_backed = collector.arena != null,
        .borrowed_geometry = borrowed,
    };
}

fn deinitColumns(
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
) void {
    if (columns.len == 0) return;
    for (columns) |column| allocator.free(column.values);
    allocator.free(columns);
}
