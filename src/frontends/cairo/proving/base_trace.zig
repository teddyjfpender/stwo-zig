//! Live assembly of an official Cairo base commitment tree.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_impl");
const adapter = @import("../adapter/mod.zig");
const claim_generator = @import("../claim_generator.zig");
const fixed_trace = @import("../conformance/fixed_trace.zig");
const component_executor = @import("../witness/component_executor.zig");
const component_layout = @import("../witness/component_layout.zig");
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

/// Storage the caller has already planned and allocated. When present every
/// generated and implicit base column is written directly at its final arena
/// offset, so no column is ever moved after execution. The arena and the claim
/// geometry both stay owned by the caller.
pub const Prepared = struct {
    geometry: *claim_generator.OwnedClaimGeometry,
    arena: *const trace_arena.Arena,
};

pub const BaseTrace = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    geometry: claim_generator.OwnedClaimGeometry,
    execution: live_graph.Execution,
    /// Column values borrow a caller-owned arena and must not be freed here.
    arena_backed: bool = false,
    /// True when the caller supplied both the geometry and the arena.
    borrowed_geometry: bool = false,

    pub fn deinit(self: *BaseTrace) void {
        if (self.arena_backed) {
            self.allocator.free(self.columns);
            self.execution.deinit();
            if (!self.borrowed_geometry) self.geometry.deinit();
            self.* = undefined;
            return;
        }
        deinitColumns(self.allocator, self.columns);
        self.execution.deinit();
        if (!self.borrowed_geometry) self.geometry.deinit();
        self.* = undefined;
    }

    pub fn takeColumns(self: *BaseTrace) []ColumnEvaluation {
        const columns = self.columns;
        self.columns = &.{};
        return columns;
    }
};

pub fn build(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    programs: *const witness_bundle.Bundle,
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
    topology: feed_topology.Loaded,
    fixed: *const fixed_tables.Bundle,
    pedersen_table: ?deductions.PedersenTable,
    recorder: ?*prover.stage_profile.Recorder,
    geometry: *claim_generator.OwnedClaimGeometry,
    collector: *Collector,
    borrowed: bool,
) !BaseTrace {
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
            geometry,
            .{
                .context = collector,
                .visit = observeGenerated,
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
        break :blk try fixed_trace.populateLiveTopology(
            allocator,
            input,
            topology,
            execution.producers,
            fixed,
        );
    };
    defer multiplicities.deinit();
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

    {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "base_memory_tables",
            "Memory-table construction",
        );
        defer stage.end();
        var counts = try cpu_memory.collectTopology(
            allocator,
            input,
            topology,
            execution.producers,
        );
        defer counts.deinit();
        var address = try implicit.memoryAddress(allocator, input, &counts);
        defer address.deinit();
        try collector.captureNamed("memory_address_to_id", 0, address.columns);
        const big_component_count = try @import("../witness/memory_tables.zig")
            .bigComponentCount(input);
        for (0..big_component_count) |component_index| {
            var big = try implicit.memoryBig(allocator, input, &counts, component_index);
            defer big.deinit();
            const big_base_columns = try memoryBaseOrder(allocator, big.columns);
            defer allocator.free(big_base_columns);
            try collector.captureNamed(
                "memory_id_to_big",
                @intCast(component_index),
                big_base_columns,
            );
        }
        var small = try implicit.memorySmall(allocator, input, &counts);
        defer small.deinit();
        const small_base_columns = try memoryBaseOrder(allocator, small.columns);
        defer allocator.free(small_base_columns);
        try collector.captureNamed("memory_id_to_small", 0, small_base_columns);
    }

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
        .arena_backed = collector.arena != null,
        .borrowed_geometry = borrowed,
    };
}

const Collector = struct {
    allocator: std.mem.Allocator,
    geometry: *const claim_generator.OwnedClaimGeometry,
    components: []?[]ColumnEvaluation,
    /// When set every captured column is written at its planned arena offset
    /// and no column values are owned by this collector.
    arena: ?*const trace_arena.Arena = null,

    fn initPrepared(
        allocator: std.mem.Allocator,
        prepared: Prepared,
    ) !Collector {
        var collector = try Collector.init(allocator, prepared.geometry);
        collector.arena = prepared.arena;
        return collector;
    }

    fn init(
        allocator: std.mem.Allocator,
        geometry: *const claim_generator.OwnedClaimGeometry,
    ) !Collector {
        const components = try allocator.alloc(?[]ColumnEvaluation, geometry.components.len);
        @memset(components, null);
        return .{
            .allocator = allocator,
            .geometry = geometry,
            .components = components,
        };
    }

    fn deinit(self: *Collector) void {
        for (self.components) |maybe_columns| {
            if (maybe_columns) |columns| {
                if (self.arena == null)
                    deinitColumns(self.allocator, columns)
                else
                    self.allocator.free(columns);
            }
        }
        self.allocator.free(self.components);
        self.* = undefined;
    }

    fn captureNamed(
        self: *Collector,
        name: []const u8,
        instance: u32,
        source_columns: []const []const u32,
    ) !void {
        const component_index = self.findIndex(name, instance) orelse
            return error.UnknownBaseComponent;
        try self.capture(component_index, source_columns);
    }

    fn capture(
        self: *Collector,
        component_index: usize,
        source_columns: []const []const u32,
    ) !void {
        if (component_index >= self.components.len or
            self.components[component_index] != null or source_columns.len == 0)
            return error.InvalidBaseTraceGeometry;
        const evaluations = try self.allocator.alloc(
            ColumnEvaluation,
            source_columns.len,
        );
        var initialized: usize = 0;
        errdefer {
            if (self.arena == null) {
                for (evaluations[0..initialized]) |evaluation| {
                    self.allocator.free(evaluation.values);
                }
            }
            self.allocator.free(evaluations);
        }
        // A planned arena fixes each column's destination before execution, so
        // the plan's predicted width for this component must match what the
        // witness actually produced. A mismatch is a planning bug, not a
        // fallback condition: fail closed rather than write outside a range.
        const arena_base: ?usize = if (self.arena) |arena| blk: {
            if (component_index >= arena.layout.component_widths.len or
                arena.layout.component_widths[component_index] != source_columns.len)
                return trace_arena.Error.ArenaPlanMismatch;
            break :blk arena.layout.component_starts[component_index];
        } else null;
        for (source_columns, evaluations, 0..) |source, *evaluation, column| {
            if (source.len < 16 or !std.math.isPowerOfTwo(source.len))
                return error.InvalidBaseTraceGeometry;
            const values = if (arena_base) |base|
                try self.arena.?.columnValues(base + column)
            else
                try self.allocator.alloc(M31, source.len);
            errdefer if (arena_base == null) self.allocator.free(values);
            if (values.len != source.len) return trace_arena.Error.ArenaPlanMismatch;
            for (source, values) |raw, *value| {
                value.* = M31.fromCanonical(raw);
            }
            evaluation.* = .{
                .log_size = @intCast(std.math.log2_int(usize, source.len)),
                .values = values,
            };
            initialized += 1;
        }
        self.components[component_index] = evaluations;
    }

    fn findIndex(self: *const Collector, name: []const u8, instance: u32) ?usize {
        for (self.geometry.components, 0..) |component, index| {
            if (component.instance == instance and
                std.mem.eql(u8, component.name, name))
                return index;
        }
        return null;
    }

    fn finish(self: *Collector) ![]ColumnEvaluation {
        var total: usize = 0;
        for (self.components, 0..) |maybe_columns, component_index| {
            const columns = maybe_columns orelse return error.MissingBaseComponent;
            const component = self.geometry.components[component_index];
            const expected_log = switch (component.log_size) {
                .known => |value| value,
                .deferred => return error.UnresolvedBaseTraceGeometry,
            };
            if (columns.len == 0 or columns[0].log_size != expected_log)
                return error.InvalidBaseTraceGeometry;
            total = std.math.add(usize, total, columns.len) catch
                return error.BaseTraceTooLarge;
        }
        const flattened = try self.allocator.alloc(ColumnEvaluation, total);
        var cursor: usize = 0;
        for (self.components) |*maybe_columns| {
            const columns = maybe_columns.*.?;
            @memcpy(flattened[cursor..][0..columns.len], columns);
            cursor += columns.len;
            self.allocator.free(columns);
            maybe_columns.* = null;
        }
        return flattened;
    }
};

fn observeGenerated(
    raw_context: *anyopaque,
    layout: component_layout.ComponentLayout,
    execution: *const component_executor.Execution,
) !void {
    const collector: *Collector = @ptrCast(@alignCast(raw_context));
    const columns = try collector.allocator.alloc(
        []const u32,
        execution.output_columns.len,
    );
    defer collector.allocator.free(columns);
    for (execution.output_columns, columns) |source, *destination| {
        destination.* = source;
    }
    const component_index: usize = layout.ordinal;
    if (component_index >= collector.components.len or
        !std.mem.eql(
            u8,
            layout.label,
            collector.geometry.components[component_index].name,
        ))
        return error.InvalidBaseTraceGeometry;
    try collector.capture(component_index, columns);
}

fn deinitColumns(
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
) void {
    if (columns.len == 0) return;
    for (columns) |column| allocator.free(column.values);
    allocator.free(columns);
}

fn memoryBaseOrder(
    allocator: std.mem.Allocator,
    source: []const []const u32,
) ![][]const u32 {
    if (source.len < 2) return error.InvalidBaseTraceGeometry;
    const ordered = try allocator.alloc([]const u32, source.len);
    ordered[0] = source[source.len - 1];
    @memcpy(ordered[1..], source[0 .. source.len - 1]);
    return ordered;
}
