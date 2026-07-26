//! Oracle-gated assembly of an official Cairo base commitment tree.
//!
//! This conformance path deliberately receives an authenticated checkpoint for
//! component geometry and value validation. Production admission must replace
//! that fixture authority with live claim geometry before accepting arbitrary
//! inputs.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_impl");
const adapter = @import("../adapter/mod.zig");
const checkpoint = @import("../conformance/checkpoint.zig");
const fixed_trace = @import("../conformance/fixed_trace.zig");
const recorded_trace = @import("../conformance/recorded_trace.zig");
const component_executor = @import("../witness/component_executor.zig");
const cpu_memory = @import("../witness/cpu_memory_multiplicity.zig");
const feed_topology = @import("../witness/feed_topology.zig");
const fixed_tables = @import("../witness/fixed_table_bundle.zig");
const implicit = @import("../witness/implicit_interaction_sources.zig");
const witness_bundle = @import("../witness/bundle.zig");

const M31 = core.fields.m31.M31;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;

pub const BaseTrace = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    execution: recorded_trace.Execution,

    pub fn deinit(self: *BaseTrace) void {
        deinitColumns(self.allocator, self.columns);
        self.execution.deinit();
        self.* = undefined;
    }
};

pub fn build(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    programs: *const witness_bundle.Bundle,
    topology: feed_topology.Loaded,
    fixed: *const fixed_tables.Bundle,
    expected: []const checkpoint.Component,
) !BaseTrace {
    var collector = try Collector.init(allocator, expected);
    defer collector.deinit();
    var execution = try recorded_trace.executeObserved(
        allocator,
        input,
        programs,
        expected,
        .{
            .context = &collector,
            .visit = observeGenerated,
        },
    );
    errdefer execution.deinit();
    if (execution.mismatch != null) return error.BaseTraceMismatch;

    var multiplicities = try fixed_trace.populateTopology(
        allocator,
        input,
        topology,
        execution.producers,
        fixed,
        expected,
    );
    defer multiplicities.deinit();
    var max_fixed_rows: usize = 0;
    for (fixed.entries) |entry| {
        max_fixed_rows = @max(max_fixed_rows, entry.row_count);
    }
    const zeros = try allocator.alloc(u32, max_fixed_rows);
    defer allocator.free(zeros);
    @memset(zeros, 0);
    for (fixed.entries) |entry| {
        const component = findExpected(expected, entry.component) orelse continue;
        const source_columns = try allocator.alloc(
            []const u32,
            entry.trace_multiplicity_columns.len,
        );
        defer allocator.free(source_columns);
        for (entry.trace_multiplicity_columns, source_columns) |relation, *source| {
            source.* = try multiplicities.column(entry.component, relation, zeros);
        }
        try collector.capture(component, source_columns);
    }

    var counts = try cpu_memory.collectTopology(
        allocator,
        input,
        topology,
        execution.producers,
    );
    defer counts.deinit();
    var address = try implicit.memoryAddress(allocator, input, &counts);
    defer address.deinit();
    try collector.capture(
        findExpected(expected, "memory_address_to_id") orelse
            return error.MissingMemoryComponent,
        address.columns,
    );
    var big = try implicit.memoryBig(allocator, input, &counts, 0);
    defer big.deinit();
    const big_base_columns = try memoryBaseOrder(allocator, big.columns);
    defer allocator.free(big_base_columns);
    try collector.capture(
        findExpected(expected, "memory_id_to_big[0]") orelse
            return error.MissingMemoryComponent,
        big_base_columns,
    );
    var small = try implicit.memorySmall(allocator, input, &counts);
    defer small.deinit();
    const small_base_columns = try memoryBaseOrder(allocator, small.columns);
    defer allocator.free(small_base_columns);
    try collector.capture(
        findExpected(expected, "memory_id_to_small") orelse
            return error.MissingMemoryComponent,
        small_base_columns,
    );

    const columns = try collector.finish();
    return .{
        .allocator = allocator,
        .columns = columns,
        .execution = execution,
    };
}

const Collector = struct {
    allocator: std.mem.Allocator,
    expected: []const checkpoint.Component,
    components: []?[]ColumnEvaluation,

    fn init(
        allocator: std.mem.Allocator,
        expected: []const checkpoint.Component,
    ) !Collector {
        const components = try allocator.alloc(?[]ColumnEvaluation, expected.len);
        @memset(components, null);
        return .{
            .allocator = allocator,
            .expected = expected,
            .components = components,
        };
    }

    fn deinit(self: *Collector) void {
        for (self.components) |maybe_columns| {
            if (maybe_columns) |columns| deinitColumns(self.allocator, columns);
        }
        self.allocator.free(self.components);
        self.* = undefined;
    }

    fn capture(
        self: *Collector,
        component: checkpoint.Component,
        source_columns: []const []const u32,
    ) !void {
        const component_index = findExpectedIndex(self.expected, component.label) orelse
            return error.UnknownBaseComponent;
        if (self.components[component_index] != null or
            source_columns.len != component.columns.len)
            return error.InvalidBaseTraceGeometry;

        const evaluations = try self.allocator.alloc(
            ColumnEvaluation,
            source_columns.len,
        );
        var initialized: usize = 0;
        errdefer {
            for (evaluations[0..initialized]) |evaluation| {
                self.allocator.free(evaluation.values);
            }
            self.allocator.free(evaluations);
        }
        for (source_columns, component.columns, evaluations) |source, oracle, *evaluation| {
            if (source.len != oracle.row_count or !std.math.isPowerOfTwo(source.len))
                return error.InvalidBaseTraceGeometry;
            const digest = try checkpoint.digestColumn(
                component.ordinal,
                component.label,
                oracle.ordinal,
                source,
            );
            if (!std.mem.eql(u8, &digest, &oracle.sha256))
                return error.BaseTraceMismatch;
            const values = try self.allocator.alloc(M31, source.len);
            errdefer self.allocator.free(values);
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

    fn finish(self: *Collector) ![]ColumnEvaluation {
        var total: usize = 0;
        for (self.components) |maybe_columns| {
            const columns = maybe_columns orelse return error.MissingBaseComponent;
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
    expected: checkpoint.Component,
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
    try collector.capture(expected, columns);
}

fn findExpected(
    components: []const checkpoint.Component,
    label: []const u8,
) ?checkpoint.Component {
    const index = findExpectedIndex(components, label) orelse return null;
    return components[index];
}

fn findExpectedIndex(
    components: []const checkpoint.Component,
    label: []const u8,
) ?usize {
    for (components, 0..) |component, index| {
        if (std.mem.eql(u8, component.label, label)) return index;
    }
    return null;
}

fn deinitColumns(
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
) void {
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
