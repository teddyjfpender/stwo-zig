//! Final-column placement and ownership for generated and implicit base tables.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const ColumnEvaluation = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const claim_generator = @import("../claim_generator.zig");
const component_layout = @import("../witness/component_layout.zig");
const component_executor = @import("../witness/component_executor.zig");
const column_lowering = @import("../witness/column_lowering.zig");
const trace_arena = @import("trace_arena.zig");

/// Storage the caller has already planned and allocated. When present every
/// generated and implicit base column is written directly at its final arena
/// offset, so no column is ever moved after execution. The arena and the claim
/// geometry both stay owned by the caller.
pub const Prepared = struct {
    geometry: *claim_generator.OwnedClaimGeometry,
    arena: *const trace_arena.Arena,
};

pub const Collector = struct {
    allocator: std.mem.Allocator,
    geometry: *const claim_generator.OwnedClaimGeometry,
    components: []?[]ColumnEvaluation,
    /// When set every captured column is written at its planned arena offset
    /// and no column values are owned by this collector.
    arena: ?*const trace_arena.Arena = null,

    pub fn initPrepared(
        allocator: std.mem.Allocator,
        prepared: Prepared,
    ) !Collector {
        var collector = try Collector.init(allocator, prepared.geometry);
        collector.arena = prepared.arena;
        return collector;
    }

    pub fn init(
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

    pub fn deinit(self: *Collector) void {
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

    pub fn captureNamed(
        self: *Collector,
        name: []const u8,
        instance: u32,
        source_columns: []const []const u32,
    ) !void {
        const component_index = self.findIndex(name, instance) orelse
            return error.UnknownBaseComponent;
        try self.capture(component_index, source_columns);
    }

    /// Reserve owned final columns for an implicit writer. Only the returned
    /// slice headers belong to the caller; values remain collector-owned until
    /// finish transfers them. A failed writer is cleaned up by collector.deinit.
    pub fn reserveNamed(
        self: *Collector,
        name: []const u8,
        instance: u32,
        width: usize,
        rows: usize,
    ) ![][]u32 {
        const index = self.findIndex(name, instance) orelse return error.UnknownBaseComponent;
        if (self.components[index] != null or width == 0 or rows < 16 or !std.math.isPowerOfTwo(rows))
            return error.InvalidBaseTraceGeometry;
        const destinations = try self.allocator.alloc([]u32, width);
        errdefer self.allocator.free(destinations);
        const columns = try self.allocateColumns(index, width, rows);
        for (columns, destinations) |column, *destination|
            destination.* = @as([*]u32, @ptrCast(@constCast(column.values.ptr)))[0..column.values.len];
        self.components[index] = columns;
        return destinations;
    }

    fn capture(
        self: *Collector,
        component_index: usize,
        source_columns: []const []const u32,
    ) !void {
        if (component_index >= self.components.len or
            self.components[component_index] != null or source_columns.len == 0)
            return error.InvalidBaseTraceGeometry;
        const evaluations = try self.allocateColumns(component_index, source_columns.len, source_columns[0].len);
        errdefer self.releaseColumns(evaluations);
        const mutable_columns = try self.allocator.alloc([]M31, source_columns.len);
        defer self.allocator.free(mutable_columns);
        for (evaluations, mutable_columns) |evaluation, *destination| destination.* = @constCast(evaluation.values);
        const parallel = if (std.posix.getenv("STWO_CAIRO_PARALLEL_BASE_LOWERING")) |value|
            std.mem.eql(u8, value, "1")
        else
            true;
        try column_lowering.lower(source_columns, mutable_columns, parallel);
        self.components[component_index] = evaluations;
    }

    fn releaseColumns(self: *Collector, columns: []ColumnEvaluation) void {
        if (self.arena == null) for (columns) |column| self.allocator.free(column.values);
        self.allocator.free(columns);
    }

    fn allocateColumns(self: *Collector, component_index: usize, width: usize, rows: usize) ![]ColumnEvaluation {
        if (component_index >= self.components.len or self.components[component_index] != null or width == 0 or
            rows < 16 or !std.math.isPowerOfTwo(rows)) return error.InvalidBaseTraceGeometry;
        const arena_base: ?usize = if (self.arena) |arena| blk: {
            if (component_index >= arena.layout.component_widths.len or arena.layout.component_widths[component_index] != width)
                return trace_arena.Error.ArenaPlanMismatch;
            break :blk arena.layout.component_starts[component_index];
        } else null;
        const columns = try self.allocator.alloc(ColumnEvaluation, width);
        var initialized: usize = 0;
        errdefer {
            if (self.arena == null) for (columns[0..initialized]) |column| self.allocator.free(column.values);
            self.allocator.free(columns);
        }
        for (columns, 0..) |*column, ordinal| {
            const values = if (arena_base) |base| try self.arena.?.columnValues(base + ordinal) else try self.allocator.alloc(M31, rows);
            if (values.len != rows) return trace_arena.Error.ArenaPlanMismatch;
            column.* = .{ .log_size = @intCast(std.math.log2_int(usize, rows)), .values = values };
            initialized += 1;
        }
        return columns;
    }

    pub fn findIndex(self: *const Collector, name: []const u8, instance: u32) ?usize {
        for (self.geometry.components, 0..) |component, index| {
            if (component.instance == instance and
                std.mem.eql(u8, component.name, name))
                return index;
        }
        return null;
    }

    pub fn finish(self: *Collector) ![]ColumnEvaluation {
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

/// Loan final commitment columns to each writer once its real domain is known.
/// Compact consumers cannot be sized before their inputs have been deduplicated;
/// component placement therefore also works without a whole-trace arena.
pub fn reserveGenerated(raw_context: *anyopaque, allocator: std.mem.Allocator, layout: component_layout.ComponentLayout) !?[][]u32 {
    const collector: *Collector = @ptrCast(@alignCast(raw_context));
    const index = layout.ordinal;
    layout.validate() catch return error.InvalidBaseTraceGeometry;
    if (index >= collector.components.len or collector.components[index] != null or !std.mem.eql(u8, layout.label, collector.geometry.components[index].name))
        return error.InvalidBaseTraceGeometry;
    const destinations = try allocator.alloc([]u32, layout.column_count);
    errdefer allocator.free(destinations);
    const columns = try collector.allocateColumns(index, layout.column_count, layout.row_count);
    for (columns, destinations) |column, *destination|
        destination.* = @as([*]u32, @ptrCast(@constCast(column.values.ptr)))[0..column.values.len];
    collector.components[index] = columns;
    return destinations;
}

pub fn observeGenerated(
    raw_context: *anyopaque,
    layout: component_layout.ComponentLayout,
    execution: *const component_executor.Execution,
) !void {
    const collector: *Collector = @ptrCast(@alignCast(raw_context));
    const component_index: usize = layout.ordinal;
    if (component_index >= collector.components.len or
        !std.mem.eql(
            u8,
            layout.label,
            collector.geometry.components[component_index].name,
        ))
        return error.InvalidBaseTraceGeometry;
    const placed = collector.components[component_index] orelse return error.InvalidBaseTraceGeometry;
    if (placed.len != execution.output_columns.len) return error.InvalidBaseTraceGeometry;
    for (placed, execution.output_columns) |evaluation, source| {
        if (evaluation.values.len != source.len or @intFromPtr(evaluation.values.ptr) != @intFromPtr(source.ptr))
            return error.InvalidBaseTraceGeometry;
        if (@import("builtin").mode == .Debug or @import("builtin").mode == .ReleaseSafe) {
            for (source) |raw| std.debug.assert(raw < 0x7fffffff);
        }
    }
}

fn deinitColumns(allocator: std.mem.Allocator, columns: []ColumnEvaluation) void {
    for (columns) |column| allocator.free(column.values);
    allocator.free(columns);
}
