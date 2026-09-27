//! Allocation-free Tree-2 views over either main-trace production authority.
//!
//! The predecessor path owns independently allocated opcode/clock buffers and
//! lookup counters through `ProofWorkspace` plus `lookup_sources.Result`. The
//! prepared R-002 path owns retained columns in one private allocation and the
//! canonical reduced counter set through `production.Prepared`. Tree 2 borrows
//! both through this union; it never transfers, copies, rescans, or frees them.
//!
//! Switching occurs once per component, clock column, or table. No tagged-union
//! dispatch appears in a row hot loop.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const lookup_counter = @import("../air/lookups/tables/counter.zig");
const lookup_schema = @import("../air/lookups/tables/schema.zig");
const statement_mod = @import("../air/statement.zig");
const infra = @import("../infra_trace.zig");
const trace_mod = @import("../runner/trace.zig");
const lookup_sources = @import("lookup_sources.zig");
const production = @import("main_trace_plan_execution_production.zig");
const proof_workspace = @import("proof_workspace.zig");

const ProofWorkspace = proof_workspace.ProofWorkspace;

pub const Error = error{
    InvalidTree2StatementAuthority,
    InvalidTree2OpcodeSource,
    InvalidTree2ClockSource,
    InvalidTree2LookupSource,
};

pub const Legacy = struct {
    workspace: *const ProofWorkspace,
    lookup_source: *const lookup_sources.Result,
};

pub const Source = union(enum) {
    legacy: Legacy,
    planned: *const production.Prepared,

    pub fn fromLegacy(
        workspace: *const ProofWorkspace,
        lookup_source: *const lookup_sources.Result,
    ) Source {
        return .{ .legacy = .{
            .workspace = workspace,
            .lookup_source = lookup_source,
        } };
    }

    pub fn fromPlanned(prepared: *const production.Prepared) Source {
        return .{ .planned = prepared };
    }

    /// Validates every retained view before Tree 2 allocates its first output.
    pub fn validate(
        self: Source,
        statement: *const statement_mod.RiscVStatement,
    ) !void {
        try self.validateStatementAuthority(statement);

        var opcode_views: [trace_mod.MAX_FAMILY_COLUMNS][]const M31 = undefined;
        for (0..statement.n_components) |component_index| {
            _ = try self.opcodeColumns(statement, component_index, &opcode_views);
        }

        var clock_views: [infra.CLOCK_UPDATE_COLS][]const M31 = undefined;
        _ = try self.clockColumns(statement, &clock_views);

        inline for (std.meta.fields(lookup_schema.Kind)) |field| {
            const kind: lookup_schema.Kind = @enumFromInt(field.value);
            _ = try self.lookupCounter(kind);
        }
    }

    /// Fills one caller-owned fixed-capacity descriptor array with borrowed
    /// columns in physical order.
    pub fn opcodeColumns(
        self: Source,
        statement: *const statement_mod.RiscVStatement,
        component_index: usize,
        output: *[trace_mod.MAX_FAMILY_COLUMNS][]const M31,
    ) ![]const []const M31 {
        if (component_index >= statement.n_components) {
            return error.InvalidTree2OpcodeSource;
        }
        const desc = statement.component_descs[component_index];
        const count: usize = @intCast(desc.n_columns);
        if (count != trace_mod.nColumnsForFamily(desc.family) or
            count > output.len or desc.log_size >= @bitSizeOf(usize))
        {
            return error.InvalidTree2OpcodeSource;
        }
        const domain = @as(usize, 1) << @intCast(desc.log_size);

        switch (self) {
            .legacy => |source| {
                const component = &source.workspace.opcode_columns.components[component_index];
                if (component.n_columns != count or component.n_real_rows != desc.n_rows) {
                    return error.InvalidTree2OpcodeSource;
                }
                for (component.columns[0..count], output[0..count]) |column, *view| {
                    if (column.len != domain) return error.InvalidTree2OpcodeSource;
                    view.* = column;
                }
            },
            .planned => |prepared| {
                for (output[0..count], 0..) |*view, column_index| {
                    const column = prepared.retainedOpcodeColumn(
                        component_index,
                        column_index,
                    ) catch return error.InvalidTree2OpcodeSource;
                    if (column.len != domain) return error.InvalidTree2OpcodeSource;
                    view.* = column;
                }
            },
        }
        return output[0..count];
    }

    pub fn clockColumns(
        self: Source,
        statement: *const statement_mod.RiscVStatement,
        output: *[infra.CLOCK_UPDATE_COLS][]const M31,
    ) ![]const []const M31 {
        const log_size = try clockLogSize(statement);
        if (log_size >= @bitSizeOf(usize)) return error.InvalidTree2ClockSource;
        const domain = @as(usize, 1) << @intCast(log_size);
        switch (self) {
            .legacy => |source| {
                for (source.workspace.clock_main, output) |column, *view| {
                    if (column.len != domain) return error.InvalidTree2ClockSource;
                    view.* = column;
                }
            },
            .planned => |prepared| {
                for (output, 0..) |*view, column_index| {
                    const column = prepared.retainedClockColumn(column_index) catch
                        return error.InvalidTree2ClockSource;
                    if (column.len != domain) return error.InvalidTree2ClockSource;
                    view.* = column;
                }
            },
        }
        return output;
    }

    pub fn lookupCounter(
        self: Source,
        kind: lookup_schema.Kind,
    ) !*const lookup_counter.Counter {
        const counter = switch (self) {
            .legacy => |source| &source.lookup_source.counters.counters[@intFromEnum(kind)],
            .planned => |prepared| prepared.retainedLookupCounter(kind) catch
                return error.InvalidTree2LookupSource,
        };
        if (counter.kind != kind or counter.values.len != lookup_schema.size(kind)) {
            return error.InvalidTree2LookupSource;
        }
        return counter;
    }

    fn validateStatementAuthority(
        self: Source,
        statement: *const statement_mod.RiscVStatement,
    ) !void {
        const source_statement = switch (self) {
            .legacy => |source| &source.workspace.statement,
            .planned => |prepared| prepared.retainedStatement() catch
                return error.InvalidTree2StatementAuthority,
        };
        if (source_statement != statement) {
            return error.InvalidTree2StatementAuthority;
        }
    }
};

fn clockLogSize(statement: *const statement_mod.RiscVStatement) !u32 {
    var found: ?u32 = null;
    for (statement.infra_descs[0..statement.n_infra]) |desc| {
        if (desc.kind != .clock_update) continue;
        if (found != null or desc.n_columns != infra.CLOCK_UPDATE_COLS) {
            return error.InvalidTree2ClockSource;
        }
        found = desc.log_size;
    }
    return found orelse error.InvalidTree2ClockSource;
}

test "Tree2 main source validates legacy authority and rejects every ownership drift" {
    const allocator = std.testing.allocator;
    const workspace = try ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);

    const family: trace_mod.OpcodeFamily = .fence;
    const column_count: usize = trace_mod.nColumnsForFamily(family);
    const log_size: u32 = 1;
    const domain = @as(usize, 1) << log_size;
    workspace.statement.n_components = 1;
    workspace.statement.component_descs[0] = .{
        .family = family,
        .log_size = log_size,
        .n_rows = 1,
        .n_columns = @intCast(column_count),
    };
    workspace.statement.n_infra = 1;
    workspace.statement.infra_descs[0] = .{
        .kind = .clock_update,
        .log_size = log_size,
        .n_rows = 1,
        .n_columns = infra.CLOCK_UPDATE_COLS,
    };

    workspace.opcode_columns.lookup_counters = null;
    const component = &workspace.opcode_columns.components[0];
    component.n_columns = column_count;
    component.n_real_rows = 1;
    var initialized_opcode: usize = 0;
    errdefer for (component.columns[0..initialized_opcode]) |column| allocator.free(column);
    for (component.columns[0..column_count]) |*column| {
        column.* = try allocator.alloc(M31, domain);
        initialized_opcode += 1;
        @memset(column.*, M31.zero());
    }
    defer workspace.releaseOpcodeColumns(allocator);

    var initialized_clock: usize = 0;
    errdefer for (workspace.clock_main[0..initialized_clock]) |column| allocator.free(column);
    for (&workspace.clock_main) |*column| {
        column.* = try allocator.alloc(M31, domain);
        initialized_clock += 1;
        @memset(column.*, M31.zero());
    }
    defer workspace.releaseClockMain(allocator);

    var lookup_source = lookup_sources.Result{
        .counters = try lookup_counter.Set.init(allocator),
    };
    defer lookup_source.deinit(allocator);
    const source = Source.fromLegacy(workspace, &lookup_source);
    try source.validate(&workspace.statement);

    var opcode_views: [trace_mod.MAX_FAMILY_COLUMNS][]const M31 = undefined;
    const actual_opcode = try source.opcodeColumns(
        &workspace.statement,
        0,
        &opcode_views,
    );
    try std.testing.expectEqual(column_count, actual_opcode.len);
    for (actual_opcode, component.columns[0..column_count]) |actual, expected| {
        try std.testing.expectEqual(expected.ptr, actual.ptr);
    }

    var clock_views: [infra.CLOCK_UPDATE_COLS][]const M31 = undefined;
    const actual_clock = try source.clockColumns(&workspace.statement, &clock_views);
    for (actual_clock, workspace.clock_main) |actual, expected| {
        try std.testing.expectEqual(expected.ptr, actual.ptr);
    }
    try std.testing.expectEqual(
        &lookup_source.counters.counters[@intFromEnum(lookup_schema.Kind.bitwise)],
        try source.lookupCounter(.bitwise),
    );

    var copied_statement = workspace.statement;
    try std.testing.expectError(
        error.InvalidTree2StatementAuthority,
        source.validate(&copied_statement),
    );

    component.n_columns -= 1;
    try std.testing.expectError(
        error.InvalidTree2OpcodeSource,
        source.validate(&workspace.statement),
    );
    component.n_columns += 1;

    const full_clock = workspace.clock_main[0];
    workspace.clock_main[0] = full_clock[0 .. domain - 1];
    try std.testing.expectError(
        error.InvalidTree2ClockSource,
        source.validate(&workspace.statement),
    );
    workspace.clock_main[0] = full_clock;

    const bitwise = &lookup_source.counters.counters[@intFromEnum(lookup_schema.Kind.bitwise)];
    bitwise.kind = .range_check_20;
    try std.testing.expectError(
        error.InvalidTree2LookupSource,
        source.validate(&workspace.statement),
    );
    bitwise.kind = .bitwise;
    try source.validate(&workspace.statement);
}
