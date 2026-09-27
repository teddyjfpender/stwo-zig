//! Shared private scalar sources for full-STARK arithmetic and hash openings.
//! Builder storage belongs to the owning parent path arena.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const boundary = @import("blake3_boundary.zig");
const deep = @import("pcs_deep_circuit.zig");
const fri = @import("fri_verifier_circuit.zig");
const wiring = @import("fri_hash_wire_plan.zig");
pub const encoding = @import("blake3_field_bytes.zig");
pub const pack = @import("qm31_pack_wire.zig");
pub const Source = struct { lane: usize, node: u32, value: M31 };
pub const ro = @import("readonly_consistency.zig");
pub const adapter = @import("readonly_input.zig");
const projection = @import("blake3_projection_links.zig");
const PACK_CIRCUIT: u32 = 5_000_001;
pub const Columns = @import("blake3_upstream_source_columns_v1.zig").ForSlots(.{ 2, 10, 11, 16, 17 });
pub const Prepared = struct {
    sources: []Source,
    source_allocator: ?std.mem.Allocator = null,
    columns: ?Columns = null,
    projection: projection.Prepared,
    readonly_rows: []ro.Row,
    fixed_readonly_rows: []ro.Row,
    adapter_rows: []adapter.Row,
    fixed_adapter_rows: []adapter.Row,
    sentinels: []boundary.Row,
    encoded: []encoding.Row,
    fixed_encoded: []encoding.Row,
    packing: []pack.Row,
    fixed_packed: []pack.Row,
    pub fn releaseSources(self: *Prepared) void {
        if (self.source_allocator) |a| {
            a.free(self.sources);
            self.sources = &.{};
            self.source_allocator = null;
        }
    }
    pub fn deinitColumns(self: *Prepared) void {
        self.releaseSources();
        if (self.columns) |*columns| columns.deinit();
        self.columns = null;
        self.projection.deinitColumns();
    }
    pub fn appendCohort(self: *const Prepared, comptime slot: usize, b: anytype) !void {
        if (self.columns) |*columns| {
            if (self.readonly_rows.len != 0 or self.fixed_readonly_rows.len != 0 or self.adapter_rows.len != 0 or self.fixed_adapter_rows.len != 0 or self.sentinels.len != 0 or self.encoded.len != 0 or self.fixed_encoded.len != 0 or self.packing.len != 0 or self.fixed_packed.len != 0) return error.InvalidOpeningInput;
            try columns.appendTo(slot, b);
            if (slot == 11) try self.projection.appendPacking(b);
        } else switch (slot) {
            2 => try b.append(2, self.sentinels, self.sentinels),
            10 => try b.append(10, self.encoded, self.fixed_encoded),
            11 => try b.append(11, self.packing, self.fixed_packed),
            16 => try b.append(16, self.readonly_rows, self.fixed_readonly_rows),
            17 => try b.append(17, self.adapter_rows, self.fixed_adapter_rows),
            else => @compileError("not an opening source cohort"),
        }
    }
};
pub const Builder = struct {
    a: std.mem.Allocator,
    output: std.mem.Allocator,
    backing: std.mem.Allocator,
    columns: ?Columns = null,
    direct: bool = false,
    trace_nodes: []u32,
    tree_starts: []usize,
    queries: usize,
    fri_plan: wiring.Plan,
    projection: projection.Prepared,
    column_logs: []u32,
    entries: []?ro.Entry,
    adapter_rows: std.ArrayList(adapter.Row) = .empty,
    fixed_adapter_rows: std.ArrayList(adapter.Row) = .empty,
    sources: std.ArrayList(Source) = .empty,
    encoded: std.ArrayList(encoding.Row) = .empty,
    fixed_encoded: std.ArrayList(encoding.Row) = .empty,
    packing: std.ArrayList(pack.Row) = .empty,
    fixed_packed: std.ArrayList(pack.Row) = .empty,
    pub fn init(a: std.mem.Allocator, capture: anytype, dg: *const deep.Circuit, fg: *const fri.Circuit, query_links: *@import("blake3_query_links.zig").Prepared) !Builder {
        return initMode(false, a, a, a, capture, dg, fg, query_links);
    }
    /// Temporary routing arrays use scratch; retained metadata uses output
    /// arena; source tuples and direct columns own bounded backing allocations.
    pub fn initColumns(scratch: std.mem.Allocator, output: std.mem.Allocator, backing: std.mem.Allocator, capture: anytype, dg: *const deep.Circuit, fg: *const fri.Circuit, query_links: *@import("blake3_query_links.zig").Prepared) !Builder {
        return initMode(true, scratch, output, backing, capture, dg, fg, query_links);
    }
    fn initMode(comptime direct: bool, a: std.mem.Allocator, output: std.mem.Allocator, backing: std.mem.Allocator, capture: anytype, dg: *const deep.Circuit, fg: *const fri.Circuit, query_links: *@import("blake3_query_links.zig").Prepared) !Builder {
        const starts = try a.alloc(usize, capture.column_log_sizes.len + 1);
        starts[0] = 0;
        for (capture.column_log_sizes, 0..) |logs, i| starts[i + 1] = try std.math.add(usize, starts[i], logs.len);
        const n = capture.queries.raw.len;
        if (n == 0 or n != dg.profile().query_count or n != fg.profile().query_count or capture.fri.layers.len == 0) return error.InvalidOpeningInput;
        const nodes = try a.alloc(u32, try std.math.mul(usize, starts[starts.len - 1], n));
        @memset(nodes, std.math.maxInt(u32));
        for (dg.bindings) |binding| switch (binding.source) {
            .queried_value => |source| {
                if (source.tree >= capture.column_log_sizes.len or source.column >= capture.column_log_sizes[source.tree].len or source.query >= n) return error.InvalidOpeningInput;
                const index = (starts[source.tree] + source.column) * n + source.query;
                if (nodes[index] != std.math.maxInt(u32)) return error.InvalidOpeningInput;
                nodes[index] = binding.node_id;
            },
            else => {},
        };
        for (nodes) |node| if (node == std.math.maxInt(u32)) return error.InvalidOpeningInput;
        const column_logs = try a.alloc(u32, starts[starts.len - 1]);
        for (capture.column_log_sizes, 0..) |logs, i| @memcpy(column_logs[starts[i]..starts[i + 1]], logs);
        const entries = try a.alloc(?ro.Entry, nodes.len);
        @memset(entries, null);
        const lifting = capture.fri.layers[0].path_depth + capture.fri.layers[0].fold_step;
        var plan = try wiring.Plan.init(a, fg, 1504, PACK_CIRCUIT);
        errdefer plan.deinit();
        var projected = if (direct) try projection.buildColumns(output, backing, lifting, column_logs, capture.queries.raw, query_links.queries) else try projection.build(output, lifting, column_logs, capture.queries.raw, query_links.queries);
        errdefer projected.deinitColumns();
        var columns: ?Columns = null;
        errdefer if (columns) |*owned| owned.deinit();
        if (direct) columns = try Columns.init(backing, .{ column_logs.len, try std.math.add(usize, nodes.len, plan.schedules.len), plan.schedules.len, nodes.len, nodes.len });
        return .{ .direct = direct, .columns = columns, .a = a, .output = output, .backing = backing, .trace_nodes = nodes, .tree_starts = starts, .queries = n, .fri_plan = plan, .column_logs = column_logs, .entries = entries, .projection = projected };
    }
    pub fn deinit(self: *Builder) void {
        self.fri_plan.deinit();
        if (self.columns) |*columns| columns.deinit();
        self.columns = null;
        self.projection.deinitColumns();
        self.sources.deinit(if (self.direct) self.backing else self.output);
    }
    pub fn trace(self: *Builder, tree: usize, column: usize, query: usize, projected: usize, value: M31, payload: u32, uses: u32) !void {
        if (tree >= self.tree_starts.len - 1 or column >= self.tree_starts[tree + 1] - self.tree_starts[tree] or query >= self.queries) return error.InvalidOpeningInput;
        const index = (self.tree_starts[tree] + column) * self.queries + query;
        const node = self.trace_nodes[index];
        if (self.entries[index] != null or projected > std.math.maxInt(u32)) return error.InvalidOpeningInput;
        self.entries[index] = .{ .index = @intCast(projected), .value = value };
        const col = self.tree_starts[tree] + column;
        const ps = self.projection.ports[self.column_logs[col]].?[query];
        const schedule = adapter.Schedule{ .index = ps, .value = .{ .circuit = 1502, .wire = node }, .table = try table(col) };
        const row = try adapter.logicalRow(schedule, @intCast(projected), value);
        const fixed = try adapter.fixedRow(schedule);
        if (self.columns) |*columns| try columns.appendFixed(17, row, fixed) else {
            try self.adapter_rows.append(self.output, row);
            try self.fixed_adapter_rows.append(self.output, fixed);
        }
        try self.sources.append(if (self.direct) self.backing else self.output, .{ .lane = 1, .node = node, .value = value });
        try self.encode(.{ .source_circuit = 1502, .source_wire = node, .destination_circuit = 3_000_000, .destination_first = payload, .uses = .{ uses, 0, 0, 0 } }, QM31.fromBase(value));
    }
    pub fn friGroup(self: *Builder, layer: usize, query: usize, values: []const QM31, payload: u32, uses: []const u32) !void {
        const schedules = try self.fri_plan.group(layer, query);
        if (schedules.len != values.len or uses.len != try std.math.mul(usize, values.len, 4)) return error.InvalidOpeningInput;
        for (schedules, values, 0..) |schedule, value, i| {
            for (schedule.source_nodes, value.toM31Array()) |node, coordinate| try self.sources.append(if (self.direct) self.backing else self.output, .{ .lane = 2, .node = node, .value = coordinate });
            const row = try pack.logicalRow(schedule, value);
            const fixed = try pack.fixedRow(schedule);
            if (self.columns) |*columns| try columns.appendFixed(11, row, fixed) else {
                try self.packing.append(self.output, row);
                try self.fixed_packed.append(self.output, fixed);
            }
            try self.encode(.{ .source_circuit = schedule.destination_circuit, .source_wire = schedule.destination_wire, .destination_circuit = 3_000_000, .destination_first = try std.math.add(u32, payload, @intCast(i * 4)), .uses = uses[i * 4 ..][0..4].* }, value);
        }
    }
    fn encode(self: *Builder, schedule: encoding.Schedule, value: QM31) !void {
        const row = try encoding.logicalRow(schedule, value);
        const fixed = try encoding.fixedRow(schedule);
        if (self.columns) |*columns| try columns.appendFixed(10, row, fixed) else {
            try self.encoded.append(self.output, row);
            try self.fixed_encoded.append(self.output, fixed);
        }
    }
    pub fn finish(self: *Builder) !Prepared {
        if (self.sources.items.len != try std.math.add(usize, self.trace_nodes.len, self.fri_plan.exports.len)) return error.InvalidOpeningInput;
        var sorted: std.ArrayList(ro.Row) = .empty;
        var fixed: std.ArrayList(ro.Row) = .empty;
        var sentinels: std.ArrayList(boundary.Row) = .empty;
        const entries = try self.a.alloc(ro.Entry, self.queries);
        defer self.a.free(entries);
        for (self.column_logs, 0..) |_, col| {
            for (entries, self.entries[col * self.queries ..][0..self.queries]) |*out, entry| out.* = entry orelse return error.InvalidOpeningInput;
            std.mem.sort(ro.Entry, entries, {}, struct {
                fn less(_: void, l: ro.Entry, r: ro.Entry) bool {
                    return l.index < r.index;
                }
            }.less);
            const table_id = try table(col);
            var previous = ro.Entry{ .index = 0, .value = M31.zero() };
            for (entries, 0..) |entry, i| {
                const schedule = ro.Schedule{ .table = table_id, .chain = table_id + 1, .rank = @intCast(i), .last = i + 1 == entries.len };
                const row = try ro.logicalRow(schedule, previous, entry);
                const fixed_row = try ro.fixedRow(schedule);
                if (self.columns) |*columns| try columns.appendFixed(16, row, fixed_row) else {
                    try sorted.append(self.output, row);
                    try fixed.append(self.output, fixed_row);
                }
                previous = entry;
            }
            if (entries.len > 0) {
                const row = try boundary.logicalCoordinates(table_id + 1, 0, M31.one(), @splat(M31.zero()));
                if (self.columns) |*columns| try columns.appendFixed(2, row, row) else try sentinels.append(self.output, row);
            }
        }
        if (self.columns) |*columns| {
            try columns.finish();
            const sources = try self.sources.toOwnedSlice(self.backing);
            const owned = columns.*;
            self.columns = null;
            const projected = self.projection;
            self.projection.columns = null;
            return .{ .source_allocator = self.backing, .columns = owned, .sources = sources, .projection = projected, .readonly_rows = &.{}, .fixed_readonly_rows = &.{}, .adapter_rows = &.{}, .fixed_adapter_rows = &.{}, .sentinels = &.{}, .encoded = &.{}, .fixed_encoded = &.{}, .packing = &.{}, .fixed_packed = &.{} };
        }
        try self.packing.appendSlice(self.output, self.projection.packing);
        try self.fixed_packed.appendSlice(self.output, self.projection.fixed_packed);
        return .{ .projection = self.projection, .readonly_rows = try sorted.toOwnedSlice(self.output), .fixed_readonly_rows = try fixed.toOwnedSlice(self.output), .adapter_rows = try self.adapter_rows.toOwnedSlice(self.output), .fixed_adapter_rows = try self.fixed_adapter_rows.toOwnedSlice(self.output), .sentinels = try sentinels.toOwnedSlice(self.output), .sources = try self.sources.toOwnedSlice(self.output), .encoded = try self.encoded.toOwnedSlice(self.output), .fixed_encoded = try self.fixed_encoded.toOwnedSlice(self.output), .packing = try self.packing.toOwnedSlice(self.output), .fixed_packed = try self.fixed_packed.toOwnedSlice(self.output) };
    }
};

fn table(column: usize) !u32 {
    const id = try std.math.add(usize, 6_000_000, try std.math.mul(usize, column, 2));
    if (id >= core.fields.m31.Modulus - 1) return error.InvalidOpeningInput;
    return @intCast(id);
}
