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
pub const Prepared = struct {
    sources: []Source,
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
};
pub const Builder = struct {
    a: std.mem.Allocator,
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
        const starts = try a.alloc(usize, capture.column_log_sizes.len + 1);
        starts[0] = 0;
        for (capture.column_log_sizes, 0..) |logs, i| starts[i + 1] = try std.math.add(usize, starts[i], logs.len);
        const n = capture.queries.raw.len;
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
        return .{ .a = a, .trace_nodes = nodes, .tree_starts = starts, .queries = n, .fri_plan = try wiring.Plan.init(a, fg, 1504, PACK_CIRCUIT), .column_logs = column_logs, .entries = entries, .projection = try projection.build(a, lifting, column_logs, capture.queries.raw, query_links.queries) };
    }
    pub fn deinit(self: *Builder) void {
        self.fri_plan.deinit();
    }
    pub fn trace(self: *Builder, tree: usize, column: usize, query: usize, projected: usize, value: M31, payload: u32, uses: u32) !void {
        const index = (self.tree_starts[tree] + column) * self.queries + query;
        const node = self.trace_nodes[index];
        if (self.entries[index] != null or projected > std.math.maxInt(u32)) return error.InvalidOpeningInput;
        self.entries[index] = .{ .index = @intCast(projected), .value = value };
        const col = self.tree_starts[tree] + column;
        const ps = self.projection.ports[self.column_logs[col]].?[query];
        const schedule = adapter.Schedule{ .index = ps, .value = .{ .circuit = 1502, .wire = node }, .table = try table(col) };
        try self.adapter_rows.append(self.a, try adapter.logicalRow(schedule, @intCast(projected), value));
        try self.fixed_adapter_rows.append(self.a, try adapter.fixedRow(schedule));
        try self.sources.append(self.a, .{ .lane = 1, .node = node, .value = value });
        try self.encode(.{ .source_circuit = 1502, .source_wire = node, .destination_circuit = 3_000_000, .destination_first = payload, .uses = .{ uses, 0, 0, 0 } }, QM31.fromBase(value));
    }
    pub fn friGroup(self: *Builder, layer: usize, query: usize, values: []const QM31, payload: u32, uses: []const u32) !void {
        const schedules = try self.fri_plan.group(layer, query);
        if (schedules.len != values.len or uses.len != values.len * 4) return error.InvalidOpeningInput;
        for (schedules, values, 0..) |schedule, value, i| {
            for (schedule.source_nodes, value.toM31Array()) |node, coordinate| try self.sources.append(self.a, .{ .lane = 2, .node = node, .value = coordinate });
            try self.packing.append(self.a, try pack.logicalRow(schedule, value));
            try self.fixed_packed.append(self.a, try pack.fixedRow(schedule));
            try self.encode(.{ .source_circuit = schedule.destination_circuit, .source_wire = schedule.destination_wire, .destination_circuit = 3_000_000, .destination_first = try std.math.add(u32, payload, @intCast(i * 4)), .uses = uses[i * 4 ..][0..4].* }, value);
        }
    }
    fn encode(self: *Builder, schedule: encoding.Schedule, value: QM31) !void {
        try self.encoded.append(self.a, try encoding.logicalRow(schedule, value));
        try self.fixed_encoded.append(self.a, try encoding.fixedRow(schedule));
    }
    pub fn finish(self: *Builder) !Prepared {
        if (self.sources.items.len != self.trace_nodes.len + self.fri_plan.exports.len) return error.InvalidOpeningInput;
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
                try sorted.append(self.a, try ro.logicalRow(schedule, previous, entry));
                try fixed.append(self.a, try ro.fixedRow(schedule));
                previous = entry;
            }
            if (entries.len > 0) try sentinels.append(self.a, try boundary.logicalCoordinates(table_id + 1, 0, M31.one(), @splat(M31.zero())));
        }
        try self.packing.appendSlice(self.a, self.projection.packing);
        try self.fixed_packed.appendSlice(self.a, self.projection.fixed_packed);
        return .{ .projection = self.projection, .readonly_rows = try sorted.toOwnedSlice(self.a), .fixed_readonly_rows = try fixed.toOwnedSlice(self.a), .adapter_rows = try self.adapter_rows.toOwnedSlice(self.a), .fixed_adapter_rows = try self.fixed_adapter_rows.toOwnedSlice(self.a), .sentinels = try sentinels.toOwnedSlice(self.a), .sources = try self.sources.toOwnedSlice(self.a), .encoded = try self.encoded.toOwnedSlice(self.a), .fixed_encoded = try self.fixed_encoded.toOwnedSlice(self.a), .packing = try self.packing.toOwnedSlice(self.a), .fixed_packed = try self.fixed_packed.toOwnedSlice(self.a) };
    }
};

fn table(column: usize) !u32 {
    const id = try std.math.add(usize, 6_000_000, try std.math.mul(usize, column, 2));
    if (id >= core.fields.m31.Modulus - 1) return error.InvalidOpeningInput;
    return @intCast(id);
}
