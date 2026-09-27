//! Shared private scalar sources for full-STARK arithmetic and hash openings.
//! Builder storage belongs to the owning parent path arena.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const deep = @import("pcs_deep_circuit.zig");
const fri = @import("fri_verifier_circuit.zig");
const wiring = @import("fri_hash_wire_plan.zig");
pub const encoding = @import("blake3_field_bytes.zig");
pub const pack = @import("qm31_pack_wire.zig");
pub const Source = struct { lane: usize, node: u32, value: f.M31, canonical: ?u32 = null };
pub const Canonical = struct { value: f.M31, uses: u32 };
pub const CANONICAL_CIRCUIT: u32 = 5_000_000;
const PACK_CIRCUIT: u32 = 5_000_001;
pub const Prepared = struct {
    sources: []Source,
    canonical: []Canonical,
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
    seen: std.AutoHashMap([3]usize, u32),
    sources: std.ArrayList(Source) = .empty,
    canonical: std.ArrayList(Canonical) = .empty,
    encoded: std.ArrayList(encoding.Row) = .empty,
    fixed_encoded: std.ArrayList(encoding.Row) = .empty,
    packing: std.ArrayList(pack.Row) = .empty,
    fixed_packed: std.ArrayList(pack.Row) = .empty,
    pub fn init(a: std.mem.Allocator, capture: anytype, dg: *const deep.Circuit, fg: *const fri.Circuit) !Builder {
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
        return .{ .a = a, .trace_nodes = nodes, .tree_starts = starts, .queries = n, .fri_plan = try wiring.Plan.init(a, fg, 1504, PACK_CIRCUIT), .seen = std.AutoHashMap([3]usize, u32).init(a) };
    }
    pub fn deinit(self: *Builder) void {
        self.fri_plan.deinit();
        self.seen.deinit();
    }
    pub fn trace(self: *Builder, tree: usize, column: usize, query: usize, projected: usize, value: f.M31, payload: u32, uses: u32) !void {
        const index = (self.tree_starts[tree] + column) * self.queries + query;
        const node = self.trace_nodes[index];
        const found = try self.seen.getOrPut(.{ tree, column, projected });
        if (!found.found_existing) {
            found.value_ptr.* = @intCast(self.canonical.items.len);
            try self.canonical.append(self.a, .{ .value = value, .uses = 0 });
        }
        const canonical = &self.canonical.items[found.value_ptr.*];
        if (!canonical.value.eql(value)) return error.InconsistentOpeningInput;
        canonical.uses = try std.math.add(u32, canonical.uses, 1);
        try self.sources.append(self.a, .{ .lane = 1, .node = node, .value = value, .canonical = found.value_ptr.* });
        try self.encode(.{ .source_circuit = 1502, .source_wire = node, .destination_circuit = 3_000_000, .destination_first = payload, .uses = .{ uses, 0, 0, 0 } }, f.QM31.fromBase(value));
    }
    pub fn friGroup(self: *Builder, layer: usize, query: usize, values: []const f.QM31, payload: u32, uses: []const u32) !void {
        const schedules = try self.fri_plan.group(layer, query);
        if (schedules.len != values.len or uses.len != values.len * 4) return error.InvalidOpeningInput;
        for (schedules, values, 0..) |schedule, value, i| {
            for (schedule.source_nodes, value.toM31Array()) |node, coordinate| try self.sources.append(self.a, .{ .lane = 2, .node = node, .value = coordinate });
            try self.packing.append(self.a, try pack.logicalRow(schedule, value));
            try self.fixed_packed.append(self.a, try pack.fixedRow(schedule));
            try self.encode(.{ .source_circuit = schedule.destination_circuit, .source_wire = schedule.destination_wire, .destination_circuit = 3_000_000, .destination_first = try std.math.add(u32, payload, @intCast(i * 4)), .uses = uses[i * 4 ..][0..4].* }, value);
        }
    }
    fn encode(self: *Builder, schedule: encoding.Schedule, value: f.QM31) !void {
        try self.encoded.append(self.a, try encoding.logicalRow(schedule, value));
        try self.fixed_encoded.append(self.a, try encoding.fixedRow(schedule));
    }
    pub fn finish(self: *Builder) !Prepared {
        if (self.sources.items.len != self.trace_nodes.len + self.fri_plan.exports.len) return error.InvalidOpeningInput;
        return .{ .sources = try self.sources.toOwnedSlice(self.a), .canonical = try self.canonical.toOwnedSlice(self.a), .encoded = try self.encoded.toOwnedSlice(self.a), .fixed_encoded = try self.fixed_encoded.toOwnedSlice(self.a), .packing = try self.packing.toOwnedSlice(self.a), .fixed_packed = try self.fixed_packed.toOwnedSlice(self.a) };
    }
};
