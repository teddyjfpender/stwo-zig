//! Canonical scalar FRI input nodes consumed by hash-payload repacking.
//! Export counts must be included by both arithmetic and input producers.
const std = @import("std");
const core = @import("stwo_core");
const fri = @import("fri_verifier_circuit.zig");
const pack = @import("qm31_pack_wire.zig");
const lowering = @import("verifier_arithmetic_lowering.zig");
pub const Plan = struct {
    allocator: std.mem.Allocator,
    schedules: []pack.Schedule,
    exports: []lowering.Export,
    layer_starts: []usize,
    widths: []u32,
    query_count: u32,
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.schedules);
        self.allocator.free(self.exports);
        self.allocator.free(self.layer_starts);
        self.allocator.free(self.widths);
        self.* = undefined;
    }
    pub fn group(self: *const Plan, layer: usize, query: usize) ![]const pack.Schedule {
        if (layer >= self.widths.len or query >= self.query_count) return error.InvalidFriHashWirePlan;
        const start = self.layer_starts[layer] + query * self.widths[layer];
        return self.schedules[start..][0..self.widths[layer]];
    }
    pub fn init(a: std.mem.Allocator, circuit: *const fri.Circuit, source: u32, destination: u32) !Plan {
        try circuit.validate();
        const fail = error.InvalidFriHashWirePlan;
        if (source >= core.fields.m31.Modulus or destination >= core.fields.m31.Modulus or source == destination) return fail;
        const widths = try a.dupe(u32, circuit.fold_widths);
        errdefer a.free(widths);
        const starts = try a.alloc(usize, widths.len);
        errdefer a.free(starts);
        var count: usize = 0;
        for (widths, starts) |width, *start| {
            start.* = count;
            count = std.math.add(usize, count, std.math.mul(usize, width, circuit.query_count) catch return fail) catch return fail;
        }
        if (count >= core.fields.m31.Modulus) return fail;
        const schedules = try a.alloc(pack.Schedule, count);
        errdefer a.free(schedules);
        for (schedules, 0..) |*schedule, i| schedule.* = .{ .source_circuit = source, .source_nodes = @splat(std.math.maxInt(u32)), .destination_circuit = destination, .destination_wire = @intCast(i) };
        const exports = try a.alloc(lowering.Export, std.math.mul(usize, count, 4) catch return fail);
        errdefer a.free(exports);
        var cursor: usize = 0;
        for (circuit.bindings) |binding| switch (binding.source) {
            .authenticated_value_word => |s| {
                if (s.layer >= widths.len or s.query >= circuit.query_count or s.offset >= widths[s.layer] or s.word >= 4 or cursor >= exports.len) return fail;
                const node = &schedules[starts[s.layer] + s.query * widths[s.layer] + s.offset].source_nodes[s.word];
                if (node.* != std.math.maxInt(u32) or (cursor != 0 and exports[cursor - 1].node_id >= binding.node_id)) return fail;
                node.* = binding.node_id;
                exports[cursor] = .{ .node_id = binding.node_id, .uses = 1 };
                cursor += 1;
            },
            else => {},
        };
        if (cursor != exports.len) return fail;
        for (schedules) |schedule| _ = try pack.fixedRow(schedule);
        return .{ .allocator = a, .schedules = schedules, .exports = exports, .layer_starts = starts, .widths = widths, .query_count = circuit.query_count };
    }
};
