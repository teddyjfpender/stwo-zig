//! Public-shape partition of the canonical compression DAG. Internal wires stay
//! inside a fused component; only inter-group and final-XOR consumers are exported.
const std = @import("std");
const topology = @import("blake3_compression_plan.zig");
const arithmetic = @import("blake3_g_packed.zig");
pub const Group = struct {
    first: u8 = 0,
    count: u8 = 0,
    input_count: u8 = 0,
    output_count: u8 = 0,
    inputs: [32]u32 = @splat(0),
    outputs: [16]u32 = @splat(0),
    output_uses: [16]u32 = @splat(0),
    pub fn mainColumns(self: Group) usize {
        return 4 * @as(usize, self.input_count) + (arithmetic.COLUMN_COUNT - 24) * @as(usize, self.count);
    }
    pub fn lookupEvents(self: Group) usize {
        // Two range events plus one caller-wire consumer per external word;
        // each exported word has one producer with its fixed multiplicity.
        return 3 * @as(usize, self.input_count) + self.output_count + (arithmetic.EVENT_COUNT - 12) * @as(usize, self.count);
    }
};
pub const Plan = struct {
    width: u8,
    count: u8,
    groups: [56]Group = @splat(.{}),
    pub fn validate(self: *const Plan) !void {
        if (!std.meta.eql(self.*, try build(self.width))) return error.InvalidCompressionPartition;
    }
};
pub fn build(width: u8) !Plan {
    if (width == 0 or width > 56) return error.InvalidCompressionPartition;
    const graph = topology.canonical();
    var result = Plan{ .width = width, .count = @intCast((56 + @as(usize, width) - 1) / width) };
    var consumers: [topology.WIRE_COUNT]u32 = @splat(0);
    for (result.groups[0..result.count], 0..) |*group, ordinal| {
        group.first = @intCast(ordinal * width);
        group.count = @intCast(@min(width, 56 - @as(usize, group.first)));
        var produced: [topology.WIRE_COUNT]bool = @splat(false);
        var imported: [topology.WIRE_COUNT]bool = @splat(false);
        for (graph.g[group.first..][0..group.count]) |call| {
            for (call.input) |wire| if (!produced[wire] and !imported[wire]) {
                if (group.input_count == group.inputs.len) return error.InvalidCompressionPartition;
                group.inputs[group.input_count] = wire;
                group.input_count += 1;
                consumers[wire] += 1;
                imported[wire] = true;
            };
            for (call.output) |wire| produced[wire] = true;
        }
    }
    for (graph.xor) |call| for (call.input) |wire| {
        consumers[wire] += 1;
    };
    for (result.groups[0..result.count]) |*group| {
        for (graph.g[group.first..][0..group.count]) |call| for (call.output) |wire| {
            if (consumers[wire] == 0) continue;
            if (group.output_count == group.outputs.len) return error.InvalidCompressionPartition;
            group.outputs[group.output_count] = wire;
            group.output_uses[group.output_count] = consumers[wire];
            group.output_count += 1;
        };
    }
    return result;
}
