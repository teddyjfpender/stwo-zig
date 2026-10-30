//! Shared exact flat source sample map for independently rebuilt PCS shapes.
const std = @import("std");
const G = @import("composition_graph_recorder.zig");
const S = G.Scalar;
const Source = @import("blake3_execution_composition.zig").Source;
pub const Samples = struct {
    offsets: [][]usize,
    lengths: [][]usize,
    values: []S,
    pub fn init(a: std.mem.Allocator, b: *G.Builder, sources: *std.ArrayList(Source), shape: *const @import("../block_v6_original_fixed_shape_v1.zig").Owned) !Samples {
        const offsets = try a.alloc([]usize, shape.columns.len);
        const lengths = try a.alloc([]usize, offsets.len);
        var count: usize = 0;
        for (shape.layouts) |layout| count = try std.math.add(usize, count, layout.sampleCount());
        const values = try a.alloc(S, count);
        var cursor: usize = 0;
        var flat: usize = 0;
        for (offsets, lengths, shape.columns) |*off, *len, columns| {
            off.* = try a.alloc(usize, columns.len);
            len.* = try a.alloc(usize, columns.len);
            for (off.*, len.*) |*start, *n| {
                start.* = cursor;
                n.* = shape.layouts[flat].sampleCount();
                for (0..n.*) |_| {
                    values[cursor] = try input(b, a, sources, .{ .sample = @intCast(cursor) });
                    cursor += 1;
                }
                flat += 1;
            }
        }
        if (cursor != values.len or flat != shape.layouts.len) return error.InvalidEndpointCompositionSamples;
        return .{ .offsets = offsets, .lengths = lengths, .values = values };
    }
    pub fn at(self: Samples, tree: usize, column: usize, sample: usize) !S {
        if (tree >= self.offsets.len or column >= self.offsets[tree].len or sample >= self.lengths[tree][column]) return error.InvalidEndpointCompositionSamples;
        return self.values[self.offsets[tree][column] + sample];
    }
};
pub const Mapped = struct {
    samples: Samples,
    map: []const usize,
    fixed_start: usize,
    fixed_count: usize,
    pub fn at(self: Mapped, tree: usize, column: usize, sample: usize) !S {
        if (tree >= self.map.len or (tree == 0 and column >= self.fixed_count)) return error.InvalidEndpointCompositionPlacement;
        return self.samples.at(self.map[tree], if (tree == 0) self.fixed_start + column else column, sample);
    }
    pub fn offsets4(self: Mapped) ![4][]const usize {
        if (self.map.len != 3) return error.InvalidEndpointCompositionPlacement;
        return .{ self.samples.offsets[0][self.fixed_start..][0..self.fixed_count], self.samples.offsets[self.map[1]], self.samples.offsets[self.map[2]], &.{} };
    }
};
pub fn input(b: *G.Builder, a: std.mem.Allocator, sources: *std.ArrayList(Source), source: Source) !S {
    const value = try b.input();
    try sources.append(a, source);
    return value.value;
}
