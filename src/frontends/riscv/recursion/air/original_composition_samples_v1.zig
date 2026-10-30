//! Shared exact sample/input mapping for independently admitted heterogeneous
//! original verifiers. This module records no equations or key authority.
const std = @import("std");
const G = @import("composition_graph_recorder.zig");
const Source = @import("blake3_execution_composition.zig").Source;
const S = G.Scalar;
pub fn input(b: *G.Builder, a: std.mem.Allocator, sources: *std.ArrayList(Source), source: Source) !S {
    const value = (try b.input()).value;
    try sources.append(a, source);
    return value;
}
pub const Samples = struct {
    offsets: [][]usize,
    lengths: [][]usize,
    values: []S,
    /// Arrays and source descriptors live in scratch; graph input nodes are
    /// owned by the builder. The shape belongs to independent source admission.
    pub fn init(a: std.mem.Allocator, b: *G.Builder, sources: *std.ArrayList(Source), shape: anytype) !Samples {
        if (shape.columns.len == 0 or shape.columns.len > 257) return error.InvalidOriginalCompositionSamples;
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
                if (flat >= shape.layouts.len) return error.InvalidOriginalCompositionSamples;
                start.* = cursor;
                n.* = shape.layouts[flat].sampleCount();
                for (0..n.*) |_| {
                    values[cursor] = try input(b, a, sources, .{ .sample = @intCast(cursor) });
                    cursor += 1;
                }
                flat += 1;
            }
        }
        if (cursor != values.len or flat != shape.layouts.len) return error.InvalidOriginalCompositionSamples;
        return .{ .offsets = offsets, .lengths = lengths, .values = values };
    }
    pub fn at(self: Samples, tree: usize, column: usize, sample: usize) !S {
        if (tree >= self.offsets.len or column >= self.offsets[tree].len or sample >= self.lengths[tree][column]) return error.InvalidOriginalCompositionSamples;
        return self.values[self.offsets[tree][column] + sample];
    }
    pub fn mapped(self: Samples, map: []const usize, fixed_start: usize, fixed_count: usize) !Mapped {
        if (map.len == 0 or map[0] != 0 or fixed_start > self.offsets[0].len or fixed_count > self.offsets[0].len - fixed_start) return error.InvalidOriginalCompositionPlacement;
        for (map) |tree| if (tree >= self.offsets.len) return error.InvalidOriginalCompositionPlacement;
        return .{ .samples = self, .map = map, .fixed_start = fixed_start, .fixed_count = fixed_count };
    }
};
pub const Mapped = struct {
    samples: Samples,
    map: []const usize,
    fixed_start: usize,
    fixed_count: usize,
    pub fn at(self: Mapped, tree: usize, column: usize, sample: usize) !S {
        if (tree >= self.map.len or (tree == 0 and column >= self.fixed_count)) return error.InvalidOriginalCompositionPlacement;
        return self.samples.at(self.map[tree], if (tree == 0) self.fixed_start + column else column, sample);
    }
    pub fn offsets4(self: Mapped) ![4][]const usize {
        if (self.map.len != 3) return error.InvalidOriginalCompositionPlacement;
        return .{ self.samples.offsets[0][self.fixed_start..][0..self.fixed_count], self.samples.offsets[self.map[1]], self.samples.offsets[self.map[2]], &.{} };
    }
};
