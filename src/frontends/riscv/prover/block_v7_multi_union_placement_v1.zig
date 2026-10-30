//! Canonical finite placement for bounded multi-window original STARKs.
//! Geometry metadata only: this module authenticates no proof or source.
const std = @import("std");
const E = @import("block_v7_execution_epoch_v1.zig");
pub const Source = struct { family: E.Family, index: u32, root_count: u32 };
pub const Part = struct {
    source: Source,
    source_trees: u32,
    map: [5]usize,
    pub fn mapping(self: *const Part) []const usize {
        return self.map[0..self.source_trees];
    }
};
pub const Plan = struct {
    allocator: std.mem.Allocator,
    parts: []Part,
    trace_trees: usize,
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.parts);
        self.* = undefined;
    }
    pub fn derive(a: std.mem.Allocator, sources: []const Source, natives: usize, callers: usize, max_trace_trees: usize) !Plan {
        return deriveForMemory(a, sources, natives, callers, max_trace_trees, .memory_joint);
    }
    pub fn deriveForMemory(a: std.mem.Allocator, sources: []const Source, natives: usize, callers: usize, max_trace_trees: usize, memory_family: E.Family) !Plan {
        if (memory_family != .memory_joint and memory_family != .window_memory_joint) return error.InvalidMultiUnionMemoryFamily;
        if (natives == 0 or callers > natives or sources.len != try std.math.add(usize, try std.math.add(usize, natives, callers), 3) or max_trace_trees == 0 or max_trace_trees > 256) return error.InvalidMultiUnionRoster;
        const parts = try a.alloc(Part, sources.len);
        errdefer a.free(parts);
        var next: usize = 1;
        for (sources, parts, 0..) |source, *part, i| {
            const family: E.Family = if (i < natives) .native else if (i < natives + callers) .caller_fused else switch (i - natives - callers) {
                0 => .program,
                1 => .lookup,
                2 => memory_family,
                else => unreachable,
            };
            const index: usize = if (i < natives) i else if (i < natives + callers) i - natives else 0;
            if (source.family != family or source.index != index) return error.InvalidMultiUnionRoster;
            const interaction_trees: u32 = switch (family) {
                .native => blk: {
                    if (source.root_count != 2 and source.root_count != 3) return error.InvalidMultiUnionSourceTrees;
                    break :blk 1;
                },
                .caller_fused => blk: {
                    if (source.root_count != 3) return error.InvalidMultiUnionSourceTrees;
                    break :blk 2;
                },
                .program, .lookup, .memory_joint, .window_memory_joint => blk: {
                    if (source.root_count != 2) return error.InvalidMultiUnionSourceTrees;
                    break :blk 1;
                },
                else => unreachable,
            };
            part.* = .{ .source = source, .source_trees = source.root_count + interaction_trees, .map = @splat(0) };
            for (1..source.root_count) |tree| {
                part.map[tree] = next;
                next = try std.math.add(usize, next, 1);
            }
        }
        // Interactions follow every first-round commitment. No absent native
        // access column/tree is padded into the transcript.
        for (parts) |*part| for (part.source.root_count..part.source_trees) |tree| {
            part.map[tree] = next;
            next = try std.math.add(usize, next, 1);
        };
        if (next > max_trace_trees) return error.MultiUnionTreeBudgetExceeded;
        return .{ .allocator = a, .parts = parts, .trace_trees = next };
    }
};
