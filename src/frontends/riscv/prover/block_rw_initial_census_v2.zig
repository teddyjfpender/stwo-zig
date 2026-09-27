//! Witness-free row sizing for initial RW paths; follows the exact emitter.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const shared = @import("blake3_shared_path_emit.zig");
const topology = @import("blake3_shared_path_topology.zig");
const air = @import("block_rw_initial_air_v2.zig");
const HashG = @import("../recursion/air/blake3_g_call.zig");
const HashXor = @import("../recursion/air/blake3_xor_call.zig");
const HashBoundary = @import("../recursion/air/blake3_boundary.zig");
const HashBridge = @import("../recursion/air/blake3_input_bridge.zig");
const HashRoute = @import("../recursion/air/blake3_byte_route.zig");
const HashPrivate = @import("../recursion/air/blake3_private_word.zig");
pub const Census = struct {
    first_touch_keys: usize,
    computed_nodes: usize,
    frontier_nodes: usize,
    namespace_end: u32 = 0,
    g_rows: u64 = 0,
    xor_rows: u64 = 0,
    boundary_rows: u64 = 0,
    bridge_rows: u64 = 0,
    route_rows: u64 = 0,
    private_rows: u64 = 0,
    pub fn totalHashRows(self: Census) u64 {
        return self.g_rows + self.xor_rows + self.boundary_rows + self.bridge_rows + self.route_rows + self.private_rows;
    }
};
const CensusSink = struct {
    census: *Census,
    pub fn appendCount(self: *CensusSink, comptime Air: type, count: usize) !void {
        const slot = if (Air == HashG) &self.census.g_rows else if (Air == HashXor) &self.census.xor_rows else if (Air == HashBoundary) &self.census.boundary_rows else if (Air == HashBridge) &self.census.bridge_rows else if (Air == HashRoute) &self.census.route_rows else if (Air == HashPrivate) &self.census.private_rows else @compileError("unrecognized shared path component");
        slot.* = try std.math.add(u64, slot.*, count);
    }
    pub fn append(_: *CensusSink, comptime Air: type, _: []const Air.Row) !void {
        return error.UnexpectedInitialRwCensusEmission;
    }
};
pub const Mode = enum { ordinary, complete_sparse, zero_query };
pub fn censusAddresses(a: std.mem.Allocator, addresses: []const u32, caller_base: u32, path_namespace: u32) !Census {
    return censusMode(a, addresses, caller_base, path_namespace, .ordinary);
}
pub fn censusCompleteSparseAddresses(a: std.mem.Allocator, addresses: []const u32, caller_base: u32, path_namespace: u32) !Census {
    return censusMode(a, addresses, caller_base, path_namespace, .complete_sparse);
}
pub fn censusZeroQueryAddresses(a: std.mem.Allocator, addresses: []const u32, caller_base: u32, path_namespace: u32) !Census {
    return censusMode(a, addresses, caller_base, path_namespace, .zero_query);
}
pub fn censusSparseShardAddresses(a: std.mem.Allocator, addresses: []const u32, caller_base: u32, path_namespace: u32, coordinate: tree.Coordinate) !Census {
    return censusModeAt(a, addresses, caller_base, path_namespace, .complete_sparse, coordinate);
}
pub fn censusMode(a: std.mem.Allocator, addresses: []const u32, caller_base: u32, path_namespace: u32, mode: Mode) !Census {
    return censusModeAt(a, addresses, caller_base, path_namespace, mode, null);
}
fn censusModeAt(a: std.mem.Allocator, addresses: []const u32, caller_base: u32, path_namespace: u32, mode: Mode, subtree: ?tree.Coordinate) !Census {
    if (addresses.len == 0 or addresses.len > air.MAX_FIRST_TOUCH_KEYS_PER_CHUNK) return error.InvalidInitialRwCensusSize;
    const upper = try std.math.add(u32, caller_base, std.math.cast(u32, addresses.len) orelse return error.InitialRwCallerOverflow);
    if (upper > path_namespace or path_namespace >= core.fields.m31.Modulus) return error.InitialRwCallerOverlap;
    const inputs = try a.alloc(shared.Input, addresses.len);
    defer a.free(inputs);
    const indices = try a.alloc(u32, addresses.len);
    defer a.free(indices);
    for (addresses, inputs, indices, 0..) |address, *input, *index, i| {
        if (address & 3 != 0 or address >= tree.ADDRESS_LIMIT or (i != 0 and addresses[i - 1] >= address)) return error.InvalidInitialRwCensusRoster;
        index.* = try tree.memoryIndex(address);
        input.* = .{ .address = index.*, .caller = .{ .circuit = caller_base + @as(u32, @intCast(i)), .wire = 0 }, .constant_zero = mode == .zero_query };
    }
    var graph = if (subtree) |coordinate| try topology.Graph.initSubtree(a, indices, coordinate.level, coordinate.index) else try topology.Graph.init(a, indices);
    defer graph.deinit();
    var result: Census = .{ .first_touch_keys = addresses.len, .computed_nodes = graph.nodes.len, .frontier_nodes = graph.frontier.len };
    var sink = CensusSink{ .census = &result };
    result.namespace_end = if (subtree) |coordinate|
        try shared.emitCompleteSparseSubtree(a, inputs, path_namespace, .memory, .{ .bytes = @splat(0) }, null, coordinate, &sink)
    else if (mode == .complete_sparse)
        try shared.emitCompleteSparse(a, inputs, path_namespace, .memory, .{ .bytes = @splat(0) }, null, &sink)
    else
        try shared.emit(a, inputs, path_namespace, .memory, .{ .bytes = @splat(0) }, null, &sink);
    return result;
}
