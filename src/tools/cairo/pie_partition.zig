//! Exact contiguous partition over already baked candidate PIEs.
//!
//! This proves optimality only for the supplied candidates and cost model.
//! It never synthesizes a Starknet OS execution or substitutes for proof
//! verification. The CLI authenticates geometry-receipt bindings first.
const std = @import("std");

pub const Block = struct {
    number: u64,
    initial_root: []const u8,
    final_root: []const u8,
};

pub const Candidate = struct {
    pie: []const u8,
    first_block: u64,
    last_block: u64,
    initial_root: []const u8,
    final_root: []const u8,
    input_sha256: []const u8,
    allocated_bytes: u64,
    estimated_ingress_and_cairo_ms: ?u64 = null,
};

pub const Objective = enum { leaves, estimated_time };

pub const Options = struct {
    admission_limit_bytes: u64,
    leaf_wrap_ms: u64,
    fold_ms: u64,
    objective: Objective,
};

pub const Selection = struct {
    indices: []usize,
    estimated_total_ms: u128,
    max_allocated_bytes: u64,
    oversized_candidates: usize,

    pub fn deinit(self: *Selection, allocator: std.mem.Allocator) void {
        allocator.free(self.indices);
        self.* = undefined;
    }
};

const State = struct {
    reachable: bool = false,
    leaves: usize = 0,
    cost_ms: u128 = 0,
    max_allocated_bytes: u64 = 0,
    chosen: ?usize = null,
};

pub fn parseRoot(root: []const u8) !u256 {
    if (root.len < 3 or root.len > 66 or !std.mem.startsWith(u8, root, "0x"))
        return error.InvalidStateRoot;
    const value = std.fmt.parseUnsigned(u256, root[2..], 16) catch return error.InvalidStateRoot;
    const starknet_prime: u256 = (@as(u256, 1) << 251) + (@as(u256, 17) << 192) + 1;
    if (value >= starknet_prime) return error.InvalidStateRoot;
    return value;
}

pub fn choose(
    allocator: std.mem.Allocator,
    blocks: []const Block,
    candidates: []const Candidate,
    options: Options,
) !Selection {
    if (blocks.len == 0 or options.admission_limit_bytes == 0)
        return error.InvalidPartitionInput;
    for (blocks, 0..) |block, index| {
        if (block.number != try std.math.add(u64, blocks[0].number, index))
            return error.NonContiguousBlocks;
        _ = try parseRoot(block.initial_root);
        const final = try parseRoot(block.final_root);
        if (index + 1 < blocks.len and final != try parseRoot(blocks[index + 1].initial_root))
            return error.BrokenBlockRootChain;
    }
    const last_number = blocks[blocks.len - 1].number;
    for (candidates) |candidate| {
        if (candidate.first_block < blocks[0].number or
            candidate.last_block > last_number or
            candidate.first_block > candidate.last_block or
            candidate.allocated_bytes == 0)
            return error.InvalidCandidateRange;
        const first = @as(usize, @intCast(candidate.first_block - blocks[0].number));
        const last = @as(usize, @intCast(candidate.last_block - blocks[0].number));
        if (try parseRoot(candidate.initial_root) != try parseRoot(blocks[first].initial_root) or
            try parseRoot(candidate.final_root) != try parseRoot(blocks[last].final_root))
            return error.CandidateRootMismatch;
        if (candidate.allocated_bytes <= options.admission_limit_bytes and
            options.objective == .estimated_time and candidate.estimated_ingress_and_cairo_ms == null)
            return error.MissingCostEstimate;
    }

    const states = try allocator.alloc(State, blocks.len + 1);
    defer allocator.free(states);
    const heads = try allocator.alloc(?usize, blocks.len);
    defer allocator.free(heads);
    const links = try allocator.alloc(?usize, candidates.len);
    defer allocator.free(links);
    @memset(states, .{});
    @memset(heads, null);
    states[blocks.len] = .{ .reachable = true };
    var oversized: usize = 0;
    for (candidates, 0..) |candidate, index| {
        if (candidate.allocated_bytes > options.admission_limit_bytes) oversized += 1;
        const first = @as(usize, @intCast(candidate.first_block - blocks[0].number));
        links[index] = heads[first];
        heads[first] = index;
    }
    var position = blocks.len;
    while (position > 0) {
        position -= 1;
        var cursor = heads[position];
        while (cursor) |index| : (cursor = links[index]) {
            const candidate = candidates[index];
            if (candidate.allocated_bytes > options.admission_limit_bytes) continue;
            const next = @as(usize, @intCast(candidate.last_block - blocks[0].number)) + 1;
            if (!states[next].reachable) continue;
            const prove = candidate.estimated_ingress_and_cairo_ms orelse 0;
            const edge = try std.math.add(u128, prove, options.leaf_wrap_ms);
            const fold = if (next == blocks.len) @as(u128, 0) else options.fold_ms;
            const cost = try std.math.add(u128, states[next].cost_ms, try std.math.add(u128, edge, fold));
            const contender = State{
                .reachable = true,
                .leaves = states[next].leaves + 1,
                .cost_ms = cost,
                .max_allocated_bytes = @max(candidate.allocated_bytes, states[next].max_allocated_bytes),
                .chosen = index,
            };
            if (better(contender, states[position], options.objective)) states[position] = contender;
        }
    }
    if (!states[0].reachable) return error.NoFeasiblePartition;
    const indices = try allocator.alloc(usize, states[0].leaves);
    var output: usize = 0;
    position = 0;
    while (position < blocks.len) {
        const index = states[position].chosen orelse return error.NoFeasiblePartition;
        indices[output] = index;
        output += 1;
        position = @as(usize, @intCast(candidates[index].last_block - blocks[0].number)) + 1;
    }
    std.debug.assert(output == indices.len);
    return .{
        .indices = indices,
        .estimated_total_ms = states[0].cost_ms,
        .max_allocated_bytes = states[0].max_allocated_bytes,
        .oversized_candidates = oversized,
    };
}

fn better(left: State, right: State, objective: Objective) bool {
    if (!right.reachable) return true;
    if (objective == .leaves) {
        if (left.leaves != right.leaves) return left.leaves < right.leaves;
        if (left.cost_ms != right.cost_ms) return left.cost_ms < right.cost_ms;
    } else {
        if (left.cost_ms != right.cost_ms) return left.cost_ms < right.cost_ms;
        if (left.leaves != right.leaves) return left.leaves < right.leaves;
    }
    return left.max_allocated_bytes < right.max_allocated_bytes;
}

test "minimum leaves respects geometry, roots, and complete blocks" {
    const blocks = [_]Block{
        .{ .number = 7, .initial_root = "0x1", .final_root = "0x2" },
        .{ .number = 8, .initial_root = "0x2", .final_root = "0x3" },
        .{ .number = 9, .initial_root = "0x3", .final_root = "0x4" },
    };
    const candidates = [_]Candidate{
        .{ .pie = "7_7", .first_block = 7, .last_block = 7, .initial_root = "0x1", .final_root = "0x2", .input_sha256 = "a", .allocated_bytes = 20, .estimated_ingress_and_cairo_ms = 10 },
        .{ .pie = "8_8", .first_block = 8, .last_block = 8, .initial_root = "0x2", .final_root = "0x3", .input_sha256 = "b", .allocated_bytes = 20, .estimated_ingress_and_cairo_ms = 10 },
        .{ .pie = "9_9", .first_block = 9, .last_block = 9, .initial_root = "0x3", .final_root = "0x4", .input_sha256 = "c", .allocated_bytes = 20, .estimated_ingress_and_cairo_ms = 10 },
        .{ .pie = "7_8", .first_block = 7, .last_block = 8, .initial_root = "0x1", .final_root = "0x3", .input_sha256 = "d", .allocated_bytes = 90, .estimated_ingress_and_cairo_ms = 40 },
        .{ .pie = "8_9", .first_block = 8, .last_block = 9, .initial_root = "0x2", .final_root = "0x4", .input_sha256 = "e", .allocated_bytes = 80, .estimated_ingress_and_cairo_ms = 40 },
        .{ .pie = "7_9", .first_block = 7, .last_block = 9, .initial_root = "0x1", .final_root = "0x4", .input_sha256 = "f", .allocated_bytes = 150, .estimated_ingress_and_cairo_ms = 100 },
    };
    var selected = try choose(std.testing.allocator, &blocks, &candidates, .{
        .admission_limit_bytes = 100,
        .leaf_wrap_ms = 5,
        .fold_ms = 2,
        .objective = .leaves,
    });
    defer selected.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(usize, &.{ 0, 4 }, selected.indices);
    try std.testing.expectEqual(@as(usize, 1), selected.oversized_candidates);
    try std.testing.expectEqual(@as(u128, 62), selected.estimated_total_ms);

    var timed = try choose(std.testing.allocator, &blocks, &candidates, .{
        .admission_limit_bytes = 100,
        .leaf_wrap_ms = 5,
        .fold_ms = 2,
        .objective = .estimated_time,
    });
    defer timed.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(usize, &.{ 0, 1, 2 }, timed.indices);
    try std.testing.expectEqual(@as(u128, 49), timed.estimated_total_ms);
}

test "root mismatch and impossible capacity fail closed" {
    const blocks = [_]Block{.{ .number = 1, .initial_root = "0x1", .final_root = "0x2" }};
    const bad = [_]Candidate{.{ .pie = "bad", .first_block = 1, .last_block = 1, .initial_root = "0x1", .final_root = "0x3", .input_sha256 = "a", .allocated_bytes = 1 }};
    try std.testing.expectError(error.CandidateRootMismatch, choose(std.testing.allocator, &blocks, &bad, .{ .admission_limit_bytes = 2, .leaf_wrap_ms = 0, .fold_ms = 0, .objective = .leaves }));
    const large = [_]Candidate{.{ .pie = "large", .first_block = 1, .last_block = 1, .initial_root = "0x1", .final_root = "0x2", .input_sha256 = "a", .allocated_bytes = 3 }};
    try std.testing.expectError(error.NoFeasiblePartition, choose(std.testing.allocator, &blocks, &large, .{ .admission_limit_bytes = 2, .leaf_wrap_ms = 0, .fold_ms = 0, .objective = .leaves }));
}
