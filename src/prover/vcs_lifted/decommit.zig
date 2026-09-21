//! Backend-neutral lifted Merkle decommitment traversal.
//!
//! A tree reader owns storage and must expose only its maximum log size and
//! selective hash reads. Host layers and device-resident trees therefore share
//! one proof-construction algorithm without erased handles or callbacks here.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const vcs_lifted_verifier = @import("stwo_core").vcs_lifted.verifier;

const M31 = m31.M31;

pub fn DecommitmentResult(comptime H: type) type {
    return struct {
        queried_values: [][]M31,
        decommitment: vcs_lifted_verifier.ExtendedMerkleDecommitmentLifted(H),

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            for (self.queried_values) |column| allocator.free(column);
            allocator.free(self.queried_values);
            self.decommitment.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub const HashReadRequest = struct {
    layer_log_size: u32,
    indices: []const u32,
};

pub fn HashReadBatch(comptime H: type) type {
    return struct {
        layers: [][]H.Hash,

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            for (self.layers) |layer| allocator.free(layer);
            allocator.free(self.layers);
            self.* = undefined;
        }
    };
}

const LayerReadPlan = struct {
    layer_log_size: u32,
    previous_queries: []usize,
    child_indices: []u32,

    fn deinit(self: *LayerReadPlan, allocator: std.mem.Allocator) void {
        allocator.free(self.previous_queries);
        allocator.free(self.child_indices);
        self.* = undefined;
    }
};

pub fn decommit(
    comptime H: type,
    reader: anytype,
    allocator: std.mem.Allocator,
    query_positions: []const usize,
    columns: []const []const M31,
) !DecommitmentResult(H) {
    comptime assertReader(@TypeOf(reader));

    const NodeValue = vcs_lifted_verifier.MerkleDecommitmentLiftedAux(H).NodeValue;
    const Decommitment = vcs_lifted_verifier.MerkleDecommitmentLifted(H);
    const max_log_size = reader.maxLogSize();

    const queried_values = if (comptime @hasDecl(@TypeOf(reader), "readQueriedValuesBatch")) blk: {
        if (try reader.readQueriedValuesBatch(
            allocator,
            query_positions,
            columns,
        )) |resident_values| break :blk resident_values;
        break :blk try readQueriedValuesHost(
            allocator,
            max_log_size,
            query_positions,
            columns,
        );
    } else try readQueriedValuesHost(
        allocator,
        max_log_size,
        query_positions,
        columns,
    );
    errdefer freeQueriedValues(allocator, queried_values);

    var hash_witness = std.ArrayList(H.Hash).empty;
    defer hash_witness.deinit(allocator);

    var all_node_values = std.ArrayList([]NodeValue).empty;
    defer {
        for (all_node_values.items) |layer| allocator.free(layer);
        all_node_values.deinit(allocator);
    }

    if (comptime @hasDecl(@TypeOf(reader), "readHashesBatch")) {
        const layer_plans = try prepareLayerReads(allocator, max_log_size, query_positions);
        defer {
            for (layer_plans) |*plan| plan.deinit(allocator);
            allocator.free(layer_plans);
        }
        const requests = try allocator.alloc(HashReadRequest, layer_plans.len);
        defer allocator.free(requests);
        for (layer_plans, requests) |plan, *request| request.* = .{
            .layer_log_size = plan.layer_log_size,
            .indices = plan.child_indices,
        };

        var batch = try reader.readHashesBatch(allocator, requests);
        defer batch.deinit(allocator);
        if (batch.layers.len != layer_plans.len) return error.InvalidColumnSize;
        for (layer_plans, batch.layers) |plan, child_hashes| {
            try appendReadLayer(
                H,
                allocator,
                plan,
                child_hashes,
                &hash_witness,
                &all_node_values,
            );
        }
    } else try appendSequentialReads(
        H,
        reader,
        allocator,
        max_log_size,
        query_positions,
        &hash_witness,
        &all_node_values,
    );

    const hash_witness_owned = try hash_witness.toOwnedSlice(allocator);
    errdefer allocator.free(hash_witness_owned);

    const all_node_values_owned = try all_node_values.toOwnedSlice(allocator);
    errdefer {
        for (all_node_values_owned) |layer| allocator.free(layer);
        allocator.free(all_node_values_owned);
    }

    return .{
        .queried_values = queried_values,
        .decommitment = .{
            .decommitment = Decommitment{ .hash_witness = hash_witness_owned },
            .aux = .{ .all_node_values = all_node_values_owned },
        },
    };
}

fn readQueriedValuesHost(
    allocator: std.mem.Allocator,
    max_log_size: u32,
    query_positions: []const usize,
    columns: []const []const M31,
) ![][]M31 {
    const queried_values = try allocator.alloc([]M31, columns.len);
    var initialized: usize = 0;
    errdefer {
        for (queried_values[0..initialized]) |column| allocator.free(column);
        allocator.free(queried_values);
    }
    for (columns, queried_values) |column, *destination| {
        if (!std.math.isPowerOfTwo(column.len) or column.len < 2) {
            return error.InvalidColumnSize;
        }
        const log_size: u32 = @intCast(std.math.log2_int(usize, column.len));
        if (log_size > max_log_size) return error.InvalidColumnSize;
        const shift = max_log_size - log_size;
        const shift_amt: std.math.Log2Int(usize) = @intCast(shift + 1);
        destination.* = try allocator.alloc(M31, query_positions.len);
        initialized += 1;
        for (query_positions, destination.*) |position, *value| {
            const column_index = ((position >> shift_amt) << 1) + (position & 1);
            if (column_index >= column.len) return error.InvalidColumnSize;
            value.* = column[column_index];
        }
    }
    return queried_values;
}

fn freeQueriedValues(allocator: std.mem.Allocator, values: [][]M31) void {
    for (values) |column| allocator.free(column);
    allocator.free(values);
}

fn appendSequentialReads(
    comptime H: type,
    reader: anytype,
    allocator: std.mem.Allocator,
    max_log_size: u32,
    query_positions: []const usize,
    hash_witness: *std.ArrayList(H.Hash),
    all_node_values: *std.ArrayList([]vcs_lifted_verifier.MerkleDecommitmentLiftedAux(H).NodeValue),
) !void {
    const NodeValue = vcs_lifted_verifier.MerkleDecommitmentLiftedAux(H).NodeValue;
    var previous_queries = std.ArrayList(usize).empty;
    defer previous_queries.deinit(allocator);
    for (query_positions, 0..) |position, index| {
        if (index == 0 or query_positions[index - 1] != position) {
            try previous_queries.append(allocator, position);
        }
    }

    var layer_log_size: i64 = @intCast(max_log_size);
    layer_log_size -= 1;
    while (layer_log_size >= 0) : (layer_log_size -= 1) {
        var current_queries = std.ArrayList(usize).empty;
        defer current_queries.deinit(allocator);
        var layer_node_values = std.ArrayList(NodeValue).empty;
        defer layer_node_values.deinit(allocator);

        const child_count = std.math.mul(usize, previous_queries.items.len, 2) catch
            return error.InvalidColumnSize;
        const child_indices = try allocator.alloc(u32, child_count);
        defer allocator.free(child_indices);
        var child_pair_count: usize = 0;
        var scan: usize = 0;
        while (scan < previous_queries.items.len) {
            const first = previous_queries.items[scan];
            const has_sibling = scan + 1 < previous_queries.items.len and
                ((first ^ 1) == previous_queries.items[scan + 1]);
            const current_index = first >> 1;
            child_indices[2 * child_pair_count] = @intCast(2 * current_index);
            child_indices[2 * child_pair_count + 1] = @intCast(2 * current_index + 1);
            child_pair_count += 1;
            scan += if (has_sibling) 2 else 1;
        }
        const child_hashes = try reader.readHashes(
            allocator,
            @intCast(layer_log_size + 1),
            child_indices[0 .. child_pair_count * 2],
        );
        defer allocator.free(child_hashes);

        var query_at: usize = 0;
        var pair_index: usize = 0;
        while (query_at < previous_queries.items.len) {
            const first = previous_queries.items[query_at];
            const has_sibling = query_at + 1 < previous_queries.items.len and
                ((first ^ 1) == previous_queries.items[query_at + 1]);
            if (!has_sibling) {
                const sibling_offset: usize = if ((first & 1) == 0) 1 else 0;
                try hash_witness.append(allocator, child_hashes[2 * pair_index + sibling_offset]);
            }

            const current_index = first >> 1;
            try current_queries.append(allocator, current_index);
            try layer_node_values.append(allocator, .{
                .index = 2 * current_index,
                .hash = child_hashes[2 * pair_index],
            });
            try layer_node_values.append(allocator, .{
                .index = 2 * current_index + 1,
                .hash = child_hashes[2 * pair_index + 1],
            });
            query_at += if (has_sibling) 2 else 1;
            pair_index += 1;
        }

        previous_queries.clearRetainingCapacity();
        try previous_queries.appendSlice(allocator, current_queries.items);
        const owned_values = try layer_node_values.toOwnedSlice(allocator);
        errdefer allocator.free(owned_values);
        try all_node_values.append(allocator, owned_values);
    }
}

fn prepareLayerReads(
    allocator: std.mem.Allocator,
    max_log_size: u32,
    query_positions: []const usize,
) ![]LayerReadPlan {
    var plans = std.ArrayList(LayerReadPlan).empty;
    defer plans.deinit(allocator);
    errdefer for (plans.items) |*plan| plan.deinit(allocator);

    var previous_queries = std.ArrayList(usize).empty;
    defer previous_queries.deinit(allocator);
    for (query_positions, 0..) |position, index| {
        if (index == 0 or query_positions[index - 1] != position) {
            try previous_queries.append(allocator, position);
        }
    }

    var layer_log_size = max_log_size;
    while (layer_log_size > 0) : (layer_log_size -= 1) {
        const plan_queries = try allocator.dupe(usize, previous_queries.items);
        errdefer allocator.free(plan_queries);
        var child_pair_count: usize = 0;
        var pair_scan: usize = 0;
        while (pair_scan < previous_queries.items.len) {
            const first = previous_queries.items[pair_scan];
            const has_sibling = pair_scan + 1 < previous_queries.items.len and
                ((first ^ 1) == previous_queries.items[pair_scan + 1]);
            child_pair_count += 1;
            pair_scan += if (has_sibling) 2 else 1;
        }
        const child_count = std.math.mul(usize, child_pair_count, 2) catch
            return error.InvalidColumnSize;
        const child_indices = try allocator.alloc(u32, child_count);
        errdefer allocator.free(child_indices);

        var current_queries = std.ArrayList(usize).empty;
        defer current_queries.deinit(allocator);
        var pair_index: usize = 0;
        var scan: usize = 0;
        while (scan < previous_queries.items.len) {
            const first = previous_queries.items[scan];
            const has_sibling = scan + 1 < previous_queries.items.len and
                ((first ^ 1) == previous_queries.items[scan + 1]);
            const current_index = first >> 1;
            const left = std.math.mul(usize, current_index, 2) catch return error.InvalidColumnSize;
            const right = std.math.add(usize, left, 1) catch return error.InvalidColumnSize;
            child_indices[2 * pair_index] = std.math.cast(u32, left) orelse return error.InvalidColumnSize;
            child_indices[2 * pair_index + 1] = std.math.cast(u32, right) orelse return error.InvalidColumnSize;
            pair_index += 1;
            try current_queries.append(allocator, current_index);
            scan += if (has_sibling) 2 else 1;
        }

        previous_queries.clearRetainingCapacity();
        try previous_queries.appendSlice(allocator, current_queries.items);
        try plans.append(allocator, .{
            .layer_log_size = layer_log_size,
            .previous_queries = plan_queries,
            .child_indices = child_indices,
        });
    }
    return plans.toOwnedSlice(allocator);
}

fn appendReadLayer(
    comptime H: type,
    allocator: std.mem.Allocator,
    plan: LayerReadPlan,
    child_hashes: []const H.Hash,
    hash_witness: *std.ArrayList(H.Hash),
    all_node_values: *std.ArrayList([]vcs_lifted_verifier.MerkleDecommitmentLiftedAux(H).NodeValue),
) !void {
    const NodeValue = vcs_lifted_verifier.MerkleDecommitmentLiftedAux(H).NodeValue;
    if (child_hashes.len != plan.child_indices.len) return error.InvalidColumnSize;

    var layer_node_values = std.ArrayList(NodeValue).empty;
    defer layer_node_values.deinit(allocator);
    var query_at: usize = 0;
    var pair_index: usize = 0;
    while (query_at < plan.previous_queries.len) {
        const first = plan.previous_queries[query_at];
        const has_sibling = query_at + 1 < plan.previous_queries.len and
            ((first ^ 1) == plan.previous_queries[query_at + 1]);

        if (!has_sibling) {
            const sibling_offset: usize = if ((first & 1) == 0) 1 else 0;
            try hash_witness.append(allocator, child_hashes[2 * pair_index + sibling_offset]);
        }

        const current_index = first >> 1;
        try layer_node_values.append(allocator, .{
            .index = 2 * current_index,
            .hash = child_hashes[2 * pair_index],
        });
        try layer_node_values.append(allocator, .{
            .index = 2 * current_index + 1,
            .hash = child_hashes[2 * pair_index + 1],
        });
        query_at += if (has_sibling) 2 else 1;
        pair_index += 1;
    }

    const owned_values = try layer_node_values.toOwnedSlice(allocator);
    errdefer allocator.free(owned_values);
    try all_node_values.append(allocator, owned_values);
}

fn assertReader(comptime Reader: type) void {
    if (!@hasDecl(Reader, "maxLogSize")) {
        @compileError("Merkle tree reader must declare `maxLogSize`.");
    }
    if (!@hasDecl(Reader, "readHashes") and !@hasDecl(Reader, "readHashesBatch")) {
        @compileError("Merkle tree reader must declare `readHashes` or `readHashesBatch`.");
    }
}
