//! Per-tree query decommitment orchestration for a PCS scheme.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const TreeVec = @import("stwo_core").pcs.TreeVec;
const vcs_verifier = @import("stwo_core").vcs_lifted.verifier;

pub fn decommit(
    comptime H: type,
    comptime Result: type,
    scheme: anytype,
    allocator: std.mem.Allocator,
    query_positions_tree: TreeVec([]const usize),
) !Result {
    if (query_positions_tree.items.len != scheme.trees.items.len) return error.ShapeMismatch;

    const queried_values = try allocator.alloc([][]M31, scheme.trees.items.len);
    errdefer allocator.free(queried_values);
    const decommitments = try allocator.alloc(
        vcs_verifier.MerkleDecommitmentLifted(H),
        scheme.trees.items.len,
    );
    errdefer allocator.free(decommitments);
    const auxiliary = try allocator.alloc(
        vcs_verifier.MerkleDecommitmentLiftedAux(H),
        scheme.trees.items.len,
    );
    errdefer allocator.free(auxiliary);

    var initialized: usize = 0;
    errdefer {
        for (queried_values[0..initialized]) |tree_values| {
            for (tree_values) |column| allocator.free(column);
            allocator.free(tree_values);
        }
        for (decommitments[0..initialized]) |*item| item.deinit(allocator);
        for (auxiliary[0..initialized]) |*item| item.deinit(allocator);
    }

    for (scheme.trees.items, query_positions_tree.items, 0..) |tree, positions, index| {
        const item = try tree.decommit(allocator, positions);
        queried_values[index] = item.queried_values;
        decommitments[index] = item.decommitment.decommitment;
        auxiliary[index] = item.decommitment.aux;
        initialized += 1;
    }

    return .{
        .queried_values = TreeVec([][]M31).initOwned(queried_values),
        .decommitments = TreeVec(vcs_verifier.MerkleDecommitmentLifted(H)).initOwned(decommitments),
        .aux = TreeVec(vcs_verifier.MerkleDecommitmentLiftedAux(H)).initOwned(auxiliary),
    };
}
