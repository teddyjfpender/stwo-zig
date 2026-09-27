//! Continuation boundary trees and pinned Merkle/Poseidon traversal order.
const std = @import("std");
const memory_boundary = @import("../air/memory_commitment/boundary.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const sparse_merkle = @import("../air/memory_commitment/sparse_merkle.zig");
const segment_v2 = @import("../recursion/segment_statement_v2.zig");
const poseidon_work = @import("poseidon_witness_work.zig");

pub fn buildV2Boundary(
    allocator: std.mem.Allocator,
    view: *const segment_v2.CanonicalWireViewV2,
) !memory_boundary.Claims {
    var initial_tree = try buildV2Tree(allocator, view, view.entry_snapshot);
    errdefer initial_tree.deinit(allocator);
    if (initial_tree.root != view.statement.entry_continuation_root)
        return error.MerkleBoundaryMismatch;

    var final_tree = try buildV2Tree(allocator, view, view.exit_snapshot);
    errdefer final_tree.deinit(allocator);
    if (final_tree.root != view.statement.exit_continuation_root)
        return error.MerkleBoundaryMismatch;

    return .{
        .rows = try allocator.alloc(memory_boundary.Row, 0),
        .initial_tree = initial_tree,
        .final_tree = final_tree,
    };
}

const BuiltV2BoundaryWithWorkReceipt = struct {
    claims: memory_boundary.Claims,
    work: poseidon_work.Shard,
};

pub fn buildV2BoundaryWithWorkReceipt(
    allocator: std.mem.Allocator,
    view: *const segment_v2.CanonicalWireViewV2,
    authority: *const poseidon_work.Authority,
) !BuiltV2BoundaryWithWorkReceipt {
    var initial_built = try buildV2TreeWithWorkReceipt(
        allocator,
        view,
        view.entry_snapshot,
        authority,
    );
    errdefer initial_built.tree.deinit(allocator);
    if (initial_built.tree.root != view.statement.entry_continuation_root)
        return error.MerkleBoundaryMismatch;

    var final_built = try buildV2TreeWithWorkReceipt(
        allocator,
        view,
        view.exit_snapshot,
        authority,
    );
    errdefer final_built.tree.deinit(allocator);
    if (final_built.tree.root != view.statement.exit_continuation_root)
        return error.MerkleBoundaryMismatch;

    var completed = poseidon_work.Shard{};
    try completed.observe(authority, initial_built.receipt);
    try completed.observe(authority, final_built.receipt);
    return .{
        .claims = .{
            .rows = try allocator.alloc(memory_boundary.Row, 0),
            .initial_tree = initial_built.tree,
            .final_tree = final_built.tree,
        },
        .work = completed,
    };
}

fn buildV2Tree(
    allocator: std.mem.Allocator,
    view: *const segment_v2.CanonicalWireViewV2,
    section: segment_v2.RetainedSectionV2,
) !sparse_merkle.Tree {
    var leaves: std.ArrayList(sparse_merkle.Leaf) = .{};
    defer leaves.deinit(allocator);
    try leaves.ensureTotalCapacity(allocator, @as(usize, section.count) * 4);
    for (0..section.count) |index| {
        const entry = view.sparseEntry(section, index);
        for (0..4) |limb| {
            const shift: u5 = @intCast(limb * 8);
            const value: u8 = @truncate(entry.value >> shift);
            if (value == 0) continue;
            leaves.appendAssumeCapacity(.{
                .index = entry.address + @as(u32, @intCast(limb)),
                .value = value,
            });
        }
    }
    return sparse_merkle.build(allocator, leaves.items);
}

fn buildV2TreeWithWorkReceipt(
    allocator: std.mem.Allocator,
    view: *const segment_v2.CanonicalWireViewV2,
    section: segment_v2.RetainedSectionV2,
    authority: *const poseidon_work.Authority,
) !sparse_merkle.BuildWithWorkReceipt {
    var leaves: std.ArrayList(sparse_merkle.Leaf) = .{};
    defer leaves.deinit(allocator);
    try leaves.ensureTotalCapacity(allocator, @as(usize, section.count) * 4);
    for (0..section.count) |index| {
        const entry = view.sparseEntry(section, index);
        for (0..4) |limb| {
            const shift: u5 = @intCast(limb * 8);
            const value: u8 = @truncate(entry.value >> shift);
            if (value == 0) continue;
            leaves.appendAssumeCapacity(.{
                .index = entry.address + @as(u32, @intCast(limb)),
                .value = value,
            });
        }
    }
    return sparse_merkle.buildWithWorkReceipt(allocator, leaves.items, authority);
}

/// Pinned Stark-V visits Poseidon calls program -> initial RW -> final RW.
pub fn appendPoseidonCalls(
    allocator: std.mem.Allocator,
    calls: *std.ArrayList(poseidon2_air.Call),
    program: program_commitment.Commitment,
    boundary: ?memory_boundary.Claims,
) !void {
    try appendTreeCalls(allocator, calls, program.tree);
    if (boundary) |claims| {
        if (claims.initial_tree) |tree| try appendTreeCalls(allocator, calls, tree);
        if (claims.final_tree) |tree| try appendTreeCalls(allocator, calls, tree);
    }
}

/// Its Merkle table visits initial RW -> final RW -> program: the reverse
/// grouping of `appendPoseidonCalls`, not a reordering of the same list.
pub fn appendMerkleRows(
    allocator: std.mem.Allocator,
    rows: *std.ArrayList(merkle_node.NodeRow),
    program: program_commitment.Commitment,
    boundary: ?memory_boundary.Claims,
) !void {
    if (boundary) |claims| {
        if (claims.initial_tree) |tree| try appendTreeRows(allocator, rows, tree);
        if (claims.final_tree) |tree| try appendTreeRows(allocator, rows, tree);
    }
    try appendTreeRows(allocator, rows, program.tree);
}

pub fn appendTreeCalls(
    allocator: std.mem.Allocator,
    calls: *std.ArrayList(poseidon2_air.Call),
    tree: sparse_merkle.Tree,
) !void {
    for (tree.nodes) |node| {
        const row = merkle_node.NodeRow.fromNode(node, tree.root);
        try calls.append(allocator, row.poseidonCall());
    }
}

pub fn appendTreeRows(
    allocator: std.mem.Allocator,
    rows: *std.ArrayList(merkle_node.NodeRow),
    tree: sparse_merkle.Tree,
) !void {
    for (tree.nodes) |node| {
        try rows.append(allocator, merkle_node.NodeRow.fromNode(node, tree.root));
    }
}
