//! Memory and program commitment witness derived from one execution.
//!
//! Four tables are derived together because they are four views of the same
//! committed memory image: the RW-memory boundary rows, the sparse decoded
//! program commitment, the Merkle node rows, and the Poseidon2 permutation
//! calls. Deriving them apart is how a reader loses the one fact that binds
//! them, recorded in `appendPoseidonCalls` and `appendMerkleRows`: the pinned
//! Stark-V layout visits the same three trees in **two different orders**, and
//! neither order is the other's.
//!
//! ## Ownership
//!
//! A built `CommitmentWitness` **owns** every allocation it holds and releases
//! all of them in `deinit`. Stages downstream take **views** (`poseidonCalls`,
//! `merkleRows`, `program.rows`, `boundary.?.rows`) that stay valid until that
//! `deinit`; none of them may outlive the proving transaction.

const std = @import("std");
const memory_boundary = @import("../air/memory_commitment/boundary.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const sparse_merkle = @import("../air/memory_commitment/sparse_merkle.zig");
const program_table = @import("../air/program/table.zig");
const public_data_mod = @import("../air/public_data.zig");
const memory_state = @import("../runner/memory_state.zig");
const trace_mod = @import("../runner/trace.zig");
const types = @import("types.zig");

const PublicData = types.PublicData;
const ProverError = types.ProverError;

/// Fixes the completion witness the rest of the proof is derived from.
///
/// A caller that supplies no completion gets the canonical self-loop at the
/// final program counter. A `halt_flag` completion is only admissible when the
/// committed memory snapshot actually carries that word with the public
/// completion role, the claimed value and the claimed clock: otherwise the
/// public statement would name a halt the memory image never performed.
pub fn bindCompletion(
    data: *PublicData,
    final_pc: u32,
    opt_memory: ?*const memory_state.Snapshot,
) ProverError!void {
    if (data.completion == null) {
        data.completion = public_data_mod.Completion.canonicalSelfLoop(final_pc);
    }
    const completion = data.completion orelse return ProverError.InvalidStatement;
    if (completion.kind != .halt_flag) return;
    const snapshot = opt_memory orelse return ProverError.InvalidStatement;
    for (snapshot.words) |word| {
        if (word.addr != completion.address) continue;
        if (!word.role.is_public_completion or
            word.final_word != completion.value or
            word.final_clock != completion.clock)
            return ProverError.InvalidStatement;
        return;
    }
    return ProverError.InvalidStatement;
}

pub const CommitmentWitness = struct {
    boundary: ?memory_boundary.Claims,
    program: program_commitment.Commitment,
    poseidon_calls: std.ArrayList(poseidon2_air.Call),
    merkle_rows: std.ArrayList(merkle_node.NodeRow),

    /// Derives every commitment table for one execution. Owned by the caller.
    pub fn build(
        allocator: std.mem.Allocator,
        exec_trace: *const trace_mod.Trace,
        opt_memory: ?*const memory_state.Snapshot,
        completion: public_data_mod.Completion,
    ) !CommitmentWitness {
        var boundary: ?memory_boundary.Claims = if (opt_memory) |snapshot|
            try memory_boundary.build(allocator, snapshot.words)
        else
            null;
        errdefer if (boundary) |*claims| claims.deinit(allocator);
        if (boundary) |claims| try claims.validate(allocator);

        var program = try buildProgram(allocator, exec_trace, opt_memory, completion);
        errdefer program.deinit(allocator);

        var poseidon_calls: std.ArrayList(poseidon2_air.Call) = .{};
        errdefer poseidon_calls.deinit(allocator);
        try appendPoseidonCalls(allocator, &poseidon_calls, program, boundary);

        var merkle_rows: std.ArrayList(merkle_node.NodeRow) = .{};
        errdefer merkle_rows.deinit(allocator);
        try appendMerkleRows(allocator, &merkle_rows, program, boundary);

        return .{
            .boundary = boundary,
            .program = program,
            .poseidon_calls = poseidon_calls,
            .merkle_rows = merkle_rows,
        };
    }

    pub fn deinit(self: *CommitmentWitness, allocator: std.mem.Allocator) void {
        self.merkle_rows.deinit(allocator);
        self.poseidon_calls.deinit(allocator);
        self.program.deinit(allocator);
        if (self.boundary) |*claims| claims.deinit(allocator);
        self.* = undefined;
    }

    /// Poseidon2 calls in pinned order, **borrowed** from this witness.
    pub fn poseidonCalls(self: *const CommitmentWitness) []const poseidon2_air.Call {
        return self.poseidon_calls.items;
    }

    /// Merkle node rows in pinned order, **borrowed** from this witness.
    pub fn merkleRows(self: *const CommitmentWitness) []const merkle_node.NodeRow {
        return self.merkle_rows.items;
    }
};

/// Decoded-program commitment over every fetched word.
///
/// An unretired self-loop completion is fetched by the public statement rather
/// than by a trace row, so its word joins the fetch list; otherwise a verifier
/// would range over a program table that omits the instruction the statement
/// claims the machine is parked on.
fn buildProgram(
    allocator: std.mem.Allocator,
    exec_trace: *const trace_mod.Trace,
    opt_memory: ?*const memory_state.Snapshot,
    completion: public_data_mod.Completion,
) !program_commitment.Commitment {
    const has_public_fetch = completion.kind == .unretired_self_loop;
    const fetches = try allocator.alloc(
        program_table.Fetch,
        exec_trace.rows.items.len + @intFromBool(has_public_fetch),
    );
    defer allocator.free(fetches);
    for (exec_trace.rows.items, fetches[0..exec_trace.rows.items.len]) |row, *fetch| {
        fetch.* = .{ .pc = row.pc, .word = row.inst_word };
    }
    if (has_public_fetch) {
        fetches[fetches.len - 1] = .{
            .pc = completion.address,
            .word = completion.value,
        };
    }
    return program_commitment.build(
        allocator,
        fetches,
        if (opt_memory) |snapshot| snapshot.program_words else &.{},
    );
}

/// Pinned Stark-V visits Poseidon calls program -> initial RW -> final RW.
fn appendPoseidonCalls(
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
fn appendMerkleRows(
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

fn appendTreeCalls(
    allocator: std.mem.Allocator,
    calls: *std.ArrayList(poseidon2_air.Call),
    tree: sparse_merkle.Tree,
) !void {
    for (tree.nodes) |node| {
        const row = merkle_node.NodeRow.fromNode(node, tree.root);
        try calls.append(allocator, row.poseidonCall());
    }
}

fn appendTreeRows(
    allocator: std.mem.Allocator,
    rows: *std.ArrayList(merkle_node.NodeRow),
    tree: sparse_merkle.Tree,
) !void {
    for (tree.nodes) |node| {
        try rows.append(allocator, merkle_node.NodeRow.fromNode(node, tree.root));
    }
}
