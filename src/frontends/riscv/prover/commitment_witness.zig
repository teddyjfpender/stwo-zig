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
const guest_program_commitment = @import("../air/guest_precompile/program_commitment.zig");
const sparse_merkle = @import("../air/memory_commitment/sparse_merkle.zig");
const program_table = @import("../air/program/table.zig");
const public_data_mod = @import("../air/public_data.zig");
const public_data_v2 = @import("../air/public_data_v2.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const segment_v2 = @import("../recursion/segment_statement_v2.zig");
const memory_state = @import("../runner/memory_state.zig");
const trace_mod = @import("../runner/trace.zig");
const guest_runner = @import("../runner/guest_precompile/poseidon2_v1.zig");
const poseidon_work = @import("poseidon_witness_work.zig");
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
    /// Present only on an explicitly profiled request. It contains every
    /// completed sparse-tree construction and validation permutation; Tree-1
    /// materialization merges into it before terminal publication.
    poseidon_work: ?poseidon_work.Shard = null,

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
            .poseidon_work = null,
        };
    }

    pub fn buildWithWorkReceipt(
        allocator: std.mem.Allocator,
        exec_trace: *const trace_mod.Trace,
        opt_memory: ?*const memory_state.Snapshot,
        completion: public_data_mod.Completion,
        authority: *const poseidon_work.Authority,
    ) !CommitmentWitness {
        var completed = poseidon_work.Shard{};
        var boundary: ?memory_boundary.Claims = if (opt_memory) |snapshot| blk: {
            var built = try memory_boundary.buildWithWorkReceipt(
                allocator,
                snapshot.words,
                authority,
            );
            errdefer built.claims.deinit(allocator);
            try completed.merge(built.work);
            break :blk built.claims;
        } else null;
        errdefer if (boundary) |*claims| claims.deinit(allocator);
        if (boundary) |claims| {
            const validated = try claims.validateWithWorkReceipt(allocator, authority);
            try completed.merge(validated);
        }

        const built_program = try buildProgramWithWorkReceipt(
            allocator,
            exec_trace,
            opt_memory,
            completion,
            authority,
        );
        var program = built_program.commitment;
        errdefer program.deinit(allocator);
        try completed.merge(built_program.work);

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
            .poseidon_work = completed,
        };
    }

    /// Version-separated resumed-segment commitment derivation.
    ///
    /// V2 public boundary events close the entire register/RW access chain, so
    /// no legacy memory-boundary row is emitted.  The exact authenticated entry
    /// and exit sparse trees are nevertheless committed by the existing Merkle
    /// and Poseidon2 components; verifier-side V2 public terms consume their
    /// retained nonzero leaves.
    pub fn buildV2(
        allocator: std.mem.Allocator,
        exec_trace: *const trace_mod.Trace,
        opt_memory: ?*const memory_state.Snapshot,
        data: *const public_data_v2.PublicDataV2,
    ) !CommitmentWitness {
        const snapshot = opt_memory orelse return ProverError.InvalidStatement;
        const view = try segment_v2.authenticateCanonicalWire(data.words());
        if (!std.meta.eql(view.wire_id, data.wireId()))
            return ProverError.InvalidStatement;

        var boundary = try buildV2Boundary(allocator, &view);
        errdefer boundary.deinit(allocator);

        const core_public = try statement_v2.canonicalCorePublicData(data);
        var program = try buildProgram(
            allocator,
            exec_trace,
            snapshot,
            core_public.completion,
        );
        errdefer program.deinit(allocator);
        if (core_public.program_root == null or
            core_public.program_root.? != program.tree.root)
        {
            return ProverError.InvalidStatement;
        }

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
            .poseidon_work = null,
        };
    }

    pub fn buildV2WithWorkReceipt(
        allocator: std.mem.Allocator,
        exec_trace: *const trace_mod.Trace,
        opt_memory: ?*const memory_state.Snapshot,
        data: *const public_data_v2.PublicDataV2,
        authority: *const poseidon_work.Authority,
    ) !CommitmentWitness {
        const snapshot = opt_memory orelse return ProverError.InvalidStatement;
        const view = try segment_v2.authenticateCanonicalWire(data.words());
        if (!std.meta.eql(view.wire_id, data.wireId()))
            return ProverError.InvalidStatement;

        const boundary_built = try buildV2BoundaryWithWorkReceipt(
            allocator,
            &view,
            authority,
        );
        var boundary = boundary_built.claims;
        errdefer boundary.deinit(allocator);
        var completed = boundary_built.work;

        const core_public = try statement_v2.canonicalCorePublicData(data);
        const built_program = try buildProgramWithWorkReceipt(
            allocator,
            exec_trace,
            snapshot,
            core_public.completion,
            authority,
        );
        var program = built_program.commitment;
        errdefer program.deinit(allocator);
        try completed.merge(built_program.work);
        if (core_public.program_root == null or
            core_public.program_root.? != program.tree.root)
        {
            return ProverError.InvalidStatement;
        }

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
            .poseidon_work = completed,
        };
    }

    /// Derives the same four commitment tables under the Poseidon2 execution
    /// profile. The only difference is program-fetch authority: ordinary and
    /// frozen CUSTOM-0 retirements are counted as two borrowed streams and all
    /// declared words are decoded under the admitted profile.
    pub fn buildPoseidon2(
        allocator: std.mem.Allocator,
        exec_trace: *const trace_mod.Trace,
        guest_execution_rows: *const guest_runner.FrozenExecutionRows,
        opt_memory: ?*const memory_state.Snapshot,
        completion: public_data_mod.Completion,
    ) !CommitmentWitness {
        var boundary: ?memory_boundary.Claims = if (opt_memory) |snapshot|
            try memory_boundary.build(allocator, snapshot.words)
        else
            null;
        errdefer if (boundary) |*claims| claims.deinit(allocator);
        if (boundary) |claims| try claims.validate(allocator);

        const snapshot = opt_memory orelse return ProverError.InvalidStatement;
        if (snapshot.program_words.len == 0) return ProverError.InvalidStatement;
        var program = try guest_program_commitment.buildDeclared(
            allocator,
            exec_trace.rows.items,
            guest_execution_rows,
            snapshot.program_words,
            completionFetch(completion),
        );
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
            .poseidon_work = null,
        };
    }

    pub fn buildPoseidon2WithWorkReceipt(
        allocator: std.mem.Allocator,
        exec_trace: *const trace_mod.Trace,
        guest_execution_rows: *const guest_runner.FrozenExecutionRows,
        opt_memory: ?*const memory_state.Snapshot,
        completion: public_data_mod.Completion,
        authority: *const poseidon_work.Authority,
    ) !CommitmentWitness {
        var completed = poseidon_work.Shard{};
        var boundary: ?memory_boundary.Claims = if (opt_memory) |snapshot| blk: {
            var built = try memory_boundary.buildWithWorkReceipt(
                allocator,
                snapshot.words,
                authority,
            );
            errdefer built.claims.deinit(allocator);
            try completed.merge(built.work);
            break :blk built.claims;
        } else null;
        errdefer if (boundary) |*claims| claims.deinit(allocator);
        if (boundary) |claims| {
            const validated = try claims.validateWithWorkReceipt(allocator, authority);
            try completed.merge(validated);
        }

        const snapshot = opt_memory orelse return ProverError.InvalidStatement;
        if (snapshot.program_words.len == 0) return ProverError.InvalidStatement;
        const built_program = try guest_program_commitment.buildDeclaredWithWorkReceipt(
            allocator,
            exec_trace.rows.items,
            guest_execution_rows,
            snapshot.program_words,
            completionFetch(completion),
            authority,
        );
        var program = built_program.commitment;
        errdefer program.deinit(allocator);
        try completed.merge(built_program.work);

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
            .poseidon_work = completed,
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

    pub fn poseidonWorkShard(self: *const CommitmentWitness) ?poseidon_work.Shard {
        return self.poseidon_work;
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
    completion: ?public_data_mod.Completion,
) !program_commitment.Commitment {
    const public_fetch = completionFetch(completion);
    const has_public_fetch = public_fetch != null;
    if (opt_memory) |snapshot| {
        if (snapshot.program_words.len != 0) {
            return program_commitment.buildDeclared(
                allocator,
                exec_trace.rows.items,
                snapshot.program_words,
                public_fetch,
            );
        }
    }
    const fetches = try allocator.alloc(
        program_table.Fetch,
        exec_trace.rows.items.len + @intFromBool(has_public_fetch),
    );
    defer allocator.free(fetches);
    for (exec_trace.rows.items, fetches[0..exec_trace.rows.items.len]) |row, *fetch| {
        fetch.* = .{ .pc = row.pc, .word = row.inst_word };
    }
    if (has_public_fetch) {
        fetches[fetches.len - 1] = public_fetch.?;
    }
    return program_commitment.build(
        allocator,
        fetches,
        if (opt_memory) |snapshot| snapshot.program_words else &.{},
    );
}

fn buildProgramWithWorkReceipt(
    allocator: std.mem.Allocator,
    exec_trace: *const trace_mod.Trace,
    opt_memory: ?*const memory_state.Snapshot,
    completion: ?public_data_mod.Completion,
    authority: *const poseidon_work.Authority,
) !program_commitment.BuiltWithWorkReceipt {
    const public_fetch = completionFetch(completion);
    const has_public_fetch = public_fetch != null;
    if (opt_memory) |snapshot| {
        if (snapshot.program_words.len != 0) {
            return program_commitment.buildDeclaredWithWorkReceipt(
                allocator,
                exec_trace.rows.items,
                snapshot.program_words,
                public_fetch,
                authority,
            );
        }
    }
    const fetches = try allocator.alloc(
        program_table.Fetch,
        exec_trace.rows.items.len + @intFromBool(has_public_fetch),
    );
    defer allocator.free(fetches);
    for (exec_trace.rows.items, fetches[0..exec_trace.rows.items.len]) |row, *fetch| {
        fetch.* = .{ .pc = row.pc, .word = row.inst_word };
    }
    if (has_public_fetch) fetches[fetches.len - 1] = public_fetch.?;
    return program_commitment.buildWithWorkReceipt(
        allocator,
        fetches,
        if (opt_memory) |snapshot| snapshot.program_words else &.{},
        authority,
    );
}

fn completionFetch(completion: ?public_data_mod.Completion) ?program_table.Fetch {
    const value = completion orelse return null;
    return if (value.kind == .unretired_self_loop)
        .{ .pc = value.address, .word = value.value }
    else
        null;
}

fn buildV2Boundary(
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

fn buildV2BoundaryWithWorkReceipt(
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
