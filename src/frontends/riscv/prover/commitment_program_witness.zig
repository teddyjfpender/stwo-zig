//! Program witness custody, completion binding and fetched-word construction.
const std = @import("std");
const program_commitment = @import("../air/program/commitment.zig");
const program_table = @import("../air/program/table.zig");
const public_data_mod = @import("../air/public_data.zig");
const memory_state = @import("../runner/memory_state.zig");
const trace_mod = @import("../runner/trace.zig");
const poseidon_work = @import("poseidon_witness_work.zig");
const PublicData = types.PublicData;
const ProverError = types.ProverError;
const types = @import("types.zig");

/// Exact work removed by one prepared-program construction.  Counts are
/// derived from retained owners and execution slices, never from timings.
/// The receipt is process-local diagnostics and enters no statement or proof.
pub const PreparedProgramWorkReceiptV1 = struct {
    execution_fetch_rows_scanned: u64,
    completion_fetch_rows_scanned: u8,
    fixed_declared_rows: u64,
    fixed_committed_rows: u64,
    fixed_sparse_leaves: u64,
    fixed_sparse_nodes: u64,
    sparse_tree_builds_elided: u8,
    sparse_tree_validation_rebuilds_elided: u8,
    declared_row_decodes_elided: u64,
    node_poseidon_call_derivations_elided: u64,

    pub fn validate(self: PreparedProgramWorkReceiptV1) !void {
        const expected_leaves = std.math.mul(
            u64,
            self.fixed_committed_rows,
            4,
        ) catch return ProverError.InvalidStatement;
        if (self.execution_fetch_rows_scanned == 0 or
            self.completion_fetch_rows_scanned > 1 or
            self.fixed_declared_rows == 0 or
            self.fixed_committed_rows == 0 or
            self.fixed_committed_rows > self.fixed_declared_rows or
            self.fixed_sparse_leaves != expected_leaves or
            self.fixed_sparse_nodes == 0 or
            self.sparse_tree_builds_elided != 1 or
            self.sparse_tree_validation_rebuilds_elided != 1 or
            self.declared_row_decodes_elided != self.fixed_committed_rows or
            self.node_poseidon_call_derivations_elided != self.fixed_sparse_nodes)
        {
            return ProverError.InvalidStatement;
        }
    }
};

/// Read-only program material retained by one commitment witness.
///
/// Ordinary constructors keep owning the complete sparse commitment.  The
/// prepared-program constructor owns only its leaf-specific row copy; the
/// fixed tree has already been projected into this witness's owned Merkle-row
/// and Poseidon-call lists, so retaining a shallow mutable tree alias would be
/// both unnecessary and an ownership bug.  `rows` and `tree.root` preserve the
/// existing downstream read surface.
pub const ProgramWitnessV1 = struct {
    rows: []const program_commitment.Row,
    tree: TreeViewV1,
    custody: CustodyV1,

    pub const TreeViewV1 = struct {
        root: u32,
        leaf_count: usize,
        node_count: usize,
    };

    pub const CustodyV1 = union(enum) {
        full_commitment: program_commitment.Commitment,
        prepared_rows: []program_commitment.Row,
    };

    pub fn fromOwned(
        commitment: program_commitment.Commitment,
    ) ProgramWitnessV1 {
        return .{
            .rows = commitment.rows,
            .tree = .{
                .root = commitment.tree.root,
                .leaf_count = commitment.tree.leaves.len,
                .node_count = commitment.tree.nodes.len,
            },
            .custody = .{ .full_commitment = commitment },
        };
    }

    pub fn fromPreparedRows(
        rows: []program_commitment.Row,
        root: u32,
        leaf_count: usize,
        node_count: usize,
    ) !ProgramWitnessV1 {
        const expected_leaves = std.math.mul(usize, rows.len, 4) catch
            return ProverError.InvalidStatement;
        if (rows.len == 0 or leaf_count != expected_leaves or node_count == 0)
            return ProverError.InvalidStatement;
        for (rows) |row| if (row.root != root)
            return ProverError.InvalidStatement;
        return .{
            .rows = rows,
            .tree = .{
                .root = root,
                .leaf_count = leaf_count,
                .node_count = node_count,
            },
            .custody = .{ .prepared_rows = rows },
        };
    }

    pub fn deinit(
        self: *ProgramWitnessV1,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.custody) {
            .full_commitment => |*commitment| commitment.deinit(allocator),
            .prepared_rows => |rows| allocator.free(rows),
        }
        self.* = undefined;
    }
};

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

pub fn validatePreparedProgramSnapshot(
    snapshot: *const memory_state.Snapshot,
    prepared_program: anytype,
) !void {
    if (!std.meta.eql(snapshot.layout, prepared_program.layout.*) or
        snapshot.program_words.len != prepared_program.declared_rows.len)
    {
        return ProverError.InvalidStatement;
    }
    for (
        snapshot.program_words,
        prepared_program.declared_rows,
    ) |actual, expected| {
        if (!std.meta.eql(actual, expected)) return ProverError.InvalidStatement;
    }
}

/// Decoded-program commitment over every fetched word.
///
/// An unretired self-loop completion is fetched by the public statement rather
/// than by a trace row, so its word joins the fetch list; otherwise a verifier
/// would range over a program table that omits the instruction the statement
/// claims the machine is parked on.
pub fn buildProgram(
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

pub fn buildProgramWithWorkReceipt(
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

pub fn completionFetch(completion: ?public_data_mod.Completion) ?program_table.Fetch {
    const value = completion orelse return null;
    return switch (value.kind) {
        .halt_flag => null,
        .unretired_self_loop, .unretired_program_fetch => .{ .pc = value.address, .word = value.value },
    };
}
