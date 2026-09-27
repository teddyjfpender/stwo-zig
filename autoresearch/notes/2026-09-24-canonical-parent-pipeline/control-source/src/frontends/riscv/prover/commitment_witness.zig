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

/// Entry/exit roots authenticated by an incremental multiproof rather than by
/// two materialized `sparse_merkle.Tree` owners. The roots are values only;
/// their node/call custody remains in `merkle_rows` and `poseidon_calls`.
pub const IncrementalRootsV3 = struct {
    entry: u32,
    exit: u32,
};

pub const IncrementalBoundaryV3 = struct {
    rows: []memory_boundary.Row,
    roots: IncrementalRootsV3,
};

const program_owner = @import("commitment_program_witness.zig");
const tree_owner = @import("commitment_tree_witness.zig");
pub const PreparedProgramWorkReceiptV1 = program_owner.PreparedProgramWorkReceiptV1;
pub const ProgramWitnessV1 = program_owner.ProgramWitnessV1;
pub const bindCompletion = program_owner.bindCompletion;
pub const validatePreparedProgramSnapshot = program_owner.validatePreparedProgramSnapshot;
const completionFetch = program_owner.completionFetch;
const buildProgram = program_owner.buildProgram;
const buildProgramWithWorkReceipt = program_owner.buildProgramWithWorkReceipt;
const buildV2Boundary = tree_owner.buildV2Boundary;
const buildV2BoundaryWithWorkReceipt = tree_owner.buildV2BoundaryWithWorkReceipt;
const appendPoseidonCalls = tree_owner.appendPoseidonCalls;
const appendMerkleRows = tree_owner.appendMerkleRows;
const appendTreeCalls = tree_owner.appendTreeCalls;
const appendTreeRows = tree_owner.appendTreeRows;

pub const CommitmentWitness = struct {
    circuit_profile: @import("ethereum_circuit_profile_v1.zig").CircuitProfileV1 = .legacy_v4,
    boundary: ?memory_boundary.Claims,
    program: ProgramWitnessV1,
    poseidon_calls: std.ArrayList(poseidon2_air.Call),
    merkle_rows: std.ArrayList(merkle_node.NodeRow),
    /// Present only for the full-state incremental profile. It is deliberately
    /// separate from legacy `memory_boundary.Claims`: active V3 rows may carry
    /// zero memory-bus multiplicity and their roots are authenticated by the
    /// retained multiproof instead of two owned full trees.
    incremental_boundary_v3: ?IncrementalBoundaryV3 = null,
    /// Present only on an explicitly profiled request. It contains every
    /// completed sparse-tree construction and validation permutation; Tree-1
    /// materialization merges into it before terminal publication.
    poseidon_work: ?poseidon_work.Shard = null,
    prepared_program_work: ?PreparedProgramWorkReceiptV1 = null,

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
            .program = .fromOwned(program),
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
            .program = .fromOwned(program),
            .poseidon_calls = poseidon_calls,
            .merkle_rows = merkle_rows,
            .poseidon_work = completed,
        };
    }

    /// Builds the ordinary program commitment and splices in one already
    /// authenticated incremental memory multiproof. The pinned table order is
    /// unchanged: Poseidon calls visit program then memory, while Merkle rows
    /// visit memory then program.
    ///
    /// The supplied slices are copied. This keeps the caller's transition
    /// owner available for the separately committed bridge component and
    /// makes this witness's deinit transaction independent.
    pub fn buildWithIncrementalBoundaryV3(
        allocator: std.mem.Allocator,
        exec_trace: *const trace_mod.Trace,
        opt_memory: ?*const memory_state.Snapshot,
        completion: public_data_mod.Completion,
        boundary_rows: []const memory_boundary.Row,
        incremental_merkle_rows: []const merkle_node.NodeRow,
        incremental_poseidon_calls: []const poseidon2_air.Call,
        roots: IncrementalRootsV3,
    ) !CommitmentWitness {
        if (boundary_rows.len == 0 or
            incremental_merkle_rows.len == 0 or
            incremental_poseidon_calls.len == 0)
        {
            return ProverError.InvalidStatement;
        }
        for (boundary_rows) |row| {
            if (row.root != roots.entry and row.root != roots.exit)
                return ProverError.InvalidStatement;
        }

        const incremental_rows = try allocator.dupe(
            memory_boundary.Row,
            boundary_rows,
        );
        errdefer allocator.free(incremental_rows);

        var program = try buildProgram(
            allocator,
            exec_trace,
            opt_memory,
            completion,
        );
        errdefer program.deinit(allocator);

        var poseidon_calls: std.ArrayList(poseidon2_air.Call) = .{};
        errdefer poseidon_calls.deinit(allocator);
        try appendTreeCalls(allocator, &poseidon_calls, program.tree);
        try poseidon_calls.appendSlice(allocator, incremental_poseidon_calls);

        var merkle_rows: std.ArrayList(merkle_node.NodeRow) = .{};
        errdefer merkle_rows.deinit(allocator);
        try merkle_rows.appendSlice(allocator, incremental_merkle_rows);
        try appendTreeRows(allocator, &merkle_rows, program.tree);

        return .{
            .boundary = null,
            .program = .fromOwned(program),
            .poseidon_calls = poseidon_calls,
            .merkle_rows = merkle_rows,
            .incremental_boundary_v3 = .{
                .rows = incremental_rows,
                .roots = roots,
            },
            .poseidon_work = null,
        };
    }

    /// External-profile twin of `buildWithIncrementalBoundaryV3`.
    ///
    /// The transition tables retain the same incremental ownership and table
    /// order. Only declared-program construction is widened to the exact
    /// statement-ordered execution sources, so host-retired CUSTOM-0 words
    /// cannot disappear from a joined Ethereum proof.
    pub fn buildExternalProfileWithIncrementalBoundaryV3(
        allocator: std.mem.Allocator,
        selected_profile: @import("../isa/execution_profile.zig").ExecutionProfile,
        execution_sources: anytype,
        opt_memory: ?*const memory_state.Snapshot,
        completion: public_data_mod.Completion,
        boundary_rows: []const memory_boundary.Row,
        incremental_merkle_rows: []const merkle_node.NodeRow,
        incremental_poseidon_calls: []const poseidon2_air.Call,
        roots: IncrementalRootsV3,
    ) !CommitmentWitness {
        if (boundary_rows.len == 0 or
            incremental_merkle_rows.len == 0 or
            incremental_poseidon_calls.len == 0)
        {
            return ProverError.InvalidStatement;
        }
        for (boundary_rows) |row| {
            if (row.root != roots.entry and row.root != roots.exit)
                return ProverError.InvalidStatement;
        }

        const snapshot = opt_memory orelse return ProverError.InvalidStatement;
        if (snapshot.program_words.len == 0)
            return ProverError.InvalidStatement;
        const incremental_rows = try allocator.dupe(
            memory_boundary.Row,
            boundary_rows,
        );
        errdefer allocator.free(incremental_rows);

        var program = try program_commitment.buildDeclaredForProfileSources(
            allocator,
            selected_profile,
            execution_sources,
            snapshot.program_words,
            completionFetch(completion),
        );
        errdefer program.deinit(allocator);

        var poseidon_calls: std.ArrayList(poseidon2_air.Call) = .{};
        errdefer poseidon_calls.deinit(allocator);
        try appendTreeCalls(allocator, &poseidon_calls, program.tree);
        try poseidon_calls.appendSlice(allocator, incremental_poseidon_calls);

        var merkle_rows: std.ArrayList(merkle_node.NodeRow) = .{};
        errdefer merkle_rows.deinit(allocator);
        try merkle_rows.appendSlice(allocator, incremental_merkle_rows);
        try appendTreeRows(allocator, &merkle_rows, program.tree);

        return .{
            .boundary = null,
            .program = .fromOwned(program),
            .poseidon_calls = poseidon_calls,
            .merkle_rows = merkle_rows,
            .incremental_boundary_v3 = .{
                .rows = incremental_rows,
                .roots = roots,
            },
            .poseidon_work = null,
        };
    }

    /// Prepared-program sibling of
    /// `buildExternalProfileWithIncrementalBoundaryV3`.
    ///
    /// `prepared_program` is a statically typed, process-local borrow. It
    /// validates its exact owner/token, derives only leaf-specific program
    /// multiplicities, and returns an owned row slice. This witness copies the
    /// fixed program calls and node rows into its ordinary contiguous tables;
    /// no prepared-owner allocation is ever adopted or freed here.
    pub fn buildExternalProfileWithPreparedProgramAndIncrementalBoundaryV3(
        allocator: std.mem.Allocator,
        selected_profile: @import("../isa/execution_profile.zig").ExecutionProfile,
        execution_sources: anytype,
        opt_memory: ?*const memory_state.Snapshot,
        completion: public_data_mod.Completion,
        prepared_program: anytype,
        boundary_rows: []const memory_boundary.Row,
        incremental_merkle_rows: []const merkle_node.NodeRow,
        incremental_poseidon_calls: []const poseidon2_air.Call,
        roots: IncrementalRootsV3,
    ) !CommitmentWitness {
        return buildExternalProfileWithProgramPolicy(.legacy_v4, allocator, selected_profile, execution_sources, opt_memory, completion, prepared_program, boundary_rows, incremental_merkle_rows, incremental_poseidon_calls, roots);
    }

    pub fn buildExternalProfileWithFixedProgramAndIncrementalBoundaryV1(
        allocator: std.mem.Allocator,
        selected_profile: @import("../isa/execution_profile.zig").ExecutionProfile,
        execution_sources: anytype,
        opt_memory: ?*const memory_state.Snapshot,
        completion: public_data_mod.Completion,
        prepared_program: anytype,
        boundary_rows: []const memory_boundary.Row,
        incremental_merkle_rows: []const merkle_node.NodeRow,
        incremental_poseidon_calls: []const poseidon2_air.Call,
        roots: IncrementalRootsV3,
    ) !CommitmentWitness {
        return buildExternalProfileWithProgramPolicy(.fixed_program_narrow_v1, allocator, selected_profile, execution_sources, opt_memory, completion, prepared_program, boundary_rows, incremental_merkle_rows, incremental_poseidon_calls, roots);
    }

    fn buildExternalProfileWithProgramPolicy(
        comptime circuit_profile: @import("ethereum_circuit_profile_v1.zig").CircuitProfileV1,
        allocator: std.mem.Allocator,
        selected_profile: @import("../isa/execution_profile.zig").ExecutionProfile,
        execution_sources: anytype,
        opt_memory: ?*const memory_state.Snapshot,
        completion: public_data_mod.Completion,
        prepared_program: anytype,
        boundary_rows: []const memory_boundary.Row,
        incremental_merkle_rows: []const merkle_node.NodeRow,
        incremental_poseidon_calls: []const poseidon2_air.Call,
        roots: IncrementalRootsV3,
    ) !CommitmentWitness {
        if (selected_profile != .rv32im_zkvm_ethereum_v1 or
            boundary_rows.len == 0 or
            incremental_merkle_rows.len == 0 or
            incremental_poseidon_calls.len == 0)
        {
            return ProverError.InvalidStatement;
        }
        for (boundary_rows) |row| {
            if (row.root != roots.entry and row.root != roots.exit)
                return ProverError.InvalidStatement;
        }
        try prepared_program.validate();
        const snapshot = opt_memory orelse return ProverError.InvalidStatement;
        try validatePreparedProgramSnapshot(snapshot, prepared_program);

        const incremental_rows = try allocator.dupe(
            memory_boundary.Row,
            boundary_rows,
        );
        errdefer allocator.free(incremental_rows);

        var leaf_program = try prepared_program.prepareLeafRows(
            allocator,
            execution_sources,
            completionFetch(completion),
        );
        var leaf_program_owned = true;
        defer if (leaf_program_owned) leaf_program.deinit();
        try leaf_program.validate();
        const work = leaf_program.workReceipt();
        try work.validate();

        var poseidon_calls: std.ArrayList(poseidon2_air.Call) = .{};
        errdefer poseidon_calls.deinit(allocator);
        if (circuit_profile.programPolicy() == .sparse_merkle_v1) try poseidon_calls.appendSlice(allocator, prepared_program.ordered_poseidon_calls);
        try poseidon_calls.appendSlice(allocator, incremental_poseidon_calls);

        var merkle_rows: std.ArrayList(merkle_node.NodeRow) = .{};
        errdefer merkle_rows.deinit(allocator);
        try merkle_rows.appendSlice(allocator, incremental_merkle_rows);
        if (circuit_profile.programPolicy() == .sparse_merkle_v1) try appendTreeRows(allocator, &merkle_rows, prepared_program.commitment.tree);

        const owned_rows = try leaf_program.takeRows();
        leaf_program_owned = false;
        errdefer allocator.free(owned_rows);
        const program = try ProgramWitnessV1.fromPreparedRows(
            owned_rows,
            prepared_program.commitment.tree.root,
            prepared_program.commitment.tree.leaves.len,
            prepared_program.commitment.tree.nodes.len,
        );
        return .{
            .circuit_profile = circuit_profile,
            .boundary = null,
            .program = program,
            .poseidon_calls = poseidon_calls,
            .merkle_rows = merkle_rows,
            .incremental_boundary_v3 = .{
                .rows = incremental_rows,
                .roots = roots,
            },
            .poseidon_work = null,
            .prepared_program_work = work,
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
            .program = .fromOwned(program),
            .poseidon_calls = poseidon_calls,
            .merkle_rows = merkle_rows,
            .poseidon_work = null,
        };
    }

    /// SegmentV2 boundary derivation with an explicitly selected external
    /// execution profile. The boundary/public-data transaction is identical
    /// to `buildV2`; only the declared-program source union is widened so
    /// CUSTOM-0 fetches are decoded and counted under their admitted profile.
    pub fn buildExternalProfileV2(
        allocator: std.mem.Allocator,
        selected_profile: @import("../isa/execution_profile.zig").ExecutionProfile,
        execution_sources: anytype,
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
        var program = try program_commitment.buildDeclaredForProfileSources(
            allocator,
            selected_profile,
            execution_sources,
            snapshot.program_words,
            completionFetch(core_public.completion),
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
            .program = .fromOwned(program),
            .poseidon_calls = poseidon_calls,
            .merkle_rows = merkle_rows,
            .poseidon_work = null,
        };
    }

    /// Candidate-only SegmentV2 commitment derivation with an explicit,
    /// statically typed declared-program decoder.
    ///
    /// The boundary, sparse-tree, Merkle, and Poseidon construction is exactly
    /// the `buildExternalProfileV2` transaction. Only program-word decoding is
    /// delegated to the caller-owned authority, which must expose the generic
    /// declared-decoder contract. Existing profile entrypoints and bytes are
    /// unchanged.
    pub fn buildExternalDecodeAuthorityV2(
        allocator: std.mem.Allocator,
        decode_authority: anytype,
        execution_sources: anytype,
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
        var program = try program_commitment.buildDeclaredWithDecodeAuthoritySources(
            allocator,
            decode_authority,
            execution_sources,
            snapshot.program_words,
            completionFetch(core_public.completion),
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
            .program = .fromOwned(program),
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
            .program = .fromOwned(program),
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
            .program = .fromOwned(program),
            .poseidon_calls = poseidon_calls,
            .merkle_rows = merkle_rows,
            .poseidon_work = null,
        };
    }

    /// Derives the unchanged commitment tables for a versioned execution
    /// profile whose CUSTOM-0 retirements live in one or more compact row
    /// tapes.  The tuple is consumed without concatenation; each element must
    /// expose `pc` and `inst_word`.
    ///
    /// Poseidon2 deliberately keeps its existing named wrapper and proof
    /// identity. Combined profiles use this seam so program, memory, Merkle,
    /// and Poseidon tables still originate in one transaction.
    pub fn buildExternalProfile(
        allocator: std.mem.Allocator,
        selected_profile: @import("../isa/execution_profile.zig").ExecutionProfile,
        execution_sources: anytype,
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
        var program = try program_commitment.buildDeclaredForProfileSources(
            allocator,
            selected_profile,
            execution_sources,
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
            .program = .fromOwned(program),
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
            .program = .fromOwned(program),
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
        if (self.incremental_boundary_v3) |boundary|
            allocator.free(boundary.rows);
        self.* = undefined;
    }

    pub fn memoryBoundaryRows(
        self: *const CommitmentWitness,
    ) []const memory_boundary.Row {
        if (self.incremental_boundary_v3) |boundary| return boundary.rows;
        if (self.boundary) |claims| return claims.rows;
        return &.{};
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

    pub fn preparedProgramWorkReceipt(
        self: *const CommitmentWitness,
    ) ?PreparedProgramWorkReceiptV1 {
        return self.prepared_program_work;
    }
};
