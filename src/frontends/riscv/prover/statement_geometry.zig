//! Component geometry of the RISC-V statement, in pinned registry order.
//!
//! Every later stage indexes trace columns, interaction columns and preprocessed
//! offsets off the descriptor list this module writes, so the **declaration
//! order here is protocol-visible**: opcode shards in `component_order` family
//! order, then program, RW-memory shards, Merkle, Poseidon2, clock update, and
//! finally the fixed lookup tables. Reordering any of them changes the proof
//! even when every witness value is identical.
//!
//! The descriptors are written directly into the caller's `ProofWorkspace`; the
//! returned `Geometry` only carries the log sizes and infrastructure indices
//! that later stages would otherwise have to re-derive by scanning the list.

const std = @import("std");
const component_order = @import("../air/component_order.zig");
const lookup_table_schema = @import("../air/lookups/tables/schema.zig");
const memory_trace = @import("../air/memory_commitment/trace.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const statement_mod = @import("../air/statement.zig");
const infra = @import("../infra_trace.zig");
const state_chain = @import("../runner/state_chain.zig");
const trace_mod = @import("../runner/trace.zig");
const commitment_witness = @import("commitment_witness.zig");
const proof_workspace = @import("proof_workspace.zig");
const statement_validation = @import("statement_validation.zig");
const types = @import("types.zig");

const CommitmentWitness = commitment_witness.CommitmentWitness;
const ProofWorkspace = proof_workspace.ProofWorkspace;
const ProverError = types.ProverError;
const PublicData = types.PublicData;
const RiscVStatement = types.RiscVStatement;
const MAX_COMPONENTS = types.MAX_COMPONENTS;
const MAX_INFRA_COMPONENTS = types.MAX_INFRA_COMPONENTS;
const computeLogSize = statement_validation.computeLogSize;
const computeOpcodeLogSize = statement_validation.computeOpcodeLogSize;

const MAX_OPCODE_SHARD_ROWS: usize = 1 << 16;
const MAX_MEMORY_SHARD_ROWS: usize = 1 << 16;

/// Sizes and registry positions the trace and interaction stages read back.
pub const Geometry = struct {
    program_log_size: u32,
    merkle_log_size: u32,
    poseidon_log_size: u32,
    clock_update_log: u32,
    merkle_infra_index: usize,
    poseidon_infra_index: usize,
    clock_infra_index: usize,
};

/// Fills `workspace.statement` and admits it.
///
/// The commitment roots are bound between the RW-memory shards and the hash
/// tables, not at the end: a statement that names a root the witness did not
/// produce must be rejected before component capacity is even considered.
pub fn build(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    exec_trace: *const trace_mod.Trace,
    witness: *const CommitmentWitness,
    opt_chain: ?*const state_chain.StateChainTracker,
    public_data: PublicData,
    policy: statement_validation.AdmissionPolicy,
) !Geometry {
    const counts = try exec_trace.groupByOpcodeFamily(allocator);

    const statement = &workspace.statement;
    statement.n_components = 0;
    statement.initial_pc = exec_trace.initial_pc;
    statement.final_pc = exec_trace.final_pc;
    statement.total_steps = @intCast(exec_trace.step_count);
    statement.public_data = public_data;

    try describeOpcodeShards(statement, counts);
    if (statement.n_components == 0) return ProverError.EmptyTrace;

    statement.n_infra = 0;
    var geometry: Geometry = .{
        .program_log_size = 0,
        .merkle_log_size = 0,
        .poseidon_log_size = 0,
        .clock_update_log = 0,
        .merkle_infra_index = 0,
        .poseidon_infra_index = 0,
        .clock_infra_index = 0,
    };
    describeProgram(statement, witness, &geometry);
    try describeMemoryShards(workspace, witness);
    try bindCommitmentRoots(statement, witness);
    describeHashTables(statement, witness, &geometry);
    describeClockUpdate(statement, opt_chain, &geometry);
    try describeLookupTables(statement);

    try workspace.validateStatement(policy);
    return geometry;
}

/// One component per opcode-family shard, at its own `log_size`.
///
/// Sharding at `MAX_OPCODE_SHARD_ROWS` keeps each FFT bounded; admission
/// (`statement_validation`) separately requires every shard but the last of a
/// family to be exactly full, which is why the split is greedy and in order.
fn describeOpcodeShards(
    statement: *RiscVStatement,
    counts: trace_mod.OpcodeFamilyCounts,
) ProverError!void {
    for (component_order.opcodeFamilies()) |family| {
        const count = counts.get(family);
        if (count == 0) continue;

        var remaining = count;
        while (remaining > 0) {
            if (statement.n_components >= MAX_COMPONENTS) return ProverError.TooManyOpcodeComponents;
            const shard_len = @min(remaining, MAX_OPCODE_SHARD_ROWS);
            statement.component_descs[statement.n_components] = .{
                .family = family,
                .log_size = computeOpcodeLogSize(shard_len),
                .n_rows = @intCast(shard_len),
                .n_columns = trace_mod.nColumnsForFamily(family),
            };
            statement.n_components += 1;
            remaining -= shard_len;
        }
    }
}

/// Exact sparse decoded-program commitment, including canonical aligned
/// address limbs (10 columns).
fn describeProgram(
    statement: *RiscVStatement,
    witness: *const CommitmentWitness,
    geometry: *Geometry,
) void {
    geometry.program_log_size = computeLogSize(witness.program.rows.len);
    statement.infra_descs[statement.n_infra] = .{
        .kind = .program,
        .log_size = geometry.program_log_size,
        .n_rows = @intCast(witness.program.rows.len),
        .n_columns = program_commitment.N_MAIN_COLUMNS,
    };
    statement.n_infra += 1;
}

/// Ordinary RW-memory boundary rows, sharded without changing relation
/// placement. Opcode-side accesses close this bus in a later soundness slice.
///
/// The shard lengths are recorded in the workspace because the Tree-1 stage has
/// to regenerate exactly this partition, and re-deriving it there would be a
/// second source of truth for a protocol-visible split.
fn describeMemoryShards(
    workspace: *ProofWorkspace,
    witness: *const CommitmentWitness,
) ProverError!void {
    const claims = witness.boundary orelse return;
    const statement = &workspace.statement;
    var remaining = claims.rows.len;
    while (remaining > 0) {
        if (statement.n_infra + 3 >= MAX_INFRA_COMPONENTS)
            return ProverError.TooManyInfrastructureComponents;
        const shard_len = @min(remaining, MAX_MEMORY_SHARD_ROWS);
        statement.infra_descs[statement.n_infra] = .{
            .kind = .memory,
            .log_size = @max(computeLogSize(shard_len), 4),
            .n_rows = @intCast(shard_len),
            .n_columns = memory_trace.N_COLUMNS,
        };
        statement.n_infra += 1;
        workspace.memory_shard_lengths[workspace.memory_shard_count] = shard_len;
        workspace.memory_shard_count += 1;
        remaining -= shard_len;
    }
}

/// Publishes the roots the witness computed, rejecting any pre-declared root
/// that disagrees, and rejecting RW roots claimed without a memory snapshot.
fn bindCommitmentRoots(
    statement: *RiscVStatement,
    witness: *const CommitmentWitness,
) ProverError!void {
    if (statement.public_data.program_root) |root| {
        if (root != witness.program.tree.root) return ProverError.InvalidStatement;
    }
    statement.public_data.program_root = witness.program.tree.root;

    if (witness.boundary) |claims| {
        const initial_root = if (claims.initial_tree) |tree| tree.root else null;
        const final_root = if (claims.final_tree) |tree| tree.root else null;
        if (statement.public_data.initial_rw_root) |root| {
            if (initial_root == null or root != initial_root.?) return ProverError.InvalidStatement;
        }
        if (statement.public_data.final_rw_root) |root| {
            if (final_root == null or root != final_root.?) return ProverError.InvalidStatement;
        }
        statement.public_data.initial_rw_root = initial_root;
        statement.public_data.final_rw_root = final_root;
    } else if (statement.public_data.initial_rw_root != null or
        statement.public_data.final_rw_root != null)
    {
        return ProverError.InvalidStatement;
    }
}

/// Merkle and Poseidon2 follow the pinned component registry order.
///
/// Both floor at `log_size` 4 so an execution with no hashed nodes still has a
/// well-formed domain rather than a degenerate one.
fn describeHashTables(
    statement: *RiscVStatement,
    witness: *const CommitmentWitness,
    geometry: *Geometry,
) void {
    const total_merkle_nodes = witness.merkleRows().len;
    geometry.merkle_log_size = if (total_merkle_nodes > 0)
        @max(4, computeLogSize(total_merkle_nodes))
    else
        4;
    geometry.merkle_infra_index = statement.n_infra;
    statement.infra_descs[geometry.merkle_infra_index] = .{
        .kind = .merkle,
        .log_size = geometry.merkle_log_size,
        .n_rows = @intCast(total_merkle_nodes),
        .n_columns = merkle_node.N_MAIN_COLUMNS,
    };
    statement.n_infra += 1;

    const total_hashes = witness.poseidonCalls().len;
    geometry.poseidon_log_size = if (total_hashes > 0)
        @max(4, computeLogSize(total_hashes))
    else
        4;
    geometry.poseidon_infra_index = statement.n_infra;
    statement.infra_descs[geometry.poseidon_infra_index] = .{
        .kind = .poseidon2,
        .log_size = geometry.poseidon_log_size,
        .n_rows = @intCast(total_hashes),
        .n_columns = poseidon2_air.N_MAIN_COLUMNS,
    };
    statement.n_infra += 1;
}

/// Unified clock update follows Poseidon2 in the pinned registry.
fn describeClockUpdate(
    statement: *RiscVStatement,
    opt_chain: ?*const state_chain.StateChainTracker,
    geometry: *Geometry,
) void {
    geometry.clock_update_log = 4;
    if (opt_chain) |chain| {
        const n_updates = chain.clock_updates_mem.items.len + chain.clock_updates_reg.items.len;
        if (n_updates > 0) geometry.clock_update_log = @max(computeLogSize(n_updates), 4);
    }
    geometry.clock_infra_index = statement.n_infra;
    statement.infra_descs[geometry.clock_infra_index] = .{
        .kind = .clock_update,
        .log_size = geometry.clock_update_log,
        .n_rows = if (opt_chain) |chain| @intCast(
            chain.clock_updates_mem.items.len + chain.clock_updates_reg.items.len,
        ) else 0,
        .n_columns = infra.CLOCK_UPDATE_COLS,
    };
    statement.n_infra += 1;
}

/// The fixed lookup tables close the registry. Their sizes come from the
/// schema, never from the witness, so they are identical in every proof.
fn describeLookupTables(statement: *RiscVStatement) ProverError!void {
    for (component_order.lookupTables()) |kind| {
        if (statement.n_infra == MAX_INFRA_COMPONENTS)
            return ProverError.TooManyInfrastructureComponents;
        statement.infra_descs[statement.n_infra] = .{
            .kind = statement_mod.infraKindForTable(kind),
            .log_size = lookup_table_schema.logSize(kind),
            .n_rows = @intCast(lookup_table_schema.size(kind)),
            .n_columns = 1,
        };
        statement.n_infra += 1;
    }
}
