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
const public_data_v2 = @import("../air/public_data_v2.zig");
const statement_mod = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const guest_artifact = @import("../air/guest_precompile/artifact_identity.zig");
const guest_proof_admission = @import("../air/guest_precompile/proof_admission.zig");
const guest_statement = @import("../air/guest_precompile/statement.zig");
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

pub const Poseidon2Geometry = struct {
    base: Geometry,
    extension: guest_statement.ExtensionStatement,
    artifact: guest_artifact.Identity,
};

pub const V2Geometry = struct {
    base: Geometry,
    statement: statement_v2.RiscVStatementV2,
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
    const total_steps = std.math.cast(u32, exec_trace.step_count) orelse
        return ProverError.InvalidStatement;
    const geometry = try populate(
        allocator,
        workspace,
        exec_trace,
        witness,
        opt_chain,
        public_data,
        total_steps,
        false,
    );
    try workspace.validateStatement(policy);
    return geometry;
}

/// Builds the unchanged typed component geometry under a V2 public envelope.
/// The V1-shaped projection exists only for internal descriptor/root plumbing;
/// admission and transcript binding consume the authenticated V2 statement.
pub fn buildV2(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    exec_trace: *const trace_mod.Trace,
    witness: *const CommitmentWitness,
    opt_chain: ?*const state_chain.StateChainTracker,
    public_data: public_data_v2.PublicDataV2,
    policy: statement_validation.AdmissionPolicy,
) !V2Geometry {
    const total_steps = std.math.cast(u32, exec_trace.step_count) orelse
        return ProverError.InvalidStatement;
    const projection = statement_v2.canonicalCorePublicData(&public_data) catch
        return ProverError.InvalidStatement;
    const geometry = try populate(
        allocator,
        workspace,
        exec_trace,
        witness,
        opt_chain,
        projection,
        total_steps,
        false,
    );
    const statement = statement_v2.RiscVStatementV2.init(
        workspace.statement,
        public_data,
    ) catch return ProverError.InvalidStatement;
    try statement_validation.validateV2(&statement, policy);
    return .{ .base = geometry, .statement = statement };
}

/// V2 statement geometry for a segment whose authenticated profile owns
/// compact retirement rows outside the base opcode trace. The resulting core
/// statement still records the complete segment cycle count, while the caller
/// must immediately bind and validate its versioned extension statement.
pub fn buildExternalV2(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    exec_trace: *const trace_mod.Trace,
    witness: *const CommitmentWitness,
    opt_chain: ?*const state_chain.StateChainTracker,
    public_data: public_data_v2.PublicDataV2,
    external_retirements: u32,
    policy: statement_validation.AdmissionPolicy,
) !V2Geometry {
    const core_steps = std.math.cast(u32, exec_trace.step_count) orelse
        return ProverError.InvalidStatement;
    const total_steps = std.math.add(
        u32,
        core_steps,
        external_retirements,
    ) catch return ProverError.InvalidStatement;
    const projection = statement_v2.canonicalCorePublicData(&public_data) catch
        return ProverError.InvalidStatement;
    const geometry = try populate(
        allocator,
        workspace,
        exec_trace,
        witness,
        opt_chain,
        projection,
        total_steps,
        false,
    );
    const statement = statement_v2.RiscVStatementV2.init(
        workspace.statement,
        public_data,
    ) catch return ProverError.InvalidStatement;
    // The closed base validator does not understand external retirements.
    // The profile statement validates the exact coefficient supplement after
    // this function returns, so only the authenticated V2 envelope is checked
    // here.
    try statement.validate();
    if (policy != .proof) return ProverError.InvalidStatement;
    return .{ .base = geometry, .statement = statement };
}

/// Builds and authenticates the profile-separated core/extension statement.
/// The core descriptor arrays continue to describe only ordinary shards; its
/// `total_steps` includes the frozen guest retirements and is admitted through
/// the extension supplement rather than the closed base validator.
pub fn buildPoseidon2(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    exec_trace: *const trace_mod.Trace,
    witness: *const CommitmentWitness,
    opt_chain: ?*const state_chain.StateChainTracker,
    public_data: PublicData,
    n_guest: u32,
    policy: statement_validation.AdmissionPolicy,
) !Poseidon2Geometry {
    const geometry = try buildExternalBase(
        allocator,
        workspace,
        exec_trace,
        witness,
        opt_chain,
        public_data,
        n_guest,
    );
    const extension = try guest_statement.ExtensionStatement.canonical(
        &workspace.statement,
        n_guest,
    );
    const artifact = try guest_proof_admission.canonical(
        &workspace.statement,
        &extension,
        policy,
    );
    return .{ .base = geometry, .extension = extension, .artifact = artifact };
}

/// Populates the unchanged base component prefix while accounting for compact
/// external retirements that are proved by an authenticated extension.
///
/// This function intentionally performs no standalone V1 admission: the
/// caller must immediately validate its versioned extension statement, whose
/// coefficient certificate owns the extra retirement and memory terms.
/// `buildPoseidon2` remains that profile's existing admitted wrapper.
pub fn buildExternalBase(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    exec_trace: *const trace_mod.Trace,
    witness: *const CommitmentWitness,
    opt_chain: ?*const state_chain.StateChainTracker,
    public_data: PublicData,
    external_retirements: u32,
) !Geometry {
    const base_steps = std.math.cast(u32, exec_trace.step_count) orelse
        return ProverError.InvalidStatement;
    const total_steps = std.math.add(u32, base_steps, external_retirements) catch
        return ProverError.InvalidStatement;
    return populate(
        allocator,
        workspace,
        exec_trace,
        witness,
        opt_chain,
        public_data,
        total_steps,
        external_retirements != 0,
    );
}

fn populate(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    exec_trace: *const trace_mod.Trace,
    witness: *const CommitmentWitness,
    opt_chain: ?*const state_chain.StateChainTracker,
    public_data: PublicData,
    total_steps: u32,
    allow_empty_opcode: bool,
) !Geometry {
    const counts = try exec_trace.groupByOpcodeFamily(allocator);

    const statement = &workspace.statement;
    statement.n_components = 0;
    statement.initial_pc = exec_trace.initial_pc;
    statement.final_pc = exec_trace.final_pc;
    statement.total_steps = total_steps;
    statement.public_data = public_data;

    try describeOpcodeShards(statement, counts);
    if (statement.n_components == 0 and !allow_empty_opcode)
        return ProverError.EmptyTrace;

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
    const rows = witness.memoryBoundaryRows();
    if (rows.len == 0) return;
    const statement = &workspace.statement;
    var remaining = rows.len;
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

    if (witness.incremental_boundary_v3) |incremental| {
        const roots = incremental.roots;
        if (statement.public_data.initial_rw_root) |root| {
            if (root != roots.entry) return ProverError.InvalidStatement;
        }
        if (statement.public_data.final_rw_root) |root| {
            if (root != roots.exit) return ProverError.InvalidStatement;
        }
        statement.public_data.initial_rw_root = roots.entry;
        statement.public_data.final_rw_root = roots.exit;
    } else if (witness.boundary) |claims| {
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
