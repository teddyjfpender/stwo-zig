//! The claim phase and Tree 2: LogUp interaction columns.
//!
//! ## Why the claim phase lives here
//!
//! `drawChallenges` is the only place a relation challenge may be drawn. It sits
//! in this module because the challenges and the columns they parameterise must
//! not be separable: every interaction column below is a function of the exact
//! `Relations` value drawn from the transcript position immediately after the
//! Tree-1 root. A second draw site, even one that produced the same value, would
//! be a second definition of the Fiat-Shamir position.
//!
//! ## Ordering
//!
//! Interaction columns are appended in the *same* declaration order Tree 1 used
//! -- opcode shards, then program, RW-memory shards, Merkle, Poseidon2, clock
//! update, lookup tables -- because `proof_finalize` walks one shared offset
//! cursor over both trees. The per-component claim written into
//! `interaction_claim` is indexed by that component's registry position, not by
//! the order it was generated in, which is why the memory and lookup-table
//! stages re-derive `infra_index` rather than counting.
//!
//! ## Ownership
//!
//! The generated `ColumnEvaluation` array is **transferred** to the commitment
//! scheme at the commit point and released here on every path that does not
//! reach it. Each generator's *shifted cumulative* columns are a different
//! matter: composition borrows them after this stage returns, so they are parked
//! in the caller's `ProofWorkspace` and released by
//! transferred to the commitment scheme, never retained as duplicate masks.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const work_pool = @import("stwo_prover_engine").work_pool;
const stage_profile = @import("stwo_prover_api").stage_profile;
const clock_update_interaction = @import("../air/clock_update_interaction.zig");
const component_order = @import("../air/component_order.zig");
const lookup_table_interaction = @import("../air/lookups/tables/interaction.zig");
const lookup_table_schema = @import("../air/lookups/tables/schema.zig");
const source_ingest = @import("../air/lookups/tables/source_ingest.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_interaction = @import("../air/program/interaction.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const proof_transcript = @import("../proof_transcript.zig");
const trace_mod = @import("../runner/trace.zig");
const commitment_witness = @import("commitment_witness.zig");
const proof_workspace = @import("proof_workspace.zig");
const statement_geometry = @import("statement_geometry.zig");
const types = @import("types.zig");

const M31 = m31.M31;
const CommitmentWitness = commitment_witness.CommitmentWitness;
const Geometry = statement_geometry.Geometry;
const ProofWorkspace = proof_workspace.ProofWorkspace;
const Relations = relation_challenges.Relations;
const RiscVInteractionClaim = types.RiscVInteractionClaim;
const RunMode = types.RunMode;

/// Draws the relation challenges that parameterise Tree 2.
///
/// In `.prove` the draw is preceded by the canonical main claim, the shard
/// manifest and the interaction proof of work, so the challenges are bound to
/// the committed main trace. `.relation_diagnostic` deliberately draws from a
/// *fresh* channel instead: the diagnostic compares relation sums across runs,
/// which requires challenges that do not depend on the witness under study.
///
/// The result is returned by value so the caller owns the storage the generated
/// components will borrow a pointer to for the rest of the proof.
pub fn drawChallenges(
    comptime Engine: type,
    comptime mode: RunMode,
    allocator: std.mem.Allocator,
    channel: *Engine.Channel,
    statement: *const types.RiscVStatement,
) !proof_transcript.ProverRelations {
    if (comptime mode == .prove) {
        return proof_transcript.proveToRelations(allocator, channel, statement);
    }
    var diagnostic_channel = Engine.Channel{};
    return .{
        .interaction_pow = 0,
        .relations = try Relations.draw(allocator, &diagnostic_channel),
    };
}

/// Generates every Tree-2 column, mixes the interaction claim, and commits.
///
/// `claim` is written in place by the caller's allocation: the boxed claim
/// outlives this proof, so allocating it at the boundary that transfers it keeps
/// its ownership visible in one function. `prefix` is **borrowed** and must
/// outlive proving -- the prover components hold `&prefix.relations`.
pub fn generateAndCommit(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    lookup_source: *const source_ingest.Result,
    prefix: *const proof_transcript.ProverRelations,
    claim: *RiscVInteractionClaim,
) !void {
    const statement = &workspace.statement;
    claim.initZeroInto();
    claim.n_components = statement.n_components;
    claim.n_infra = statement.n_infra;
    claim.interaction_pow = prefix.interaction_pow;

    const relations = &prefix.relations;
    const n_interaction = statement.nInteractionColumns();

    var stage = try stage_profile.StageScope.begin(recorder, "riscv_interaction_commit", "RISC-V interaction trace generation and commit");
    defer stage.end();

    var columns = try Columns.init(allocator, n_interaction);
    defer columns.deinit(allocator);

    {
        var sub = try stage_profile.StageScope.begin(recorder, "riscv_interaction_opcode", "RISC-V opcode interactions");
        defer sub.end();
        try generateOpcode(allocator, workspace, &columns, relations, claim);
    }
    {
        var sub = try stage_profile.StageScope.begin(recorder, "riscv_interaction_program", "RISC-V program interactions");
        defer sub.end();
        try generateProgram(allocator, &columns, witness, geometry, relations, claim);
    }
    {
        var sub = try stage_profile.StageScope.begin(recorder, "riscv_interaction_memory", "RISC-V memory interactions");
        defer sub.end();
        try generateMemory(allocator, workspace, &columns, witness, relations, claim);
    }
    {
        var sub = try stage_profile.StageScope.begin(recorder, "riscv_interaction_merkle", "RISC-V Merkle interactions");
        defer sub.end();
        try generateMerkle(allocator, &columns, witness, geometry, relations, claim);
    }
    {
        var sub = try stage_profile.StageScope.begin(recorder, "riscv_interaction_poseidon", "RISC-V Poseidon interactions");
        defer sub.end();
        try generatePoseidon(allocator, &columns, witness, geometry, relations, claim);
    }
    {
        var sub = try stage_profile.StageScope.begin(recorder, "riscv_interaction_clock", "RISC-V clock interactions");
        defer sub.end();
        try generateClock(allocator, workspace, &columns, geometry, relations, claim);
    }
    {
        var sub = try stage_profile.StageScope.begin(recorder, "riscv_interaction_tables", "RISC-V lookup-table interactions");
        defer sub.end();
        try generateLookupTables(allocator, workspace, &columns, lookup_source, relations, claim);
    }
    std.debug.assert(columns.filled == n_interaction);

    try proof_transcript.mixInteractionClaim(channel, statement, claim);
    columns.moved = true;
    try Engine.commit(scheme, allocator, columns.values, recorder, channel);
}

/// One opcode shard's interactions, from the exact buffers Tree 1 committed.
///
/// The result is parked in the workspace before its columns are taken: the
/// shifted cumulative columns it also holds are borrowed by composition, so the
/// value may not stay in this frame.
fn generateOpcode(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    columns: *Columns,
    relations: *const Relations,
    claim: *RiscVInteractionClaim,
) !void {
    const statement = &workspace.statement;
    if (statement.n_components > 1) {
        if (work_pool.getGlobalPool()) |pool| {
            return generateOpcodeParallel(
                allocator,
                workspace,
                columns,
                relations,
                claim,
                pool,
            );
        }
    }
    var opcode_main_offset: usize = 0;
    for (0..statement.n_components) |i| {
        const desc = statement.component_descs[i];
        const n_family_columns: usize = @intCast(desc.n_columns);
        var family_columns: [trace_mod.MAX_FAMILY_COLUMNS][]const M31 = undefined;
        for (
            workspace.opcode_columns.components[i].columns[0..n_family_columns],
            family_columns[0..n_family_columns],
        ) |column, *values| values.* = column;
        var generated = try opcode_interaction.generate(
            allocator,
            desc.family,
            family_columns[0..n_family_columns],
            desc.log_size,
            relations,
        );
        @memcpy(
            claim.opcode_claims[i][0..generated.n_batches],
            generated.claims[0..generated.n_batches],
        );
        const n_columns = generated.nColumns();
        const taken = generated.takeColumns();
        for (taken[0..n_columns]) |values| columns.append(desc.log_size, values);
        opcode_main_offset += n_family_columns;
    }
    std.debug.assert(opcode_main_offset == statement.nOpcodeMainColumns());
}

/// Gives each large opcode family the whole bounded pool in turn. This avoids
/// nested waits and lets the family generator parallelize its row-local tuple,
/// inversion and scan work before results are appended in protocol order.
fn generateOpcodeParallel(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    columns: *Columns,
    relations: *const Relations,
    claim: *RiscVInteractionClaim,
    pool: *work_pool.WorkPool,
) !void {
    const statement = &workspace.statement;
    var opcode_main_offset: usize = 0;
    for (0..statement.n_components) |index| {
        const desc = statement.component_descs[index];
        const n_family_columns: usize = @intCast(desc.n_columns);
        var family_columns: [trace_mod.MAX_FAMILY_COLUMNS][]const M31 = undefined;
        for (
            workspace.opcode_columns.components[index].columns[0..n_family_columns],
            family_columns[0..n_family_columns],
        ) |column, *values| values.* = column;
        var generated = if (desc.log_size >= 12)
            try opcode_interaction.generateParallel(
                allocator,
                desc.family,
                family_columns[0..n_family_columns],
                desc.log_size,
                relations,
                pool,
            )
        else
            try opcode_interaction.generate(
                allocator,
                desc.family,
                family_columns[0..n_family_columns],
                desc.log_size,
                relations,
            );
        @memcpy(
            claim.opcode_claims[index][0..generated.n_batches],
            generated.claims[0..generated.n_batches],
        );
        const n_columns = generated.nColumns();
        const taken = generated.takeColumns();
        for (taken[0..n_columns]) |values| columns.append(desc.log_size, values);
        opcode_main_offset += @intCast(desc.n_columns);
    }
    std.debug.assert(opcode_main_offset == statement.nOpcodeMainColumns());
}

/// Program-table interactions. Program is infrastructure index 0 by
/// construction, which is the index its claim is published under.
fn generateProgram(
    allocator: std.mem.Allocator,
    columns: *Columns,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    relations: *const Relations,
    claim: *RiscVInteractionClaim,
) !void {
    const generated = try program_interaction.generate(
        allocator,
        witness.program.rows,
        geometry.program_log_size,
        relations,
    );
    claim.program_claims[0] = generated.claims.sums;
    for (generated.columns) |values| columns.append(geometry.program_log_size, values);
}

/// RW-memory boundary interactions, over the shard partition Tree 1 committed.
///
/// The rows are consumed by walking the declared shard descriptors rather than
/// `memory_shard_lengths`, because each shard's claim is published under its
/// infrastructure index; the running `row_start` and the final assertion are
/// what tie the two views of the same partition together.
fn generateMemory(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    columns: *Columns,
    witness: *const CommitmentWitness,
    relations: *const Relations,
    claim: *RiscVInteractionClaim,
) !void {
    const boundary = witness.boundary orelse return;
    const statement = &workspace.statement;
    var row_start: usize = 0;
    for (0..statement.n_infra) |infra_index| {
        const desc = statement.infra_descs[infra_index];
        if (desc.kind != .memory) continue;
        const row_end = row_start + desc.n_rows;
        const generated = try memory_interaction.generate(
            allocator,
            boundary.rows[row_start..row_end],
            desc.log_size,
            relations,
        );
        claim.memory_claims[infra_index] = generated.claims.sums;
        for (generated.columns) |values| columns.append(desc.log_size, values);
        row_start = row_end;
    }
    std.debug.assert(row_start == boundary.rows.len);
}

fn generateMerkle(
    allocator: std.mem.Allocator,
    columns: *Columns,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    relations: *const Relations,
    claim: *RiscVInteractionClaim,
) !void {
    const generated = try merkle_node.generateInteraction(
        allocator,
        witness.merkleRows(),
        geometry.merkle_log_size,
        relations,
    );
    claim.merkle_claims[geometry.merkle_infra_index] = generated.claims.sums;
    for (generated.columns) |values| columns.append(geometry.merkle_log_size, values);
}

fn generatePoseidon(
    allocator: std.mem.Allocator,
    columns: *Columns,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    relations: *const Relations,
    claim: *RiscVInteractionClaim,
) !void {
    const generated = try poseidon2_air.generateInteraction(
        allocator,
        witness.poseidonCalls(),
        geometry.poseidon_log_size,
        relations,
    );
    claim.poseidon_claims[geometry.poseidon_infra_index] = generated.claims.sums;
    for (generated.columns) |values| columns.append(geometry.poseidon_log_size, values);
}

/// Clock-update interactions read the workspace copy of the clock main columns,
/// which is byte-identical to the copy Tree 1 transferred to the scheme.
fn generateClock(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    columns: *Columns,
    geometry: Geometry,
    relations: *const Relations,
    claim: *RiscVInteractionClaim,
) !void {
    var views: [clock_update_interaction.N_MAIN_COLUMNS][]const M31 = undefined;
    for (&views, workspace.clock_main) |*view, column| view.* = column;
    var generated = try clock_update_interaction.generate(
        allocator,
        &views,
        geometry.clock_update_log,
        relations,
    );
    claim.clock_claims[geometry.clock_infra_index] = generated.claims;
    const taken = generated.takeColumns();
    for (taken) |values| columns.append(geometry.clock_update_log, values);
}

/// The fixed lookup tables close the registry, so their infrastructure indices
/// are the last `LOOKUP_TABLE_COUNT` slots in declaration order.
fn generateLookupTables(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    columns: *Columns,
    lookup_source: *const source_ingest.Result,
    relations: *const Relations,
    claim: *RiscVInteractionClaim,
) !void {
    if (work_pool.getGlobalPool()) |pool| {
        return generateLookupTablesParallel(
            allocator,
            workspace,
            columns,
            lookup_source,
            relations,
            claim,
            pool,
        );
    }
    const table_infra_start = workspace.statement.n_infra - component_order.LOOKUP_TABLE_COUNT;
    for (component_order.lookupTables(), 0..) |kind, table_index| {
        var generated = try lookup_table_interaction.generate(
            allocator,
            &lookup_source.counters.counters[@intFromEnum(kind)],
            relations,
        );
        claim.lookup_claims[table_infra_start + table_index] = generated.claim;
        const taken = generated.takeColumns();
        for (taken) |values| columns.append(lookup_table_schema.logSize(kind), values);
    }
}

/// Gives each large fixed table the whole bounded pool in turn. The table
/// generator performs a chunk-local scan plus ordered offset fix-up, while
/// columns and claims are still appended in protocol declaration order.
fn generateLookupTablesParallel(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    columns: *Columns,
    lookup_source: *const source_ingest.Result,
    relations: *const Relations,
    claim: *RiscVInteractionClaim,
    pool: *work_pool.WorkPool,
) !void {
    const table_infra_start = workspace.statement.n_infra - component_order.LOOKUP_TABLE_COUNT;
    for (component_order.lookupTables(), 0..) |kind, table_index| {
        var generated = try lookup_table_interaction.generateParallel(
            allocator,
            &lookup_source.counters.counters[@intFromEnum(kind)],
            relations,
            pool,
        );
        claim.lookup_claims[table_infra_start + table_index] = generated.claim;
        const taken = generated.takeColumns();
        for (taken) |values| columns.append(lookup_table_schema.logSize(kind), values);
    }
}

/// The committed column array, filled strictly front to back.
///
/// A prefix counter is enough here (unlike Tree 1, which writes two disjoint
/// regions) because interaction columns are appended in declaration order and
/// never addressed absolutely.
const Columns = struct {
    values: []prover_pcs.ColumnEvaluation,
    filled: usize,
    moved: bool,

    fn init(allocator: std.mem.Allocator, n_interaction: usize) !Columns {
        return .{
            .values = try allocator.alloc(prover_pcs.ColumnEvaluation, n_interaction),
            .filled = 0,
            .moved = false,
        };
    }

    fn append(self: *Columns, log_size: u32, values: []M31) void {
        self.values[self.filled] = .{ .log_size = log_size, .values = values };
        self.filled += 1;
    }

    /// Releases the filled prefix only while this array still owns it: after
    /// `moved` the commitment scheme does.
    fn deinit(self: *Columns, allocator: std.mem.Allocator) void {
        if (self.moved) return;
        for (self.values[0..self.filled]) |column| allocator.free(@constCast(column.values));
        allocator.free(self.values);
    }
};
