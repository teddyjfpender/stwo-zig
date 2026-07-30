//! RISC-V proof transcript reconstruction and verification.
//!
//! Verifier component values and the canonical interaction claim live in a
//! heap `VerificationWorkspace`: `core_verifier.verify` borrows a
//! `[]const Component` of fat pointers into the component values, and the
//! canonical claim carries a fixed-capacity log-size table that must not sit in
//! a stack frame. The workspace is one allocation per verification, released by
//! `defer`. See `proof_workspace.zig`.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const prover_engine = @import("stwo_prover_engine").engine;
const component_order = @import("../air/component_order.zig");
const clock_update_component = @import("../air/clock_update_component.zig");
const clock_update_interaction = @import("../air/clock_update_interaction.zig");
const diagnostic_hints = @import("../air/diagnostic_hints.zig");
const opcode_component = @import("../air/lookups/opcode_component.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const lookup_table_component = @import("../air/lookups/tables/component.zig");
const lookup_table_interaction = @import("../air/lookups/tables/interaction.zig");
const lookup_table_schema = @import("../air/lookups/tables/schema.zig");
const logup = @import("../air/logup.zig");
const public_logup = @import("../air/public_logup.zig");
const riscv_component = @import("../air/component.zig");
const semantic_component = @import("../air/semantic_component.zig");
const statement_mod = @import("../air/statement.zig");
const proof_transcript = @import("../proof_transcript.zig");
const preprocessed_trace = @import("preprocessed.zig");
const proof_workspace = @import("proof_workspace.zig");
const statement_validation = @import("statement_validation.zig");
const types = @import("types.zig");

const VerificationWorkspace = proof_workspace.VerificationWorkspace;

/// Verify a RISC-V STARK proof with per-opcode-family components.
/// Consumes `proof_in` on both success and failure.
pub fn verifyRiscVWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: types.RiscVStatement,
    proof_in: types.Proof,
    claim: *const types.RiscVInteractionClaim,
) !void {
    var channel = Engine.Channel{};
    return verifyRiscVWithEngineUsingChannel(
        Engine,
        allocator,
        pcs_config,
        statement,
        proof_in,
        claim,
        &channel,
    );
}

/// Verifies through the production path using a caller-owned transcript channel.
/// The default entrypoint above remains monomorphic and has no tracing branch.
pub fn verifyRiscVWithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: types.RiscVStatement,
    proof_in: types.Proof,
    claim: *const types.RiscVInteractionClaim,
    channel: *Engine.Channel,
) !void {
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);

    try statement_validation.validate(statement, .proof);
    if (claim.n_components != statement.n_components or claim.n_infra != statement.n_infra) {
        return types.ProverError.InvalidInteractionClaim;
    }
    if (proof.commitment_scheme_proof.commitments.items.len != 4) {
        return core_verifier.VerificationError.InvalidStructure;
    }
    try statement_validation.verifyPreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        statement,
        proof.commitment_scheme_proof.commitments.items[0],
    );

    pcs_config.mixInto(channel);
    statement.public_data.mixInto(channel);

    var commitment_scheme = try pcs_verifier.CommitmentSchemeVerifier(
        types.Hasher,
        Engine.MerkleChannel,
    ).init(allocator, pcs_config);
    defer commitment_scheme.deinit(allocator);

    // Tree 0: selector pairs plus exact lookup-table tuple columns.
    const preproc_log_sizes = try preprocessed_trace.logSizes(allocator, statement);
    defer allocator.free(preproc_log_sizes);
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        preproc_log_sizes,
        channel,
    );

    // Tree 1: opcode and infrastructure main columns.
    const n_main = statement.nMainColumns();
    const main_log_sizes = try allocator.alloc(u32, n_main);
    defer allocator.free(main_log_sizes);
    var col_offset: usize = 0;
    for (0..statement.n_components) |i| {
        const desc = statement.component_descs[i];
        for (0..desc.n_columns) |c| main_log_sizes[col_offset + c] = desc.log_size;
        col_offset += desc.n_columns;
    }
    for (0..statement.n_infra) |i| {
        const desc = statement.infra_descs[i];
        for (0..desc.n_columns) |c| main_log_sizes[col_offset + c] = desc.log_size;
        col_offset += desc.n_columns;
    }
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        main_log_sizes,
        channel,
    );

    const relations = try proof_transcript.verifyToRelations(
        allocator,
        channel,
        &statement,
        claim.interaction_pow,
    );

    const n_interaction = statement.nInteractionColumns();
    const interaction_log_sizes = try allocator.alloc(u32, n_interaction);
    defer allocator.free(interaction_log_sizes);
    var inter_col_offset: usize = 0;
    for (0..statement.n_components) |i| {
        const n_cols = opcode_interaction.nColumns(statement.component_descs[i].family);
        for (0..n_cols) |c| {
            interaction_log_sizes[inter_col_offset + c] = statement.component_descs[i].log_size;
        }
        inter_col_offset += n_cols;
    }
    for (0..statement.n_infra) |i| {
        const n_cols = statement_mod.nInteractionColsForInfra(statement.infra_descs[i].kind);
        for (0..n_cols) |c| {
            interaction_log_sizes[inter_col_offset + c] = statement.infra_descs[i].log_size;
        }
        inter_col_offset += n_cols;
    }
    std.debug.assert(inter_col_offset == n_interaction);
    try proof_transcript.mixInteractionClaim(channel, &statement, claim);
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        interaction_log_sizes,
        channel,
    );

    const workspace = try VerificationWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    const components = &workspace.components;

    try workspace.canonicalize(claim, &statement);
    const canonical_view = workspace.canonical.view();
    const component_total = canonical_view.total();
    const public_boundary = try public_logup.sum(&statement.public_data, &relations);
    logup.verifyGlobalCancellation(&.{component_total}, public_boundary) catch |err| {
        // `LogupSumNonZero` names the symptom and stops. Which relation is
        // unbalanced is not derivable here -- a component's claimed sum is a
        // single field element over every relation that component touches --
        // but it *is* derivable by `riscv-trace-dump --relation-sums`, which
        // ships next to this binary. Say so at the point of failure rather than
        // leaving the reader to rediscover the tooling.
        diagnostic_hints.reportLogupImbalance(
            component_total.add(public_boundary),
            statement.public_data.declaresPublicIo(),
        );
        return err;
    };

    var main_offset: usize = 0;
    var interaction_offset: usize = 0;
    for (0..statement.n_components) |i| {
        const desc = statement.component_descs[i];
        components.semantic[i] = try semantic_component.SemanticComponent.init(
            desc.family,
            desc.log_size,
            2 * i + 1,
            main_offset,
        );
        components.push(components.semantic[i].asVerifierComponent());
        components.opcode_lookup[i] = try opcode_component.OpcodeLookupComponent.initVerifier(
            desc.family,
            desc.log_size,
            2 * i,
            main_offset,
            interaction_offset,
            &relations,
            try claim.opcodeClaims(desc.family, i),
        );
        components.push(components.opcode_lookup[i].asVerifierComponent());
        main_offset += desc.n_columns;
        interaction_offset += opcode_interaction.nColumns(desc.family);
    }
    for (0..statement.n_infra) |i| {
        const desc = statement.infra_descs[i];
        const preprocessed_base = statement.preprocessedOffsetForInfra(i);
        if (desc.kind == .poseidon2 or desc.kind == .merkle) {
            const hash = components.nextHash();
            hash.* = .{
                .kind = if (desc.kind == .poseidon2) .poseidon2 else .merkle,
                .log_size = desc.log_size,
                .n_rows = desc.n_rows,
                .is_first_col_idx = preprocessed_base,
                .is_active_col_idx = preprocessed_base + 1,
                .main_col_offset = main_offset,
                .interaction_col_offset = interaction_offset,
                .relations = &relations,
                .merkle_claims = claim.merkle_claims[i],
                .poseidon_claims = claim.poseidon_claims[i],
            };
            components.push(hash.asVerifierComponent());
            main_offset += desc.n_columns;
            interaction_offset += statement_mod.nInteractionColsForInfra(desc.kind);
            continue;
        }
        if (statement_mod.tableKind(desc.kind)) |table_kind| {
            const table_index = component_order.lookupTableIndex(table_kind);
            var tuple_indices: [lookup_table_schema.MAX_ARITY]usize = undefined;
            for (tuple_indices[0..lookup_table_schema.arity(table_kind)], 0..) |*index, offset| {
                index.* = preprocessed_base + 1 + offset;
            }
            components.table[table_index] = try lookup_table_component.LookupTableComponent.initVerifier(
                table_kind,
                preprocessed_base,
                tuple_indices[0..lookup_table_schema.arity(table_kind)],
                main_offset,
                interaction_offset,
                &relations,
                claim.lookup_claims[i],
            );
            components.push(components.table[table_index].asVerifierComponent());
            main_offset += desc.n_columns;
            interaction_offset += lookup_table_interaction.N_COLUMNS;
            continue;
        }
        if (desc.kind == .clock_update) {
            components.clock = clock_update_component.ClockUpdateComponent.initVerifier(
                desc.log_size,
                preprocessed_base,
                preprocessed_base + 1,
                main_offset,
                interaction_offset,
                &relations,
                claim.clock_claims[i],
            );
            components.push(components.clock.asVerifierComponent());
            main_offset += desc.n_columns;
            interaction_offset += clock_update_interaction.N_INTERACTION_COLUMNS;
            continue;
        }
        const kind: riscv_component.Kind = switch (desc.kind) {
            .program => .program,
            .memory => .memory,
            else => return types.ProverError.InvalidStatement,
        };
        components.infra[i] = .{
            .desc = .{
                .family = .base_alu_reg,
                .log_size = desc.log_size,
                .n_rows = desc.n_rows,
                .n_columns = desc.n_columns,
            },
            .initial_pc = statement.initial_pc,
            .total_steps = statement.total_steps,
            .is_first_col_idx = preprocessed_base,
            .is_active_col_idx = preprocessed_base + 1,
            .main_col_offset = main_offset,
            .kind = kind,
            .relations = &relations,
            .interaction_col_offset = interaction_offset,
            .program_claims = claim.program_claims[i],
            .memory_claims = claim.memory_claims[i],
        };
        components.push(components.infra[i].asVerifierComponent());
        main_offset += desc.n_columns;
        interaction_offset += statement_mod.nInteractionColsForInfra(desc.kind);
    }
    std.debug.assert(main_offset == n_main);
    std.debug.assert(interaction_offset == n_interaction);

    proof_moved = true;
    try core_verifier.verify(
        types.Hasher,
        Engine.MerkleChannel,
        allocator,
        components.active(),
        channel,
        &commitment_scheme,
        proof,
    );
}
