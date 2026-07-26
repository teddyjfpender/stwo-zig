//! Prover component assembly and final proof construction.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const prover_component = @import("stwo_prover_impl").air.component_prover;
const stage_profile = @import("stwo_prover_impl").stage_profile;
const component_order = @import("../air/component_order.zig");
const clock_update_component = @import("../air/clock_update_component.zig");
const clock_update_interaction = @import("../air/clock_update_interaction.zig");
const hash_component = @import("../air/memory_commitment/hash_component.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const opcode_component = @import("../air/lookups/opcode_component.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const lookup_table_component = @import("../air/lookups/tables/component.zig");
const lookup_table_interaction = @import("../air/lookups/tables/interaction.zig");
const lookup_table_schema = @import("../air/lookups/tables/schema.zig");
const program_interaction = @import("../air/program/interaction.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const riscv_component = @import("../air/component.zig");
const semantic_component = @import("../air/semantic_component.zig");
const statement_mod = @import("../air/statement.zig");
const types = @import("types.zig");

const M31 = m31.M31;

pub fn prove(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    recorder: ?*stage_profile.Recorder,
    scheme: Engine.Scheme,
    channel: *Engine.Channel,
    statement: types.RiscVStatement,
    relations: *const relation_challenges.Relations,
    interaction_claim: *const types.RiscVInteractionClaim,
    opcode_results: []const opcode_interaction.Result,
    table_results: []const lookup_table_interaction.Result,
    clock_result: *const clock_update_interaction.InteractionTrace,
    program_prev: program_interaction.Previous,
    merkle_prev: merkle_node.Previous,
    poseidon_prev: poseidon2_air.Previous,
    memory_prev: []const memory_interaction.Previous,
    n_main: usize,
    n_interaction: usize,
) !types.Proof {
    const semantic_storage = try allocator.alloc(
        semantic_component.SemanticComponent,
        statement.n_components,
    );
    defer allocator.free(semantic_storage);
    const opcode_lookup_storage = try allocator.alloc(
        opcode_component.OpcodeLookupComponent,
        statement.n_components,
    );
    defer allocator.free(opcode_lookup_storage);
    const infra_storage = try allocator.alloc(
        riscv_component.RiscVTraceComponent,
        statement.n_infra,
    );
    defer allocator.free(infra_storage);
    var hash_storage: [2]hash_component.HashComponent = undefined;
    var n_hash_components: usize = 0;
    var clock_storage: clock_update_component.ClockUpdateComponent = undefined;
    var table_storage: [component_order.LOOKUP_TABLE_COUNT]lookup_table_component.LookupTableComponent = undefined;
    const components = try allocator.alloc(
        prover_component.ComponentProver,
        2 * statement.n_components + statement.n_infra,
    );
    defer allocator.free(components);
    var n_components: usize = 0;

    var main_offset: usize = 0;
    var interaction_offset: usize = 0;
    for (0..statement.n_components) |i| {
        const desc = statement.component_descs[i];
        semantic_storage[i] = try semantic_component.SemanticComponent.init(
            desc.family,
            desc.log_size,
            2 * i + 1,
            main_offset,
        );
        components[n_components] = semantic_storage[i].asProverComponent();
        n_components += 1;
        opcode_lookup_storage[i] = try opcode_component.OpcodeLookupComponent.initProver(
            desc.family,
            desc.log_size,
            2 * i,
            main_offset,
            interaction_offset,
            relations,
            try interaction_claim.opcodeClaims(desc.family, i),
            constOpcodePrev(opcode_results[i].previous),
        );
        components[n_components] = opcode_lookup_storage[i].asProverComponent();
        n_components += 1;
        main_offset += desc.n_columns;
        interaction_offset += opcode_interaction.nColumns(desc.family);
    }

    for (0..statement.n_infra) |i| {
        const desc = statement.infra_descs[i];
        const preprocessed_base = statement.preprocessedOffsetForInfra(i);
        if (desc.kind == .poseidon2 or desc.kind == .merkle) {
            hash_storage[n_hash_components] = .{
                .kind = if (desc.kind == .poseidon2) .poseidon2 else .merkle,
                .log_size = desc.log_size,
                .n_rows = desc.n_rows,
                .is_first_col_idx = preprocessed_base,
                .is_active_col_idx = preprocessed_base + 1,
                .main_col_offset = main_offset,
                .interaction_col_offset = interaction_offset,
                .relations = relations,
                .merkle_claims = interaction_claim.merkle_claims[i],
                .poseidon_claims = interaction_claim.poseidon_claims[i],
                .s_merkle_prev = constMerklePrev(merkle_prev),
                .s_poseidon_prev = constPoseidonPrev(poseidon_prev),
            };
            components[n_components] = hash_storage[n_hash_components].asProverComponent();
            n_components += 1;
            n_hash_components += 1;
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
            table_storage[table_index] = try lookup_table_component.LookupTableComponent.initProver(
                table_kind,
                preprocessed_base,
                tuple_indices[0..lookup_table_schema.arity(table_kind)],
                main_offset,
                interaction_offset,
                relations,
                interaction_claim.lookup_claims[i],
                constPrev(table_results[table_index].previous),
            );
            components[n_components] = table_storage[table_index].asProverComponent();
            n_components += 1;
            main_offset += desc.n_columns;
            interaction_offset += lookup_table_interaction.N_COLUMNS;
            continue;
        }
        if (desc.kind == .clock_update) {
            clock_storage = try clock_update_component.ClockUpdateComponent.initProver(
                desc.log_size,
                preprocessed_base,
                preprocessed_base + 1,
                main_offset,
                interaction_offset,
                relations,
                interaction_claim.clock_claims[i],
                constPrev(clock_result.previous),
            );
            components[n_components] = clock_storage.asProverComponent();
            n_components += 1;
            main_offset += desc.n_columns;
            interaction_offset += clock_update_interaction.N_INTERACTION_COLUMNS;
            continue;
        }
        const kind: riscv_component.Kind = switch (desc.kind) {
            .program => .program,
            .memory => .memory,
            else => return types.ProverError.InvalidStatement,
        };
        infra_storage[i] = .{
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
            .relations = relations,
            .interaction_col_offset = interaction_offset,
            .program_claims = interaction_claim.program_claims[i],
            .s_program_prev = constProgramPrev(program_prev),
            .memory_claims = interaction_claim.memory_claims[i],
            .s_memory_prev = constMemoryPrev(memory_prev[i]),
        };
        components[n_components] = infra_storage[i].asProverComponent();
        n_components += 1;
        main_offset += desc.n_columns;
        interaction_offset += statement_mod.nInteractionColsForInfra(desc.kind);
    }
    std.debug.assert(main_offset == n_main);
    std.debug.assert(interaction_offset == n_interaction);

    var extended = try Engine.prove(
        allocator,
        components[0..n_components],
        channel,
        scheme,
        .{ .recorder = recorder },
    );
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    return proof;
}

fn constPrev(bufs: [4][]M31) [4][]const M31 {
    return .{ bufs[0], bufs[1], bufs[2], bufs[3] };
}

fn constOpcodePrev(
    bufs: [opcode_interaction.MAX_BATCHES][4][]M31,
) [opcode_interaction.MAX_BATCHES][4][]const M31 {
    var result: [opcode_interaction.MAX_BATCHES][4][]const M31 = undefined;
    for (&result, bufs) |*dst, src| dst.* = constPrev(src);
    return result;
}

fn constMemoryPrev(bufs: memory_interaction.Previous) [memory_interaction.N_SUMS][4][]const M31 {
    var result: [memory_interaction.N_SUMS][4][]const M31 = undefined;
    for (&result, bufs) |*dst, src| dst.* = constPrev(src);
    return result;
}

fn constProgramPrev(bufs: program_interaction.Previous) [program_interaction.N_SUMS][4][]const M31 {
    var result: [program_interaction.N_SUMS][4][]const M31 = undefined;
    for (&result, bufs) |*dst, src| dst.* = constPrev(src);
    return result;
}

fn constMerklePrev(bufs: merkle_node.Previous) [merkle_node.N_SUMS][4][]const M31 {
    var result: [merkle_node.N_SUMS][4][]const M31 = undefined;
    for (&result, bufs) |*dst, src| dst.* = constPrev(src);
    return result;
}

fn constPoseidonPrev(bufs: poseidon2_air.Previous) [poseidon2_air.N_SUMS][4][]const M31 {
    var result: [poseidon2_air.N_SUMS][4][]const M31 = undefined;
    for (&result, bufs) |*dst, src| dst.* = constPrev(src);
    return result;
}
