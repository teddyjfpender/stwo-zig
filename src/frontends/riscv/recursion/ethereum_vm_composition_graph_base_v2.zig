//! ProfileV2 base-AIR replay for the recursive Ethereum verifier program.
//!
//! Every physical entry is dispatched from the frozen typed registry. Opcode
//! lookup batches are lowered by the authenticated selected-batch compiler;
//! infrastructure and semantic constraints reuse their production evaluators.

const clock_component = @import("../air/clock_update_component.zig");
const clock_interaction = @import("../air/clock_update_interaction.zig");
const logup = @import("../air/logup.zig");
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const program_interaction = @import("../air/program/interaction.zig");
const semantic_eval = @import("../air/semantic_eval.zig");
const statement_mod = @import("../air/statement.zig");
const table_interaction = @import("../air/lookups/tables/interaction.zig");
const table_schema = @import("../air/lookups/tables/schema.zig");
const trace = @import("../runner/trace.zig");

const support = @import("ethereum_vm_composition_graph_support_v2.zig");
const relations_mod = @import("ethereum_composition_relations_v2.zig");
const lookup_manifest = @import("../air/lang/lookup_physical_manifest_v2.zig");
const lookup_compiler = @import("vm_selected_lookup_compiler_v2.zig");
const profile_mod = @import("vm_air_profile_v2.zig");

const Scalar = support.Scalar;
const SampleLayout = support.SampleLayoutV2;

pub const Result = struct {
    accumulation: Scalar,
    instruction_count: u32,
};

pub fn record(
    profile: *const profile_mod.ProfileV2,
    manifest: *const lookup_manifest.Manifest,
    compiler: *const lookup_compiler.CompilerV2,
    layout: *const SampleLayout,
    claims: []const Scalar,
    relations: *const relations_mod.RelationsV2,
    point: anytype,
    composition_randomness: Scalar,
    max_log_degree_bound: u32,
    denominators: *[31]?Scalar,
) !Result {
    try profile.validate();
    try manifest.validate();
    try compiler.validateAgainstManifest(manifest);
    if (claims.len != profile.input_profile.claimed_sum_count)
        return error.InvalidClaimCount;

    var result = Result{ .accumulation = Scalar.zero(), .instruction_count = 0 };
    for (profile.entries) |entry| {
        const denominator = support.quotientDenominator(
            entry.log_size,
            max_log_degree_bound,
            point,
            denominators,
        );
        switch (entry.registry) {
            .opcode_semantic => |key| try recordSemantic(
                key.descriptor,
                entry,
                layout,
                denominator,
                composition_randomness,
                &result,
            ),
            .opcode_lookup => |key| try recordLookup(
                key.family,
                entry,
                manifest,
                compiler,
                layout,
                claims,
                &relations.base,
                denominator,
                composition_randomness,
                &result,
            ),
            .infrastructure => |key| try recordInfrastructure(
                key.kind,
                entry,
                layout,
                claims,
                &relations.base,
                denominator,
                composition_randomness,
                &result,
            ),
        }
        try currentBuilder().check();
    }
    if (result.instruction_count != profile.air_instruction_count)
        return error.InvalidInstructionCount;
    return result;
}

fn recordSemantic(
    descriptor: statement_mod.FamilyComponentDesc,
    entry: profile_mod.EntryV2,
    layout: *const SampleLayout,
    denominator: Scalar,
    randomness: Scalar,
    result: *Result,
) !void {
    const n_main = semantic_eval.mainColumnCount(descriptor.family);
    if (n_main > entry.main.sampled_columns)
        return error.InvalidMainTraceShape;
    var main: [trace.MAX_FAMILY_COLUMNS]Scalar = undefined;
    for (main[0..n_main], 0..) |*value, column| value.* = try layout.atBase(
        1,
        entry.main.offset + column,
        0,
    );
    const active = try layout.atBase(0, entry.preprocessed.offset, 0);
    const direct = try semantic_eval.Eval(Scalar).evaluate(
        descriptor.family,
        main[0..n_main],
        active,
    );
    if (direct.len != entry.constraint_count)
        return error.InvalidInstructionCount;
    for (direct.values[0..direct.len]) |constraint|
        append(result, randomness, denominator, constraint);
}

fn recordLookup(
    family: trace.OpcodeFamily,
    entry: profile_mod.EntryV2,
    manifest: *const lookup_manifest.Manifest,
    compiler: *const lookup_compiler.CompilerV2,
    layout: *const SampleLayout,
    claims: []const Scalar,
    relations: anytype,
    denominator: Scalar,
    randomness: Scalar,
    result: *Result,
) !void {
    const n_main = trace.nColumnsForFamily(family);
    if (n_main > entry.main.sampled_columns or
        @as(usize, entry.claimed_sum_offset) + entry.claimed_sum_count >
            claims.len)
    {
        return error.InvalidInteractionShape;
    }
    var main: [trace.MAX_FAMILY_COLUMNS]Scalar = undefined;
    for (main[0..n_main], 0..) |*value, column| value.* = try layout.atBase(
        1,
        entry.main.offset + column,
        0,
    );
    var entries = try lookup_compiler.buildTypedEntries(
        Scalar,
        family,
        main[0..n_main],
    );
    if (entry.interaction_batch_count != entry.claimed_sum_count)
        return error.InvalidInteractionShape;
    const is_first = try layout.atBase(0, entry.preprocessed.offset, 0);
    for (0..entry.interaction_batch_count) |batch| {
        const current = try layout.sampledBaseSecure(
            entry.interaction.offset + 4 * batch,
            0,
        );
        const previous = try layout.sampledBaseSecure(
            entry.interaction.offset + 4 * batch,
            1,
        );
        const pair = try lookup_compiler.rowPairForProfileEntry(
            Scalar,
            compiler,
            entry,
            manifest,
            &entries,
            batch,
            relations,
        );
        const constraint = logup.pairConstraintGeneric(
            Scalar,
            current,
            previous,
            is_first,
            claims[@as(usize, entry.claimed_sum_offset) + batch],
            pair,
        );
        append(result, randomness, denominator, constraint);
    }
}

fn recordInfrastructure(
    kind: statement_mod.InfraKind,
    entry: profile_mod.EntryV2,
    layout: *const SampleLayout,
    claims: []const Scalar,
    relations: anytype,
    denominator: Scalar,
    randomness: Scalar,
    result: *Result,
) !void {
    if (@as(usize, entry.claimed_sum_offset) + entry.claimed_sum_count >
        claims.len)
        return error.InvalidInteractionShape;
    const before = result.instruction_count;
    const is_first = try layout.atBase(0, entry.preprocessed.offset, 0);
    const claim_offset: usize = entry.claimed_sum_offset;
    const claim_count: usize = entry.claimed_sum_count;
    const component_claims = claims[claim_offset..][0..claim_count];
    switch (kind) {
        .program => {
            const main = try sampledMain(
                program_commitment.N_MAIN_COLUMNS,
                layout,
                entry.main.offset,
            );
            const current = try sampledInteraction(
                program_interaction.N_SUMS,
                layout,
                entry.interaction.offset,
                0,
            );
            const previous = try sampledInteraction(
                program_interaction.N_SUMS,
                layout,
                entry.interaction.offset,
                1,
            );
            const active = try layout.atBase(0, entry.preprocessed.offset + 1, 0);
            const constraints = program_interaction.evaluateGeneric(
                Scalar,
                main,
                active,
                is_first,
                current,
                previous,
                component_claims[0..program_interaction.N_SUMS].*,
                relations,
            );
            appendMany(result, randomness, denominator, &constraints);
        },
        .memory => {
            const main = try sampledMain(8, layout, entry.main.offset);
            const current = try sampledInteraction(
                memory_interaction.N_SUMS,
                layout,
                entry.interaction.offset,
                0,
            );
            const previous = try sampledInteraction(
                memory_interaction.N_SUMS,
                layout,
                entry.interaction.offset,
                1,
            );
            const active = try layout.atBase(0, entry.preprocessed.offset + 1, 0);
            const constraints = memory_interaction.evaluateGeneric(
                Scalar,
                main,
                active,
                is_first,
                current,
                previous,
                component_claims[0..memory_interaction.N_SUMS].*,
                relations,
            );
            appendMany(result, randomness, denominator, &constraints);
        },
        .clock_update => {
            const main = try sampledMain(
                clock_interaction.N_MAIN_COLUMNS,
                layout,
                entry.main.offset,
            );
            const current = try sampledInteraction(
                clock_interaction.N_SUMS,
                layout,
                entry.interaction.offset,
                0,
            );
            const previous = try sampledInteraction(
                clock_interaction.N_SUMS,
                layout,
                entry.interaction.offset,
                1,
            );
            const active = try layout.atBase(0, entry.preprocessed.offset + 1, 0);
            const constraints = try clock_component.evaluateGeneric(
                Scalar,
                &main,
                current,
                previous,
                is_first,
                active,
                component_claims[0..clock_interaction.N_SUMS].*,
                relations,
            );
            appendMany(result, randomness, denominator, &constraints);
        },
        .merkle => {
            const main = try sampledMain(
                merkle_node.N_MAIN_COLUMNS,
                layout,
                entry.main.offset,
            );
            const current = try sampledInteraction(
                merkle_node.N_SUMS,
                layout,
                entry.interaction.offset,
                0,
            );
            const previous = try sampledInteraction(
                merkle_node.N_SUMS,
                layout,
                entry.interaction.offset,
                1,
            );
            const active = try layout.atBase(0, entry.preprocessed.offset + 1, 0);
            const constraints = merkle_node.evaluateGeneric(
                Scalar,
                main,
                active,
                is_first,
                current,
                previous,
                component_claims[0..merkle_node.N_SUMS].*,
                relations,
            );
            appendMany(result, randomness, denominator, &constraints);
        },
        .poseidon2 => {
            const main = try sampledMain(
                poseidon2_air.N_MAIN_COLUMNS,
                layout,
                entry.main.offset,
            );
            const current = try sampledInteraction(
                poseidon2_air.N_SUMS,
                layout,
                entry.interaction.offset,
                0,
            );
            const previous = try sampledInteraction(
                poseidon2_air.N_SUMS,
                layout,
                entry.interaction.offset,
                1,
            );
            const active = try layout.atBase(0, entry.preprocessed.offset + 1, 0);
            const air_constraints = poseidon2_air.evaluateGeneric(Scalar, main);
            appendMany(result, randomness, denominator, &air_constraints);
            const shell = [_]Scalar{
                main[0].sub(active),
                main[poseidon2_air.WIDE_COLUMN],
                main[poseidon2_air.IO_COLUMN],
            };
            appendMany(result, randomness, denominator, &shell);
            const interaction_constraints = poseidon2_air.interactionConstraintsGeneric(
                Scalar,
                main,
                is_first,
                current,
                previous,
                component_claims[0..poseidon2_air.N_SUMS].*,
                relations,
            );
            appendMany(result, randomness, denominator, &interaction_constraints);
        },
        .bitwise,
        .range_check_20,
        .range_check_8_11,
        .range_check_8_8_4,
        .range_check_8_8,
        .range_check_m31,
        => {
            const table_kind = statement_mod.tableKind(kind) orelse unreachable;
            var tuple: [table_schema.MAX_ARITY]Scalar = undefined;
            for (tuple[0..table_schema.arity(table_kind)], 0..) |*value, index| {
                value.* = try layout.atBase(
                    0,
                    entry.preprocessed.offset + 1 + index,
                    0,
                );
            }
            const multiplicity = try layout.atBase(1, entry.main.offset, 0);
            const current = try layout.sampledBaseSecure(entry.interaction.offset, 0);
            const previous = try layout.sampledBaseSecure(entry.interaction.offset, 1);
            const constraint = try table_interaction.evaluateGeneric(
                Scalar,
                table_kind,
                tuple[0..table_schema.arity(table_kind)],
                multiplicity,
                current,
                previous,
                is_first,
                component_claims[0],
                relations,
            );
            append(result, randomness, denominator, constraint);
        },
    }
    if (result.instruction_count - before != entry.constraint_count)
        return error.InvalidInstructionCount;
}

fn sampledMain(
    comptime count: usize,
    layout: *const SampleLayout,
    offset: usize,
) ![count]Scalar {
    var result: [count]Scalar = undefined;
    for (&result, 0..) |*value, column| value.* = try layout.atBase(
        1,
        offset + column,
        0,
    );
    return result;
}

fn sampledInteraction(
    comptime count: usize,
    layout: *const SampleLayout,
    offset: usize,
    sample: usize,
) ![count]Scalar {
    var result: [count]Scalar = undefined;
    for (&result, 0..) |*value, index| value.* = try layout.sampledBaseSecure(
        offset + 4 * index,
        sample,
    );
    return result;
}

fn append(
    result: *Result,
    randomness: Scalar,
    denominator: Scalar,
    constraint: Scalar,
) void {
    support.accumulate(&result.accumulation, randomness, constraint, denominator);
    result.instruction_count += 1;
}

fn appendMany(
    result: *Result,
    randomness: Scalar,
    denominator: Scalar,
    constraints: []const Scalar,
) void {
    for (constraints) |constraint|
        append(result, randomness, denominator, constraint);
}

fn currentBuilder() *support.Builder {
    return @import("vm_air_composition_circuit_circuit.zig").currentBuilder();
}
