//! ProfileV2 base-AIR replay for the recursive Ethereum verifier program.
//!
//! Every physical entry is dispatched from the frozen typed registry. Opcode
//! lookup batches are lowered by the authenticated selected-batch compiler;
//! infrastructure and semantic constraints reuse their production evaluators.

const clock_component = @import("../air/clock_update_component.zig");
const clock_interaction = @import("../air/clock_update_interaction.zig");
const logup = @import("../air/logup.zig");
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const MemoryBoundaryPolicy = @import("../air/component.zig").MemoryBoundaryPolicy;
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const circuit_profile_mod = @import("../prover/ethereum_circuit_profile_v1.zig");
const poseidon2_narrow = @import("../air/memory_commitment/poseidon2_narrow_degree3_v1.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const program_interaction = @import("../air/program/interaction.zig");
const semantic_eval = @import("../air/semantic_eval.zig");
const statement_mod = @import("../air/statement.zig");
const table_interaction = @import("../air/lookups/tables/interaction.zig");
const table_schema = @import("../air/lookups/tables/schema.zig");
const trace = @import("../runner/trace.zig");

const support = @import("ethereum_vm_composition_graph_support_v2.zig");
const circuit = @import("vm_air_composition_circuit.zig");
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
    comptime memory_boundary_policy: MemoryBoundaryPolicy,
    profile: *const profile_mod.ProfileV2,
    manifest: *const lookup_manifest.Manifest,
    compiler: *const lookup_compiler.CompilerV2,
    layout: *const SampleLayout,
    claims: []const Scalar,
    relations: *const circuit.GraphRelations,
    point: anytype,
    composition_randomness: Scalar,
    max_log_degree_bound: u32,
    denominators: *[31]?Scalar,
) !Result {
    return recordWithFixedProgram(memory_boundary_policy, profile, manifest, compiler, layout, null, claims, relations, point, composition_randomness, max_log_degree_bound, denominators);
}

pub fn recordWithFixedProgram(
    comptime memory_boundary_policy: MemoryBoundaryPolicy,
    profile: *const profile_mod.ProfileV2,
    manifest: *const lookup_manifest.Manifest,
    compiler: *const lookup_compiler.CompilerV2,
    layout: *const SampleLayout,
    fixed_program_samples: ?[program_interaction.FIXED_COLUMN_COUNT]Scalar,
    claims: []const Scalar,
    relations: *const circuit.GraphRelations,
    point: anytype,
    composition_randomness: Scalar,
    max_log_degree_bound: u32,
    denominators: *[31]?Scalar,
) !Result {
    try profile.validate();
    if ((profile.circuit_profile.programPolicy() == .fixed_decoded_table_v1) != (fixed_program_samples != null)) return error.InvalidMainTraceShape;
    try manifest.validate();
    try compiler.validateAgainstManifest(manifest);
    if (claims.len != profile.input_profile.claimed_sum_count)
        return error.InvalidClaimCount;

    var result = Result{ .accumulation = Scalar.zero(), .instruction_count = 0 };
    for (profile.entries, 0..) |entry, ordinal| {
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
                relations,
                denominator,
                composition_randomness,
                &result,
            ),
            .infrastructure => |key| try recordInfrastructure(
                memory_boundary_policy,
                profile.circuit_profile,
                fixed_program_samples,
                key.kind,
                entry,
                layout,
                claims,
                relations,
                denominator,
                composition_randomness,
                &result,
            ),
        }
        support.diagnosticCheckpoint("base", ordinal, result.instruction_count, result.accumulation);
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
    comptime memory_boundary_policy: MemoryBoundaryPolicy,
    circuit_profile: circuit_profile_mod.CircuitProfileV1,
    fixed_program_samples: ?[program_interaction.FIXED_COLUMN_COUNT]Scalar,
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
            if (fixed_program_samples) |fixed| {
                const constraints = program_interaction.evaluateFixedGeneric(Scalar, main, fixed, active, is_first, current, previous, component_claims[0..program_interaction.N_SUMS].*, relations);
                appendMany(result, randomness, denominator, &constraints);
            } else {
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
            }
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
            const constraints = memory_boundary_policy.evaluateGeneric(
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
            if (circuit_profile.poseidonLayout() == .narrow_degree3_v1) {
                const main = try sampledMain(poseidon2_narrow.N_MAIN_COLUMNS, layout, entry.main.offset);
                const current = try sampledInteraction(poseidon2_narrow.N_SUMS, layout, entry.interaction.offset, 0);
                const previous = try sampledInteraction(poseidon2_narrow.N_SUMS, layout, entry.interaction.offset, 1);
                const active = try layout.atBase(0, entry.preprocessed.offset + 1, 0);
                const constraints = poseidon2_narrow.evaluateGeneric(Scalar, main, active);
                appendMany(result, randomness, denominator, &constraints);
                const interaction = poseidon2_narrow.interactionConstraintsGeneric(Scalar, main, is_first, current, previous, component_claims[0..poseidon2_narrow.N_SUMS].*, relations);
                appendMany(result, randomness, denominator, &interaction);
            } else {
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
            }
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

test "authenticated VM AIR ProfileV2 schema5 infrastructure recording equals native evaluator order" {
    const std = @import("std");
    const core = @import("stwo_core");
    const QM31 = core.fields.qm31.QM31;
    const allocator = std.testing.allocator;
    var builder = circuit.Builder.init(allocator);
    defer builder.deinit();
    circuit.installBuilder(&builder);
    defer circuit.uninstallBuilder();
    const z = QM31.fromU32Unchecked(41, 5, 8, 2);
    const alpha = QM31.fromU32Unchecked(7, 3, 1, 6);
    const relation_mod = @import("../air/relation_challenges.zig");
    var native_relations: relation_mod.Relations = undefined;
    inline for (std.meta.fields(relation_mod.Relations)) |field|
        @field(native_relations, field.name) = @TypeOf(@field(native_relations, field.name)).init(z, alpha);
    const relations = circuit.GraphRelations.init(.{.{ Scalar.fromSecure(z), Scalar.fromSecure(alpha) }} ** relation_mod.RELATION_COUNT);
    const randomness = QM31.fromU32Unchecked(13, 2, 4, 9);
    const denominator = QM31.fromU32Unchecked(17, 4, 1, 3);
    inline for (.{ statement_mod.InfraKind.program, statement_mod.InfraKind.poseidon2 }) |kind| {
        const main_count = if (kind == .program) program_commitment.N_MAIN_COLUMNS else poseidon2_narrow.N_MAIN_COLUMNS;
        const sum_count = if (kind == .program) program_interaction.N_SUMS else poseidon2_narrow.N_SUMS;
        const constraint_count = if (kind == .program) program_interaction.N_FIXED_CONSTRAINTS else poseidon2_narrow.N_CONSTRAINTS + sum_count;
        const interaction_count = sum_count * 4;
        var pp_columns: [2]@import("vm_composition_base_geometry_v2.zig").ColumnV2 = undefined;
        var main_columns: [main_count]@import("vm_composition_base_geometry_v2.zig").ColumnV2 = undefined;
        var interaction_columns: [interaction_count]@import("vm_composition_base_geometry_v2.zig").ColumnV2 = undefined;
        var base: @import("vm_composition_base_geometry_v2.zig").GeometryV2 = undefined;
        base.columns = .{ &pp_columns, &main_columns, &interaction_columns, &.{} };
        var main_offsets: [main_count + 1]u32 = undefined;
        var interaction_offsets: [interaction_count + 1]u32 = undefined;
        for (&main_offsets, 0..) |*offset, index| offset.* = @intCast(index);
        for (&interaction_offsets, 0..) |*offset, index| offset.* = @intCast(2 * index);
        var values: [2 + main_count + 2 * interaction_count]Scalar = undefined;
        for (&values, 0..) |*value, index| value.* = Scalar.fromSecure(QM31.fromU32Unchecked(@intCast(index + 1), 3, 2, 1));
        var pp_offsets = [_]u32{ 0, 1, 2 };
        var empty_offsets = [_]u32{0};
        const layout: SampleLayout = .{ .allocator = allocator, .base = &base, .extension = null, .values = &values, .tree_offsets = .{ 0, 2, 2 + main_count, values.len, values.len }, .base_offsets = .{ &pp_offsets, &main_offsets, &interaction_offsets, &empty_offsets }, .extension_offsets = .{ &empty_offsets, &empty_offsets, &empty_offsets } };
        const entry: profile_mod.EntryV2 = .{ .physical_index = 0, .shard_ordinal = 0, .active = true, .registry = .{ .infrastructure = .{ .kind = kind, .adapter_kind = if (kind == .program) .trace else .hash } }, .log_size = 1, .n_rows = 1, .preprocessed = .{ .offset = 0, .sampled_columns = 2, .declared_columns = 2 }, .main = .{ .offset = 0, .sampled_columns = main_count, .declared_columns = main_count }, .interaction = .{ .offset = 0, .sampled_columns = interaction_count, .declared_columns = interaction_count }, .constraint_count = constraint_count, .relation_event_count = sum_count, .interaction_batch_count = sum_count, .claimed_sum_offset = 0, .claimed_sum_count = sum_count, .max_constraint_log_degree_bound = 2, .composition_log_split = 1 };
        var claims: [sum_count]Scalar = undefined;
        var native_claims: [sum_count]QM31 = undefined;
        for (&claims, &native_claims, 0..) |*claim, *native, index| {
            native.* = QM31.fromU32Unchecked(@intCast(71 + index), 2, 1, 4);
            claim.* = Scalar.fromSecure(native.*);
        }
        const fixed: [program_interaction.FIXED_COLUMN_COUNT]Scalar = .{Scalar.fromSecure(z)} ** program_interaction.FIXED_COLUMN_COUNT;
        var result: Result = .{ .accumulation = Scalar.zero(), .instruction_count = 0 };
        try recordInfrastructure(.full_state_split_multiplicity_v3, .fixed_program_narrow_v1, fixed, kind, entry, &layout, &claims, &relations, Scalar.fromSecure(denominator), Scalar.fromSecure(randomness), &result);
        var main: [main_count]QM31 = undefined;
        for (&main, values[2..][0..main_count]) |*native, value| native.* = value.handle.constant;
        const current = try sampledInteraction(sum_count, &layout, 0, 0);
        const previous = try sampledInteraction(sum_count, &layout, 0, 1);
        var native_current: [sum_count]QM31 = undefined;
        var native_previous: [sum_count]QM31 = undefined;
        for (&native_current, &native_previous, current, previous) |*a, *b, x, y| {
            a.* = x.handle.constant;
            b.* = y.handle.constant;
        }
        const first = values[0].handle.constant;
        const active = values[1].handle.constant;
        var expected: [constraint_count]QM31 = undefined;
        if (kind == .program) {
            expected = program_interaction.evaluateFixedGeneric(QM31, main, .{z} ** program_interaction.FIXED_COLUMN_COUNT, active, first, native_current, native_previous, native_claims, &native_relations);
        } else {
            expected[0..poseidon2_narrow.N_CONSTRAINTS].* = poseidon2_narrow.evaluateGeneric(QM31, main, active);
            expected[poseidon2_narrow.N_CONSTRAINTS..].* = poseidon2_narrow.interactionConstraintsGeneric(QM31, main, first, native_current, native_previous, native_claims, &native_relations);
        }
        var accumulation = QM31.zero();
        for (expected) |constraint| accumulation = accumulation.mul(randomness).add(constraint.mul(denominator));
        try std.testing.expectEqual(constraint_count, result.instruction_count);
        try std.testing.expect(accumulation.eql(result.accumulation.handle.constant));
    }
    try builder.check();
}
