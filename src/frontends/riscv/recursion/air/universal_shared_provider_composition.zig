//! Exact symbolic composition replay for universal shared-provider rows 34/35.
//!
//! These providers predate the typed `direct_constraint_program` shell used by
//! rows 0--33, so they cannot enter recursion through an opaque list of roots.
//! Instead this module invokes their existing generic AIR evaluators over the
//! composition recorder's symbolic scalar.  Constraint order is therefore the
//! native verifier order:
//!
//! * Poseidon2: 430 generated permutation/flag roots, then its two independent
//!   pairs-batched LogUp roots;
//! * range-check-(8,8): its one native singleton LogUp root.
//!
//! Poseidon2's two boundary claims are deliberately explicit.  The universal
//! roster carries only their total, so callers must make both auxiliary claims
//! verifier inputs and constrain `partial[0] + partial[1] == roster_total`.
//! Embedding proof-specific claim values as graph constants is forbidden.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const poseidon_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const table_interaction = @import("../../air/lookups/tables/interaction.zig");
const table_schema = @import("../../air/lookups/tables/schema.zig");
const recorder = @import("composition_graph_recorder.zig");

pub const POSEIDON_AUXILIARY_CLAIM_COUNT: usize = poseidon_air.N_SUMS;
pub const POSEIDON_CONSTRAINT_COUNT: usize =
    poseidon_air.N_CONSTRAINTS + poseidon_air.N_SUMS;
pub const RANGE_CHECK_8_8_CONSTRAINT_COUNT: usize = 1;

comptime {
    if (POSEIDON_AUXILIARY_CLAIM_COUNT != 2 or
        POSEIDON_CONSTRAINT_COUNT != 432 or
        table_schema.arity(.range_check_8_8) != 2)
    {
        @compileError("shared-provider composition geometry drifted");
    }
}

pub const Error = recorder.Error || error{
    InvalidProviderChallengeGeometry,
    InvalidRelationArity,
    InvalidTraceShape,
};

fn Element(comptime arity: usize) type {
    return struct {
        z: recorder.Scalar,
        alpha_powers: [arity]recorder.Scalar,

        fn init(source: *const recorder.ChallengeSet.Element) Error!@This() {
            if (source.arity < arity)
                return error.InvalidProviderChallengeGeometry;
            return .{
                .z = source.z,
                .alpha_powers = source.alpha_powers[0..arity].*,
            };
        }

        pub fn combine(
            self: *const @This(),
            values: [arity]recorder.Scalar,
        ) recorder.Scalar {
            var result = recorder.Scalar.zero();
            for (values, self.alpha_powers) |value, power|
                result = result.add(power.mul(value));
            return result.sub(self.z);
        }
    };
}

/// Symbolic view of the twelve shipped VM relations.  `poseidon2_air` reaches
/// this through the same generic lookup-entry switch as the native verifier.
/// The universal Merkle draw has arity 18 while the legacy VM entry has arity
/// 4; row 34 never emits a Merkle entry, so retaining the authenticated
/// universal element here is safe and avoids inventing a dummy challenge.
pub const SymbolicRelations = struct {
    registers_state: Element(2),
    memory_access: Element(7),
    program_access: Element(5),
    merkle: Element(4),
    poseidon2: Element(16),
    poseidon2_io: Element(32),
    bitwise: Element(4),
    range_check_20: Element(1),
    range_check_8_11: Element(2),
    range_check_8_8_4: Element(3),
    range_check_8_8: Element(2),
    range_check_m31: Element(2),

    pub fn init(challenges: *const recorder.ChallengeSet) Error!SymbolicRelations {
        return .{
            .registers_state = try Element(2).init(challenges.get(.registers_state)),
            .memory_access = try Element(7).init(challenges.get(.memory_access)),
            .program_access = try Element(5).init(challenges.get(.program_access)),
            .merkle = try Element(4).init(challenges.get(.merkle)),
            .poseidon2 = try Element(16).init(challenges.get(.poseidon2)),
            .poseidon2_io = try Element(32).init(challenges.get(.poseidon2_io)),
            .bitwise = try Element(4).init(challenges.get(.bitwise)),
            .range_check_20 = try Element(1).init(challenges.get(.range_check_20)),
            .range_check_8_11 = try Element(2).init(challenges.get(.range_check_8_11)),
            .range_check_8_8_4 = try Element(3).init(challenges.get(.range_check_8_8_4)),
            .range_check_8_8 = try Element(2).init(challenges.get(.range_check_8_8)),
            .range_check_m31 = try Element(2).init(challenges.get(.range_check_m31)),
        };
    }
};

/// Replays row 34 in the exact native `HashComponent(.universal)` order.
/// No concrete field value is inspected and no memory is allocated here.
pub fn recordPoseidon2(
    main: [poseidon_air.N_MAIN_COLUMNS]recorder.Scalar,
    is_first: recorder.Scalar,
    current: [poseidon_air.N_SUMS]recorder.Scalar,
    previous: [poseidon_air.N_SUMS]recorder.Scalar,
    partial_claims: [poseidon_air.N_SUMS]recorder.Scalar,
    challenges: *const recorder.ChallengeSet,
    composition_randomness: recorder.Scalar,
    denominator_inverse: recorder.Scalar,
    accumulation: *recorder.Scalar,
) Error!usize {
    const symbolic_relations = try SymbolicRelations.init(challenges);

    const direct_roots = poseidon_air.evaluateGeneric(recorder.Scalar, main);
    for (direct_roots) |root| recorder.accumulate(
        accumulation,
        composition_randomness,
        root,
        denominator_inverse,
    );
    const interaction_roots = poseidon_air.interactionConstraintsGeneric(
        recorder.Scalar,
        main,
        is_first,
        current,
        previous,
        partial_claims,
        &symbolic_relations,
    );
    for (interaction_roots) |root| recorder.accumulate(
        accumulation,
        composition_randomness,
        root,
        denominator_inverse,
    );
    return POSEIDON_CONSTRAINT_COUNT;
}

/// Constraint that binds the two row-34 native claims to the single roster
/// claim.  This is a graph output, not a composition-polynomial root.
pub fn poseidonClaimClosure(
    partial_claims: [poseidon_air.N_SUMS]recorder.Scalar,
    roster_total: recorder.Scalar,
) recorder.Scalar {
    return partial_claims[0].add(partial_claims[1]).sub(roster_total);
}

/// Replays row 35 through the shipped lookup-table interaction evaluator.
/// The range provider has one native claim, so no auxiliary-claim ABI exists.
pub fn recordRangeCheck8x8(
    tuple: [2]recorder.Scalar,
    signed_multiplicity: recorder.Scalar,
    current: recorder.Scalar,
    previous: recorder.Scalar,
    is_first: recorder.Scalar,
    claimed_sum: recorder.Scalar,
    challenges: *const recorder.ChallengeSet,
    composition_randomness: recorder.Scalar,
    denominator_inverse: recorder.Scalar,
    accumulation: *recorder.Scalar,
) Error!usize {
    const symbolic_relations = try SymbolicRelations.init(challenges);
    const root = try table_interaction.evaluateGeneric(
        recorder.Scalar,
        .range_check_8_8,
        &tuple,
        signed_multiplicity,
        current,
        previous,
        is_first,
        claimed_sum,
        &symbolic_relations,
    );
    recorder.accumulate(
        accumulation,
        composition_randomness,
        root,
        denominator_inverse,
    );
    return RANGE_CHECK_8_8_CONSTRAINT_COUNT;
}

test "R-012 shared providers symbolically equal native row 34 and row 35" {
    const universal = @import("universal_challenges.zig");
    const native_relations_mod = @import("../../air/relation_challenges.zig");

    const universal_relations = universal.UniversalRelations.dummy();
    const native_draws = [native_relations_mod.DRAW_COUNT]QM31{
        universal_relations.elements[0].z,
        universal_relations.elements[0].alpha,
        universal_relations.elements[1].z,
        universal_relations.elements[1].alpha,
        universal_relations.elements[2].z,
        universal_relations.elements[2].alpha,
        // The shipped VM Merkle relation is unused by both provider rows.
        QM31.zero(),
        QM31.one(),
        universal_relations.elements[4].z,
        universal_relations.elements[4].alpha,
        universal_relations.elements[5].z,
        universal_relations.elements[5].alpha,
        universal_relations.elements[6].z,
        universal_relations.elements[6].alpha,
        universal_relations.elements[7].z,
        universal_relations.elements[7].alpha,
        universal_relations.elements[8].z,
        universal_relations.elements[8].alpha,
        universal_relations.elements[9].z,
        universal_relations.elements[9].alpha,
        universal_relations.elements[10].z,
        universal_relations.elements[10].alpha,
        universal_relations.elements[11].z,
        universal_relations.elements[11].alpha,
    };
    const native_relations = native_relations_mod.Relations.fromDrawSequence(
        &native_draws,
    );

    var builder = recorder.Builder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.reserve(600, 12_000);

    var concrete = std.ArrayList(QM31).empty;
    defer concrete.deinit(std.testing.allocator);
    const Input = struct {
        fn add(
            b: *recorder.Builder,
            values: *std.ArrayList(QM31),
            value: QM31,
        ) !recorder.Scalar {
            const input = try b.input();
            try values.append(std.testing.allocator, value);
            return input.value;
        }
    };

    const call = poseidon_air.Call{
        .input = .{ 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584, 4181 },
        .wide = true,
    };
    const native_main_base = poseidon_air.fill(call);
    var native_main: [poseidon_air.N_MAIN_COLUMNS]QM31 = undefined;
    var symbolic_main: [poseidon_air.N_MAIN_COLUMNS]recorder.Scalar = undefined;
    for (&native_main, &symbolic_main, native_main_base) |*native, *symbolic, value| {
        native.* = QM31.fromBase(value);
        symbolic.* = try Input.add(&builder, &concrete, native.*);
    }

    const native_is_first = QM31.fromU32Unchecked(7, 11, 13, 17);
    const symbolic_is_first = try Input.add(&builder, &concrete, native_is_first);
    const native_current = [_]QM31{
        QM31.fromU32Unchecked(19, 23, 29, 31),
        QM31.fromU32Unchecked(37, 41, 43, 47),
    };
    const native_previous = [_]QM31{
        QM31.fromU32Unchecked(53, 59, 61, 67),
        QM31.fromU32Unchecked(71, 73, 79, 83),
    };
    const native_partials = [_]QM31{
        QM31.fromU32Unchecked(89, 97, 101, 103),
        QM31.fromU32Unchecked(107, 109, 113, 127),
    };
    var symbolic_current: [2]recorder.Scalar = undefined;
    var symbolic_previous: [2]recorder.Scalar = undefined;
    var symbolic_partials: [2]recorder.Scalar = undefined;
    for (0..2) |index| {
        symbolic_current[index] = try Input.add(&builder, &concrete, native_current[index]);
        symbolic_previous[index] = try Input.add(&builder, &concrete, native_previous[index]);
        symbolic_partials[index] = try Input.add(&builder, &concrete, native_partials[index]);
    }

    var symbolic_draws: [universal.RELATION_COUNT][2]recorder.Scalar = undefined;
    for (&symbolic_draws, universal_relations.elements) |*pair, element| {
        pair[0] = try Input.add(&builder, &concrete, element.z);
        pair[1] = try Input.add(&builder, &concrete, element.alpha);
    }

    const native_random = QM31.fromU32Unchecked(131, 137, 139, 149);
    const native_denominator = QM31.fromU32Unchecked(151, 157, 163, 167);
    const symbolic_random = try Input.add(&builder, &concrete, native_random);
    const symbolic_denominator = try Input.add(&builder, &concrete, native_denominator);

    const native_direct = poseidon_air.evaluate(native_main);
    const native_interaction = poseidon_air.interactionConstraints(
        native_main,
        native_is_first,
        native_current,
        native_previous,
        native_partials,
        &native_relations,
    );
    var native_accumulation = QM31.zero();
    for (native_direct) |root| native_accumulation = native_accumulation
        .mul(native_random).add(root.mul(native_denominator));
    for (native_interaction) |root| native_accumulation = native_accumulation
        .mul(native_random).add(root.mul(native_denominator));
    const expected_poseidon = try Input.add(&builder, &concrete, native_accumulation);
    const roster_total = native_partials[0].add(native_partials[1]);
    const symbolic_total = try Input.add(&builder, &concrete, roster_total);

    const native_range_tuple = [_]QM31{
        QM31.fromBase(M31.fromU64(17)),
        QM31.fromBase(M31.fromU64(29)),
    };
    const native_range_multiplicity = QM31.fromU32Unchecked(173, 0, 0, 0);
    const native_range_current = QM31.fromU32Unchecked(179, 181, 191, 193);
    const native_range_previous = QM31.fromU32Unchecked(197, 199, 211, 223);
    const native_range_first = QM31.fromU32Unchecked(227, 229, 233, 239);
    const native_range_claim = QM31.fromU32Unchecked(241, 251, 257, 263);
    var symbolic_range_tuple: [2]recorder.Scalar = undefined;
    for (&symbolic_range_tuple, native_range_tuple) |*symbolic, value|
        symbolic.* = try Input.add(&builder, &concrete, value);
    const symbolic_range_multiplicity = try Input.add(
        &builder,
        &concrete,
        native_range_multiplicity,
    );
    const symbolic_range_current = try Input.add(&builder, &concrete, native_range_current);
    const symbolic_range_previous = try Input.add(&builder, &concrete, native_range_previous);
    const symbolic_range_first = try Input.add(&builder, &concrete, native_range_first);
    const symbolic_range_claim = try Input.add(&builder, &concrete, native_range_claim);
    const native_range_root = try table_interaction.evaluate(
        .range_check_8_8,
        &native_range_tuple,
        native_range_multiplicity,
        native_range_current,
        native_range_previous,
        native_range_first,
        native_range_claim,
        &native_relations,
    );
    const native_range_accumulation = native_accumulation.mul(native_random)
        .add(native_range_root.mul(native_denominator));
    const expected_all = try Input.add(&builder, &concrete, native_range_accumulation);

    try builder.activate();
    const symbolic_challenges = try recorder.ChallengeSet.init(symbolic_draws);
    var accumulation = recorder.Scalar.zero();
    try std.testing.expectEqual(
        POSEIDON_CONSTRAINT_COUNT,
        try recordPoseidon2(
            symbolic_main,
            symbolic_is_first,
            symbolic_current,
            symbolic_previous,
            symbolic_partials,
            &symbolic_challenges,
            symbolic_random,
            symbolic_denominator,
            &accumulation,
        ),
    );
    try builder.constrainZero(accumulation.sub(expected_poseidon));
    try builder.constrainZero(poseidonClaimClosure(
        symbolic_partials,
        symbolic_total,
    ));
    try std.testing.expectEqual(
        RANGE_CHECK_8_8_CONSTRAINT_COUNT,
        try recordRangeCheck8x8(
            symbolic_range_tuple,
            symbolic_range_multiplicity,
            symbolic_range_current,
            symbolic_range_previous,
            symbolic_range_first,
            symbolic_range_claim,
            &symbolic_challenges,
            symbolic_random,
            symbolic_denominator,
            &accumulation,
        ),
    );
    try builder.constrainZero(accumulation.sub(expected_all));
    builder.deactivate();

    var circuit = try builder.finish();
    defer circuit.deinit();
    const scratch = try std.testing.allocator.alloc(QM31, circuit.nodes.len);
    defer std.testing.allocator.free(scratch);
    try circuit.evaluateInto(concrete.items, scratch);

    concrete.items[concrete.items.len - 1] = concrete.items[concrete.items.len - 1]
        .add(QM31.one());
    try std.testing.expectError(
        error.UnsatisfiedCircuit,
        circuit.evaluateInto(concrete.items, scratch),
    );
}
