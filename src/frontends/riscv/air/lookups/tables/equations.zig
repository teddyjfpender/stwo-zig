//! Single table relation and LogUp recurrence owner; no trace generation.
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const entry = @import("../entry.zig");
const schema = @import("schema_definition.zig");
const relations_mod = @import("../../relation_challenges.zig");
const logup = @import("../../logup_equations.zig");
pub const N_COLUMNS = @import("layout.zig").N_INTERACTION_COLUMNS;

pub fn tableEntry(
    kind: schema.Kind,
    tuple: schema.Tuple,
    signed_multiplicity: M31,
) entry.Entry {
    var values: [schema.MAX_ARITY]QM31 = undefined;
    for (tuple.slice(), values[0..tuple.len]) |value, *dst| dst.* = QM31.fromBase(value);
    return tableEntryGeneric(QM31, kind, values[0..tuple.len], QM31.fromBase(signed_multiplicity));
}

pub fn tableEntryGeneric(comptime S: type, kind: schema.Kind, tuple: []const S, signed_multiplicity: S) entry.Builder(S).Entry {
    var result = entry.Builder(S).Entry{
        .domain = schema.domain(kind),
        .numerator = signed_multiplicity.neg(),
        .arity = @intCast(tuple.len),
    };
    @memcpy(result.values[0..tuple.len], tuple);
    return result;
}

pub fn rowPair(
    kind: schema.Kind,
    tuple: schema.Tuple,
    signed_multiplicity: M31,
    relations: *const relations_mod.Relations,
) !logup.RowPair {
    const relation_entry = tableEntry(kind, tuple, signed_multiplicity);
    return logup.RowPair.single(relation_entry.numerator, try relation_entry.denominator(relations));
}

pub fn evaluate(
    kind: schema.Kind,
    tuple: []const QM31,
    signed_multiplicity: QM31,
    current: QM31,
    previous: QM31,
    is_first: QM31,
    claim: QM31,
    relations: *const relations_mod.Relations,
) !QM31 {
    return evaluateGeneric(
        QM31,
        kind,
        tuple,
        signed_multiplicity,
        current,
        previous,
        is_first,
        claim,
        relations,
    );
}

pub fn evaluateBaseTuple(
    kind: schema.Kind,
    tuple: []const M31,
    signed_multiplicity: M31,
    current: QM31,
    previous: QM31,
    is_first: M31,
    claim: QM31,
    relations: *const relations_mod.Relations,
) !QM31 {
    // Match the public generic evaluator's malformed-trace contract. The
    // internal relation combiner reports InvalidArity at its lower boundary.
    if (tuple.len != schema.arity(kind)) return error.InvalidTraceShape;
    return logup.pairConstraint(
        current,
        previous,
        QM31.fromBase(is_first),
        claim,
        logup.RowPair.single(
            QM31.fromBase(signed_multiplicity).neg(),
            try denominatorBaseValues(kind, tuple, relations),
        ),
    );
}

pub fn evaluateGeneric(
    comptime S: type,
    kind: schema.Kind,
    tuple: []const S,
    signed_multiplicity: S,
    current: S,
    previous: S,
    is_first: S,
    claim: S,
    relations: anytype,
) !S {
    if (tuple.len != schema.arity(kind)) return error.InvalidTraceShape;
    const relation_entry = tableEntryGeneric(S, kind, tuple, signed_multiplicity);
    return logup.pairConstraintGeneric(
        S,
        current,
        previous,
        is_first,
        claim,
        logup.RowPairFor(S).single(
            relation_entry.numerator,
            try relation_entry.denominatorWith(relations),
        ),
    );
}

pub fn denominatorBase(
    kind: schema.Kind,
    tuple: schema.Tuple,
    relations: *const relations_mod.Relations,
) !QM31 {
    return denominatorBaseValues(kind, tuple.slice(), relations);
}

pub fn denominatorBaseValues(
    kind: schema.Kind,
    values: []const M31,
    relations: *const relations_mod.Relations,
) !QM31 {
    if (values.len != schema.arity(kind)) return error.InvalidArity;
    return switch (kind) {
        .bitwise => relations.bitwise.combineBase(values[0..4].*),
        .range_check_20 => relations.range_check_20.combineBase(values[0..1].*),
        .range_check_8_11 => relations.range_check_8_11.combineBase(values[0..2].*),
        .range_check_8_8_4 => relations.range_check_8_8_4.combineBase(values[0..3].*),
        .range_check_8_8 => relations.range_check_8_8.combineBase(values[0..2].*),
        .range_check_m31 => relations.range_check_m31.combineBase(values[0..2].*),
    };
}
