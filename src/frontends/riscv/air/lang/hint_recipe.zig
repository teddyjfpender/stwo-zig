//! Closed, versioned registry of deterministic witness-hint recipes.
//!
//! Recipe IDs, signatures, algorithms, and exceptional-case policies are
//! protocol metadata. Human-readable names are descriptive and are never used
//! for dispatch. Honest evaluation is useful for witness generation, but AIR
//! constraints and effects remain the authority for every output.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const types = @import("types.zig");

pub const Kind = enum(u16) {
    identity_felt,
    field_inverse_or_zero,
};

pub const Algorithm = enum(u16) {
    identity_felt,
    field_inverse_or_zero,
};

pub const ExceptionalCasePolicy = enum(u8) {
    none,
    /// For input zero, both the inverse and nonzero marker are zero.
    zero_returns_zero_inverse_and_false,
};

pub const Recipe = struct {
    id: types.HintRecipeId,
    kind: Kind,
    version: u16,
    name: []const u8,
    input_types: []const types.Type,
    output_types: []const types.Type,
    algorithm: Algorithm,
    exceptional_cases: ExceptionalCasePolicy,
};

pub const InvocationError = error{
    InvalidHintInputArity,
    InvalidHintInputType,
    InvalidHintOutputArity,
    InvalidHintOutputType,
    UnknownHintRecipe,
};

pub const EvaluationError = error{
    InvalidHintInputArity,
    InvalidHintOutputArity,
    NonCanonicalHintInput,
    UnknownHintRecipe,
};

const one_felt = [_]types.Type{.felt};
const inverse_outputs = [_]types.Type{ .felt, .bit };

pub const recipes = [_]Recipe{
    recipe(
        .identity_felt,
        "stwo.air.hint.identity_felt",
        &one_felt,
        &one_felt,
        .identity_felt,
        .none,
    ),
    recipe(
        .field_inverse_or_zero,
        "stwo.air.hint.field_inverse_or_zero",
        &one_felt,
        &inverse_outputs,
        .field_inverse_or_zero,
        .zero_returns_zero_inverse_and_false,
    ),
};

pub fn id(kind: Kind) types.HintRecipeId {
    return @enumFromInt(@intFromEnum(kind));
}

pub fn get(kind: Kind) *const Recipe {
    return &recipes[@intFromEnum(kind)];
}

pub fn getById(recipe_id: types.HintRecipeId) ?*const Recipe {
    const index = types.idIndex(recipe_id);
    if (index >= recipes.len) return null;
    return &recipes[index];
}

pub fn validateInvocation(
    recipe_id: types.HintRecipeId,
    input_types: []const types.Type,
    output_types: []const types.Type,
) InvocationError!void {
    const item = getById(recipe_id) orelse return error.UnknownHintRecipe;
    if (input_types.len != item.input_types.len)
        return error.InvalidHintInputArity;
    if (output_types.len != item.output_types.len)
        return error.InvalidHintOutputArity;
    for (item.input_types, input_types) |expected, actual| {
        actual.validate() catch return error.InvalidHintInputType;
        if (!std.meta.eql(expected, actual)) return error.InvalidHintInputType;
    }
    for (item.output_types, output_types) |expected, actual| {
        actual.validate() catch return error.InvalidHintOutputType;
        if (!std.meta.eql(expected, actual)) return error.InvalidHintOutputType;
    }
}

/// Evaluates field-only v1 recipes into canonical M31 representatives.
///
/// This honest algorithm is deliberately separate from validation: callers
/// must still provide binding constraints or effects for every output.
pub fn evaluateField(
    recipe_id: types.HintRecipeId,
    inputs: []const u32,
    outputs: []u32,
) EvaluationError!void {
    const item = getById(recipe_id) orelse return error.UnknownHintRecipe;
    if (inputs.len != item.input_types.len)
        return error.InvalidHintInputArity;
    if (outputs.len != item.output_types.len)
        return error.InvalidHintOutputArity;
    for (inputs) |input| {
        if (input >= m31.Modulus) return error.NonCanonicalHintInput;
    }

    switch (item.algorithm) {
        .identity_felt => outputs[0] = inputs[0],
        .field_inverse_or_zero => {
            const input = m31.M31.fromCanonical(inputs[0]);
            if (input.isZero()) {
                outputs[0] = 0;
                outputs[1] = 0;
            } else {
                outputs[0] = input.invUncheckedNonZero().toU32();
                outputs[1] = 1;
            }
        },
    }
}

fn recipe(
    kind: Kind,
    name: []const u8,
    input_types: []const types.Type,
    output_types: []const types.Type,
    algorithm: Algorithm,
    exceptional_cases: ExceptionalCasePolicy,
) Recipe {
    return .{
        .id = id(kind),
        .kind = kind,
        .version = 1,
        .name = name,
        .input_types = input_types,
        .output_types = output_types,
        .algorithm = algorithm,
        .exceptional_cases = exceptional_cases,
    };
}

comptime {
    if (recipes.len != @typeInfo(Kind).@"enum".fields.len)
        @compileError("hint recipe registry must cover every kind");
    for (recipes, 0..) |item, index| {
        if (@intFromEnum(item.kind) != index or types.idIndex(item.id) != index)
            @compileError("hint recipe order must match stable IDs");
        if (item.version == 0 or item.name.len == 0 or
            item.input_types.len == 0 or item.output_types.len == 0)
        {
            @compileError("hint recipes require identity, version, and signature");
        }
        if (item.output_types.len > @as(usize, std.math.maxInt(u16)) + 1)
            @compileError("hint recipe output index exceeds its canonical width");
        for (item.input_types) |ty| ty.validate() catch
            @compileError("hint recipe contains an invalid input type");
        for (item.output_types) |ty| ty.validate() catch
            @compileError("hint recipe contains an invalid output type");
    }
}
