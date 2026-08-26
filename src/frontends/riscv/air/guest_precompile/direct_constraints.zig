//! Fixed-shape direct AIR for the two guest Poseidon2 components.
//!
//! These row evaluators own no storage and perform no allocation.  Their
//! public offsets are the canonical constraint order consumed by C-009's
//! eventual Stwo adapter; this module deliberately contains no orchestration.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const poseidon2_air = @import("../memory_commitment/poseidon2_air.zig");
const components = @import("component_registry.zig");

pub const maximum_constraint_degree: u8 = 3;
pub const canonical_word_count: usize = 32;
pub const canonical_constraints_per_word: usize = 4;

pub const caller_main_column_count: usize = components.caller_layout.main_columns;
pub const caller_padding_constraint_count: usize = caller_main_column_count - 1;
pub const caller_canonical_constraint_count: usize =
    canonical_word_count * canonical_constraints_per_word;
pub const caller_constraint_count: usize =
    2 + caller_padding_constraint_count + 2 + caller_canonical_constraint_count;

pub const provider_main_column_count: usize = poseidon2_air.N_MAIN_COLUMNS;
pub const provider_poseidon_constraint_count: usize = poseidon2_air.N_CONSTRAINTS;
pub const provider_padding_constraint_count: usize = provider_main_column_count - 3;
pub const provider_constraint_count: usize =
    provider_poseidon_constraint_count + 3 + provider_padding_constraint_count;

pub const CanonicalPart = enum(u2) { s0, s1, nz, inverse };

/// Canonical caller order: selector, padding, pointer geometry, then the 32
/// word gadgets in input-lane then output-lane order.
pub const CallerOrder = struct {
    pub const enabler_boolean: usize = 0;
    pub const enabler_activity: usize = 1;
    pub const padding_start: usize = 2;
    pub const pointer_composition: usize =
        padding_start + caller_padding_constraint_count;
    pub const pointer_span: usize = pointer_composition + 1;
    pub const canonical_start: usize = pointer_span + 1;
    pub const end: usize = canonical_start + caller_canonical_constraint_count;

    pub fn padding(main_column: usize) usize {
        std.debug.assert(main_column > components.caller_layout.enabler and
            main_column < caller_main_column_count);
        return padding_start + main_column - 1;
    }

    pub fn canonical(output: bool, lane: u8, part: CanonicalPart) usize {
        std.debug.assert(lane < 16);
        const word = @as(usize, @intFromBool(output)) * 16 + lane;
        return canonical_start + canonical_constraints_per_word * word +
            @intFromEnum(part);
    }
};

/// Canonical provider order preserves the exact compatibility Poseidon2 AIR,
/// then binds the guest selector/modes, then closes every non-mode pad cell.
pub const ProviderOrder = struct {
    pub const poseidon_start: usize = 0;
    pub const enabler_activity: usize = provider_poseidon_constraint_count;
    pub const io_activity: usize = enabler_activity + 1;
    pub const wide_zero: usize = io_activity + 1;
    pub const padding_start: usize = wide_zero + 1;
    pub const end: usize = padding_start + provider_padding_constraint_count;

    pub fn padding(main_column: usize) usize {
        std.debug.assert(main_column > 0 and main_column < provider_wide_column);
        return padding_start + main_column - 1;
    }
};

pub const DegreeBounds = struct {
    pub const selector_boolean: u8 = 2;
    pub const selector_binding: u8 = 1;
    pub const padding: u8 = 2;
    pub const pointer: u8 = 1;
    pub const canonical_materialization: u8 = 3;
    pub const canonical_inverse: u8 = 2;
    pub const poseidon2_compatibility: u8 = 3;
    pub const provider_mode: u8 = 1;
};

pub fn callerConstraintDegreeBound(index: usize) u8 {
    std.debug.assert(index < caller_constraint_count);
    if (index == CallerOrder.enabler_boolean) return DegreeBounds.selector_boolean;
    if (index == CallerOrder.enabler_activity) return DegreeBounds.selector_binding;
    if (index < CallerOrder.pointer_composition) return DegreeBounds.padding;
    if (index <= CallerOrder.pointer_span) return DegreeBounds.pointer;
    const part = (index - CallerOrder.canonical_start) %
        canonical_constraints_per_word;
    return if (part == @intFromEnum(CanonicalPart.inverse))
        DegreeBounds.canonical_inverse
    else
        DegreeBounds.canonical_materialization;
}

pub fn providerConstraintDegreeBound(index: usize) u8 {
    std.debug.assert(index < provider_constraint_count);
    if (index < provider_poseidon_constraint_count)
        return DegreeBounds.poseidon2_compatibility;
    if (index < ProviderOrder.padding_start) return DegreeBounds.provider_mode;
    return DegreeBounds.padding;
}

pub fn evaluateCaller(
    main: [caller_main_column_count]QM31,
    is_active: QM31,
) [caller_constraint_count]QM31 {
    return evaluateCallerGeneric(QM31, main, is_active);
}

pub fn evaluateCallerGeneric(
    comptime S: type,
    main: [caller_main_column_count]S,
    is_active: S,
) [caller_constraint_count]S {
    const layout = components.caller_layout;
    const enabler = main[layout.enabler];
    const one = S.one();
    var result: [caller_constraint_count]S = undefined;

    result[CallerOrder.enabler_boolean] = enabler.mul(one.sub(enabler));
    result[CallerOrder.enabler_activity] = enabler.sub(is_active);
    const padding_mask = one.sub(is_active);
    for (1..caller_main_column_count) |column| {
        result[CallerOrder.padding(column)] = padding_mask.mul(main[column]);
    }

    const pointer_bytes = main[layout.pointer_bytes..][0..4].*;
    result[CallerOrder.pointer_composition] = composeLittleEndian(
        S,
        pointer_bytes,
    ).sub(mulSmall(S, main[layout.pointer_word_index], 4));
    const span_limbs = main[layout.span_end_limbs..][0..4].*;
    result[CallerOrder.pointer_span] = main[layout.pointer_word_index]
        .add(mulSmall(S, enabler, 15))
        .sub(composeLittleEndian(S, span_limbs));

    inline for (0..canonical_word_count) |word| {
        const output = comptime word >= 16;
        const lane: u8 = @intCast(word % 16);
        const constraints = canonicalWordConstraints(
            S,
            &main,
            enabler,
            output,
            lane,
        );
        inline for (constraints, 0..) |constraint, part| {
            result[
                CallerOrder.canonical(
                    output,
                    lane,
                    @enumFromInt(part),
                )
            ] = constraint;
        }
    }
    return result;
}

pub fn evaluateProvider(
    main: [provider_main_column_count]QM31,
    is_active: QM31,
) [provider_constraint_count]QM31 {
    return evaluateProviderGeneric(QM31, main, is_active);
}

pub fn evaluateProviderGeneric(
    comptime S: type,
    main: [provider_main_column_count]S,
    is_active: S,
) [provider_constraint_count]S {
    var result: [provider_constraint_count]S = undefined;
    const poseidon = poseidon2_air.evaluateGeneric(S, main);
    @memcpy(result[ProviderOrder.poseidon_start..][0..poseidon.len], &poseidon);

    result[ProviderOrder.enabler_activity] = main[provider_enabler_column]
        .sub(is_active);
    result[ProviderOrder.io_activity] = main[provider_io_column].sub(is_active);
    result[ProviderOrder.wide_zero] = main[provider_wide_column];
    const padding_mask = S.one().sub(is_active);
    for (1..provider_wide_column) |column| {
        result[ProviderOrder.padding(column)] = padding_mask.mul(main[column]);
    }
    return result;
}

fn canonicalWordConstraints(
    comptime F: type,
    main: []const F,
    active: F,
    comptime output: bool,
    comptime lane: u8,
) [canonical_constraints_per_word]F {
    const layout = components.caller_layout;
    const byte_start = if (output)
        layout.outputByte(lane, 0)
    else
        layout.inputByte(lane, 0);
    const bytes = main[byte_start..][0..4];
    const s0 = main[layout.canonicalMaterialization(output, lane, 0)];
    const s1 = main[layout.canonicalMaterialization(output, lane, 1)];
    const nz = main[layout.canonicalMaterialization(output, lane, 2)];
    const inverse = main[layout.canonicalMaterialization(output, lane, 3)];
    const d0 = bytes[0].sub(constant(F, 255));
    const d1 = bytes[1].sub(constant(F, 255));
    const d2 = bytes[2].sub(constant(F, 255));
    const d3 = bytes[3].sub(constant(F, 127));
    const expected_s0 = d0.square().add(d1.square());
    const expected_s1 = d2.square().add(d3.square());
    const expected_nz = s0.square().add(s1.square());
    return .{
        active.mul(s0.sub(expected_s0)),
        active.mul(s1.sub(expected_s1)),
        active.mul(nz.sub(expected_nz)),
        nz.mul(inverse).sub(active),
    };
}

fn composeLittleEndian(comptime F: type, limbs: [4]F) F {
    return limbs[0]
        .add(mulSmall(F, limbs[1], 1 << 8))
        .add(mulSmall(F, limbs[2], 1 << 16))
        .add(mulSmall(F, limbs[3], 1 << 24));
}

fn mulSmall(comptime F: type, value: F, coefficient: u32) F {
    if (comptime F == M31) return value.mul(M31.fromCanonical(coefficient));
    if (comptime F == QM31) return value.mulM31(M31.fromCanonical(coefficient));
    return value.mul(F.fromBase(M31.fromCanonical(coefficient)));
}

fn constant(comptime F: type, value: u32) F {
    if (comptime F == M31) return M31.fromCanonical(value);
    if (comptime F == QM31) return QM31.fromBase(M31.fromCanonical(value));
    return F.fromBase(M31.fromCanonical(value));
}

const provider_enabler_column: usize = 0;
const provider_wide_column: usize = provider_main_column_count - 2;
const provider_io_column: usize = provider_main_column_count - 1;

comptime {
    if (caller_main_column_count != 286 or caller_constraint_count != 417 or
        CallerOrder.end != caller_constraint_count)
    {
        @compileError("guest caller direct-constraint geometry drifted");
    }
    if (provider_main_column_count != 445 or
        provider_poseidon_constraint_count != 430 or
        provider_constraint_count != 875 or
        ProviderOrder.end != provider_constraint_count or
        provider_wide_column != 443 or provider_io_column != 444)
    {
        @compileError("guest provider direct-constraint geometry drifted");
    }
    if (components.CallerConstraintIdentity.canonical().maximum_constraint_degree !=
        maximum_constraint_degree or
        components.ProviderCompatibilityIdentity.canonical().maximum_constraint_degree !=
            maximum_constraint_degree)
    {
        @compileError("guest direct-constraint degree authority drifted");
    }
}
