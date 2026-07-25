//! Exact two-component State Machine v2 constraint composition policy.

const field = @import("../../../backends/cuda/abi/field.zig");
const common = @import(
    "../../../backends/cuda/runtime/stages/common.zig",
);
const geometry_mod = @import("geometry.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const source_column_count: usize = 12;
pub const constraint_count: usize = 2;

pub const Buffers = struct {
    source_evaluations: common.WordMatrix,
    random_coefficient_powers: common.SecureFields,
    denominator_inverses: common.Words,
    lookup_elements: common.SecureFields,
    claimed_sums: common.SecureFields,
    composition_coordinates: common.WordMatrix,
};

/// The M5 host can validate exact row semantics and terminal scheduling but
/// cannot manufacture the CUDA AOT kernel. Native execution therefore stays
/// fail-closed until the generated v2 entry is built and pinned on CUDA.
pub fn evaluate(
    _: anytype,
    _: Buffers,
    _: geometry_mod.Geometry,
) !void {
    return error.StateMachineV2AotUnavailable;
}

pub const DomainRowInput = struct {
    log_rows: u32,
    coordinate: usize,
    state: [2]M31,
    cumulative_previous: QM31,
    cumulative_current: QM31,
    lookup_z: QM31,
    lookup_alpha: QM31,
    claimed_sum: QM31,
    random_power: QM31,
    denominator_inverse: M31,
};

pub fn evaluateDomainRow(input: DomainRowInput) QM31 {
    var output = input.state;
    output[input.coordinate] =
        output[input.coordinate].add(M31.one());
    const input_denominator = combine(
        input.lookup_z,
        input.lookup_alpha,
        input.state,
    );
    const output_denominator = combine(
        input.lookup_z,
        input.lookup_alpha,
        output,
    );
    const inverse_rows = if (input.log_rows == 0)
        M31.one()
    else
        M31.fromCanonical(
            @as(u32, 1) << @intCast(31 - input.log_rows),
        );
    const delta = input.cumulative_current
        .sub(input.cumulative_previous)
        .add(input.claimed_sum.mulM31(inverse_rows));
    const constraint_value = delta
        .mul(input_denominator)
        .mul(output_denominator)
        .sub(output_denominator.sub(input_denominator));
    return input.random_power
        .mul(constraint_value)
        .mulM31(input.denominator_inverse);
}

fn combine(z: QM31, alpha: QM31, state: [2]M31) QM31 {
    return QM31.fromBase(state[0])
        .add(alpha.mulM31(state[1]))
        .sub(z);
}

test "State v2 row formula vanishes on an exact transition fraction" {
    const std = @import("std");
    const state = [2]M31{
        M31.fromU64(29),
        M31.fromU64(31),
    };
    const z = QM31.fromU32Unchecked(37, 41, 43, 47);
    const alpha = QM31.fromU32Unchecked(3, 5, 7, 11);
    var output = state;
    output[1] = output[1].add(M31.one());
    const input_denominator = combine(z, alpha, state);
    const output_denominator = combine(z, alpha, output);
    const fraction = output_denominator
        .sub(input_denominator)
        .div(input_denominator.mul(output_denominator)) catch
        unreachable;
    const value = evaluateDomainRow(.{
        .log_rows = 5,
        .coordinate = 1,
        .state = state,
        .cumulative_previous = QM31.zero(),
        .cumulative_current = fraction,
        .lookup_z = z,
        .lookup_alpha = alpha,
        .claimed_sum = QM31.zero(),
        .random_power = QM31.one(),
        .denominator_inverse = M31.one(),
    });
    try std.testing.expect(value.isZero());
}

test "State v2 hardware constraint stays fail-closed without AOT" {
    const empty_words = common.Words{
        .address = 0,
        .len = 0,
        .owner = 0,
    };
    const empty_secure = try empty_words.cast(field.SecureField);
    try @import("std").testing.expectError(
        error.StateMachineV2AotUnavailable,
        evaluate(
            {},
            .{
                .source_evaluations = .{
                    .storage = empty_words,
                    .column_stride_words = 1,
                },
                .random_coefficient_powers = empty_secure,
                .denominator_inverses = empty_words,
                .lookup_elements = empty_secure,
                .claimed_sums = empty_secure,
                .composition_coordinates = .{
                    .storage = empty_words,
                    .column_stride_words = 1,
                },
            },
            undefined,
        ),
    );
}
