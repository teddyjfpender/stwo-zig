//! Exact Plonk/LogUp policy for its resident three-constraint composition.

const std = @import("std");
const runtime_constraint = @import(
    "../../../backends/cuda/runtime/constraints/plonk_logup.zig",
);
const cpu_component = @import(
    "../../../examples/plonk_logup/component.zig",
);
const geometry_mod = @import("geometry.zig");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const Buffers = runtime_constraint.Buffers;

pub fn prepare(
    session: anytype,
    buffers: Buffers,
    geometry: geometry_mod.Geometry,
) !runtime_constraint.PreparedLaunch {
    if (geometry.traceColumnCount() !=
        runtime_constraint.source_column_count)
    {
        return error.InvalidKernelDescriptor;
    }
    return runtime_constraint.prepare(
        session,
        buffers,
        geometry.traceLogSize(),
    );
}

pub fn evaluate(
    session: anytype,
    buffers: Buffers,
    geometry: geometry_mod.Geometry,
) !void {
    var launch = try prepare(session, buffers, geometry);
    try launch.launch(session);
}

test "exact Plonk composition binds all trace trees and three powers" {
    try std.testing.expectEqual(
        @as(u32, 16),
        runtime_constraint.source_column_count,
    );
    try std.testing.expectEqual(
        @as(u32, 3),
        runtime_constraint.constraint_count,
    );
}

test "CUDA row semantics match exact CPU component across sizes" {
    var prng = std.Random.DefaultPrng.init(0x4f4f_4453_504c_4f4e);
    const random = prng.random();
    for ([_]u32{ 1, 4, 16, 28 }) |log_n_rows| {
        for (0..64) |_| {
            const input = cpu_component.DomainRowInput{
                .log_n_rows = log_n_rows,
                .preprocessed = randomM31Array(4, random),
                .main = randomM31Array(4, random),
                .first_sum = randomQM31(random),
                .cumulative_previous = randomQM31(random),
                .cumulative_current = randomQM31(random),
                .lookup_elements = .{
                    .z = randomM31Array(4, random),
                    .alpha = randomM31Array(4, random),
                },
                .claimed_sum = randomM31Array(4, random),
                .random_powers = .{
                    randomQM31(random),
                    randomQM31(random),
                    randomQM31(random),
                },
                .denominator_inverse = randomM31(random),
            };
            const cpu = try cpu_component.evaluateDomainRow(input);
            const cuda = cudaScalarDomainRow(input);
            for (
                cpu.toM31Array(),
                cuda.toM31Array(),
            ) |expected, actual| {
                try std.testing.expectEqual(
                    expected.toU32(),
                    actual.toU32(),
                );
            }
        }
    }
}

fn cudaScalarDomainRow(input: cpu_component.DomainRowInput) QM31 {
    const op = input.preprocessed[3];
    const a = input.main[1];
    const b = input.main[2];
    const c = input.main[3];
    const algebraic = c.sub(op.mul(a.add(b)))
        .add(M31.one().sub(op).mul(a).mul(b));

    const z = QM31.fromM31Array(input.lookup_elements.z);
    const alpha = QM31.fromM31Array(input.lookup_elements.alpha);
    const q0 = combineLookup(
        z,
        alpha,
        input.preprocessed[0],
        input.main[1],
    );
    const q1 = combineLookup(
        z,
        alpha,
        input.preprocessed[1],
        input.main[2],
    );
    const first_logup = input.first_sum.mul(q0).mul(q1)
        .sub(q0.add(q1));
    const q2 = combineLookup(
        z,
        alpha,
        input.preprocessed[2],
        input.main[3],
    );
    const inverse_rows = if (input.log_n_rows == 0)
        M31.one()
    else
        M31.fromCanonical(
            @as(u32, 1) << @intCast(31 - input.log_n_rows),
        );
    const shift = QM31.fromM31Array(input.claimed_sum)
        .mulM31(inverse_rows);
    const final_logup = input.cumulative_current
        .sub(input.cumulative_previous)
        .sub(input.first_sum)
        .add(shift)
        .mul(q2)
        .addM31(input.main[0]);
    return input.random_powers[2].mulM31(algebraic)
        .add(input.random_powers[1].mul(first_logup))
        .add(input.random_powers[0].mul(final_logup))
        .mulM31(input.denominator_inverse);
}

fn combineLookup(
    z: QM31,
    alpha: QM31,
    wire: M31,
    value: M31,
) QM31 {
    return QM31.fromBase(wire).add(alpha.mulM31(value)).sub(z);
}

fn randomQM31(random: std.Random) QM31 {
    return QM31.fromM31Array(randomM31Array(4, random));
}

fn randomM31Array(
    comptime count: usize,
    random: std.Random,
) [count]M31 {
    var result: [count]M31 = undefined;
    for (&result) |*value| value.* = randomM31(random);
    return result;
}

fn randomM31(random: std.Random) M31 {
    return M31.fromCanonical(
        random.intRangeLessThan(u32, 0, m31.Modulus),
    );
}
