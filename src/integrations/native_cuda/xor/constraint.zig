//! Exact XOR truth-table LogUp policy for its resident 14-constraint AIR.

const std = @import("std");
const runtime_constraint = @import("stwo_cuda_backend").runtime.constraints.xor_logup;
const cpu_component = @import("stwo_native_examples").backend_support.xor.component;
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

test "exact XOR composition binds all trace trees and fourteen powers" {
    try std.testing.expectEqual(
        @as(u32, 15),
        runtime_constraint.source_column_count,
    );
    try std.testing.expectEqual(
        @as(u32, cpu_component.N_CONSTRAINTS),
        runtime_constraint.constraint_count,
    );
}

test "CUDA XOR row semantics match exact CPU component across sizes" {
    var prng = std.Random.DefaultPrng.init(0x584f_525f_4c4f_4755);
    const random = prng.random();
    for ([_]u32{ 2, 4, 16, 28 }) |log_size| {
        for (0..64) |_| {
            const input = cpu_component.DomainRowInput{
                .log_size = log_size,
                .preprocessed = randomM31Array(7, random),
                .main = randomM31Array(4, random),
                .current = randomQM31(random),
                .previous = randomQM31(random),
                .lookup_elements = .{
                    .z = randomQM31(random),
                    .alpha = randomQM31(random),
                },
                .claimed_sum = randomQM31(random),
                .random_powers = randomQM31Array(
                    cpu_component.N_CONSTRAINTS,
                    random,
                ),
                .denominator_inverse = randomM31(random),
            };
            const cpu = cpu_component.evaluateDomainRow(input);
            const cuda = cudaScalarDomainRow(input);
            for (cpu.toM31Array(), cuda.toM31Array()) |expected, actual| {
                try std.testing.expectEqual(
                    expected.toU32(),
                    actual.toU32(),
                );
            }
        }
    }
}

fn cudaScalarDomainRow(input: cpu_component.DomainRowInput) QM31 {
    var preprocessed: [7]QM31 = undefined;
    for (&preprocessed, input.preprocessed) |*out, value| {
        out.* = QM31.fromBase(value);
    }
    var main: [4]QM31 = undefined;
    for (&main, input.main) |*out, value| {
        out.* = QM31.fromBase(value);
    }
    const table_denominator = combineLookup(
        input.lookup_elements.z,
        input.lookup_elements.alpha,
        preprocessed[4],
        preprocessed[5],
        preprocessed[6],
    );
    const execution_denominator = combineLookup(
        input.lookup_elements.z,
        input.lookup_elements.alpha,
        main[0],
        main[1],
        main[2],
    );
    const delta = input.current
        .sub(input.previous)
        .add(preprocessed[0].mul(input.claimed_sum));
    const constraints = [cpu_component.N_CONSTRAINTS]QM31{
        booleanConstraint(preprocessed[0]),
        booleanConstraint(main[0]),
        booleanConstraint(main[1]),
        booleanConstraint(main[2]),
        xorConstraint(main[0], main[1], main[2]),
        main[0].sub(preprocessed[2]),
        main[1].sub(preprocessed[1]),
        booleanConstraint(preprocessed[3]),
        booleanConstraint(preprocessed[4]),
        booleanConstraint(preprocessed[5]),
        booleanConstraint(preprocessed[6]),
        xorConstraint(preprocessed[4], preprocessed[5], preprocessed[6]),
        main[3].mul(QM31.one().sub(preprocessed[3])),
        delta.mul(table_denominator).mul(execution_denominator)
            .sub(main[3].mul(execution_denominator))
            .add(table_denominator),
    };
    var combined = QM31.zero();
    for (constraints, 0..) |value, index| {
        combined = combined.add(
            input.random_powers[cpu_component.N_CONSTRAINTS - 1 - index]
                .mul(value),
        );
    }
    return combined.mulM31(input.denominator_inverse);
}

fn combineLookup(
    z: QM31,
    alpha: QM31,
    a: QM31,
    b: QM31,
    c: QM31,
) QM31 {
    return a.add(alpha.mul(b))
        .add(alpha.square().mul(c))
        .sub(z);
}

fn booleanConstraint(value: QM31) QM31 {
    return value.mul(value.sub(QM31.one()));
}

fn xorConstraint(a: QM31, b: QM31, c: QM31) QM31 {
    return c.sub(a).sub(b).add(a.mul(b).mulM31(M31.fromCanonical(2)));
}

fn randomQM31Array(
    comptime count: usize,
    random: std.Random,
) [count]QM31 {
    var result: [count]QM31 = undefined;
    for (&result) |*value| value.* = randomQM31(random);
    return result;
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
