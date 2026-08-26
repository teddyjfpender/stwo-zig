//! Packed scalar-equivalence test for RISC-V composition.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const composition = @import("riscv_composition.zig");
const lanes = @import("riscv_composition_lanes.zig");
const profile_test = @import("riscv_composition_profile_test.zig");
const composition_work = prover.air.composition_work;

const constraints = core.constraints;
const m31 = core.fields.m31;
const qm31 = core.fields.qm31;
const packed_qm31 = core.fields.packed_qm31;
const canonic = core.poly.circle.canonic;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const PackedM31 = m31.PackedM31;
const PackedQM31 = packed_qm31.PackedQM31;
const Component = prover.air.component_prover.ComponentProver;
const BaseProgram = prover.air.component_prover.OwnedBasePolynomialProgram;
const LookupProgram = prover.air.component_prover.OwnedLookupPolynomialProgram;
const LookupProgramV2 = prover.air.component_prover.OwnedLookupPolynomialProgramV2;
const LookupAuthorityV2 = prover.air.component_prover.LookupPolynomialAuthorityV2;
const Poly = prover.air.component_prover.Poly;
const Trace = prover.air.component_prover.Trace;
const Accumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const ColumnAccumulator = prover.air.accumulation.ColumnAccumulator;
const PreparedDomainEvaluation = prover.air.prepared_domain.PreparedDomainEvaluation;
const TaskContext = prover.task_graph.TaskContext;

const evaluate = composition.evaluate;
const evaluateWithExecution = composition.evaluateWithExecution;
const telemetrySnapshot = composition.telemetrySnapshot;

fn denominatorScalars(eval_log_size: u32) ![2]M31 {
    if (eval_log_size == 0) return error.InvalidCompositionLogSize;
    const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
    const trace_coset = canonic.CanonicCoset.new(eval_log_size - 1).coset();
    var result: [2]M31 = undefined;
    for (&result, 0..) |*inverse, index| {
        inverse.* = try constraints.cosetVanishing(
            M31,
            trace_coset,
            eval_domain.at(core.utils.bitReverseIndex(index, 1)),
        ).inv();
    }
    return result;
}

test "cpu RISC-V composition: packed secure arithmetic matches scalar QM31" {
    const Helpers = struct {
        fn pack(values: [m31.PACK_WIDTH]QM31) PackedQM31 {
            var coordinates: [qm31.SECURE_EXTENSION_DEGREE]PackedM31 = .{
                @splat(0), @splat(0), @splat(0), @splat(0),
            };
            for (values, 0..) |value, lane| {
                const scalar = value.toM31Array();
                inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                    coordinates[coordinate][lane] = scalar[coordinate].v;
                }
            }
            return .{
                .c0 = .{ .a = coordinates[0], .b = coordinates[1] },
                .c1 = .{ .a = coordinates[2], .b = coordinates[3] },
            };
        }

        fn expectEqual(expected: [m31.PACK_WIDTH]QM31, actual: PackedQM31) !void {
            const coordinates = actual.coordinates();
            for (expected, 0..) |value, lane| {
                const unpacked = QM31.fromM31(
                    M31.fromCanonical(coordinates[0][lane]),
                    M31.fromCanonical(coordinates[1][lane]),
                    M31.fromCanonical(coordinates[2][lane]),
                    M31.fromCanonical(coordinates[3][lane]),
                );
                try std.testing.expect(value.eql(unpacked));
            }
        }
    };

    var lhs: [m31.PACK_WIDTH]QM31 = undefined;
    var rhs: [m31.PACK_WIDTH]QM31 = undefined;
    var products: [m31.PACK_WIDTH]QM31 = undefined;
    var base_products: [m31.PACK_WIDTH]QM31 = undefined;
    const base = M31.fromCanonical(17);
    for (0..m31.PACK_WIDTH) |lane| {
        const value: u32 = @intCast(lane + 1);
        lhs[lane] = QM31.fromU32Unchecked(value, value + 2, value + 4, value + 6);
        rhs[lane] = QM31.fromU32Unchecked(value + 8, value + 10, value + 12, value + 14);
        products[lane] = lhs[lane].mul(rhs[lane]);
        base_products[lane] = lhs[lane].mulM31(base);
    }
    try Helpers.expectEqual(products, Helpers.pack(lhs).mul(Helpers.pack(rhs)));
    try Helpers.expectEqual(
        base_products,
        Helpers.pack(lhs).mulBase(m31.splatPacked(base)),
    );
}
