//! Generic-prover component for an authenticated captured Cairo AIR program.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_impl");
const composition = @import("../../witness/composition_bundle.zig");
const geometry = @import("../../witness/resident_geometry.zig");
const verifier_runtime = @import("../../witness/resident_verifier.zig");
const simd = @import("simd_evaluator.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const CoreComponent = core.air.components.Component;
const ComponentProver = prover.air.component_prover.ComponentProver;
const Trace = prover.air.component_prover.Trace;
const DomainAccumulator = prover.air.accumulation.DomainEvaluationAccumulator;

pub const Component = struct {
    runtime: verifier_runtime.RuntimeComponent,

    const Adapter = core.air.derive.ComponentAdapter(
        @This(),
        ComponentProver,
        Trace,
        DomainAccumulator,
    );

    pub fn init(
        allocator: std.mem.Allocator,
        captured: *const composition.Component,
        preprocessed_logs: []const u32,
        lifting_log_size: u32,
        lookup_z: QM31,
        lookup_alpha: QM31,
        claimed_sum: QM31,
    ) Component {
        return .{ .runtime = .{
            .allocator = allocator,
            .captured = captured,
            .preprocessed_logs = preprocessed_logs,
            .lifting_log_size = lifting_log_size,
            .lookup_z = lookup_z,
            .lookup_alpha = lookup_alpha,
            .claimed_sum = claimed_sum,
        } };
    }

    pub fn asProverComponent(self: *const Component) ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn asVerifierComponent(self: *const Component) CoreComponent {
        return self.runtime.asComponent();
    }

    pub fn nConstraints(self: *const Component) usize {
        return self.asVerifierComponent().nConstraints();
    }

    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        return self.asVerifierComponent().maxConstraintLogDegreeBound();
    }

    pub fn traceLogDegreeBounds(
        self: *const Component,
        allocator: std.mem.Allocator,
    ) !core.air.components.TraceLogDegreeBounds {
        return self.asVerifierComponent().traceLogDegreeBounds(allocator);
    }

    pub fn maskPoints(
        self: *const Component,
        allocator: std.mem.Allocator,
        point: Point,
        max_log_degree_bound: u32,
    ) !core.air.components.MaskPoints {
        return self.asVerifierComponent().maskPoints(
            allocator,
            point,
            max_log_degree_bound,
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const Component,
        allocator: std.mem.Allocator,
    ) ![]usize {
        return self.asVerifierComponent().preprocessedColumnIndices(allocator);
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const Component,
        point: Point,
        mask: *const core.air.components.MaskValues,
        accumulator: *core.air.accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        return self.asVerifierComponent().evaluateConstraintQuotientsAtPoint(
            point,
            mask,
            accumulator,
            max_log_degree_bound,
        );
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const Component,
        trace: *const Trace,
        accumulator: *DomainAccumulator,
    ) !void {
        const captured = self.runtime.captured;
        const requests = [_]prover.air.accumulation.ColumnRequest{.{
            .log_size = captured.evaluation_log_size,
            .n_cols = captured.n_constraints,
        }};
        const columns = try accumulator.columns(accumulator.allocator, &requests);
        defer accumulator.allocator.free(columns);
        const column = &columns[0];

        const parameters = try self.runtime.extensionParameters();
        defer self.runtime.allocator.free(parameters);
        const coefficients = try orderedCoefficients(
            accumulator.allocator,
            column.random_coeff_powers,
        );
        defer accumulator.allocator.free(coefficients);
        const context = TraceContext{
            .trace = trace,
            .captured = captured,
            .evaluation_log_size = captured.evaluation_log_size,
        };
        for (captured.parts) |part| {
            try simd.evaluatePart(
                accumulator.allocator,
                part.program,
                .{
                    .evaluation_log_size = captured.evaluation_log_size,
                    .trace_log_size = captured.trace_log_size,
                    .trace = .{ .context = &context, .read = readTrace },
                    .extension_parameters = parameters,
                    .random_coefficients = coefficients,
                    .constraint_base = part.rc_base,
                    .denominator_inverses = captured.denominator_inverses,
                },
                column,
            );
        }
    }
};

const TraceContext = struct {
    trace: *const Trace,
    captured: *const composition.Component,
    evaluation_log_size: u32,
};

fn readTrace(
    raw_context: *const anyopaque,
    interaction: u8,
    local_column: u32,
    row: usize,
    offset: i32,
) !simd.PackedM31 {
    const context: *const TraceContext = @ptrCast(@alignCast(raw_context));
    if (context.trace.polys.items.len < 3) return error.InvalidTraceShape;
    const column = switch (interaction) {
        0 => blk: {
            if (local_column >= context.captured.preprocessed_indices.len)
                return error.InvalidTraceShape;
            const global = context.captured.preprocessed_indices[local_column];
            if (global >= context.trace.polys.items[0].len)
                return error.InvalidTraceShape;
            break :blk context.trace.polys.items[0][global];
        },
        1, 2 => blk: {
            const span = try geometry.componentSpan(
                context.captured.*,
                interaction,
            );
            const global = std.math.add(
                usize,
                span.start,
                local_column,
            ) catch return error.InvalidTraceShape;
            if (global >= span.end or global >= context.trace.polys.items[interaction].len)
                return error.InvalidTraceShape;
            break :blk context.trace.polys.items[interaction][global];
        },
        else => return error.InvalidTraceShape,
    };

    var values: simd.PackedM31 = undefined;
    inline for (0..simd.lane_count) |lane| {
        const position = row + lane;
        const shifted = if (offset == 0)
            position
        else
            core.utils.offsetBitReversedCircleDomainIndex(
                position,
                context.captured.trace_log_size,
                context.evaluation_log_size,
                offset,
            );
        const value: M31 = try column.valueAtLiftingPosition(
            context.evaluation_log_size,
            shifted,
        );
        values[lane] = value.toU32();
    }
    return values;
}

fn orderedCoefficients(
    allocator: std.mem.Allocator,
    powers: []const QM31,
) ![]QM31 {
    const output = try allocator.alloc(QM31, powers.len);
    for (output, 0..) |*value, index| {
        value.* = powers[powers.len - 1 - index];
    }
    return output;
}

test "Cairo coefficients preserve point-accumulator order" {
    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
    };
    const ordered = try orderedCoefficients(std.testing.allocator, &values);
    defer std.testing.allocator.free(ordered);
    try std.testing.expect(ordered[0].eql(values[2]));
    try std.testing.expect(ordered[1].eql(values[1]));
    try std.testing.expect(ordered[2].eql(values[0]));
}
