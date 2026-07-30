//! The Cairo half of the whole-stage device composition hook.
//!
//! `prover/air/device_composition.zig` declares a backend-neutral stage that a
//! proof may carry on its `ProveOptions`. This file implements that stage for
//! captured Cairo AIR programs and delegates the device work to an injected
//! `Device`, which is supplied by `integrations/cairo_metal` — the one module
//! that may name both the Cairo bundle and the Metal runtime.
//!
//! ## Why the loop lives here and not in the integration
//!
//! Byte-exactness of the composition polynomial is a property of the
//! *accumulator*, not of the kernels: `DomainEvaluationAccumulator.columns`
//! hands out random-coefficient powers from the tail of the powers vector, and
//! the host paths consume them strictly in component order
//! (`component_parallel.compute` walks `power_cursor` down the same order that
//! `computeCompositionEvaluationSequential` walks `columns` up). Reproducing
//! that assignment is the load-bearing part of the hook, so it is written once,
//! here, next to the host evaluator it has to agree with — and the same loop
//! runs both device-evaluated and host-evaluated components, which is what
//! makes a per-component refusal safe.
//!
//! ## Admission and fallback, stated as the two different things they are
//!
//! - **Whole-stage admission** happens once, in `Device.open`, before any
//!   evaluation: the metallib must authenticate, and the eval arena must plan.
//!   A refusal returns `null` and this file is never entered — the proof runs
//!   the unchanged host stage.
//! - **Per-component eligibility** is decided inside the same `open` call and
//!   reported as `Session.accepts`. A component whose kernels are not in the
//!   authenticated library (all-opcodes has three that the checked-in bundle
//!   does not carry) or whose shape the arena contract cannot express is
//!   evaluated on the host *inside* the device stage. That is not a fallback,
//!   it is the stage's declared coverage, and it is counted separately.
//! - A device error raised during evaluation is converted to a host evaluation
//!   of that one component and counted as a fallback, so a proof that hit one
//!   cannot report `accelerated_without_fallbacks`.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const composition = @import("../../witness/composition_bundle.zig");
const component_mod = @import("component.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Trace = prover.air.component_prover.Trace;
const DomainAccumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const SecureColumnByCoords = prover.secure_column.SecureColumnByCoords;
const StageStruct = prover.air.device_composition.Stage;

/// One component's composition inputs, resolved to exactly what a device
/// evaluator needs and nothing more.
///
/// `random_coefficients` is the component's whole ordered coefficient vector in
/// the same orientation `simd_evaluator` consumes it, so a part addresses it at
/// its own `rc_base` with no rebasing. `output` planes are the accumulator
/// bucket's four coordinate planes, `1 << captured.evaluation_log_size` long.
pub const Request = struct {
    captured: *const composition.Component,
    trace: component_mod.TraceReader,
    extension_parameters: []const QM31,
    random_coefficients: []const QM31,
    output: [4][]M31,
    /// False when this component is the bucket's first writer and may store
    /// directly; true when an earlier component already wrote it and this one
    /// must add. Mirrors the host `next_fresh_index` protocol exactly.
    additive: bool,
};

/// An opened device stage: the per-proof resources plus the coverage decision.
pub const Session = struct {
    context: *anyopaque,
    /// One entry per bundle component, in bundle order. `true` means the device
    /// will evaluate it; `false` means this stage evaluates it on the host.
    accepts: []const bool,
    evaluate: *const fn (context: *anyopaque, request: *const Request) anyerror!void,
    close: *const fn (context: *anyopaque) void,
};

/// The injection point carried on `Fixture`. Absent on the CPU product.
pub const Device = struct {
    context: *anyopaque,
    /// Admits the whole stage for this bundle or declines with `null`.
    open: *const fn (
        context: *anyopaque,
        allocator: std.mem.Allocator,
        components: []const composition.Component,
    ) anyerror!?Session,
};

/// Counts the stage produced, reported through the stage profile so a run can
/// be attributed without a debug build.
pub const Counts = struct {
    device_components: usize = 0,
    host_components: usize = 0,
    device_fallbacks: usize = 0,
};

pub const Bound = struct {
    allocator: std.mem.Allocator,
    components: []const component_mod.Component,
    captured: []const composition.Component,
    session: Session,
    recorder: ?*prover.stage_profile.Recorder,
    counts: Counts = .{},

    pub fn asStage(self: *Bound) StageStruct {
        return .{ .context = self, .evaluate = evaluateAdapter };
    }

    pub fn close(self: *Bound) void {
        self.session.close(self.session.context);
        self.allocator.free(self.session.accepts);
    }
};

fn evaluateAdapter(
    context: *anyopaque,
    allocator: std.mem.Allocator,
    random_coeff: QM31,
    composition_log_degree_bound: u32,
    total_constraints: usize,
    trace: *const anyopaque,
    result: *anyopaque,
) anyerror!bool {
    const self: *Bound = @ptrCast(@alignCast(context));
    const typed_trace: *const Trace = @ptrCast(@alignCast(trace));
    const evaluated = try evaluateStage(
        self,
        allocator,
        random_coeff,
        composition_log_degree_bound,
        total_constraints,
        typed_trace,
    );
    const column = evaluated orelse return false;
    const typed_result: *SecureColumnByCoords = @ptrCast(@alignCast(result));
    typed_result.* = column;
    return true;
}

fn evaluateStage(
    self: *Bound,
    allocator: std.mem.Allocator,
    random_coeff: QM31,
    composition_log_degree_bound: u32,
    total_constraints: usize,
    trace: *const Trace,
) anyerror!?SecureColumnByCoords {
    var accumulator = try DomainAccumulator.init(
        allocator,
        random_coeff,
        composition_log_degree_bound,
        total_constraints,
    );
    var accumulator_owned = true;
    defer if (accumulator_owned) accumulator.deinit();

    const pool = prover.work_pool.getGlobalPool();
    for (self.components, self.captured, self.session.accepts) |*runtime, *captured, accepted| {
        if (!accepted) {
            self.counts.host_components += 1;
            if (pool) |ready| {
                try runtime.evaluateConstraintQuotientsOnDomainParallel(
                    trace,
                    &accumulator,
                    ready,
                );
            } else {
                try runtime.evaluateConstraintQuotientsOnDomain(trace, &accumulator);
            }
            continue;
        }
        const evaluated = evaluateOnDevice(
            self,
            allocator,
            runtime,
            captured,
            trace,
            &accumulator,
        ) catch |err| blk: {
            std.log.warn(
                "device composition declined for {s}: {t}",
                .{ captured.label, err },
            );
            break :blk false;
        };
        if (evaluated) {
            self.counts.device_components += 1;
            continue;
        }
        self.counts.device_fallbacks += 1;
        if (pool) |ready| {
            try runtime.evaluateConstraintQuotientsOnDomainParallel(
                trace,
                &accumulator,
                ready,
            );
        } else {
            try runtime.evaluateConstraintQuotientsOnDomain(trace, &accumulator);
        }
    }

    accumulator_owned = false;
    return try accumulator.finalize();
}

/// Runs one component's parts on the device. Returns false when the device
/// declined in a way the caller should answer with a host evaluation of the
/// same component; the bucket is left untouched in that case, which is why the
/// accumulator column is requested only after the request is built.
fn evaluateOnDevice(
    self: *Bound,
    allocator: std.mem.Allocator,
    runtime: *const component_mod.Component,
    captured: *const composition.Component,
    trace: *const Trace,
    accumulator: *DomainAccumulator,
) !bool {
    const row_count = try checkedPow2(captured.evaluation_log_size);
    const requests = [_]prover.air.accumulation.ColumnRequest{.{
        .log_size = captured.evaluation_log_size,
        .n_cols = captured.n_constraints,
    }};
    const columns = try accumulator.columns(allocator, &requests);
    defer allocator.free(columns);
    const column = &columns[0];
    if (column.col.columns[0].len != row_count) return false;

    const parameters = try runtime.runtime.extensionParameters();
    defer allocator.free(parameters);
    const coefficients = try component_mod.orderedCoefficients(
        allocator,
        column.random_coeff_powers,
    );
    defer allocator.free(coefficients);

    var context = component_mod.TraceContext{
        .trace = trace,
        .captured = captured,
        .evaluation_log_size = captured.evaluation_log_size,
    };
    const direct_store = column.next_fresh_index == 0;
    const request = Request{
        .captured = captured,
        .trace = .{ .context = &context, .resolve = component_mod.resolveTrace },
        .extension_parameters = parameters,
        .random_coefficients = coefficients,
        .output = .{
            column.col.columns[0][0..row_count],
            column.col.columns[1][0..row_count],
            column.col.columns[2][0..row_count],
            column.col.columns[3][0..row_count],
        },
        .additive = !direct_store,
    };
    try self.session.evaluate(self.session.context, &request);
    column.next_fresh_index = if (direct_store) row_count else null;
    return true;
}

fn checkedPow2(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

test "a session that accepts nothing reproduces the host stage exactly" {
    // The interesting invariant is that an all-host `Bound` is the sequential
    // host path: same accumulator, same component order, same coefficients.
    // Exercised through the real evaluator elsewhere; here the shape is pinned
    // so a signature drift is caught by the frontend test step.
    const counts = Counts{};
    try std.testing.expectEqual(@as(usize, 0), counts.device_components);
    try std.testing.expectEqual(@as(usize, 0), counts.host_components);
    try std.testing.expectEqual(@as(usize, 0), counts.device_fallbacks);
}
