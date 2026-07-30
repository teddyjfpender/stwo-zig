//! Per-proof injection point for a whole-stage device composition evaluator.
//!
//! `ComponentProvers.computeCompositionEvaluationForBackend` already dispatches
//! an optional accelerator through the proof's backend *type*, which keeps CPU
//! and Metal proofs isolated when they run concurrently in one process. That
//! mechanism cannot carry a Cairo-specific evaluator: the Metal backend module
//! does not — and must not — know what a captured Cairo AIR program is.
//!
//! This is the other half of the same discipline. The stage is a value carried
//! on `ProveOptions`, so it is scoped to exactly one `prove` call, it is
//! supplied by whoever owns both the frontend types and the backend runtime
//! (`integrations/cairo_metal`), and no process-global hook participates in
//! dispatch. A proof that was given no stage behaves exactly as before.
//!
//! ## The fail-closed contract, which is the reason for the `?` in the return
//!
//! `evaluate` returns `false` to **decline**, and declining is not an error: the
//! caller then runs the unchanged host composition path for the whole stage.
//! Implementations must convert every internal refusal — an unauthenticated
//! library, an unresolvable kernel, an arena that will not plan, a device error
//! — into a decline, and must count it so that a proof which fell back cannot
//! report itself as fully accelerated. An error returned from `evaluate` is
//! therefore a *bug*, not a fallback, and propagates.

const std = @import("std");
const qm31 = @import("stwo_core").fields.qm31;
const api = @import("stwo_prover_api").device_composition;
const secure_column = @import("../secure_column.zig");

const QM31 = qm31.QM31;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;

/// The trace type is threaded as an opaque pointer so this module does not
/// depend on `component_prover.zig`, which depends on the accumulator that
/// implementations of this interface need. The concrete pointee is
/// `component_prover.Trace`; the only producer is the composition stage in
/// `prove.zig` and the only consumers are frontend-owned stages that already
/// name that type.
pub const Stage = api.Stage;

/// Everything the stage needs, grouped so the call site stays one statement.
pub const Inputs = struct {
    allocator: std.mem.Allocator,
    random_coeff: QM31,
    composition_log_degree_bound: u32,
    total_constraints: usize,
    trace: *const anyopaque,
};

/// Consults `stage` if there is one. `null` in, `null` out.
pub fn tryStage(stage: ?Stage, inputs: Inputs) anyerror!?SecureColumnByCoords {
    const ready = stage orelse return null;
    var result: SecureColumnByCoords = undefined;
    const evaluated = try ready.evaluate(
        ready.context,
        inputs.allocator,
        inputs.random_coeff,
        inputs.composition_log_degree_bound,
        inputs.total_constraints,
        inputs.trace,
        &result,
    );
    return if (evaluated) result else null;
}

test "an absent stage is a no-op" {
    try std.testing.expect((try tryStage(null, .{
        .allocator = std.testing.allocator,
        .random_coeff = QM31.zero(),
        .composition_log_degree_bound = 4,
        .total_constraints = 1,
        .trace = &@as(u8, 0),
    })) == null);
}

test "a stage that declines is representable and returns null" {
    const Declining = struct {
        fn evaluate(
            _: *anyopaque,
            _: std.mem.Allocator,
            _: QM31,
            _: u32,
            _: usize,
            _: *const anyopaque,
            _: *anyopaque,
        ) anyerror!bool {
            return false;
        }
    };
    var context: u8 = 0;
    const stage = Stage{ .context = &context, .evaluate = Declining.evaluate };
    try std.testing.expect((try tryStage(stage, .{
        .allocator = std.testing.allocator,
        .random_coeff = QM31.zero(),
        .composition_log_degree_bound = 4,
        .total_constraints = 1,
        .trace = &context,
    })) == null);
}
