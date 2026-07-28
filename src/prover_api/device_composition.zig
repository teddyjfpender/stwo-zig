//! Stable, per-proof contract for an optional device composition stage.
//!
//! The callback is deliberately type-erased at the result boundary. The API
//! package owns the transaction shape without importing the prover's concrete
//! secure-column representation; the engine supplies correctly aligned result
//! storage and adapts it back to its implementation type.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const Stage = struct {
    context: *anyopaque,

    /// Evaluates the whole composition stage.
    ///
    /// On `true`, `result` must have been initialized with the engine result
    /// type. On `false`, `result` must remain untouched and the engine runs the
    /// host path. Errors are terminal; ordinary device refusal is `false`.
    evaluate: *const fn (
        context: *anyopaque,
        allocator: std.mem.Allocator,
        random_coeff: QM31,
        composition_log_degree_bound: u32,
        total_constraints: usize,
        trace: *const anyopaque,
        result: *anyopaque,
    ) anyerror!bool,
};

test "a device composition stage can decline without initializing a result" {
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
    var result: u8 = 0;
    const stage = Stage{ .context = &context, .evaluate = Declining.evaluate };
    try std.testing.expect(!try stage.evaluate(
        stage.context,
        std.testing.allocator,
        QM31.zero(),
        4,
        1,
        &context,
        &result,
    ));
}
