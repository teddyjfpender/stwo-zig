//! Stable, per-proof contract for an optional device composition stage.
//!
//! The callback is deliberately type-erased at the result boundary. The API
//! package owns the transaction shape without importing the prover's concrete
//! secure-column representation; the engine supplies correctly aligned result
//! storage and adapts it back to its implementation type.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const Stage = StageFor(QM31);
pub const Om31Stage = StageFor(@import("stwo_core").fields.om31.OM31);

pub fn StageFor(comptime Secure: type) type {
    return struct {
        context: *anyopaque,

        /// Evaluates the whole composition stage.
        ///
        /// On `true`, `result` must have been initialized with the engine result
        /// type. On `false`, `result` must remain untouched and the engine runs the
        /// host path. Errors are terminal; ordinary device refusal is `false`.
        evaluate: *const fn (
            context: *anyopaque,
            allocator: std.mem.Allocator,
            random_coeff: Secure,
            composition_log_degree_bound: u32,
            total_constraints: usize,
            trace: *const anyopaque,
            result: *anyopaque,
        ) anyerror!bool,
    };
}

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

/// Earlier resident boundary: evaluate, GPU interpolate/split, and commit the
/// composition tree without constructing a host polynomial. The callback owns
/// returned descriptors and device coefficients until the proof returns.
/// This requires the native device PCS stage; errors are terminal.
pub const ResidentOm31Stage = struct {
    context: *anyopaque,
    evaluate_and_commit: *const fn (
        *anyopaque,
        std.mem.Allocator,
        @import("stwo_core").fields.om31.OM31,
        u32,
        u32,
        usize,
        *const anyopaque,
    ) anyerror!@import("device_pcs.zig").Tree,
};

pub fn validateResidentTree(tree: @import("device_pcs.zig").Tree, log: u32, split: u32) !void {
    if (split < 1 or split > 2 or log > 28 or log <= split + 1) return error.InvalidResidentCompositionTree;
    const count = @as(usize, 8) << @intCast(split);
    if (tree.columns.len != count) return error.InvalidResidentCompositionTree;
    var owner: ?u64 = null;
    for (tree.columns) |column| {
        const device = column.device orelse return error.ResidentCompositionHostColumn;
        if (column.log_size != log - split or column.coefficients.len != 0 or device.context_token == 0 or device.generation == 0 or device.count != @as(u64, 1) << @intCast(column.log_size)) return error.InvalidResidentCompositionTree;
        if (owner) |token| {
            if (device.context_token != token) return error.InvalidResidentCompositionTree;
        } else owner = device.context_token;
    }
}
