//! External exact pre-change capture; baseline source is supplied by the command.
pub const baseline = @import("baseline");
test {
    _ = @import("lookups/owned_fold_test.zig");
    _ = @import("lookups/eq_parallel_test.zig");
    _ = @import("lookups/gkr_interpolation_test.zig");
    _ = @import("lookups/packed_rows_test.zig");
    _ = @import("lookups/parallel_rows_test.zig");
}

test "explicit pinned scalar Q baseline capture" {
    const S = @import("stwo_core").fields.qm31.QM31;
    try @import("lookups/parallel_rows_test.zig").exerciseWithBaseline(S, baseline.ForField(S));
}
test "explicit pinned scalar OM baseline capture" {
    const S = @import("stwo_core").fields.om31.OM31;
    try @import("lookups/parallel_rows_test.zig").exerciseWithBaseline(S, baseline.ForField(S));
}
