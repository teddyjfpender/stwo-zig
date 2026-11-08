//! Explicit independent frozen-source protocol capture; command supplies baseline.
const core = @import("stwo_core");
const baseline = @import("baseline");
test {
    _ = @import("lookups/lazy_checkpoint_test.zig");
}
test "lazy checkpoint pinned original Q proof and next draw match all worker counts" {
    try @import("lookups/parallel_rows_test.zig").exerciseCheckpointWithBaseline(core.fields.qm31.QM31, baseline.ForField(core.fields.qm31.QM31));
}
test "lazy checkpoint pinned original OM proof and next draw match all worker counts" {
    try @import("lookups/parallel_rows_test.zig").exerciseCheckpointWithBaseline(core.fields.om31.OM31, baseline.ForField(core.fields.om31.OM31));
}
