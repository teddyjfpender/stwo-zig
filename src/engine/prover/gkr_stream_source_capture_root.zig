const core = @import("stwo_core");
const baseline = @import("baseline");
test "opaque source Q proof and draw match frozen dense source" {
    try @import("lookups/stream_source_test.zig").checkWithBaseline(core.fields.qm31.QM31, baseline.ForField(core.fields.qm31.QM31), 3);
}
test "opaque source OM proof and draw match frozen dense source" {
    try @import("lookups/stream_source_test.zig").checkWithBaseline(core.fields.om31.OM31, baseline.ForField(core.fields.om31.OM31), 3);
}
